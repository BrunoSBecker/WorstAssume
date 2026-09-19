"""
cross_account_gate.py — shared cross-account access gate.

AWS evaluates cross-account access from both sides: the caller's identity policy
must allow the action *and* the target's resource-based policy must admit the
caller. An ``s3:*`` grant in account B says nothing about a bucket in account A.
Same-account access needs only the identity policy, so it passes straight through.

This module holds the single implementation of that rule so both engines agree:
  * reverse_index.py  — the demand-driven "who can reach this asset?" engine
  * attack_graph.py   — the forward BFS attack-path engine (via a lazy import)

Only ``_can_do`` from iam_actions is imported, so this module has no cycle with
either engine.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from worstassume.core.iam_actions import _can_do

if TYPE_CHECKING:
    from worstassume.core.threat_model import Accessor


#: Families whose grant *is* the target-side policy, so they are valid across
#: account boundaries on their own.
#: ``runs_as`` and ``network`` are same-account by construction — an execution
#: role and a VPC membership cannot span accounts — so they never need the
#: resource-policy confirmation the identity/abuse families do.
_RESOURCE_SIDE_FAMILIES = frozenset({
    "resource_policy", "trust_policy", "runs_as", "network",
})

#: Abuse edge types backed by the target role's trust policy (or by the
#: cross-account link table, which is itself built from trust statements).
#: Every other abuse edge is identity-side only and needs the same
#: cross-account confirmation as an identity-policy grant.
_TRUST_BACKED_EDGE_TYPES = frozenset({"assume_role", "cross_account_assume"})


@dataclass(frozen=True)
class GateEdge:
    """Minimal edge shape the gate reads (family / edge_type / action).

    Both ``reverse_index.InboundEdge`` and this dataclass satisfy the gate's
    duck-typed contract. Forward-engine callers use ``GateEdge`` so they can gate
    an edge without importing the reverse engine's richer result shapes.
    """
    family: str
    edge_type: str
    action: str


def _edge_actions(action: str) -> list[str]:
    """Pull IAM action names out of an edge's action string.

    Edge actions are human-facing and vary: a comma-joined list, a single
    action, "iam:PassRole + lambda:CreateFunction", or prose like
    "http://169.254.169.254/ (IMDSv1)". Only service:Action tokens are usable.
    """
    out = []
    for part in action.replace(" + ", ",").split(","):
        tok = part.strip()
        if tok.count(":") == 1 and " " not in tok and tok[0].isalpha():
            out.append(tok)
    return out


class _CrossAccountGate:
    """Decides whether a neighbour in another account can really reach the target.

    AWS evaluates cross-account access from both sides: the caller's identity
    policy must allow the action *and* the target's resource-based policy must
    admit the caller. An `s3:*` grant in account B says nothing about a bucket in
    account A. Same-account access needs only the identity policy, so it passes
    straight through.

    Two kinds of edge are exempt because the grant they represent already *is*
    the target-side policy: the resource_policy / trust_policy families, and the
    trust-backed assume-role edges (whose whole basis is the target role's own
    trust policy).

    The gate only applies to targets we actually enumerated. For those, an
    absent policy is real evidence — the S3 and Lambda collectors record the
    negative explicitly, and EC2/ECS/VPC have no resource-policy concept, so
    cross-account access genuinely is impossible. For an ARN we never collected
    we know nothing, and guessing "denied" would hide real exposure.
    """

    __slots__ = ("target_account", "have_evidence", "_grants")

    def __init__(self, target_account: str | None, respol: "list[Accessor]",
                 have_evidence: bool) -> None:
        self.target_account = target_account
        # False when the target is not in our catalogue: we then hold no
        # resource-policy evidence either way, and "we did not enumerate it" is
        # not the same as "it denies everyone".
        self.have_evidence = have_evidence
        # Admitted principal key -> the actions that key is admitted *for*.
        # Action granularity matters: a Lambda policy that lets another account
        # call InvokeFunction does not let it call UpdateFunctionCode, and
        # treating admission as all-or-nothing turns one into the other.
        self._grants: dict[str, list[str]] = {}
        for a in respol:
            self._grants.setdefault(a.arn, []).extend(a.actions or ["*"])

    def _admitted(self, arn: str, account_id: str) -> list[str]:
        """Action patterns the target's policy admits for this principal."""
        pats = list(self._grants.get("*", ()))
        pats += self._grants.get(arn, ())
        # A ":root" entry admits every principal in that account; an exact
        # principal ARN admits only itself.
        pats += self._grants.get(f"arn:aws:iam::{account_id}:root", ())
        return pats

    def _exempt(self, account_id: str | None, edge) -> bool:
        if not self.have_evidence:
            return True
        if not self.target_account or not account_id:
            return True  # unknown ownership — cannot judge, so do not hide
        if account_id == self.target_account:
            return True
        if edge.family in _RESOURCE_SIDE_FAMILIES:
            return True
        return edge.edge_type in _TRUST_BACKED_EDGE_TYPES

    def allows(self, arn: str, account_id: str | None, edge) -> bool:
        if self._exempt(account_id, edge):
            return True
        pats = self._admitted(arn, account_id)
        if not pats:
            return False
        wanted = _edge_actions(edge.action)
        if not wanted:
            # No parseable action (e.g. "ECS task metadata endpoint") — fall
            # back to plain admission rather than guessing.
            return True
        granted = set(pats)
        return any(_can_do(granted, w) for w in wanted)

    def admitted_subset(self, arn: str, account_id: str | None,
                        actions: list[str]) -> list[str]:
        """Narrow an identity-policy grant to what the target also admits.

        Same-account grants pass through untouched. Cross-account, only the
        actions the resource policy actually allows survive, so the reason shown
        to the analyst is the real one rather than the caller's whole wish list.
        """
        if self._exempt(account_id, GateEdge(
                family="identity_policy", edge_type="identity_policy",
                action="")):
            return actions
        granted = set(self._admitted(arn, account_id))
        if not granted:
            return []
        return [a for a in actions if _can_do(granted, a)]
