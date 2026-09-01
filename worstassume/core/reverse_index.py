"""
reverse_index.py — demand-driven "who can reach this ARN?" engine.

The Threat Model page walks the access graph *backwards*, one hop at a time:
the analyst picks an asset, expands it to see everything that can touch it,
then expands one of those neighbours, and so on. That makes a single reverse
hop the hot path, so it has to be cheap.

Building the full forward graph and reversing it is not: on a large org it is
tens of millions of edges and minutes of work to answer a question that only
needs one node's predecessors. This module inverts each access family directly
off pre-built indexes instead.

Three families make up an inbound hop (see inbound_page):

  * identity_policy  — principals whose identity policies grant sensitive
                       actions on the target (the reverse of direct_accessors,
                       accelerated by a pre-normalized statement index).
  * resource_policy  — principals admitted by the target's own resource-based
    / trust_policy     policy or role trust policy.
  * abuse            — attack-graph edges: assume-role, PassRole, resource
                       takeover, lateral movement, cross-account links. This is
                       exactly the inverse of
                       NeighborContext.get_access_neighbors(), and is covered by
                       a parity test against build_access_graph().

Everything works in raw ARNs; the API layer maps to prefixed graph node IDs.
"""
from __future__ import annotations

import logging
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from worstassume.core.attack_graph import (
    _EXPLANATIONS,
    _abuse_rule_matches_resource,
    _PASSROLE_SERVICE_TRUST,
    _PASSROLE_TABLE,
    _RESOURCE_ABUSE_TABLE,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    NeighborContext,
    _abuse_edge_action,
    _abuse_rule_allowed,
    _normalize_stmts,
)
from worstassume.core.iam_actions import (
    _can_do,
    _is_dangerous_action_set,
    _resource_matches,
)
from worstassume.core.threat_model import (
    Accessor,
    _account_of,
    _candidate_actions,
    identity_access_applies,
    _effective_identity_statements,
    _statement_grants,
    resource_policy_accessors,
)
from worstassume.db.models import Principal

log = logging.getLogger(__name__)

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

#: Families accepted by inbound_page(); also the default set.
FAMILIES = ("identity_policy", "resource_policy", "abuse", "runs_as", "network")

#: Default page size for one expansion — small enough to keep a graph readable.
DEFAULT_LIMIT = 50

#: Network membership is capped separately: one VPC holds ~600 security groups,
#: and _score() ranks by IAM danger, which says nothing useful about a subnet.
NETWORK_LIMIT = 40

#: Families whose grant *is* the target-side policy, so they are valid across
#: account boundaries on their own.
#: `runs_as` and `network` are same-account by construction — an execution role
#: and a VPC membership cannot span accounts — so they never need the
#: resource-policy confirmation the identity/abuse families do.
_RESOURCE_SIDE_FAMILIES = frozenset({
    "resource_policy", "trust_policy", "runs_as", "network",
})

#: Abuse edge types backed by the target role's trust policy (or by the
#: cross-account link table, which is itself built from trust statements).
#: Every other abuse edge is identity-side only and needs the same
#: cross-account confirmation as an identity-policy grant.
_TRUST_BACKED_EDGE_TYPES = frozenset({"assume_role", "cross_account_assume"})


#: Human-facing labels for the topology edge types.
_NETWORK_LABELS = {
    "in_vpc": "in VPC", "in_subnet": "in subnet", "uses_sg": "uses security group",
}


def _worst(severities) -> str:
    sevs = [s for s in severities if s]
    if not sevs:
        return "MEDIUM"
    return min(sevs, key=lambda s: _SEV_ORDER.get(s, 9))


# ── Result shapes ────────────────────────────────────────────────────────────

@dataclass
class InboundEdge:
    """One reason a neighbour can reach the target."""
    family: str                 # identity_policy | resource_policy | trust_policy | abuse
    edge_type: str
    action: str
    severity: str
    explanation: str = ""
    detail: str | None = None


@dataclass
class InboundNeighbor:
    arn: str
    label: str
    node_type: str              # principal | resource | service | external | wildcard
    principal_type: str | None
    service: str | None
    resource_type: str | None
    account_id: str | None
    external: bool
    worst_severity: str
    score: int
    edges: list[InboundEdge] = field(default_factory=list)


@dataclass
class InboundPage:
    node: dict
    neighbors: list[InboundNeighbor]
    total_found: int
    returned: int
    truncated: bool
    #: Cross-account principals dropped because nothing on the target's side
    #: grants them access. Reported so the filtering is visible, not silent.
    filtered_cross_account: int = 0
    #: False for network containers (VPC, subnet, security group), where IAM
    #: identity policies are simply not how access is granted. Lets the UI
    #: explain the right lens instead of showing a bare "nothing found".
    identity_applies: bool = True
    #: The attached execution / instance-profile role, when the target has one.
    runs_as: str | None = None


# ── ReverseIndex ─────────────────────────────────────────────────────────────

class ReverseIndex:
    """Inverted views over a NeighborContext. Build once, query per hop.

    Everything here is derived from data NeighborContext already loaded, so
    construction costs a few passes over principals/resources and no DB work.
    The expensive per-action actor sets are computed lazily and memoized —
    the rule tables only reference ~20 distinct actions in total.
    """

    def __init__(self, ctx: NeighborContext,
                 known_accounts: set[str] | None = None) -> None:
        self.ctx = ctx
        self.known_accounts = known_accounts or {
            p.account.account_id for p in ctx.principals if p.account
        }

        # Only users and roles can be an actor in the access graph.
        self._actors: list[Principal] = [
            p for p in ctx.principals if p.principal_type in ("user", "role")
        ]
        self._actor_arns: set[str] = {p.arn for p in self._actors}

        self._principals_by_account: dict[str, list[Principal]] = {}
        for p in self._actors:
            if p.account:
                self._principals_by_account.setdefault(
                    p.account.account_id, []).append(p)

        # Memo for _actors_who_can()
        self._can_cache: dict[str, list[Principal]] = {}
        # Memo for _score(): scanning a principal's whole action set is
        # expensive and gets asked once per ranked neighbour.
        self._dangerous_cache: dict[str, bool] = {}

        # Invert the per-rule abuse target sets: target ARN -> rule edge_types.
        self._abuse_rules_by_target: dict[str, set[str]] = {}
        for edge_type, targets in ctx._abuse_targets_by_rule.items():
            for t in targets:
                self._abuse_rules_by_target.setdefault(t, set()).add(edge_type)
        self._abuse_rule_by_edge_type = {
            row[3]: row for row in _RESOURCE_ABUSE_TABLE
        }

        # The forward graph collapses an abuse edge onto the resource's
        # execution role, because what an attacker gains is that role's
        # credentials. That is right for privilege escalation but wrong for a
        # threat model of the resource itself: "who can overwrite this Lambda's
        # code" would otherwise have no answer at all. This second index keeps
        # the rules addressable by their *source* resource. Only inbound_page()
        # reads it, so reverse_neighbors() stays a faithful inverse of the
        # forward graph and the parity test still holds.
        self._abuse_rules_by_source: dict[str, set[str]] = {}
        for svc, rtype, _action, edge_type, _pid, _sev in _RESOURCE_ABUSE_TABLE:
            for r in ctx.resources:
                if not r.execution_role:
                    continue  # already addressable by its own ARN
                if _abuse_rule_matches_resource(edge_type, svc, rtype, r):
                    self._abuse_rules_by_source.setdefault(
                        r.arn, set()).add(edge_type)

        # Lateral-movement target sets (mirror the forward generators).
        self._ssm_lateral_targets: set[str] = {
            r.execution_role.arn for r in ctx.resources
            if r.service == "ec2" and r.execution_role
        }
        self._secret_targets: set[str] = {
            r.arn for r in ctx.resources
            if r.service in ("secretsmanager", "ssm")
        }

        # Network topology, mirroring graph_store._add_network_edges but keyed on
        # bare ARNs so this module stays independent of GraphStore. Direction is
        # member -> container, so a VPC's inbound answers "what sits in it".
        self._network_members: dict[str, list[tuple[str, str]]] = {}
        by_vpc: dict[str, str] = {}
        by_subnet: dict[str, str] = {}
        by_sg: dict[str, str] = {}
        for r in ctx.resources:
            meta = r.extra or {}
            if r.resource_type == "vpc" and meta.get("vpc_id"):
                by_vpc[meta["vpc_id"]] = r.arn
            elif r.resource_type == "subnet" and meta.get("subnet_id"):
                by_subnet[meta["subnet_id"]] = r.arn
            elif r.resource_type == "security-group" and meta.get("group_id"):
                by_sg[meta["group_id"]] = r.arn

        def _member(container_arn, member_arn, edge_type):
            if container_arn and container_arn != member_arn:
                self._network_members.setdefault(
                    container_arn, []).append((member_arn, edge_type))

        for r in ctx.resources:
            meta = r.extra or {}
            if meta.get("vpc_id") and r.resource_type != "vpc":
                _member(by_vpc.get(meta["vpc_id"]), r.arn, "in_vpc")
            if meta.get("subnet_id") and r.resource_type != "subnet":
                _member(by_subnet.get(meta["subnet_id"]), r.arn, "in_subnet")
            for gid in meta.get("security_groups") or []:
                _member(by_sg.get(gid), r.arn, "uses_sg")
            for vid in meta.get("attaches_to_vpcs") or []:
                _member(by_vpc.get(vid), r.arn, "in_vpc")

        # Identity-policy statement index — see _build_statement_index().
        self._stmts_by_principal: dict[str, list[dict]] = {}
        self._principals_by_service: dict[str, set[str]] = {}
        self._principals_any_service: set[str] = set()
        self._build_statement_index()

    # ── Memoized actor sets ──────────────────────────────────────────────

    def _actors_who_can(self, action: str) -> list[Principal]:
        """Users/roles whose effective actions grant *action*. Memoized."""
        hit = self._can_cache.get(action)
        if hit is None:
            cache = self.ctx.action_cache
            hit = [p for p in self._actors
                   if _can_do(cache.get(p.arn, frozenset()), action)]
            self._can_cache[action] = hit
        return hit

    def _actors_where(self, key: str, predicate) -> list[Principal]:
        """Like _actors_who_can but for compound predicates, memoized on *key*."""
        hit = self._can_cache.get(key)
        if hit is None:
            cache = self.ctx.action_cache
            hit = [p for p in self._actors
                   if predicate(cache.get(p.arn, frozenset()))]
            self._can_cache[key] = hit
        return hit

    # ── Identity-policy statement index ──────────────────────────────────

    def _build_statement_index(self) -> None:
        """Normalize every principal's effective statements exactly once.

        direct_accessors() otherwise re-parses every attached policy document on
        every call (Policy.document is a json.loads property), which is far too
        slow to sit behind an interactive click. Statements are additionally
        bucketed by the service prefixes they can match so a lookup only has to
        consider principals that could plausibly grant one of the candidate
        actions; the full statement list is still evaluated for those, so Deny
        and NotAction semantics are unchanged.
        """
        for p in self.ctx.principals:
            stmts = _effective_identity_statements(p)
            if not stmts:
                continue
            self._stmts_by_principal[p.arn] = stmts
            for stmt in stmts:
                svcs = _statement_services(stmt)
                if svcs is None:
                    self._principals_any_service.add(p.arn)
                    break
                for svc in svcs:
                    self._principals_by_service.setdefault(svc, set()).add(p.arn)

    def candidate_principals(self, actions: list[str]) -> set[str]:
        """Principal ARNs with at least one statement that could match *actions*."""
        arns = set(self._principals_any_service)
        for a in actions:
            svc = a.split(":", 1)[0] if ":" in a else None
            if svc is None or "*" in svc:
                return set(self._stmts_by_principal)
            arns |= self._principals_by_service.get(svc, set())
        return arns

    # ── Reverse abuse-edge expansion ─────────────────────────────────────

    def reverse_neighbors(self, arn: str) -> Iterator[tuple[str, dict[str, Any]]]:
        """Yield (predecessor_arn, edge_data) for every access edge *into* arn.

        The exact inverse of NeighborContext.get_access_neighbors(): edge_data
        carries the same keys (edge_type, path_id, action, severity,
        explanation) so downstream path rendering is unchanged.

        The defensive_blind self-loop is intentionally dropped — it is a
        property of a principal, not a route to it, and would otherwise show
        every such principal as its own inbound neighbour.
        """
        yield from self._reverse_passrole(arn)
        yield from self._reverse_resource_abuse(arn)
        yield from self._reverse_lateral(arn)

    def _reverse_passrole(self, arn: str) -> Iterator[tuple[str, dict]]:
        ctx = self.ctx
        for path_id, edge_type, extra, severity in _PASSROLE_TABLE:
            required_service = _PASSROLE_SERVICE_TRUST.get(edge_type)
            if required_service:
                if arn not in ctx.exec_roles_by_service.get(required_service, ()):
                    continue
            elif arn not in ctx._resources_by_exec_role:
                continue
            key = "passrole::" + edge_type
            actors = self._actors_where(
                key,
                lambda acts, extra=extra: (
                    _can_do(acts, "iam:PassRole")
                    and all(_can_do(acts, a) for a in extra)
                ),
            )
            if not actors:
                continue
            expl = _EXPLANATIONS.get(path_id, edge_type)
            action = "iam:PassRole + " + ", ".join(extra)
            for actor in actors:
                patterns = ctx.passrole_resource_map.get(actor.arn, ["*"])
                if not _resource_matches(arn, patterns):
                    continue
                yield actor.arn, dict(
                    edge_type=edge_type, path_id=path_id,
                    action=action, severity=severity, explanation=expl,
                )

    def _reverse_resource_abuse(self, arn: str) -> Iterator[tuple[str, dict]]:
        for edge_type in sorted(self._abuse_rules_by_target.get(arn, ())):
            svc, rtype, action, _et, path_id, severity = \
                self._abuse_rule_by_edge_type[edge_type]
            key = "abuse::" + edge_type
            actors = self._actors_where(
                key,
                lambda acts, et=edge_type, ac=action: _abuse_rule_allowed(et, ac, acts),
            )
            if not actors:
                continue
            expl = _EXPLANATIONS.get(path_id, edge_type)
            edge_action = _abuse_edge_action(edge_type, action)
            for actor in actors:
                yield actor.arn, dict(
                    edge_type=edge_type, path_id=path_id,
                    action=edge_action, severity=severity, explanation=expl,
                )

    def _reverse_lateral(self, arn: str) -> Iterator[tuple[str, dict]]:
        ctx = self.ctx

        # sts:AssumeRole — read the target role's own trust policy (O(1)).
        target_role = ctx._role_by_arn.get(arn)
        if target_role is not None:
            target_acct = target_role.account.account_id if target_role.account else ""
            for actor in self._trusted_actors(arn):
                actor_acct = actor.account.account_id if actor.account else ""
                is_cross = actor_acct != target_acct
                edge_type = "cross_account_assume" if is_cross else "assume_role"
                path_id = "PATH-031" if is_cross else "PATH-030"
                severity = SEVERITY_CRITICAL if is_cross else SEVERITY_HIGH
                yield actor.arn, dict(
                    edge_type=edge_type, path_id=path_id,
                    action="sts:AssumeRole", severity=severity,
                    explanation=_EXPLANATIONS.get(path_id, edge_type),
                )

        # ssm:SendCommand → the EC2 instance's execution role.
        if arn in self._ssm_lateral_targets:
            for actor in self._actors_who_can("ssm:SendCommand"):
                yield actor.arn, dict(
                    edge_type="ssm_lateral", path_id="PATH-032",
                    action="ssm:SendCommand", severity=SEVERITY_HIGH,
                    explanation=_EXPLANATIONS.get("PATH-032", "ssm_lateral"),
                )

        # Secret harvest → secretsmanager / ssm resources.
        if arn in self._secret_targets:
            actors = self._actors_where(
                "secret_harvest",
                lambda acts: (_can_do(acts, "secretsmanager:GetSecretValue")
                              or _can_do(acts, "ssm:GetParameter")),
            )
            for actor in actors:
                yield actor.arn, dict(
                    edge_type="secret_harvest", path_id="PATH-036",
                    action="secretsmanager:GetSecretValue",
                    severity=SEVERITY_HIGH,
                    explanation=_EXPLANATIONS.get("PATH-036", "secret_harvest"),
                )

        # Cross-account link table.
        for link in ctx._cross_links_by_role.get(arn, ()):
            src = link.trust_principal_arn
            if not src or src not in self._actor_arns:
                continue
            sev = SEVERITY_CRITICAL if link.is_wildcard else SEVERITY_HIGH
            yield src, dict(
                edge_type="cross_account_assume", path_id="PATH-031",
                action="sts:AssumeRole (cross-account)", severity=sev,
                explanation=_EXPLANATIONS.get("PATH-031", "cross_account_assume"),
            )

    def _trusted_actors(self, role_arn: str) -> list[Principal]:
        """Actors admitted by role_arn's trust policy, in deterministic order.

        Mirrors attack_graph._actor_can_assume() exactly: a wildcard Principal,
        an exact principal ARN, or the actor's account-root ARN.
        """
        trust = self.ctx._trust_cache.get(role_arn)
        if not trust:
            return []
        assumers = self._actors_who_can("sts:AssumeRole")
        matched: dict[str, Principal] = {}
        for stmt in _normalize_stmts(trust):
            if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            entries: list[str]
            if principal == "*":
                entries = ["*"]
            else:
                aws = principal.get("AWS", []) if isinstance(principal, dict) else []
                if isinstance(aws, str):
                    aws = [aws]
                entries = [a for a in aws if isinstance(a, str)]
            for entry in entries:
                if entry == "*":
                    return list(assumers)
                if entry.endswith(":root"):
                    acct = entry.split(":")[4] if len(entry.split(":")) > 4 else ""
                    for p in self._principals_by_account.get(acct, ()):
                        if _can_do(self.ctx.action_cache.get(p.arn, frozenset()),
                                   "sts:AssumeRole"):
                            matched[p.arn] = p
                    continue
                p = self.ctx._principal_by_arn.get(entry)
                if p is not None and p.arn in self._actor_arns and _can_do(
                        self.ctx.action_cache.get(p.arn, frozenset()), "sts:AssumeRole"):
                    matched[p.arn] = p
        return [matched[a] for a in sorted(matched)]

    # ── Node metadata ────────────────────────────────────────────────────

    def resolve_type(self, arn: str) -> str:
        if arn in self.ctx._principal_by_arn:
            return "principal"
        if arn in self.ctx._resource_by_arn:
            return "resource"
        return "unknown"

    def node_meta(self, arn: str, target_account: str | None = None) -> dict:
        """Display metadata for a graph node, resolved from the loaded context."""
        p = self.ctx._principal_by_arn.get(arn)
        if p is not None:
            acct = p.account.account_id if p.account else None
            return {
                "arn": arn, "node_type": "principal", "label": p.name,
                "principal_type": p.principal_type, "service": None,
                "resource_type": None, "account_id": acct,
                "external": _is_external(acct, target_account, self.known_accounts),
            }
        r = self.ctx._resource_by_arn.get(arn)
        if r is not None:
            acct = r.account.account_id if r.account else None
            return {
                "arn": arn, "node_type": "resource",
                "label": r.name or arn.split(":")[-1],
                "principal_type": None, "service": r.service,
                "resource_type": r.resource_type, "account_id": acct,
                "external": _is_external(acct, target_account, self.known_accounts),
            }
        return _unknown_node_meta(arn, target_account, self.known_accounts)

    # ── Identity-policy accessors (indexed fast path) ────────────────────

    def identity_accessors(self, target_arn: str, target_type: str,
                           actions: list[str] | None = None,
                           resource_type: str | None = None) -> list[Accessor]:
        """Same contract as threat_model.direct_accessors(), off the index.

        Only principals whose statements could match one of the candidate
        actions are evaluated; for those the *full* statement list is used, so
        Deny and NotAction handling is identical.
        """
        candidates = _candidate_actions(target_arn, target_type, actions,
                                        resource_type=resource_type)
        if not candidates:
            return []   # identity policies are not how this type is accessed
        out: list[Accessor] = []
        for arn in self.candidate_principals(candidates):
            if arn == target_arn:
                continue  # a principal is not its own accessor
            stmts = self._stmts_by_principal.get(arn)
            if not stmts:
                continue
            matched, conditional = _statement_grants(stmts, target_arn, candidates)
            if not matched:
                continue
            p = self.ctx._principal_by_arn[arn]
            out.append(Accessor(
                arn=arn,
                principal_type=p.principal_type,
                account_id=p.account.account_id if p.account else None,
                external=False,  # set relative to the target account by the caller
                via="identity_policy",
                actions=sorted(matched),
                detail="conditional (policy has Condition)" if conditional else None,
            ))
        out.sort(key=lambda a: (-len(a.actions), a.arn))
        return out

    # ── One inbound hop ──────────────────────────────────────────────────

    def inbound_page(self, target_arn: str, *,
                     families: tuple[str, ...] | list[str] = FAMILIES,
                     limit: int = DEFAULT_LIMIT,
                     offset: int = 0) -> InboundPage:
        """Everything that can reach *target_arn* in one hop, ranked and paged.

        Merges the three families, collapses parallel edges onto a single
        neighbour entry, ranks by exposure, then slices. total_found always
        reports the full pre-slice count so the UI can say "top N of M".
        """
        families = tuple(families)
        target_type = self.resolve_type(target_arn)
        node = self.node_meta(target_arn)
        target_account = node.get("account_id")
        # A node is never external relative to itself.
        node["external"] = False

        target_res = self.ctx._resource_by_arn.get(target_arn)
        target_obj = self.ctx._principal_by_arn.get(target_arn) or target_res
        resource_type = target_res.resource_type if target_res else None

        # The target's own resource-based / trust policy is needed even when the
        # caller filtered the resource_policy family out, because it is what
        # decides whether a cross-account grant is real.
        respol: list[Accessor] = []
        if target_obj is not None:
            respol, _flags = resource_policy_accessors(
                target_obj, target_type, self.known_accounts, target_account)
        gate = _CrossAccountGate(target_account, respol,
                                 have_evidence=target_obj is not None)

        acc: dict[str, InboundNeighbor] = {}
        dropped: set[str] = set()

        def _add(arn: str, edge: InboundEdge) -> None:
            if arn == target_arn:
                return  # self-edges are not a route in
            n = acc.get(arn)
            # Gate every edge, not just the first one for a neighbour: admission
            # is per-action, so a principal let in for lambda:InvokeFunction
            # must not carry an unadmitted lambda:UpdateFunctionCode edge in
            # behind it.
            meta = n or self.node_meta(arn, target_account)
            account_id = meta.account_id if n else meta["account_id"]
            if not gate.allows(arn, account_id, edge):
                if n is None:
                    dropped.add(arn)
                return
            if n is None:
                n = InboundNeighbor(
                    arn=arn, label=meta["label"], node_type=meta["node_type"],
                    principal_type=meta["principal_type"], service=meta["service"],
                    resource_type=meta["resource_type"],
                    account_id=meta["account_id"], external=meta["external"],
                    worst_severity=edge.severity, score=0,
                )
                acc[arn] = n
            n.edges.append(edge)

        if "identity_policy" in families:
            for a in self.identity_accessors(target_arn, target_type,
                                             resource_type=resource_type):
                acts = gate.admitted_subset(a.arn, a.account_id, a.actions)
                if not acts:
                    if a.account_id and a.account_id != target_account:
                        dropped.add(a.arn)
                    continue
                cross = bool(a.account_id) and a.account_id != target_account
                _add(a.arn, InboundEdge(
                    family="identity_policy", edge_type="identity_policy",
                    action=", ".join(acts), severity=_actions_severity(acts),
                    explanation=(
                        f"Identity policy grants {', '.join(acts)} on this target"
                        + (", and the target's resource policy admits this account."
                           if cross else ".")),
                    detail=a.detail,
                ))

        if "resource_policy" in families:
            for a in respol:
                _add(a.arn, InboundEdge(
                    family=a.via, edge_type=a.via,
                    action=", ".join(a.actions) or "sts:AssumeRole",
                    severity="CRITICAL" if a.arn == "*" else "HIGH",
                    explanation="The target's own policy admits this principal.",
                    detail=a.detail,
                ))

        if "abuse" in families:
            for src, data in self.reverse_neighbors(target_arn):
                _add(src, InboundEdge(
                    family="abuse", edge_type=data["edge_type"],
                    action=data["action"], severity=data["severity"],
                    explanation=data.get("explanation", ""),
                ))
            for src, data in self._abuse_on_resource(target_arn):
                _add(src, InboundEdge(
                    family="abuse", edge_type=data["edge_type"],
                    action=data["action"], severity=data["severity"],
                    explanation=data.get("explanation", ""),
                ))

        # ── runs_as ──────────────────────────────────────────────────────
        # A resource is a strictly weaker view of its own role: an EC2 instance
        # cannot show passrole_ec2 or ssm_lateral, but its instance profile can,
        # and compromising either yields the same credentials. Surface the role
        # and fold its accessors in rather than making the analyst know to go
        # look the role up separately.
        role_arn = None
        if "runs_as" in families and target_res is not None and target_res.execution_role:
            role = target_res.execution_role
            role_arn = role.arn
            _add(role_arn, InboundEdge(
                family="runs_as", edge_type="runs_as",
                action="sts:AssumeRole (service)", severity="HIGH",
                explanation=(
                    f"{target_res.resource_type or 'This resource'} runs as this role — "
                    "compromising either yields the same credentials."),
            ))
            for src, data in self.reverse_neighbors(role_arn):
                if src == target_arn:
                    continue
                _add(src, InboundEdge(
                    family="abuse", edge_type=data["edge_type"],
                    action=data["action"], severity=data["severity"],
                    explanation=data.get("explanation", ""),
                    detail=f"via {role.name}",
                ))

        # ── network ──────────────────────────────────────────────────────
        network: list[InboundNeighbor] = []
        if "network" in families:
            members = self._network_members.get(target_arn, ())
            for member_arn, edge_type in members[:NETWORK_LIMIT]:
                meta = self.node_meta(member_arn, target_account)
                network.append(InboundNeighbor(
                    arn=member_arn, label=meta["label"], node_type=meta["node_type"],
                    principal_type=meta["principal_type"], service=meta["service"],
                    resource_type=meta["resource_type"],
                    account_id=meta["account_id"], external=False,
                    worst_severity="LOW", score=-1,
                    edges=[InboundEdge(
                        family="network", edge_type=edge_type,
                        action=_NETWORK_LABELS.get(edge_type, edge_type),
                        severity="LOW",
                        explanation="Network topology, from resource metadata.",
                    )],
                ))
            network_total = len(members)
        else:
            network_total = 0

        neighbors = list(acc.values())
        for n in neighbors:
            n.worst_severity = _worst([e.severity for e in n.edges])
            n.score = self._score(n)
            n.edges.sort(key=lambda e: (_SEV_ORDER.get(e.severity, 9), e.family,
                                        e.edge_type))
        neighbors.sort(key=lambda n: (-n.score,
                                      _SEV_ORDER.get(n.worst_severity, 9), n.arn))

        total = len(neighbors)
        page = neighbors[offset:offset + limit] if limit > 0 else neighbors[offset:]
        # Network members are appended after the ranked access neighbours and
        # capped on their own, so a busy VPC cannot crowd out the access view.
        shown_network = [n for n in network if n.arn not in acc]
        page = page + shown_network
        truncated = ((offset + len(page) - len(shown_network)) < total
                     or len(shown_network) < network_total)
        return InboundPage(
            node=node, neighbors=page, total_found=total + network_total,
            returned=len(page), truncated=truncated,
            filtered_cross_account=len(dropped - set(acc)),
            identity_applies=identity_access_applies(resource_type),
            runs_as=role_arn,
        )

    def _abuse_on_resource(self, arn: str) -> Iterator[tuple[str, dict[str, Any]]]:
        """Abuse edges where *arn* is the resource being acted on.

        reverse_neighbors() answers "who ends up with this role's credentials",
        which is the privilege-escalation question. This answers "who can act on
        this resource" — for a Lambda with an execution role those are different
        nodes, and only the second one makes sense when the Lambda itself is the
        asset under review.
        """
        for edge_type in sorted(self._abuse_rules_by_source.get(arn, ())):
            _svc, _rtype, action, _et, path_id, severity = \
                self._abuse_rule_by_edge_type[edge_type]
            actors = self._actors_where(
                "abuse::" + edge_type,
                lambda acts, et=edge_type, ac=action: _abuse_rule_allowed(et, ac, acts),
            )
            expl = _EXPLANATIONS.get(path_id, edge_type)
            edge_action = _abuse_edge_action(edge_type, action)
            for actor in actors:
                yield actor.arn, dict(
                    edge_type=edge_type, path_id=path_id,
                    action=edge_action, severity=severity, explanation=expl,
                )

    def _score(self, n: InboundNeighbor) -> int:
        """Rank by how much exposure the neighbour represents.

        External identities and wildcard/root grants come first because they are
        the ones an analyst has to triage; severity only breaks the remaining
        ties.
        """
        score = 0
        if n.external:
            score += 4
        if n.arn == "*" or n.arn.endswith(":root"):
            score += 3
        if self._is_dangerous(n.arn):
            score += 2
        score += 3 - _SEV_ORDER.get(n.worst_severity, 3)
        return score

    def _is_dangerous(self, arn: str) -> bool:
        hit = self._dangerous_cache.get(arn)
        if hit is None:
            actions = self.ctx.action_cache.get(arn)
            hit = bool(actions) and _is_dangerous_action_set(actions)
            self._dangerous_cache[arn] = hit
        return hit

    # ── Multi-hop expansion ──────────────────────────────────────────────

    def expand_hops(self, target_arn: str, hops: int = 2, *,
                    families: tuple[str, ...] | list[str] = FAMILIES,
                    per_node_limit: int = DEFAULT_LIMIT,
                    node_budget: int = 300) -> list[InboundPage]:
        """Breadth-first inbound expansion, capped so it cannot flood the canvas.

        Returns one InboundPage per expanded node (including the root) so the
        caller can render nodes and edges without re-querying. Stops as soon as
        node_budget distinct ARNs have been seen.
        """
        pages: list[InboundPage] = []
        seen: set[str] = {target_arn}
        queue: deque[tuple[str, int]] = deque([(target_arn, 0)])
        while queue:
            arn, depth = queue.popleft()
            if depth >= hops:
                continue
            page = self.inbound_page(arn, families=families, limit=per_node_limit)
            kept: list[InboundNeighbor] = []
            for n in page.neighbors:
                if n.arn in seen:
                    # Already on the canvas — keep the edge, it costs no budget.
                    kept.append(n)
                    continue
                if len(seen) >= node_budget:
                    continue
                seen.add(n.arn)
                kept.append(n)
                queue.append((n.arn, depth + 1))
            dropped = len(page.neighbors) - len(kept)
            if dropped:
                log.debug("[expand_hops] node budget %d reached, dropped %d from %s",
                          node_budget, dropped, arn)
            page.neighbors = kept
            page.returned = len(kept)
            page.truncated = page.truncated or dropped > 0
            pages.append(page)
        return pages


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

    def __init__(self, target_account: str | None, respol: list[Accessor],
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

    def _exempt(self, account_id: str | None, edge: InboundEdge) -> bool:
        if not self.have_evidence:
            return True
        if not self.target_account or not account_id:
            return True  # unknown ownership — cannot judge, so do not hide
        if account_id == self.target_account:
            return True
        if edge.family in _RESOURCE_SIDE_FAMILIES:
            return True
        return edge.edge_type in _TRUST_BACKED_EDGE_TYPES

    def allows(self, arn: str, account_id: str | None, edge: InboundEdge) -> bool:
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
        if self._exempt(account_id, InboundEdge(
                family="identity_policy", edge_type="identity_policy",
                action="", severity="MEDIUM")):
            return actions
        granted = set(self._admitted(arn, account_id))
        if not granted:
            return []
        return [a for a in actions if _can_do(granted, a)]


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


# ── Module-level helpers ─────────────────────────────────────────────────────

def _is_external(account_id: str | None, target_account: str | None,
                 known_accounts: set[str]) -> bool:
    """External = belongs to an account we do not enumerate, or a different one
    from the target when the target's account is known."""
    if not account_id:
        return False
    if account_id not in known_accounts:
        return True
    return bool(target_account) and account_id != target_account


def _unknown_node_meta(arn: str, target_account: str | None,
                       known_accounts: set[str]) -> dict:
    """Metadata for an ARN that is not a loaded principal or resource — a
    wildcard, a service principal, or an identity in an un-enumerated account."""
    from worstassume.core.threat_model import _account_of, _principal_type_of

    if arn == "*":
        return {"arn": arn, "node_type": "wildcard", "label": "* (any principal)",
                "principal_type": "wildcard", "service": None,
                "resource_type": None, "account_id": None, "external": True}
    if arn.endswith(".amazonaws.com"):
        return {"arn": arn, "node_type": "service", "label": arn,
                "principal_type": "service", "service": arn.split(".")[0],
                "resource_type": None, "account_id": None, "external": False}
    acct = _account_of(arn)
    return {
        "arn": arn, "node_type": "external",
        "label": arn.split("/")[-1] or arn,
        "principal_type": _principal_type_of(arn), "service": None,
        "resource_type": None, "account_id": acct,
        "external": _is_external(acct, target_account, known_accounts),
    }


def _actions_severity(actions: list[str]) -> str:
    """Severity for an identity-policy grant, based on what it allows."""
    if _is_dangerous_action_set(set(actions)):
        return "HIGH"
    return "MEDIUM"


def _statement_services(stmt: dict) -> set[str] | None:
    """Service prefixes a normalized statement can match, or None for 'any'.

    None is returned for NotAction statements and for action strings without an
    unambiguous service prefix ("*", "s3*"), so those principals always stay in
    the candidate set rather than being wrongly filtered out.
    """
    action_set = stmt.get("action_set")
    if action_set is None:
        return None
    svcs: set[str] = set()
    for a in action_set:
        if not isinstance(a, str) or ":" not in a:
            return None
        svc = a.split(":", 1)[0]
        if "*" in svc:
            return None
        svcs.add(svc)
    return svcs or None
