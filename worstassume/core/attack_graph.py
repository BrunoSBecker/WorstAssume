"""
attack_graph.py — NetworkX MultiDiGraph builder for IAM attack paths.

Pure builder: produces a graph of principals and resources with directed
edges representing exploitable attack steps. Does not write to the DB.
Consumed by attack_path.py for traversal and path ranking.
"""
from __future__ import annotations
import logging
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
import networkx as nx
from sqlalchemy.orm import Session, joinedload
from worstassume.db.models import Account, CrossAccountLink, Principal, Resource
from worstassume.core.iam_actions import (
    _build_action_cache,
    _build_passrole_resource_map,
    _can_do,
    _resource_matches,
)
from worstassume.core.cross_account_gate import GateEdge, _CrossAccountGate

log = logging.getLogger(__name__)

# ── Severity constants (local — do NOT import from attack_chains) ─────────────
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"

# ── Human-readable explanation strings keyed by path_id ──────────────────────
# Each path_id corresponds to a specific attack technique. These strings are
# embedded in graph edges and surfaced in the web UI and persisted reports.
_EXPLANATIONS: dict[str, str] = {
    # IAM identity manipulation
    "PATH-001": "Attacker can create a new policy version with administrative permissions on any managed policy.",
    "PATH-002": "Attacker can promote an existing (potentially permissive) policy version to become the active default.",
    "PATH-003": "Attacker can attach any managed policy to any IAM user, granting arbitrary permissions.",
    "PATH-004": "Attacker can attach any managed policy to any IAM role, granting arbitrary permissions.",
    "PATH-005": "Attacker can attach any managed policy to any IAM group, granting arbitrary permissions to its members.",
    "PATH-006": "Attacker can inject an arbitrary inline policy directly into any IAM user.",
    "PATH-007": "Attacker can inject an arbitrary inline policy directly into any IAM role.",
    "PATH-008": "Attacker can inject an arbitrary inline policy directly into any IAM group.",
    "PATH-009": "Attacker can add any user to a privileged IAM group, inheriting all its permissions.",
    "PATH-010": "Attacker can replace any role's trust policy to allow any principal to assume it.",
    "PATH-011": "Attacker can create a new long-term access key for any IAM user, gaining persistent API access.",
    "PATH-012": "Attacker can create a console login profile for any IAM user that currently lacks one.",
    "PATH-013": "Attacker can overwrite any IAM user's existing console password.",
    # PassRole abuse paths
    "PATH-015": "Attacker can pass a privileged role to a new EC2 instance (ec2:RunInstances) and steal credentials via IMDS.",
    "PATH-016": "Attacker can create a Lambda function with a privileged execution role (iam:PassRole + lambda:CreateFunction) and invoke it to exfiltrate credentials.",
    "PATH-018": "Attacker can create a Lambda and attach an event source mapping so it executes under a privileged role automatically.",
    "PATH-021": "Attacker can create a Glue Dev Endpoint with a privileged IAM role attached, then SSH in to access credentials.",
    "PATH-023": "Attacker can create or update a CloudFormation stack that passes a privileged service role to managed resources.",
    "PATH-024": "Attacker can create a Data Pipeline whose activities execute under a privileged role.",
    "PATH-025": "Attacker can create a SageMaker Notebook Instance attached to a privileged role and access credentials from within it.",
    "PATH-027": "Attacker can create a CodeStar project passing a privileged role to the provisioned project resources.",
    # PR 4-C — Resource abuse + lateral movement
    "PATH-014": "Attacker can reach the EC2 IMDS endpoint (IMDSv1) from within an instance to steal the attached instance role credentials.",
    "PATH-019": "Attacker can overwrite Lambda function code to exfiltrate the execution role credentials at next invocation.",
    "PATH-020": "Attacker can update Lambda configuration (e.g. inject a malicious layer) to steal execution role credentials.",
    "PATH-022": "Attacker can update a Glue Dev Endpoint's SSH key to hijack the endpoint session and access its attached role.",
    "PATH-026": "Attacker can generate a presigned URL for an existing SageMaker notebook to hijack its session and role.",
    "PATH-030": "Attacker can assume a same-account role whose trust policy explicitly trusts their identity.",
    "PATH-031": "Attacker can assume a cross-account role whose trust policy trusts their identity, pivoting to another account.",
    "PATH-032": "Attacker can run SSM Run Command on an EC2 instance to execute code and steal the instance profile credentials.",
    "PATH-033": "Attacker can push an SSH public key to any EC2 instance via EC2 Instance Connect to gain shell access.",
    "PATH-035": "Attacker can replace an S3 bucket policy to grant themselves or an external principal access to the bucket contents.",
    "PATH-038": "Attacker can read objects from this S3 bucket (s3:GetObject) to exfiltrate its contents.",
    "PATH-039": "Attacker can list this S3 bucket (s3:ListBucket) to enumerate its objects.",
    "PATH-040": "This resource runs as the target execution role — compromising the resource yields that role's credentials.",
    "PATH-036": "Attacker can harvest plaintext credentials or secrets from Secrets Manager or SSM Parameter Store.",
    "PATH-037": "Attacker can access the ECS task metadata endpoint from within a task to steal the task's IAM role credentials.",
    "PATH-042": "Attacker can disable CloudTrail logging or delete GuardDuty detectors to blind defensive monitoring.",
}


# ── Public entry point ────────────────────────────────────────────────────────

def build_attack_graph(
    db: Session,
    account: Account | None = None,
) -> nx.MultiDiGraph:
    """Build a full attack graph for the viz server / offline analysis.

    Internally powered by NeighborContext so edge logic is shared with the
    demand-driven BFS path.  External callers see no change.
    """
    ctx = NeighborContext(db, account=account)
    G   = nx.MultiDiGraph()
    _build_nodes(G, ctx.principals, ctx.resources)
    log.debug("[attack_graph] nodes built: %d principals, %d resources",
              len(ctx.principals), len(ctx.resources))

    edge_count = 0
    for p in ctx.principals:
        if p.principal_type not in ("user", "role"):
            continue
        for neighbor_arn, edge_data in ctx.get_neighbors(p.arn):
            src = p.arn
            if src not in G or neighbor_arn not in G:
                continue
            G.add_edge(src, neighbor_arn, **edge_data)
            edge_count += 1

    # Resource -> execution-role runs_as edges (compute pivots)
    for r in ctx.resources:
        for neighbor_arn, edge_data in ctx.get_neighbors(r.arn):
            if r.arn not in G or neighbor_arn not in G:
                continue
            G.add_edge(r.arn, neighbor_arn, **edge_data)
            edge_count += 1

    log.info("[attack_graph] built: %d nodes, %d edges",
             G.number_of_nodes(), G.number_of_edges())
    return G


def build_access_graph(
    db: Session,
    account: Account | None = None,
) -> nx.MultiDiGraph:
    """Build a *sparse access/pivot* graph for reverse-reachability analysis.

    Same nodes as build_attack_graph() but only the access/pivot edge families
    (assume-role, cross-account, PassRole→compute credential-theft, resource
    abuse, lateral movement, secret harvest) — see
    NeighborContext.get_access_neighbors().

    Excludes the dense IAM-manipulation / group-membership escalation edges
    (O(P²)), so it scales to large orgs. Consumed by core/threat_model.py.
    """
    ctx = NeighborContext(db, account=account)
    G   = nx.MultiDiGraph()
    _build_nodes(G, ctx.principals, ctx.resources)

    edge_count = 0
    for p in ctx.principals:
        if p.principal_type not in ("user", "role"):
            continue
        for neighbor_arn, edge_data in ctx.get_access_neighbors(p.arn):
            if p.arn not in G or neighbor_arn not in G:
                continue
            G.add_edge(p.arn, neighbor_arn, **edge_data)
            edge_count += 1

    log.info("[access_graph] built: %d nodes, %d edges",
             G.number_of_nodes(), G.number_of_edges())
    return G


# ── NeighborContext ────────────────────────────────────────────────────────

class NeighborContext:
    """Pre-loads all DB data and caches once; exposes get_neighbors(arn).

    Used by both build_attack_graph() (full graph build for the viz server)
    and find_paths_bfs() (demand-driven traversal for the privesc command).
    No edge computation happens in __init__ — only data loading and indexing.
    """

    def __init__(self, db: Session, account: Account | None = None) -> None:
        self.principals  = _load_principals(db, account)
        self.resources   = _load_resources(db, account)
        self.cross_links = _load_cross_links(db, account)

        # O(N) caches — built once, shared across all get_neighbors() calls
        self.action_cache          = _build_action_cache(self.principals)
        self.passrole_resource_map = _build_passrole_resource_map(self.principals)
        self.exec_roles_by_service = _build_exec_roles_by_service(self.resources)

        # ARN lookup indexes
        self._principal_by_arn: dict[str, Principal] = {
            p.arn: p for p in self.principals
        }
        self._resource_by_arn: dict[str, Resource] = {
            r.arn: r for r in self.resources
        }
        self._roles: list[Principal] = [
            p for p in self.principals if p.principal_type == "role"
        ]
        self._role_by_arn: dict[str, Principal] = {p.arn: p for p in self._roles}
        self._groups: list[Principal] = [
            p for p in self.principals if p.principal_type == "group"
        ]

        # Resources grouped by the execution role they hand credentials to.
        self._resources_by_exec_role: dict[str, list[Resource]] = {}
        for r in self.resources:
            if r.execution_role:
                self._resources_by_exec_role.setdefault(
                    r.execution_role.arn, []).append(r)

        # Cross-account links grouped by the role they grant access to.
        self._cross_links_by_role: dict[str, list[CrossAccountLink]] = {}
        for link in self.cross_links:
            if link.role_arn:
                self._cross_links_by_role.setdefault(link.role_arn, []).append(link)

        # Parse each role's trust policy exactly once (the .trust_policy property
        # does a json.loads on every access). Reused by the assume-role scan so
        # it is O(roles) parses instead of O(attackers × roles).
        self._trust_cache: dict[str, dict | None] = {
            p.arn: p.trust_policy for p in self._roles
        }

        # Inverted trust index: trusted-principal key -> set of role ARNs that
        # trust it. Keys are "*" (wildcard), an exact principal ARN, or an
        # account root ARN — exactly the three forms _actor_can_assume matches.
        # Replaces the O(attackers × roles) pair-check in _lateral_neighbors.
        self._roles_trusting: dict[str, set[str]] = _build_trust_index(
            self._roles, self._trust_cache)

        # Deduped abuse targets per rule, computed once. Targets collapse via
        # execution_role.arn, so e.g. thousands of Lambdas become far fewer
        # unique roles. Also avoids re-reading Resource.extra (a json.loads
        # property) on every expansion.
        # Accounts we actually enumerated — lets the cross-account gate tell
        # "target has no resource policy" (real evidence) apart from "target not
        # in our catalogue".
        self.known_accounts: set[str] = {
            p.account.account_id for p in self.principals if p.account
        } | {
            r.account.account_id for r in self.resources if r.account
        }

        self._abuse_targets_by_rule: dict[str, list[_AbuseTarget]] = \
            _build_abuse_targets(self.resources, self.known_accounts)

        # Lazily-built cross-account gates for lateral targets (secrets/SSM/EC2).
        self._resource_gate_cache: dict[str, _CrossAccountGate] = {}

    # ── Public interface ─────────────────────────────────────────────────

    def get_neighbors(
        self, arn: str
    ) -> Iterator[tuple[str, dict[str, Any]]]:
        """Yield (neighbor_arn, edge_data) for every attack step from arn.

        Each yielded dict has keys: edge_type, path_id, action, severity,
        explanation.  Callers add 'actor' / 'target' as needed.
        """
        attacker = self._principal_by_arn.get(arn)
        if attacker is not None and attacker.principal_type in ("user", "role"):
            log.debug("[neighbors] expanding %s", arn)
            yield from self._iam_neighbors(attacker)
            yield from self._passrole_neighbors(attacker)
            yield from self._resource_abuse_neighbors(attacker)
            yield from self._compute_resource_neighbors(attacker)
            yield from self._lateral_neighbors(attacker)
            yield from self._group_membership_neighbors(attacker)
            return
        # Resource node: expand to the execution role it runs as, so a path that
        # compromises the resource (e.g. UpdateFunctionCode on a Lambda) pivots
        # to that role's credentials. Privesc traversal only; the threat-model
        # view (get_access_neighbors) already models this via its runs_as family.
        res = self._resource_by_arn.get(arn)
        if res is not None and res.execution_role:
            yield res.execution_role.arn, dict(
                edge_type="runs_as", path_id="PATH-040",
                action="sts:AssumeRole (service role)", severity=SEVERITY_HIGH,
                explanation=_EXPLANATIONS.get("PATH-040", "runs_as"),
            )

    def get_access_neighbors(
        self, arn: str
    ) -> Iterator[tuple[str, dict[str, Any]]]:
        """Yield only *access / pivot* edges for arn — assume-role, cross-account,
        PassRole→compute credential-theft, resource-abuse, lateral movement and
        secret harvesting.

        Deliberately excludes the dense IAM-manipulation (_iam_neighbors) and
        group-membership (_group_membership_neighbors) families: those model
        *privilege escalation* ("X can rewrite Y's permissions"), fan out one
        privileged principal to every other principal (O(P²)), and are the
        domain of the PrivEsc scan. Used by the Threat Model reverse-reachability
        analysis so it scales to large orgs and answers "if this identity is
        compromised, can it reach the target?".
        """
        attacker = self._principal_by_arn.get(arn)
        if attacker is None or attacker.principal_type not in ("user", "role"):
            return
        yield from self._passrole_neighbors(attacker)
        yield from self._resource_abuse_neighbors(attacker, access_only=True)
        yield from self._lateral_neighbors(attacker)

    # ── Neighbor generators (one per edge family) ──────────────────────

    def _iam_neighbors(
        self, attacker: Principal
    ) -> Iterator[tuple[str, dict]]:
        actions = self.action_cache.get(attacker.arn, frozenset())
        for path_id, edge_type, action, severity, target_filter in _IAM_EDGE_TABLE:
            if not _can_do(actions, action):
                continue
            expl = _EXPLANATIONS.get(path_id, action)
            targets = [
                v for v in self.principals
                if (not target_filter or v.principal_type == target_filter)
                and not _is_aws_managed_principal(v)
            ]
            log.debug("[iam] %s can %s → %d targets",
                      attacker.arn, action, len(targets))
            for victim in targets:
                yield victim.arn, dict(
                    edge_type=edge_type, path_id=path_id,
                    action=action, severity=severity, explanation=expl,
                )

    def _passrole_neighbors(
        self, attacker: Principal
    ) -> Iterator[tuple[str, dict]]:
        actions = self.action_cache.get(attacker.arn, frozenset())
        if not _can_do(actions, "iam:PassRole"):
            return
        passrole_resources = self.passrole_resource_map.get(attacker.arn, ["*"])
        for path_id, edge_type, extra, severity in _PASSROLE_TABLE:
            if not all(_can_do(actions, a) for a in extra):
                continue
            required_service = _PASSROLE_SERVICE_TRUST.get(edge_type)
            eligible = self.exec_roles_by_service.get(required_service, set()) \
                       if required_service else \
                       {r.execution_role.arn for r in self.resources if r.execution_role}
            scoped = {arn for arn in eligible
                      if _resource_matches(arn, passrole_resources)}
            if not scoped:
                log.debug("[passrole] %s / %s: no eligible roles (eligible=%d, scoped=0)",
                          attacker.arn, edge_type, len(eligible))
                continue
            log.debug("[passrole] %s / %s: %d eligible roles → emitting edges",
                      attacker.arn, edge_type, len(scoped))
            expl = _EXPLANATIONS.get(path_id, edge_type)
            for target_arn in scoped:
                yield target_arn, dict(
                    edge_type=edge_type, path_id=path_id,
                    action="iam:PassRole + " + ", ".join(extra),
                    severity=severity, explanation=expl,
                )

    def _resource_abuse_neighbors(
        self, attacker: Principal, access_only: bool = False
    ) -> Iterator[tuple[str, dict]]:
        actions = self.action_cache.get(attacker.arn, frozenset())
        attacker_acct = attacker.account.account_id if attacker.account else ""
        for svc, rtype, action, edge_type, path_id, severity in _RESOURCE_ABUSE_TABLE:
            if access_only and edge_type in _READ_ONLY_REACH_EDGES:
                continue
            if not _abuse_rule_allowed(edge_type, action, actions):
                continue
            expl = _EXPLANATIONS.get(path_id, edge_type)
            edge_action = _abuse_edge_action(edge_type, action)
            gedge = GateEdge(family="abuse", edge_type=edge_type, action=edge_action)
            for t in self._abuse_targets_by_rule.get(edge_type, ()):
                # Cross-account resource abuse only counts when the abused
                # resource's own policy admits the attacker; same-account is
                # exempt (identity policy suffices) inside the gate.
                if not t.gate.allows(attacker.arn, attacker_acct, gedge):
                    continue
                yield t.target_arn, dict(
                    edge_type=edge_type, path_id=path_id,
                    action=edge_action, severity=severity, explanation=expl,
                )

    def _gate_for_resource(self, r: Resource) -> _CrossAccountGate:
        """Cross-account gate for a lateral target resource (secret/SSM/EC2).

        Cached per resource ARN. EC2/SSM with no resource policy yield an empty
        gate, so cross-account lateral movement to them is correctly dropped;
        secrets with a resource policy are gated on that policy. Same-account is
        exempt inside the gate.
        """
        g = self._resource_gate_cache.get(r.arn)
        if g is None:
            from worstassume.core.threat_model import resource_policy_accessors
            acct = r.account.account_id if r.account else None
            respol, _flags = resource_policy_accessors(
                r, "resource", self.known_accounts, acct)
            g = _CrossAccountGate(acct, respol, have_evidence=True)
            self._resource_gate_cache[r.arn] = g
        return g

    def _compute_resource_neighbors(
        self, attacker: Principal
    ) -> Iterator[tuple[str, dict]]:
        """Privesc-only: reach the compute *resource* itself, not just its
        collapsed execution role, so a scan can target the resource and route a
        path through it (resource -> runs_as -> execution role). Only resources
        that hand out an execution role become pivots; S3 reads already point at
        the bucket directly and are skipped here.
        """
        actions = self.action_cache.get(attacker.arn, frozenset())
        attacker_acct = attacker.account.account_id if attacker.account else ""
        for svc, rtype, action, edge_type, path_id, severity in _RESOURCE_ABUSE_TABLE:
            if edge_type in _READ_ONLY_REACH_EDGES:
                continue
            if not _abuse_rule_allowed(edge_type, action, actions):
                continue
            expl = _EXPLANATIONS.get(path_id, edge_type)
            edge_action = _abuse_edge_action(edge_type, action)
            gedge = GateEdge(family="abuse", edge_type=edge_type, action=edge_action)
            for r in self.resources:
                if not r.execution_role:
                    continue
                if not _abuse_rule_matches_resource(edge_type, svc, rtype, r):
                    continue
                if not self._gate_for_resource(r).allows(attacker.arn, attacker_acct, gedge):
                    continue
                yield r.arn, dict(
                    edge_type=edge_type, path_id=path_id,
                    action=edge_action, severity=severity, explanation=expl,
                )

    def _lateral_neighbors(
        self, attacker: Principal
    ) -> Iterator[tuple[str, dict]]:
        actions = self.action_cache.get(attacker.arn, frozenset())
        acct_id = attacker.account.account_id if attacker.account else ""

        # sts:AssumeRole — candidates come from the inverted trust index, so this
        # is O(assumable roles) instead of O(all roles) trust checks.
        if _can_do(actions, "sts:AssumeRole"):
            assume_count = 0
            for target_role in self._assumable_roles(attacker, acct_id):
                target_acct = target_role.account.account_id \
                              if target_role.account else ""
                is_cross  = target_acct != acct_id
                edge_type = "cross_account_assume" if is_cross else "assume_role"
                path_id   = "PATH-031" if is_cross else "PATH-030"
                severity  = SEVERITY_CRITICAL if is_cross else SEVERITY_HIGH
                assume_count += 1
                yield target_role.arn, dict(
                    edge_type=edge_type, path_id=path_id,
                    action="sts:AssumeRole", severity=severity,
                    explanation=_EXPLANATIONS.get(path_id, edge_type),
                )
            log.debug("[assume] %s can assume %d / %d roles",
                      attacker.arn, assume_count, len(self._roles))

        # ssm:SendCommand
        if _can_do(actions, "ssm:SendCommand"):
            gedge = GateEdge("abuse", "ssm_lateral", "ssm:SendCommand")
            for r in self.resources:
                if r.service == "ec2" and r.execution_role:
                    if not self._gate_for_resource(r).allows(attacker.arn, acct_id, gedge):
                        continue
                    yield r.execution_role.arn, dict(
                        edge_type="ssm_lateral", path_id="PATH-032",
                        action="ssm:SendCommand", severity=SEVERITY_HIGH,
                        explanation=_EXPLANATIONS.get("PATH-032", "ssm_lateral"),
                    )

        # Secret harvest
        if _can_do(actions, "secretsmanager:GetSecretValue") or \
           _can_do(actions, "ssm:GetParameter"):
            gedge = GateEdge("abuse", "secret_harvest", "secretsmanager:GetSecretValue")
            for r in self.resources:
                if r.service in ("secretsmanager", "ssm"):
                    if not self._gate_for_resource(r).allows(attacker.arn, acct_id, gedge):
                        continue
                    yield r.arn, dict(
                        edge_type="secret_harvest", path_id="PATH-036",
                        action="secretsmanager:GetSecretValue",
                        severity=SEVERITY_HIGH,
                        explanation=_EXPLANATIONS.get("PATH-036", "secret_harvest"),
                    )

        # Defensive blind
        if _can_do(actions, "cloudtrail:StopLogging") or \
           _can_do(actions, "guardduty:DeleteDetector"):
            yield attacker.arn, dict(
                edge_type="defensive_blind", path_id="PATH-042",
                action="cloudtrail:StopLogging", severity=SEVERITY_HIGH,
                explanation=_EXPLANATIONS.get("PATH-042", "defensive_blind"),
            )

        # Cross-account links
        for link in self.cross_links:
            if link.role_arn and link.trust_principal_arn == attacker.arn:
                sev = SEVERITY_CRITICAL if link.is_wildcard else SEVERITY_HIGH
                yield link.role_arn, dict(
                    edge_type="cross_account_assume", path_id="PATH-031",
                    action="sts:AssumeRole (cross-account)", severity=sev,
                    explanation=_EXPLANATIONS.get("PATH-031", "cross_account_assume"),
                )

    def _assumable_roles(
        self, attacker: Principal, actor_acct: str
    ) -> Iterator[Principal]:
        """Yield the roles whose trust policy admits *attacker*.

        Uses the inverted trust index built in __init__ rather than evaluating
        _actor_can_assume() against every role. Equivalent by construction:
        the index keys are the same three forms that helper matches.
        """
        candidates: set[str] = set(self._roles_trusting.get("*", ()))
        candidates |= self._roles_trusting.get(attacker.arn, set())
        if actor_acct:
            candidates |= self._roles_trusting.get(
                f"arn:aws:iam::{actor_acct}:root", set())
        for role_arn in sorted(candidates):
            role = self._role_by_arn.get(role_arn)
            if role is not None:
                yield role

    def _group_membership_neighbors(
        self, attacker: Principal
    ) -> Iterator[tuple[str, dict]]:
        """PATH-009: iam:AddUserToGroup (user → group only)."""
        if attacker.principal_type != "user":
            return
        if not _can_do(self.action_cache.get(attacker.arn, frozenset()),
                       "iam:AddUserToGroup"):
            return
        already_member_of = {
            gm.group_id for gm in attacker.group_memberships_as_user
        }
        for grp in self._groups:
            if grp.id in already_member_of:
                continue
            yield grp.arn, dict(
                edge_type="group_membership", path_id="PATH-009",
                action="iam:AddUserToGroup", severity=SEVERITY_HIGH,
                explanation=(
                    f"Can add themselves to group '{grp.name}' "
                    f"(not currently a member) to inherit group permissions"
                ),
            )


# ── DB loaders ────────────────────────────────────────────────────────────────

def _load_principals(db, account):
    from worstassume.db.models import GroupMembership
    q = db.query(Principal).options(
        joinedload(Principal.policies),
        joinedload(Principal.account),
        # Eagerly load group memberships so _collect_allowed_actions() can
        # traverse inherited policies without triggering lazy loads in threads.
        joinedload(Principal.group_memberships_as_user)
            .joinedload(GroupMembership.group)
            .joinedload(Principal.policies),
    )
    if account:
        q = q.filter(Principal.account_id == account.id)
    return q.all()

def _load_resources(db, account):
    q = db.query(Resource).options(
        joinedload(Resource.execution_role),
        joinedload(Resource.account),
    )
    if account:
        q = q.filter(Resource.account_id == account.id)
    return q.all()

def _load_cross_links(db, account):
    q = db.query(CrossAccountLink)
    if account:
        q = q.filter(
            (CrossAccountLink.source_account_id == account.id) |
            (CrossAccountLink.target_account_id == account.id)
        )
    return q.all()


# ── Node builder ──────────────────────────────────────────────────────────────

def _build_nodes(G, principals, resources):
    for p in principals:
        G.add_node(p.arn, **{
            "node_type":      "principal",
            "label":          p.name,
            "account_id":     p.account.account_id if p.account else "",
            "principal_type": p.principal_type,
            "service":        None,
            "resource_type":  None,
        })
    for r in resources:
        G.add_node(r.arn, **{
            "node_type":      "resource",
            "label":          r.name or r.arn.split(":")[-1],
            "account_id":     r.account.account_id if r.account else "",
            "principal_type": None,
            "service":        r.service,
            "resource_type":  r.resource_type,
        })
        if r.execution_role and r.execution_role.arn not in G:
            role = r.execution_role
            G.add_node(role.arn, **{
                "node_type":      "principal",
                "label":          role.name,
                "account_id":     role.account.account_id if role.account else "",
                "principal_type": "role",
                "service":        None,
                "resource_type":  None,
            })


# ── Edge helper (DRY wrapper) ─────────────────────────────────────────────────

def _add_edge(G, src, dst, *, edge_type, path_id, action, severity, explanation):
    if src not in G or dst not in G:
        return
    G.add_edge(src, dst,
               edge_type=edge_type, path_id=path_id,
               action=action, severity=severity, explanation=explanation)


# ── IAM identity manipulation edges ─────────────────────────────────

_IAM_EDGE_TABLE = [
    # (path_id, edge_type, action, severity, target_filter)
    # target_filter: None = all principals, "role", "user", "group"
    ("PATH-001", "iam_policy_inject",   "iam:CreatePolicyVersion",    SEVERITY_CRITICAL, None),
    ("PATH-002", "iam_policy_inject",   "iam:SetDefaultPolicyVersion", SEVERITY_CRITICAL, None),
    ("PATH-003", "iam_policy_inject",   "iam:AttachUserPolicy",        SEVERITY_CRITICAL, None),
    ("PATH-004", "iam_policy_inject",   "iam:AttachRolePolicy",        SEVERITY_CRITICAL, None),
    ("PATH-005", "iam_policy_inject",   "iam:AttachGroupPolicy",       SEVERITY_CRITICAL, None),
    ("PATH-006", "iam_policy_inject",   "iam:PutUserPolicy",           SEVERITY_CRITICAL, None),
    ("PATH-007", "iam_policy_inject",   "iam:PutRolePolicy",           SEVERITY_CRITICAL, None),
    ("PATH-008", "iam_policy_inject",   "iam:PutGroupPolicy",          SEVERITY_CRITICAL, None),
    ("PATH-009", "group_membership",    "iam:AddUserToGroup",          SEVERITY_HIGH,     "group"),
    ("PATH-010", "trust_policy_update", "iam:UpdateAssumeRolePolicy",  SEVERITY_CRITICAL, "role"),
    ("PATH-011", "credential_theft",    "iam:CreateAccessKey",         SEVERITY_CRITICAL, "user"),
    ("PATH-012", "credential_theft",    "iam:CreateLoginProfile",      SEVERITY_HIGH,     "user"),
    ("PATH-013", "credential_theft",    "iam:UpdateLoginProfile",      SEVERITY_CRITICAL, "user"),
]

# ── PassRole edges ───────────────────────────────────────────────────────

_PASSROLE_TABLE = [
    # (path_id, edge_type, extra_actions, severity)
    ("PATH-016", "passrole_lambda_create",  ["lambda:CreateFunction"],                                    SEVERITY_CRITICAL),
    ("PATH-018", "passrole_lambda_trigger", ["lambda:CreateFunction", "lambda:CreateEventSourceMapping"], SEVERITY_CRITICAL),
    ("PATH-015", "passrole_ec2",            ["ec2:RunInstances"],                                         SEVERITY_HIGH),
    ("PATH-021", "passrole_glue_new",       ["glue:CreateDevEndpoint"],                                   SEVERITY_HIGH),
    ("PATH-023", "passrole_cfn",            ["cloudformation:CreateStack"],                               SEVERITY_CRITICAL),
    ("PATH-023", "passrole_cfn_update",     ["cloudformation:UpdateStack"],                               SEVERITY_HIGH),
    ("PATH-024", "passrole_datapipeline",   ["datapipeline:CreatePipeline"],                              SEVERITY_MEDIUM),
    ("PATH-025", "passrole_sagemaker_new",  ["sagemaker:CreateNotebookInstance"],                         SEVERITY_HIGH),
    ("PATH-027", "codestar_create",         ["codestar:CreateProject"],                                   SEVERITY_HIGH),
]

_PASSROLE_SERVICE_TRUST: dict[str, str] = {
    "passrole_lambda_create":  "lambda.amazonaws.com",
    "passrole_lambda_trigger": "lambda.amazonaws.com",
    "passrole_ec2":            "ec2.amazonaws.com",
    "passrole_glue_new":       "glue.amazonaws.com",
    "passrole_cfn":            "cloudformation.amazonaws.com",
    "passrole_cfn_update":     "cloudformation.amazonaws.com",
    "passrole_datapipeline":   "datapipeline.amazonaws.com",
    "passrole_sagemaker_new":  "sagemaker.amazonaws.com",
    "codestar_create":         "codestar.amazonaws.com",
}

# ── Resource abuse edges ──────────────────────────────────────────────────

# Edge types that model plain (allowed) resource READ, not a privilege change.
# They let a forward privesc path terminate on a resource the actor can read
# (e.g. an S3 bucket). The access / threat-model view already covers reads via
# the identity_policy family, so these are excluded there to avoid a redundant,
# mislabeled "abuse" edge.
_READ_ONLY_REACH_EDGES = frozenset({"s3_object_read", "s3_bucket_read"})

_RESOURCE_ABUSE_TABLE = [
    # (service, resource_type, action, edge_type, path_id, severity)
    ("lambda",    "function",  "lambda:UpdateFunctionCode",                    "lambda_code_overwrite",     "PATH-019", SEVERITY_HIGH),
    ("lambda",    "function",  "lambda:UpdateFunctionConfiguration",           "lambda_layer_inject",       "PATH-020", SEVERITY_HIGH),
    ("glue",      None,        "glue:UpdateDevEndpoint",                       "glue_endpoint_hijack",      "PATH-022", SEVERITY_HIGH),
    ("sagemaker", None,        "sagemaker:CreatePresignedNotebookInstanceUrl", "sagemaker_notebook_hijack", "PATH-026", SEVERITY_HIGH),
    ("ec2",       "instance",  None,                                           "imds_steal",                "PATH-014", SEVERITY_MEDIUM),
    ("ecs",       "task-definition", None,                                      "ecs_metadata_steal",        "PATH-037", SEVERITY_MEDIUM),
    ("ec2",       "instance",  "ec2-instance-connect:SendSSHPublicKey",        "ec2_instance_connect",      "PATH-033", SEVERITY_MEDIUM),
    ("s3",        "bucket",    "s3:PutBucketPolicy",                           "s3_bucket_policy_abuse",    "PATH-035", SEVERITY_HIGH),
    ("s3",        "bucket",    "s3:GetObject",                                 "s3_object_read",            "PATH-038", SEVERITY_HIGH),
    ("s3",        "bucket",    "s3:ListBucket",                                "s3_bucket_read",            "PATH-039", SEVERITY_MEDIUM),
]

# Actions that let an attacker execute code *on* an instance / task. Without one
# of these (or the credentials already being on the box) the metadata endpoint is
# unreachable, so imds_steal / ecs_metadata_steal must not fan out from every
# principal in the account.
_IMDS_LANDING_ACTIONS = (
    "ssm:SendCommand",
    "ec2-instance-connect:SendSSHPublicKey",
    "ec2:RunInstances",
)
_ECS_LANDING_ACTIONS = (
    "ecs:RunTask",
    "ecs:ExecuteCommand",
    "ecs:UpdateService",
    "ecs:RegisterTaskDefinition",
    "ssm:SendCommand",
    "ec2:RunInstances",
)



# ── Resource-abuse rule helpers ──────────────────────────────────────────────

def _abuse_edge_action(edge_type: str, action: str | None) -> str:
    """The human-facing action string stamped on a resource-abuse edge."""
    if edge_type == "imds_steal":
        return "http://169.254.169.254/ (IMDSv1)"
    if edge_type == "ecs_metadata_steal":
        return "ECS task metadata endpoint"
    return action or edge_type


def _abuse_rule_allowed(
    edge_type: str, action: str | None, actions: frozenset[str] | set[str]
) -> bool:
    """Return True if *actions* lets the attacker exercise this abuse rule.

    The two metadata-theft rules have no single API action to gate on: reaching
    IMDS or the ECS task metadata endpoint requires code execution on the
    instance/task, so they are gated on the actions that get you there.
    """
    if edge_type == "imds_steal":
        return any(_can_do(actions, a) for a in _IMDS_LANDING_ACTIONS)
    if edge_type == "ecs_metadata_steal":
        return any(_can_do(actions, a) for a in _ECS_LANDING_ACTIONS)
    return bool(action) and _can_do(actions, action)


def _abuse_rule_matches_resource(
    edge_type: str, svc: str | None, rtype: str | None, r: Resource
) -> bool:
    """Return True if resource *r* is a valid target for this abuse rule."""
    if edge_type == "imds_steal":
        if r.service != "ec2" or r.resource_type != "instance":
            return False
        extra = r.extra or {}
        # IMDSv2-only instances do not leak credentials to a bare GET.
        return extra.get("MetadataOptions", {}).get("HttpTokens") != "required"
    if edge_type == "ecs_metadata_steal":
        # Historically matched on service alone (the table's "task-definition"
        # resource_type was never applied); kept as-is, but an execution role is
        # required since that is what the edge points at.
        return r.service == "ecs" and r.execution_role is not None
    if svc and r.service != svc:
        return False
    if rtype and r.resource_type != rtype:
        return False
    return True


@dataclass(frozen=True)
class _AbuseTarget:
    """A resource-abuse edge target plus the gate guarding it cross-account."""
    target_arn: str
    resource_account: str | None
    gate: _CrossAccountGate


def _build_abuse_targets(
    resources: list, known_accounts: set[str]
) -> dict[str, list[_AbuseTarget]]:
    """Precompute deduped abuse targets per rule, each with a cross-account gate.

    Targets collapse onto execution_role.arn where one exists, so many resources
    share a target. Each target carries a _CrossAccountGate built from the abused
    resource's own resource policy, so a cross-account edge only survives when
    that policy admits the attacker (same-account targets are exempt inside the
    gate). Built once per NeighborContext.
    """
    from worstassume.core.threat_model import resource_policy_accessors  # lazy: cycle

    out: dict[str, list[_AbuseTarget]] = {}
    for svc, rtype, _action, edge_type, _pid, _sev in _RESOURCE_ABUSE_TABLE:
        merged: dict[tuple[str, str | None], list] = {}
        for r in resources:
            if not _abuse_rule_matches_resource(edge_type, svc, rtype, r):
                continue
            target_arn = r.execution_role.arn if r.execution_role else r.arn
            racct = r.account.account_id if r.account else None
            respol, _flags = resource_policy_accessors(
                r, "resource", known_accounts, racct)
            merged.setdefault((target_arn, racct), []).extend(respol)
        out[edge_type] = [
            _AbuseTarget(target_arn=tarn, resource_account=racct,
                         gate=_CrossAccountGate(racct, respol, have_evidence=True))
            for (tarn, racct), respol in sorted(merged.items(), key=lambda kv: kv[0][0])
        ]
    return out


def _build_trust_index(
    roles: list, trust_cache: dict[str, dict | None]
) -> dict[str, set[str]]:
    """Invert role trust policies: trusted-principal key -> role ARNs.

    Keys mirror the three forms _actor_can_assume() accepts: "*" for a wildcard
    Principal (or a "*" entry under Principal.AWS), and otherwise the literal
    string from Principal.AWS — which covers both exact principal ARNs and
    account-root ARNs.
    """
    index: dict[str, set[str]] = {}
    for role in roles:
        trust = trust_cache.get(role.arn)
        if not trust:
            continue
        for stmt in _normalize_stmts(trust):
            if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            if principal == "*":
                index.setdefault("*", set()).add(role.arn)
                continue
            aws = principal.get("AWS", []) if isinstance(principal, dict) else []
            if isinstance(aws, str):
                aws = [aws]
            for entry in aws:
                if isinstance(entry, str):
                    index.setdefault(entry, set()).add(role.arn)
    return index


# ── Trust-policy helpers ─────────────────────────────────────────────────────────

def _actor_can_assume(actor: Principal, target_role: Principal,
                      trust: dict | None = None) -> bool:
    """Return True if actor's ARN or account root is trusted by target_role's trust policy.

    `trust` may be supplied pre-parsed (from NeighborContext._trust_cache) to
    avoid re-running json.loads for every attacker; falls back to the property.
    """
    if trust is None:
        trust = target_role.trust_policy  # uses @property from models.py
    if not trust:
        return False
    actor_acct = actor.account.account_id if actor.account else ""
    for stmt in _normalize_stmts(trust):
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal", {})
        if principal == "*":
            return True
        aws = principal.get("AWS", []) if isinstance(principal, dict) else []
        if isinstance(aws, str):
            aws = [aws]
        for p in aws:
            if p == "*" or p == actor.arn:
                return True
            if actor_acct and p == f"arn:aws:iam::{actor_acct}:root":
                return True
    return False


def _normalize_stmts(policy: dict) -> list:
    stmts = policy.get("Statement", [])
    return [stmts] if isinstance(stmts, dict) else stmts


def _is_aws_managed_principal(p: Principal) -> bool:
    """Return True for AWS-managed principals that are not viable IAM attack targets.

    Covers:
    - Service-linked roles: path contains '/aws-service-role/' or name starts
      with 'AWSServiceRole'.  AWS blocks iam:PutRolePolicy, iam:AttachRolePolicy,
      etc. on these at the API level, so edges to them are false positives.
    - SSO reserved roles: ARN contains '/AWSReservedSSO_' or the legacy
      '/aws-reserved/sso.amazonaws.com/' path segment.
    """
    arn  = p.arn  or ""
    path = p.path or "/"
    return (
        "/aws-service-role/" in path
        or p.name.startswith("AWSServiceRole")
        or "/AWSReservedSSO_" in arn
        or "/aws-reserved/sso.amazonaws.com/" in arn
    )


def _role_trusts_service(role: Principal, service_principal: str) -> bool:
    """Return True if the role's trust policy allows the given service principal."""
    trust = role.trust_policy or {}
    for stmt in trust.get("Statement", []):
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal", {})
        if principal == "*":
            return True
        services = principal.get("Service", []) if isinstance(principal, dict) else []
        if isinstance(services, str):
            services = [services]
        if any(service_principal in svc for svc in services):
            return True
    return False


def _build_exec_roles_by_service(resources: list) -> dict[str, set]:
    """Pre-index exec role ARNs by service they trust. O(roles × services) total."""
    exec_roles: dict[str, object] = {}
    for r in resources:
        if r.execution_role and r.execution_role.arn not in exec_roles:
            exec_roles[r.execution_role.arn] = r.execution_role
    services = set(_PASSROLE_SERVICE_TRUST.values())
    result: dict[str, set] = {svc: set() for svc in services}
    for role_arn, role in exec_roles.items():
        for svc in services:
            if _role_trusts_service(role, svc):
                result[svc].add(role_arn)
    return result


# ── Group membership edges (PATH-009: iam:AddUserToGroup) ──────────────────────

def _add_group_membership_edges(
    G: nx.MultiDiGraph,
    principals: list,
    action_cache: dict,
) -> None:
    """
    PATH-009: iam:AddUserToGroup

    If a user can call iam:AddUserToGroup they can add themselves to any IAM group
    and inherit its permissions. Only emits an edge when the user is NOT already a
    member of the target group (checked via the group_memberships_as_user relationship
    — no extra DB query needed since principals are pre-loaded with that joinedload).
    """
    users  = [p for p in principals if p.principal_type == "user"]
    groups = [p for p in principals if p.principal_type == "group"]

    for user in users:
        if not _can_do(action_cache.get(user.arn, frozenset()), "iam:AddUserToGroup"):
            continue
        user_nid = user.arn
        if user_nid not in G:
            continue
        # O(1) set built from the already-loaded relationship
        already_member_of: set[int] = {
            gm.group_id for gm in user.group_memberships_as_user
        }
        for grp in groups:
            if grp.id in already_member_of:
                continue  # already a member — not an escalation path
            grp_nid = grp.arn
            if grp_nid not in G:
                continue
            G.add_edge(
                user_nid, grp_nid,
                key="group_membership",
                edge_type="group_membership",
                action="iam:AddUserToGroup",
                severity="HIGH",
                path_id="PATH-009",
                explanation=(
                    f"Can add themselves to group '{grp.name}' "
                    f"(not currently a member) to inherit group permissions"
                ),
            )
