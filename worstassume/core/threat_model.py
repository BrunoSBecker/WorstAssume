"""
threat_model.py — reverse-reachability / blast-radius analysis.

Given a *target* (an IAM principal ARN or a resource ARN), answer "who can
access or reach this target?" across three lenses:

  1. direct_accessors()          — principals whose *identity* policies grant
                                    actions on the target (statement-level:
                                    Action/NotAction + Resource/NotResource +
                                    Effect, honoring Deny).
  2. resource_policy_accessors() — principals/accounts/externals granted by the
                                    target's own *resource-based* policy
                                    (S3 bucket policy, Lambda resource policy)
                                    or role trust policy, fully resolved.
  3. reverse_reachability()      — principals who can *reach* a direct accessor
                                    (or the target) via the sparse access/pivot
                                    graph reversed (nx.reverse of the access
                                    MultiDiGraph): assume-role, PassRole,
                                    credential/secret theft, lateral movement.
                                    Privilege escalation onto an accessor is the
                                    PrivEsc scan's domain, not modelled here.

analyze_threat_model() orchestrates all three and computes blast-radius +
attack-surface aggregates.  Everything works in raw ARNs; the API layer maps
to prefixed graph node IDs (principal:/resource:).
"""
from __future__ import annotations

import logging
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import networkx as nx
from sqlalchemy.orm import Session

from worstassume.db.models import Account, Principal, Resource
from worstassume.core.attack_graph import NeighborContext, build_access_graph
from worstassume.core.iam_actions import _can_do, _resource_matches

if TYPE_CHECKING:  # pragma: no cover - typing only
    from worstassume.core.reverse_index import ReverseIndex

log = logging.getLogger(__name__)

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _worst(severities: list[str]) -> str:
    """Return the highest-severity label (lowest _SEV_ORDER index)."""
    if not severities:
        return "MEDIUM"
    return min(severities, key=lambda s: _SEV_ORDER.get(s, 9))


# ── Candidate action vocabularies ────────────────────────────────────────────
# For a *principal* target: IAM control verbs an attacker could use against it.
_PRINCIPAL_TARGET_ACTIONS: list[str] = [
    "iam:PassRole", "iam:PutRolePolicy", "iam:AttachRolePolicy",
    "iam:PutUserPolicy", "iam:AttachUserPolicy",
    "iam:PutGroupPolicy", "iam:AttachGroupPolicy",
    "iam:UpdateAssumeRolePolicy", "iam:CreateAccessKey",
    "iam:CreateLoginProfile", "iam:UpdateLoginProfile", "iam:AddUserToGroup",
]

# For a *resource* target: sensitive actions per service. Falls back to the
# service wildcard for services not listed here.
_SERVICE_SENSITIVE_ACTIONS: dict[str, list[str]] = {
    "s3": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject",
           "s3:ListBucket", "s3:GetBucketPolicy", "s3:PutBucketPolicy"],
    "lambda": ["lambda:InvokeFunction", "lambda:UpdateFunctionCode",
               "lambda:UpdateFunctionConfiguration", "lambda:GetFunction",
               "lambda:AddPermission"],
    "secretsmanager": ["secretsmanager:GetSecretValue",
                       "secretsmanager:PutSecretValue",
                       "secretsmanager:DescribeSecret"],
    "kms": ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"],
    "dynamodb": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem",
                 "dynamodb:Scan", "dynamodb:Query"],
    "sqs": ["sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage"],
    "sns": ["sns:Publish", "sns:Subscribe"],
    "ssm": ["ssm:GetParameter", "ssm:GetParameters", "ssm:SendCommand"],
    "ecs": ["ecs:RunTask", "ecs:ExecuteCommand", "ecs:UpdateService",
            "ecs:RegisterTaskDefinition", "ecs:DescribeTaskDefinition"],
    "ec2": ["ec2:StartInstances", "ec2:StopInstances",
            "ec2:TerminateInstances", "ec2:ModifyInstanceAttribute"],
}

# Per resource *type*, where the service alone is too coarse. An ARN's service
# field says "ec2" for instances, VPCs, subnets, route tables and security
# groups alike — scoring a subnet against ec2:TerminateInstances produces
# nothing but false positives, which is what this table exists to stop.
_RESOURCE_TYPE_ACTIONS: dict[str, list[str]] = {
    "instance": ["ec2:StartInstances", "ec2:StopInstances",
                 "ec2:TerminateInstances", "ec2:ModifyInstanceAttribute",
                 "ec2-instance-connect:SendSSHPublicKey", "ssm:SendCommand"],
    "task-definition": ["ecs:RunTask", "ecs:RegisterTaskDefinition",
                        "ecs:DescribeTaskDefinition"],
    "cluster": ["ecs:RunTask", "ecs:ExecuteCommand", "ecs:UpdateService"],
    "bucket": _SERVICE_SENSITIVE_ACTIONS["s3"],
    "function": _SERVICE_SENSITIVE_ACTIONS["lambda"],
}

#: Resource types where IAM identity policies are not how access is granted.
#: A VPC or a subnet is a network container: you do not "call an API on" it in
#: any way that constitutes access to it. Returning no candidate actions is the
#: honest answer, and lets the UI explain the right lens instead of listing
#: principals that hold an unrelated ec2:* grant.
_NON_IAM_RESOURCE_TYPES = frozenset({
    "vpc", "subnet", "route-table", "internet-gateway", "igw",
    "nat-gateway", "nat", "security-group",
})


def identity_access_applies(resource_type: str | None) -> bool:
    """False when identity-policy access is not a meaningful lens for a type."""
    return (resource_type or "") not in _NON_IAM_RESOURCE_TYPES


def _candidate_actions(target_arn: str, target_type: str,
                       actions: list[str] | None,
                       resource_type: str | None = None) -> list[str]:
    """Actions worth testing against this target.

    `resource_type` is the authoritative discriminator where it is known; the
    ARN's service field is only a fallback, because several very different
    resource types share one service (everything network-shaped is "ec2").

    Note the `f"{service}:*"` fallback is a *wildcard detector*, not an access
    model: `_ActionMatcher` only matches it against a policy that literally
    grants `svc:*` or `*`, so a principal holding `svc:SomeRealAction` will not
    appear. Services that matter should get a real entry above.
    """
    if actions:
        return list(actions)
    if target_type == "principal":
        return list(_PRINCIPAL_TARGET_ACTIONS)
    if resource_type:
        if not identity_access_applies(resource_type):
            return []
        by_type = _RESOURCE_TYPE_ACTIONS.get(resource_type)
        if by_type:
            return list(by_type)
    service = _service_of(target_arn)
    return _SERVICE_SENSITIVE_ACTIONS.get(service) or [f"{service}:*"]


def _service_of(arn: str) -> str:
    parts = arn.split(":")
    return parts[2] if len(parts) > 2 else ""


def _account_of(arn: str) -> str | None:
    parts = arn.split(":")
    return parts[4] if len(parts) > 4 and parts[4] else None


def _principal_type_of(arn: str) -> str:
    if arn == "*":
        return "wildcard"
    if ":role/" in arn or ":assumed-role/" in arn:
        return "role"
    if ":user/" in arn:
        return "user"
    if ":group/" in arn:
        return "group"
    if arn.endswith(":root"):
        return "account"
    return "external"


# ── Data structures ──────────────────────────────────────────────────────────

@dataclass
class Accessor:
    arn: str
    principal_type: str | None
    account_id: str | None
    external: bool
    via: str                        # identity_policy | resource_policy | trust_policy | acl
    actions: list[str] = field(default_factory=list)
    detail: str | None = None


@dataclass
class ThreatStep:
    actor: str
    action: str
    target: str
    edge_type: str
    severity: str
    explanation: str = ""


@dataclass
class TransitiveAccessor:
    arn: str
    principal_type: str | None
    account_id: str | None
    external: bool
    hops: int
    severity: str
    entry_arn: str
    path: list[ThreatStep] = field(default_factory=list)


@dataclass
class ThreatModelResult:
    target: dict
    direct_accessors: list[Accessor]
    resource_policy: dict
    transitive_accessors: list[TransitiveAccessor]
    blast_radius: dict
    attack_surface: dict


# ── Statement-level identity-policy matching ─────────────────────────────────

class _ActionMatcher:
    """Pre-compiled form of a statement's Action / NotAction list.

    _can_do() rescans the whole action list for every (statement, action) pair,
    which is fine for one principal but not when the Threat Model page tests
    thousands of principals against a target on every click — AWS managed
    policies routinely carry hundreds of actions. Splitting the list into exact
    names, service wildcards and prefix wildcards once turns each test into a
    couple of set lookups. Match semantics are identical to _can_do().
    """

    __slots__ = ("star", "exact", "service_star", "prefixes")

    def __init__(self, actions) -> None:
        self.star = False
        self.exact: set[str] = set()
        self.service_star: set[str] = set()
        self.prefixes: list[str] = []
        for a in actions or ():
            if not isinstance(a, str):
                continue
            if a == "*":
                self.star = True
            elif a.endswith(":*"):
                self.service_star.add(a[:-2])
            elif a.endswith("*"):
                self.prefixes.append(a[:-1])
            else:
                self.exact.add(a)

    def matches(self, action: str) -> bool:
        if self.star or action in self.exact:
            return True
        if self.service_star and action.partition(":")[0] in self.service_star:
            return True
        return any(action.startswith(p) for p in self.prefixes)


def _normalize_statement(stmt: dict) -> dict | None:
    """Normalize a policy statement into {effect, action_set, notaction_set,
    resources, notresources, has_condition}. Returns None for junk."""
    if not isinstance(stmt, dict):
        return None
    effect = stmt.get("Effect")
    if effect not in ("Allow", "Deny"):
        return None

    def _as_list(v):
        if v is None:
            return None
        return [v] if isinstance(v, str) else list(v)

    action_set = _as_list(stmt.get("Action"))
    notaction_set = _as_list(stmt.get("NotAction"))
    resources = _as_list(stmt.get("Resource"))
    notresources = _as_list(stmt.get("NotResource"))
    return {
        "effect": effect,
        "action_set": set(action_set) if action_set is not None else None,
        "notaction_set": set(notaction_set) if notaction_set is not None else None,
        "action_match": _ActionMatcher(action_set) if action_set is not None else None,
        "notaction_match": (_ActionMatcher(notaction_set)
                            if notaction_set is not None else None),
        "resources": resources,
        "notresources": notresources,
        "has_condition": bool(stmt.get("Condition")),
    }


def _effective_identity_statements(principal: Principal) -> list[dict]:
    """All normalized statements from a principal's identity policies, plus
    group-inherited policies for users (mirrors _collect_allowed_actions)."""
    out: list[dict] = []

    def _scan(policies) -> None:
        for policy in policies or []:
            doc = policy.document
            if not doc:
                continue
            stmts = doc.get("Statement", [])
            if isinstance(stmts, dict):
                stmts = [stmts]
            for s in stmts:
                n = _normalize_statement(s)
                if n:
                    out.append(n)

    _scan(principal.policies)
    for gm in getattr(principal, "group_memberships_as_user", []):
        if gm.group:
            _scan(gm.group.policies)
    return out


def _stmt_action_matches(stmt: dict, action: str) -> bool:
    matcher = stmt.get("action_match")
    if matcher is not None:
        return matcher.matches(action)
    matcher = stmt.get("notaction_match")
    if matcher is not None:
        return not matcher.matches(action)
    # Statements normalized before matchers existed (or hand-built in tests).
    if stmt["action_set"] is not None:
        return _can_do(stmt["action_set"], action)
    if stmt["notaction_set"] is not None:
        return not _can_do(stmt["notaction_set"], action)
    return False


def _stmt_resource_matches(stmt: dict, target_arn: str) -> bool:
    if stmt["resources"] is not None:
        return _resource_matches(target_arn, stmt["resources"])
    if stmt["notresources"] is not None:
        return not _resource_matches(target_arn, stmt["notresources"])
    # No Resource/NotResource (e.g. some resource-based statements) → treat as any
    return True


def _statement_grants(stmts: list[dict], target_arn: str,
                      candidate_actions: list[str]) -> tuple[set[str], bool]:
    """Return (granted_actions, has_conditional). An action is granted when some
    Allow statement matches it on target_arn and no Deny statement does."""
    granted: set[str] = set()
    conditional = False
    for action in candidate_actions:
        allowed = False
        denied = False
        allow_conditional = False
        for s in stmts:
            if not _stmt_action_matches(s, action):
                continue
            if not _stmt_resource_matches(s, target_arn):
                continue
            if s["effect"] == "Deny":
                denied = True
                break
            allowed = True
            if s["has_condition"]:
                allow_conditional = True
        if allowed and not denied:
            granted.add(action)
            conditional = conditional or allow_conditional
    return granted, conditional


def direct_accessors(ctx: NeighborContext, target_arn: str, target_type: str,
                     actions: list[str] | None = None) -> list[Accessor]:
    """Principals whose identity policies grant actions on the target ARN."""
    candidates = _candidate_actions(target_arn, target_type, actions)
    out: list[Accessor] = []
    for p in ctx.principals:
        if p.arn == target_arn:
            continue  # a principal is not its own accessor
        stmts = _effective_identity_statements(p)
        if not stmts:
            continue
        matched, conditional = _statement_grants(stmts, target_arn, candidates)
        if not matched:
            continue
        out.append(Accessor(
            arn=p.arn,
            principal_type=p.principal_type,
            account_id=p.account.account_id if p.account else None,
            external=False,  # set by orchestrator relative to target account
            via="identity_policy",
            actions=sorted(matched),
            detail="conditional (policy has Condition)" if conditional else None,
        ))
    out.sort(key=lambda a: (-len(a.actions), a.arn))
    return out


# ── Resource-based / trust policy resolution ─────────────────────────────────

def _principal_entries(principal_block: Any) -> list[tuple[str, str]]:
    """Return [(principal_string, kind)] from a policy Principal block.
    kind ∈ {AWS, Service, Federated, CanonicalUser}."""
    if principal_block == "*":
        return [("*", "AWS")]
    if not isinstance(principal_block, dict):
        return []
    out: list[tuple[str, str]] = []
    for kind in ("AWS", "Service", "Federated", "CanonicalUser"):
        vals = principal_block.get(kind)
        if vals is None:
            continue
        if isinstance(vals, str):
            vals = [vals]
        for v in vals:
            out.append((v, kind))
    return out


def _policy_statements(doc: dict | None) -> list[dict]:
    if not doc:
        return []
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    return [s for s in stmts if isinstance(s, dict)]


def resource_policy_accessors(target_obj: Any, target_type: str,
                              known_accounts: set[str],
                              target_account: str | None) -> tuple[list[Accessor], dict]:
    """Resolve principals granted by the target's resource-based / trust policy."""
    flags = {"has_policy": False, "public": False,
             "cross_account": False, "acl_grants": 0}
    accessors: list[Accessor] = []

    if target_type == "principal":
        doc = getattr(target_obj, "trust_policy", None)
        via = "trust_policy"
        default_actions = ["sts:AssumeRole"]
    else:
        extra = (getattr(target_obj, "extra", None) or {})
        doc = extra.get("policy") or extra.get("resource_policy")
        via = "resource_policy"
        default_actions = []
        flags["acl_grants"] = extra.get("acl_grants") or 0

    flags["has_policy"] = doc is not None

    for stmt in _policy_statements(doc):
        if stmt.get("Effect") != "Allow":
            continue
        raw_actions = stmt.get("Action", default_actions)
        if isinstance(raw_actions, str):
            raw_actions = [raw_actions]
        actions = sorted(set(raw_actions)) if raw_actions else default_actions
        for pval, kind in _principal_entries(stmt.get("Principal", {})):
            if pval == "*":
                flags["public"] = True
                accessors.append(Accessor(
                    arn="*", principal_type="wildcard", account_id=None,
                    external=True, via=via, actions=actions,
                    detail="Public — any principal",
                ))
                continue
            if kind == "Service":
                accessors.append(Accessor(
                    arn=pval, principal_type="service", account_id=None,
                    external=False, via=via, actions=actions,
                    detail="AWS service principal",
                ))
                continue
            acct = _account_of(pval)
            external = bool(acct) and acct not in known_accounts
            if bool(acct) and target_account and acct != target_account:
                flags["cross_account"] = True
            accessors.append(Accessor(
                arn=pval, principal_type=_principal_type_of(pval),
                account_id=acct, external=external, via=via, actions=actions,
                detail=(kind if kind != "AWS" else None),
            ))
    return accessors, flags


# ── Reverse reachability over the attack graph ───────────────────────────────

def _worst_edge(G: nx.MultiDiGraph, u: str, v: str) -> dict:
    edict = G.get_edge_data(u, v) or {}
    best: dict | None = None
    for attrs in edict.values():
        if best is None or _SEV_ORDER.get(attrs.get("severity"), 9) < \
                _SEV_ORDER.get(best.get("severity"), 9):
            best = attrs
    return best or {"action": "", "edge_type": "", "severity": "MEDIUM",
                    "explanation": ""}


def reverse_reachability(seed_arns: set[str], max_hops: int = 5,
                         graph: nx.MultiDiGraph | None = None,
                         db: Session | None = None,
                         account: Account | None = None,
                         limit: int = 500,
                         index: "ReverseIndex | None" = None) -> list[TransitiveAccessor]:
    """Principals who can reach any seed ARN via reversed access edges.

    A path X → … → seed in the forward access graph means X can pivot (via
    assume-role, PassRole, credential/secret theft, lateral movement) to reach
    the seed. We BFS backwards from the seeds and reconstruct each forward path
    for display.

    Backed by ReverseIndex.reverse_neighbors(), which inverts each access family
    directly off pre-built indexes. Building the whole forward graph just to call
    nx.reverse() on it costs tens of millions of edges on a large org to answer a
    question that only needs each visited node's predecessors.

    `index` is the fast path (a cached ReverseIndex). `graph` is accepted for
    backwards compatibility and, when no index is supplied, its in-edges are used
    directly. Otherwise a NeighborContext is built from `db`.
    """
    from worstassume.core.reverse_index import ReverseIndex

    if index is None:
        if graph is not None:
            return _reverse_reachability_graph(graph, seed_arns, max_hops, limit)
        if db is None:
            return []
        index = ReverseIndex(NeighborContext(db, account=account))

    seeds = [s for s in seed_arns if index.resolve_type(s) != "unknown"]
    if not seeds:
        return []

    dist: dict[str, int] = {}
    parent: dict[str, str] = {}
    edge_of: dict[str, dict] = {}
    entry: dict[str, str] = {}
    dq: deque[str] = deque()
    for s in seeds:
        dist[s] = 0
        entry[s] = s
        dq.append(s)

    while dq:
        u = dq.popleft()
        if dist[u] >= max_hops:
            continue
        best: dict[str, dict] = {}
        for v, data in index.reverse_neighbors(u):
            if v in dist:
                continue
            cur = best.get(v)
            if cur is None or _SEV_ORDER.get(data.get("severity"), 9) < \
                    _SEV_ORDER.get(cur.get("severity"), 9):
                best[v] = data
        for v, data in best.items():
            dist[v] = dist[u] + 1
            parent[v] = u
            edge_of[v] = data
            entry[v] = entry[u]
            dq.append(v)

    results: list[TransitiveAccessor] = []
    for node, d in dist.items():
        if d == 0:
            continue  # seed itself is a direct accessor / the target
        p = index.ctx._principal_by_arn.get(node)
        if p is None or p.principal_type not in ("user", "role"):
            continue
        steps: list[ThreatStep] = []
        sevs: list[str] = []
        cur = node
        while cur in parent:
            nxt = parent[cur]  # forward edge cur → nxt
            edge = edge_of[cur]
            steps.append(ThreatStep(
                actor=cur, target=nxt, action=edge.get("action", ""),
                edge_type=edge.get("edge_type", ""),
                severity=edge.get("severity", "MEDIUM"),
                explanation=edge.get("explanation", ""),
            ))
            sevs.append(edge.get("severity", "MEDIUM"))
            cur = nxt
        results.append(TransitiveAccessor(
            arn=node,
            principal_type=p.principal_type,
            account_id=p.account.account_id if p.account else None,
            external=False,  # set by orchestrator
            hops=d,
            severity=_worst(sevs),
            entry_arn=entry[node],
            path=steps,
        ))
    results.sort(key=lambda a: (_SEV_ORDER.get(a.severity, 9), a.hops, a.arn))
    return results[:limit]


def _reverse_reachability_graph(G: nx.MultiDiGraph, seed_arns: set[str],
                                max_hops: int, limit: int) -> list[TransitiveAccessor]:
    """Legacy path: BFS over an already-built access MultiDiGraph.

    Kept so callers that hold a prebuilt graph (and tests that construct one
    directly) keep working; ReverseIndex is the path everything else takes.
    """
    if G.number_of_nodes() == 0:
        return []
    Gr = G.reverse(copy=False)
    seeds = [s for s in seed_arns if s in Gr]
    if not seeds:
        return []

    dist: dict[str, int] = {}
    parent: dict[str, str] = {}
    entry: dict[str, str] = {}
    dq: deque[str] = deque()
    for s in seeds:
        dist[s] = 0
        entry[s] = s
        dq.append(s)

    while dq:
        u = dq.popleft()
        if dist[u] >= max_hops:
            continue
        for v in Gr.successors(u):
            if v in dist:
                continue
            dist[v] = dist[u] + 1
            parent[v] = u
            entry[v] = entry[u]
            dq.append(v)

    results: list[TransitiveAccessor] = []
    for node, d in dist.items():
        if d == 0:
            continue
        data = G.nodes.get(node, {})
        if data.get("node_type") != "principal":
            continue
        if data.get("principal_type") not in ("user", "role"):
            continue
        steps: list[ThreatStep] = []
        sevs: list[str] = []
        cur = node
        while cur in parent:
            nxt = parent[cur]
            edge = _worst_edge(G, cur, nxt)
            steps.append(ThreatStep(
                actor=cur, target=nxt, action=edge.get("action", ""),
                edge_type=edge.get("edge_type", ""),
                severity=edge.get("severity", "MEDIUM"),
                explanation=edge.get("explanation", ""),
            ))
            sevs.append(edge.get("severity", "MEDIUM"))
            cur = nxt
        results.append(TransitiveAccessor(
            arn=node,
            principal_type=data.get("principal_type"),
            account_id=data.get("account_id") or None,
            external=False,
            hops=d,
            severity=_worst(sevs),
            entry_arn=entry[node],
            path=steps,
        ))
    results.sort(key=lambda a: (_SEV_ORDER.get(a.severity, 9), a.hops, a.arn))
    return results[:limit]


# ── Orchestrator ─────────────────────────────────────────────────────────────

def _resolve_target(db: Session, target_arn: str):
    principal = db.query(Principal).filter_by(arn=target_arn).first()
    if principal:
        return "principal", principal
    resource = db.query(Resource).filter_by(arn=target_arn).first()
    if resource:
        return "resource", resource
    return "unknown", None


def analyze_threat_model(db: Session, target_arn: str, max_hops: int = 5,
                         account: Account | None = None,
                         graph: nx.MultiDiGraph | None = None,
                         index: "ReverseIndex | None" = None) -> ThreatModelResult:
    """Full threat-model analysis for a single target ARN.

    Pass a cached `index` (ReverseIndex) to skip rebuilding the NeighborContext
    and the identity-policy statement index on every call.
    """
    target_type, target_obj = _resolve_target(db, target_arn)

    if target_type == "principal":
        target_account = target_obj.account.account_id if target_obj.account else None
        target_meta = {
            "arn": target_arn, "type": "principal",
            "label": target_obj.name,
            "account_id": target_account,
            "principal_type": target_obj.principal_type,
            "service": None, "resource_type": None,
        }
    elif target_type == "resource":
        target_account = target_obj.account.account_id if target_obj.account else None
        target_meta = {
            "arn": target_arn, "type": "resource",
            "label": target_obj.name or target_arn,
            "account_id": target_account,
            "principal_type": None,
            "service": target_obj.service, "resource_type": target_obj.resource_type,
        }
    else:
        target_account = _account_of(target_arn)
        target_meta = {
            "arn": target_arn, "type": "unknown",
            "label": target_arn.split("/")[-1] or target_arn,
            "account_id": target_account,
            "principal_type": None, "service": None, "resource_type": None,
        }

    known_accounts = {a.account_id for a in db.query(Account).all()}

    if index is not None:
        ctx = index.ctx
        direct = index.identity_accessors(target_arn, target_type)
    else:
        ctx = NeighborContext(db, account=account)
        direct = direct_accessors(ctx, target_arn, target_type)

    respol_accessors, respol_flags = resource_policy_accessors(
        target_obj, target_type, known_accounts, target_account
    ) if target_obj is not None else ([], {"has_policy": False, "public": False,
                                            "cross_account": False, "acl_grants": 0})

    # Mark identity direct accessors external relative to the target account
    for a in direct:
        a.external = bool(a.account_id) and a.account_id != target_account

    seeds = {target_arn} | {a.arn for a in direct if a.arn != "*"}
    transitive = reverse_reachability(
        seeds, max_hops=max_hops, graph=graph, db=db, account=account, index=index
    )
    for t in transitive:
        t.external = bool(t.account_id) and t.account_id != target_account

    # ── Aggregates ────────────────────────────────────────────────────────
    direct_arns = {a.arn for a in direct if a.arn != "*"}
    respol_arns = {a.arn for a in respol_accessors if a.arn != "*"}
    trans_arns = {t.arn for t in transitive}
    total_unique = direct_arns | respol_arns | trans_arns

    external_arns = (
        {a.arn for a in direct if a.external and a.arn != "*"}
        | {a.arn for a in respol_accessors if a.external and a.arn != "*"}
        | {t.arn for t in transitive if t.external}
    )
    by_sev = Counter(t.severity for t in transitive)

    blast_radius = {
        "direct": len(direct),
        "resource_policy": len(respol_accessors),
        "transitive": len(transitive),
        "total_unique": len(total_unique),
        "external": len(external_arns),
        "public": respol_flags.get("public", False),
        "by_severity": {
            "CRITICAL": by_sev.get("CRITICAL", 0),
            "HIGH": by_sev.get("HIGH", 0),
            "MEDIUM": by_sev.get("MEDIUM", 0),
            "LOW": by_sev.get("LOW", 0),
        },
    }

    edge_types = Counter(
        step.edge_type for t in transitive for step in t.path if step.edge_type
    )
    services = Counter(
        a.split(":")[0] for acc in direct for a in acc.actions if ":" in a
    )
    attack_surface = {
        "by_edge_type": dict(edge_types),
        "by_service": dict(services),
    }

    resource_policy = {
        **respol_flags,
        "accessors": respol_accessors,
    }

    return ThreatModelResult(
        target=target_meta,
        direct_accessors=direct,
        resource_policy=resource_policy,
        transitive_accessors=transitive,
        blast_radius=blast_radius,
        attack_surface=attack_surface,
    )
