"""
Privilege escalation detector — thin orchestrator .

Delegates all detection logic to sub-modules:
  iam_actions.py    — shared IAM primitives (_can_do, action cache, …)
  attack_chains.py  — PrivEscFinding dataclass + family checkers A–F
                      PrivEscChain dataclass + multi-hop chain builders I–VII
  attack_graph.py   — NetworkX MultiDiGraph builder
  attack_path.py    — Path finding + persistence
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session, joinedload

from worstassume.db.models import Account, CrossAccountLink, Resource, Principal
from worstassume.core.iam_actions import (
    _build_action_cache,
    _can_do,                    # noqa: F401 — re-exported for tests
    _collect_allowed_actions,   # noqa: F401 — re-exported for tests
    _has_wildcard,              # noqa: F401 — re-exported for tests
    _is_dangerous_action_set,
    is_sso_managed,
)
from worstassume.core.attack_chains import (
    # PrivEscFinding system (single-hop)
    CATEGORY_ADMIN_ACCESS,        # noqa: F401 — re-exported for tests/server
    CATEGORY_MISCONFIGURATION,    # noqa: F401 — re-exported for tests/server
    CATEGORY_PRIV_ESC_PATH,       # noqa: F401 — re-exported for tests/server
    CATEGORY_RISK_PERMISSION,     # noqa: F401 — re-exported for tests/server
    CATEGORY_WILDCARD_TRUST,      # noqa: F401 — re-exported for tests/server
    PrivEscFinding,               # noqa: F401 — re-exported for tests/server
    _check_ec2_imdsv1,
    _sort_and_dedup,
    check_all_findings,
    # PrivEscChain system (multi-hop)
    SEVERITY_CRITICAL,            # noqa: F401 — re-exported for tests/server
    SEVERITY_HIGH,                # noqa: F401 — re-exported for tests/server
    SEVERITY_MEDIUM,              # noqa: F401 — re-exported for tests/server
    ChainStep,                    # noqa: F401 — re-exported for server
    PrivEscChain,                 # noqa: F401 — re-exported for server
    _dedup_chains,
    detect_chains,
)
from worstassume.core.attack_path import PathResult  # noqa: F401 — re-exported

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def analyze(
    db: Session,
    account: Account | None = None,
    max_workers: int = 8,  # kept for API compatibility; 
) -> list[PrivEscFinding]:
    """
    Analyze all (or one account's) principals for known priv-esc paths.
    Returns a deduplicated list sorted by severity (CRITICAL → HIGH → MEDIUM).
    """
    query = (
        db.query(Principal)
        .options(joinedload(Principal.policies), joinedload(Principal.account))
        .filter(Principal.principal_type.in_(["user", "role"]))
    )
    if account:
        query = query.filter(Principal.account_id == account.id)
    principals = query.all()

    log.info("[privesc] analyzing %d principals", len(principals))

    action_cache: dict[str, frozenset[str]] = _build_action_cache(principals)
    log.debug("[privesc] action cache built for %d principals", len(action_cache))
    findings: list[PrivEscFinding] = []

    # ── Per-principal checks (families A–F) ────────────────────────────────
    for i, p in enumerate(principals):
        log.debug("[privesc] principal %d/%d: %s", i + 1, len(principals), p.arn)
        actions = action_cache.get(p.arn, frozenset())
        acct_id = p.account.account_id if p.account else "unknown"
        sso     = is_sso_managed(p.arn)
        check_all_findings(p, actions, acct_id, sso, findings)

    # ── Resource-aware checks (EC2 IMDSv1) ────────────────────────────────
    resources = db.query(Resource).options(joinedload(Resource.execution_role)).all()
    log.debug("[privesc] resource checks on %d resources", len(resources))
    _check_ec2_imdsv1(resources, findings)

    # ── Cross-account wildcard trust ───────────────────────────────────────
    for link in db.query(CrossAccountLink).filter_by(is_wildcard=True).all():
        findings.append(PrivEscFinding(
            severity=SEVERITY_CRITICAL,
            path="CrossAccountWildcardTrust",
            principal_arn=link.role_arn,
            account_id=link.target_account.account_id if link.target_account else "",
            description=(
                "Role trust policy uses a wildcard principal (*), allowing any "
                "AWS principal to assume this role cross-account."
            ),
            category=CATEGORY_WILDCARD_TRUST,
            details={
                "source_account": link.source_account.account_id if link.source_account else "",
                "target_account": link.target_account.account_id if link.target_account else "",
                "role_arn": link.role_arn,
            },
        ))

    # ── Cross-account links to dangerous roles → proven priv-esc path ─────
    for link in db.query(CrossAccountLink).filter(
        CrossAccountLink.is_wildcard == False, 
        CrossAccountLink.role_arn.isnot(None),
    ).all():
        ta = action_cache.get(link.role_arn)
        if ta is None or not _is_dangerous_action_set(ta):
            continue
        src = link.source_account.account_id if link.source_account else "?"
        dst = link.target_account.account_id if link.target_account else "?"
        sso = is_sso_managed(link.role_arn)
        findings.append(PrivEscFinding(
            severity=SEVERITY_CRITICAL,
            path="CrossAccountPrivEscPath",
            principal_arn=link.role_arn,
            account_id=dst,
            description=(
                f"A cross-account trust link allows principals in account {src} "
                f"to assume role {link.role_arn} in account {dst}, which has "
                f"dangerous permissions enabling privilege escalation."
            ),
            category=CATEGORY_PRIV_ESC_PATH,
            details={
                "source_account": src,
                "target_account": dst,
                "role_arn": link.role_arn,
                "trust_principal_arn": link.trust_principal_arn or "(any)",
            },
            suppressed=sso,
            suppress_reason="AWS SSO managed role" if sso else "",
        ))

    return _sort_and_dedup(findings)


def analyze_chains(
    db: Session,
    account: Account | None = None,
    max_workers: int = 8,  # kept for API compatibility;
) -> list[PrivEscChain]:
    """
    Detect multi-hop privilege escalation chains across all principals.

    Delegates per-principal detection to detect_chains() (attack_chains.py).
    Returns a deduplicated list sorted by severity.
    """
    query = (
        db.query(Principal)
        .options(joinedload(Principal.policies), joinedload(Principal.account))
    )
    if account:
        query = query.filter(Principal.account_id == account.id)
    all_principals = query.all()

    all_resources: list[Resource] = db.query(Resource).options(
        joinedload(Resource.execution_role)
    ).all()
    cross_links: list[CrossAccountLink] = db.query(CrossAccountLink).all()

    log.info("[chains] analyzing %d principals for chains", len(all_principals))

    action_cache: dict[str, frozenset[str]] = _build_action_cache(all_principals)
    chains: list[PrivEscChain] = []

    for attacker in all_principals:
        if attacker.principal_type not in ("user", "role"):
            continue
        actions = action_cache.get(attacker.arn, frozenset())
        acct_id = attacker.account.account_id if attacker.account else "unknown"
        sso     = is_sso_managed(attacker.arn)
        chains.extend(detect_chains(
            attacker=attacker,
            actions=actions,
            acct_id=acct_id,
            sso=sso,
            all_principals=all_principals,
            all_resources=all_resources,
            cross_links=cross_links,
            action_cache=action_cache,
        ))

    return _dedup_chains(chains)


def analyze_attack_paths(
    db: Session,
    from_arn: str,
    objective: str | None = None,
    max_hops: int = 10,
    account: Account | None = None,
    persist_paths: bool = True,
) -> list[PathResult]:
    """
    Find attack paths from a starting identity using demand-driven BFS.

    Replaces the full build_attack_graph() + find_paths() pipeline with
    NeighborContext + find_paths_bfs(): neighbors are expanded on demand so
    only nodes reachable from from_arn within max_hops are evaluated.
    Scales to org-size environments (O(reachable) vs O(N^2)).

    Objective syntax:
        permission:*:*                    - full admin / any permission
        permission:<svc>:<action>         - specific IAM action reachable
        principal:<arn>                   - reach a specific IAM identity
        resource:*                        - any resource node
        resource:<arn>                    - specific resource ARN
        None                              - unconstrained (all reachable nodes)

    Returns a list of PathResult objects sorted by severity DESC, hops ASC.
    Note: build_attack_graph() is still used by the viz server; it is unaffected.
    """
    from worstassume.core.attack_graph import NeighborContext
    from worstassume.core.attack_path import find_paths_bfs, persist

    log.info(
        "[privesc] analyze_attack_paths from=%s objective=%r max_hops=%d",
        from_arn, objective, max_hops,
    )

    ctx = NeighborContext(db, account=account)
    log.info("[privesc] context ready: %d principals, %d resources",
             len(ctx.principals), len(ctx.resources))

    paths = find_paths_bfs(ctx, from_arn=from_arn, objective=objective, max_hops=max_hops)
    log.info("[privesc] found %d attack paths", len(paths))

    if persist_paths and paths:
        persist(db, paths, from_arn=from_arn, objective=objective, account=account)
        db.commit()
        log.info("[privesc] %d path(s) persisted to DB", len(paths))

    return paths
