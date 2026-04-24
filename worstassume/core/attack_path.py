"""
attack_path.py — Path finding on the pre-built attack graph + DB persistence.

Consumes the nx.MultiDiGraph produced by attack_graph.build_attack_graph().
Writes AttackPath + AttackPathStep ORM rows via persist().
"""
from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field

import networkx as nx
from sqlalchemy.orm import Session

from worstassume.db.models import Account, AttackPath, AttackPathStep

log = logging.getLogger(__name__)

# ── Severity order (lower index = higher severity) ────────────────────────────
_SEV_ORDER: dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}


# ── Public data-transfer object ───────────────────────────────────────────────

@dataclass
class PathResult:
    """A single attack path from one identity to another."""
    from_arn:  str
    to_arn:    str
    severity:  str             # highest-severity edge across the entire path
    hops:      int
    steps:     list[dict]      # [{actor, action, target, edge_type, explanation}]
    objective: str | None      # the objective string passed to find_paths(), or None


# ── Internal helpers ──────────────────────────────────────────────────────────

def _path_to_result(
    G: nx.MultiDiGraph,
    path: list[str],
    from_arn: str,
    objective: str | None,
) -> PathResult:
    """
    Convert a list of node ARNs into a PathResult.
    Reads edge data between each consecutive pair.
    """
    steps: list[dict] = []
    worst_sev = "MEDIUM"

    for actor, target in zip(path, path[1:]):
        # MultiDiGraph: multiple edges possible; pick the highest-severity one
        edges_data = [data for _, _, data in G.edges(actor, data=True) if _ == actor]
        # Filter to edges pointing at target
        target_edges = [
            data for u, v, data in G.edges(data=True)
            if u == actor and v == target
        ]
        # Select the most severe edge for this hop
        if target_edges:
            best = min(target_edges, key=lambda d: _SEV_ORDER.get(d.get("severity", "MEDIUM"), 99))
        else:
            best = {"action": "?", "edge_type": "unknown", "explanation": "", "severity": "MEDIUM"}

        sev = best.get("severity", "MEDIUM")
        if _SEV_ORDER.get(sev, 99) < _SEV_ORDER.get(worst_sev, 99):
            worst_sev = sev

        steps.append({
            "actor":       actor,
            "action":      best.get("action", ""),
            "target":      target,
            "edge_type":   best.get("edge_type", ""),
            "explanation": best.get("explanation", ""),
            "severity":    sev,
        })

    return PathResult(
        from_arn=from_arn,
        to_arn=path[-1],
        severity=worst_sev,
        hops=len(steps),
        steps=steps,
        objective=objective,
    )


def _resolve_targets(G: nx.MultiDiGraph, objective: str) -> list[str]:
    """
    Resolve an objective string to a list of target node ARNs in G.

    Objective syntax:
        principal:<arn>           → specific principal ARN
        resource:*                → all resource-type nodes
        resource:<arn>            → specific resource ARN
        permission:<svc>:<action> → all nodes that can perform this action via
                                    outbound edges, OR nodes from which a
                                    policy-write edge can inject it
        permission:*:*            → all nodes reachable via any edge (treat as
                                    unconstrained — return all non-source nodes)
    """
    obj_type, _, obj_rest = objective.partition(":")

    # ── principal ────────────────────────────────────────────────────────────
    if obj_type == "principal":
        return [obj_rest] if obj_rest in G else []

    # ── resource ─────────────────────────────────────────────────────────────
    if obj_type == "resource":
        if obj_rest == "*":
            return [n for n, d in G.nodes(data=True) if d.get("node_type") == "resource"]
        return [obj_rest] if obj_rest in G else []

    # ── permission ───────────────────────────────────────────────────────────
    if obj_type == "permission":
        action = obj_rest   # e.g. "*:*" or "iam:CreatePolicyVersion"

        if action == "*:*":
            # "full admin" — all nodes are potential targets
            return list(G.nodes)

        # Find nodes whose outbound edge actions match the target
        targets: set[str] = set()
        for u, v, data in G.edges(data=True):
            edge_action = data.get("action", "")
            # Simple substring match: action requested must appear in edge action
            if action.lower() in edge_action.lower():
                targets.add(v)
        # Also include nodes reachable via iam_policy_inject (inject path creates the perm)
        for u, v, data in G.edges(data=True):
            if data.get("edge_type") == "iam_policy_inject":
                targets.add(v)
        return list(targets)

    return []


# ── Public API ────────────────────────────────────────────────────────────────

def find_paths(
    G: nx.MultiDiGraph,
    from_arn: str,
    objective: str | None = None,
    max_hops: int = 10,
) -> list[PathResult]:
    """
    Find all attack paths from from_arn to nodes satisfying objective.

    If objective is None: unconstrained traversal — return all nodes
    reachable within max_hops.

    Returns list sorted by severity DESC, hops ASC.
    """
    if from_arn not in G:
        log.warning("[attack_path] from_arn %s not in graph — no paths", from_arn)
        return []

    results: list[PathResult] = []

    if objective is None:
        # ── Unconstrained mode ─────────────────────────────────────────────
        reachable = nx.single_source_shortest_path(G, source=from_arn, cutoff=max_hops)
        for target_arn, path in reachable.items():
            if target_arn == from_arn:
                continue
            results.append(_path_to_result(G, path, from_arn, objective=None))
    else:
        # ── Targeted mode ──────────────────────────────────────────────────
        target_nodes = _resolve_targets(G, objective)
        if not target_nodes:
            log.info("[attack_path] No target nodes resolved for objective %r", objective)
            return []
        for target in target_nodes:
            if target == from_arn:
                continue
            if target not in G:
                continue
            try:
                for path in nx.all_simple_paths(G, source=from_arn, target=target, cutoff=max_hops):
                    results.append(_path_to_result(G, path, from_arn, objective))
            except nx.NetworkXNoPath:
                pass
            except nx.NodeNotFound:
                pass

    # Sort: CRITICAL first, then fewest hops
    results.sort(key=lambda r: (_SEV_ORDER.get(r.severity, 99), r.hops))
    log.info("[attack_path] find_paths(%s, %r) → %d paths", from_arn, objective, len(results))
    return results


# ── Demand-driven BFS (no pre-built graph required) ─────────────────────────

def _resolve_objective_bfs(objective: str | None, ctx) -> set[str] | None:
    """Resolve an objective string to a target ARN set using NeighborContext data.

    Returns:
        None          → unconstrained (stop at nothing, collect all reachable)
        set of ARNs   → stop when any of these ARNs is reached
        empty set     → objective is unresolvable (no matching nodes)
    """
    if objective is None:
        return None

    obj_type, _, obj_rest = objective.partition(":")

    if obj_type == "principal":
        all_arns = {p.arn for p in ctx.principals}
        return {obj_rest} if obj_rest in all_arns else set()

    if obj_type == "resource":
        if obj_rest == "*":
            return {r.arn for r in ctx.resources}
        all_arns = {r.arn for r in ctx.resources}
        return {obj_rest} if obj_rest in all_arns else set()

    if obj_type == "permission":
        # Any principal that has this action in its action_cache
        if obj_rest == "*:*":
            return {p.arn for p in ctx.principals}  # unconstrained over principals
        from worstassume.core.iam_actions import _can_do
        return {
            arn for arn, actions in ctx.action_cache.items()
            if _can_do(actions, obj_rest)
        }

    return set()


def find_paths_bfs(
    ctx,                          # NeighborContext
    from_arn: str,
    objective: str | None = None,
    max_hops: int = 10,
) -> list[PathResult]:
    """Demand-driven BFS: expand neighbors on demand, no pre-built graph.

    Complexity: O(reachable_nodes × edge_types) instead of O(N²).
    The graph is never fully materialized in memory.

    Returns the same PathResult list as find_paths(), sorted by severity then hops.
    """
    all_arns = {p.arn for p in ctx.principals} | {r.arn for r in ctx.resources}
    if from_arn not in all_arns:
        log.warning("[attack_path_bfs] from_arn %s not in context — no paths", from_arn)
        return []

    targets = _resolve_objective_bfs(objective, ctx)
    if targets is not None and not targets:
        log.info("[attack_path_bfs] objective %r resolved to empty set", objective)
        return []

    results: list[PathResult] = []
    # visited ARNs to avoid cycles
    visited: set[str] = {from_arn}
    # queue: (current_arn, steps_so_far)
    # steps_so_far is a list of step dicts with keys:
    #   actor, action, target, edge_type, explanation, severity
    queue: deque = deque([(from_arn, [])])

    while queue:
        current, steps = queue.popleft()

        if len(steps) >= max_hops:
            continue

        for neighbor_arn, edge_data in ctx.get_neighbors(current):
            if neighbor_arn == from_arn:
                continue  # don’t loop back to source

            step = {
                "actor":       current,
                "action":      edge_data.get("action", ""),
                "target":      neighbor_arn,
                "edge_type":   edge_data.get("edge_type", ""),
                "explanation": edge_data.get("explanation", ""),
                "severity":    edge_data.get("severity", "MEDIUM"),
            }
            new_steps = steps + [step]

            is_target = (
                targets is None or          # unconstrained
                neighbor_arn in targets     # matches objective
            )

            if is_target:
                worst_sev = min(
                    new_steps,
                    key=lambda s: _SEV_ORDER.get(s["severity"], 99)
                )["severity"]
                results.append(PathResult(
                    from_arn=from_arn,
                    to_arn=neighbor_arn,
                    severity=worst_sev,
                    hops=len(new_steps),
                    steps=new_steps,
                    objective=objective,
                ))
                log.debug("[attack_path_bfs] path found: %s → %s (%d hops)",
                          from_arn, neighbor_arn, len(new_steps))
                # Don’t add to visited — other paths might reach same target
                # via different intermediate routes; but do stop expanding it.
                continue

            if neighbor_arn not in visited:
                visited.add(neighbor_arn)
                queue.append((neighbor_arn, new_steps))

    results.sort(key=lambda r: (_SEV_ORDER.get(r.severity, 99), r.hops))
    log.info("[attack_path_bfs] find_paths_bfs(%s, %r) → %d paths",
             from_arn, objective, len(results))
    return results


# ── Persistence ────────────────────────────────────────────────────────────────

def _infer_account_id(db: Session, from_arn: str) -> int | None:
    """Try to resolve the DB account.id from the ARN's account segment."""
    from worstassume.db.models import Account as _Account
    parts = from_arn.split(":")
    if len(parts) >= 5 and parts[4]:
        acct = db.query(_Account).filter_by(account_id=parts[4]).first()
        return acct.id if acct else None
    return None


def persist(
    db: Session,
    paths: list[PathResult],
    from_arn: str,
    objective: str | None,
    account: Account | None = None,
) -> list[AttackPath]:
    """
    Upsert PathResults into attack_paths + attack_path_steps tables.

    Deduplication key: (account_id, from_principal_arn, objective_type,
                        objective_value, summary).
    If a matching row exists, its steps are deleted and re-inserted.

    Returns list of AttackPath ORM objects.
    """
    if not paths:
        return []

    # Resolve account_id
    acct_id: int | None
    if account is not None:
        acct_id = account.id
    else:
        acct_id = _infer_account_id(db, from_arn)
    if acct_id is None:
        raise ValueError(
            f"Cannot resolve account for from_arn={from_arn!r}. "
            "Pass account= explicitly or ensure the account is in the DB."
        )

    # Parse objective string
    if objective:
        obj_type, _, obj_value = objective.partition(":")
    else:
        obj_type, obj_value = None, None

    persisted: list[AttackPath] = []

    for result in paths:
        summary = f"{result.from_arn} → {result.to_arn} ({result.hops} hops)"

        # Check for existing row (dedup)
        existing = (
            db.query(AttackPath)
            .filter_by(
                account_id=acct_id,
                from_principal_arn=result.from_arn,
                objective_type=obj_type,
                objective_value=obj_value or None,
                summary=summary,
            )
            .first()
        )

        if existing is not None:
            # Delete old steps and override severity/hops (idempotent re-run)
            for step in list(existing.steps):
                db.delete(step)
            db.flush()
            ap = existing
            ap.severity   = result.severity
            ap.total_hops = result.hops
        else:
            ap = AttackPath(
                account_id=acct_id,
                from_principal_arn=result.from_arn,
                objective_type=obj_type or None,
                objective_value=obj_value or None,
                severity=result.severity,
                total_hops=result.hops,
                summary=summary,
            )
            db.add(ap)
            db.flush()   # populate ap.id

        # Insert steps
        for i, step in enumerate(result.steps):
            db.add(AttackPathStep(
                path_id=ap.id,
                step_index=i,
                actor_arn=step["actor"],
                action=step["action"],
                target_arn=step["target"],
                explanation=step["explanation"],
                edge_type=step["edge_type"],
            ))

        persisted.append(ap)

    db.flush()
    log.info("[attack_path] persisted %d attack paths", len(persisted))
    return persisted
