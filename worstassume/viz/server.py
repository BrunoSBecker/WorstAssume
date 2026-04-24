"""FastAPI visualization server — serves the React graph builder UI."""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path

import networkx as nx
from fastapi import Body, FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from worstassume.core import privilege_escalation
from worstassume.core.graph_store import GraphStore
from worstassume.db.engine import get_session
from worstassume.db.models import Account, CrossAccountLink, Policy, Principal, Resource, SecurityFinding

log = logging.getLogger(__name__)

app = FastAPI(title="WorstAssume Viz", docs_url=None, redoc_url=None)

_FRONTEND_DIST = Path(__file__).parent / "frontend" / "dist"
_TEMPLATES_DIR = Path(__file__).parent / "templates"


# ── GraphCache ────────────────────────────────────────────────────────────────
# ── Static frontend (built React app) ────────────────────────────────────────

if _FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=_FRONTEND_DIST / "assets"), name="assets")

    @app.get("/", response_class=HTMLResponse)
    async def index():
        return HTMLResponse(content=(_FRONTEND_DIST / "index.html").read_text())
else:
    @app.get("/", response_class=HTMLResponse)
    async def index():
        return HTMLResponse(content=(_TEMPLATES_DIR / "index.html").read_text())


# ── GraphCache — single process-level graph store ─────────────────────────────

class GraphCache:
    """
    Process-level singleton that holds a built GraphStore.

    Auto-rebuilds when the SQLite file is newer than the last build (mtime check).
    Thread-safe via a simple lock — only one rebuild runs at a time.
    """

    def __init__(self) -> None:
        self._store: GraphStore | None = None
        self._db_path: str | None = None
        self._lock = threading.Lock()

    def get(self, db, db_path: str | None = None) -> GraphStore:
        """Return a fresh (or cached) GraphStore, rebuilding if stale."""
        with self._lock:
            stale = (
                self._store is None
                or (db_path and self._store.is_stale(db_path))
            )
            if stale:
                log.info("[graph_cache] building graph store…")
                self._store = GraphStore.build(db)
                self._db_path = db_path
                log.info(
                    "[graph_cache] ready: %d nodes, %d edges",
                    len(self._store.nodes), len(self._store.edges),
                )
        return self._store


_CACHE = GraphCache()


def _db_path() -> str | None:
    """Return the SQLite file path used by the engine (mirrors CLI default)."""
    try:
        from worstassume.db.engine import get_db_path
        return str(get_db_path())
    except Exception:
        return os.environ.get("WORST_DB")


def _get_store(db) -> GraphStore:
    return _CACHE.get(db, _db_path())


def _prewarm_cache() -> None:
    """Build the GraphStore once at server startup so the first request is instant."""
    db = get_session()
    try:
        _CACHE.get(db, _db_path())
    except Exception as exc:
        log.warning("[graph_cache] pre-warm failed (non-fatal): %s", exc)
    finally:
        db.close()


@app.on_event("startup")
async def startup() -> None:
    # Run in a thread so it doesn't block Uvicorn's async loop
    t = threading.Thread(target=_prewarm_cache, daemon=True, name="graph-prewarm")
    t.start()


# ────────────────────────────────────────────────────────────────────────────────
# Helpers shared between /api/entities and /api/graph/node
# ────────────────────────────────────────────────────────────────────────────────

def _collect_principal_actions(principal) -> list[str]:
    actions: set[str] = set()
    for policy in principal.policies:
        doc = policy.document
        if not doc:
            continue
        stmts = doc.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        for stmt in stmts:
            if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
                continue
            a = stmt.get("Action", [])
            if isinstance(a, str):
                a = [a]
            actions.update(a)
    return sorted(actions)


def _extract_trust_principals(principal) -> list[str]:
    if principal.principal_type != "role" or not principal.trust_policy:
        return []
    result: set[str] = set()
    for stmt in principal.trust_policy.get("Statement", []):
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue
        pval = stmt.get("Principal", {})
        if pval == "*":
            result.add("* (anyone)")
            continue
        if isinstance(pval, str):
            result.add(pval)
        elif isinstance(pval, dict):
            for _, v in pval.items():
                if isinstance(v, str):
                    result.add(v)
                elif isinstance(v, list):
                    result.update(v)
    return sorted(result)


# ── API: accounts ─────────────────────────────────────────────────────────────

@app.get("/api/accounts")
async def api_accounts():
    db = get_session()
    try:
        accounts = db.query(Account).all()
        return JSONResponse(content=[
            {
                "account_id": a.account_id,
                "account_name": a.account_name,
                "org_id": a.org_id,
                "last_enumerated_at": str(a.last_enumerated_at) if a.last_enumerated_at else None,
                "principals": db.query(Principal).filter_by(account_id=a.id).count(),
                "resources":  db.query(Resource).filter_by(account_id=a.id).count(),
            }
            for a in accounts
        ])
    finally:
        db.close()


# ── API: dashboard stats ───────────────────────────────────────────────────────

@app.get("/api/stats")
async def api_stats():
    """
    Fast dashboard stats — DB COUNT queries only.
    Findings are NOT computed here; use GET /api/security-findings (persisted)
    or POST /api/security-findings/run (on-demand) instead.
    """
    db = get_session()
    try:
        return JSONResponse(content={
            "accounts":   db.query(Account).count(),
            "principals": db.query(Principal).count(),
            "resources":  db.query(Resource).count(),
            "policies":   db.query(Policy).count(),
        })
    finally:
        db.close()


def _collect_policy_actions(policy) -> list[str]:
    """Extract all Allow actions from a policy document."""
    doc = policy.document
    if not doc:
        return []
    actions: set[str] = set()
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for stmt in stmts:
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue
        a = stmt.get("Action", [])
        if isinstance(a, str):
            a = [a]
        actions.update(a)
    return sorted(actions)


# ── API: entity catalogue (paginated) ─────────────────────────────────────────

@app.get("/api/entities")
async def api_entities(page: int = 1, page_size: int = 0):
    """
    Flat catalogue of all principals, policies, resources and accounts.
    page_size=0 (default) returns everything for backwards compat.
    """
    db = get_session()
    try:
        from sqlalchemy.orm import joinedload as jl
        principals = (
            db.query(Principal)
            .options(jl(Principal.policies), jl(Principal.account))
            .all()
        )
        policies   = (
            db.query(Policy)
            .options(jl(Policy.account), jl(Policy.principals))
            .all()
        )
        resources  = (
            db.query(Resource)
            .options(jl(Resource.account), jl(Resource.execution_role))
            .all()
        )
        accounts   = db.query(Account).all()
        return JSONResponse(content={
            "accounts": [
                {
                    "node_id": f"account:{a.account_id}",
                    "label": a.account_name or a.account_id,
                    "account_id": a.account_id,
                    "node_type": "account",
                }
                for a in accounts
            ],
            "principals": [
                {
                    "node_id": f"principal:{p.arn}",
                    "label": p.name,
                    "arn": p.arn,
                    "principal_type": p.principal_type,
                    "account_id": p.account.account_id if p.account else None,
                    "node_type": "principal",
                    "actions": _collect_principal_actions(p),
                    "trust_principals": _extract_trust_principals(p),
                    # Full policy list for sidebar
                    "policies": [
                        {
                            "name": pol.name,
                            "arn": pol.arn,
                            "type": pol.policy_type,
                        }
                        for pol in p.policies
                    ],
                }
                for p in principals
            ],
            "policies": [
                {
                    "node_id": f"policy:{pol.arn}",
                    "label": pol.name,
                    "arn": pol.arn,
                    "policy_type": pol.policy_type,
                    "account_id": pol.account.account_id if pol.account else None,
                    "node_type": "policy",
                    # Actions granted by this policy
                    "actions": _collect_policy_actions(pol),
                    # Principals that have this policy attached
                    "attached_principals": [
                        {"name": pr.name, "arn": pr.arn, "type": pr.principal_type}
                        for pr in pol.principals
                    ],
                }
                for pol in policies
            ],
            "resources": [
                {
                    "node_id": f"resource:{r.arn}",
                    "label": r.name or r.arn,
                    "arn": r.arn,
                    "service": r.service,
                    "resource_type": r.resource_type,
                    "region": r.region,
                    "account_id": r.account.account_id if r.account else None,
                    "node_type": "resource",
                    # Execution role if present
                    "execution_role": {
                        "name": r.execution_role.name,
                        "arn": r.execution_role.arn,
                    } if r.execution_role else None,
                    # Actions from execution role policies
                    "actions": _collect_principal_actions(r.execution_role) if r.execution_role else [],
                }
                for r in resources
            ],
            "total": len(principals) + len(policies) + len(resources) + len(accounts),
        })
    finally:
        db.close()


# ── API: new graph endpoints (fast, O(1) lookups via GraphStore) ──────────────

@app.get("/api/graph/node/{node_id:path}")
async def api_graph_node(node_id: str, depth: int = 1):
    """Return node attributes + neighbors up to `depth` hops. O(1) via pre-index."""
    db = get_session()
    try:
        store = _get_store(db)
        result = store.neighbors(node_id, depth=depth)
        return JSONResponse(content=result)
    finally:
        db.close()


@app.get("/api/graph/nodes")
async def api_graph_nodes(ids: str = ""):
    """Batch node lookup. `ids` is a comma-separated list of node IDs."""
    db = get_session()
    try:
        store = _get_store(db)
        id_list = [i.strip() for i in ids.split(",") if i.strip()]
        nodes = [store.nodes[nid].to_dict() for nid in id_list if nid in store.nodes]
        # Collect edges between the requested nodes
        id_set = set(id_list)
        edges = [
            e.to_dict()
            for (src, dst), e in store.edges.items()
            if src in id_set and dst in id_set
        ]
        return JSONResponse(content={"nodes": nodes, "edges": edges})
    finally:
        db.close()


@app.get("/api/graph/export")
async def api_graph_export():
    """Export the full graph in graphology-compatible JSON format."""
    db = get_session()
    try:
        store = _get_store(db)
        return JSONResponse(content=store.export())
    finally:
        db.close()


# ── API: legacy neighbor endpoint (kept for compatibility) ────────────────────

@app.get("/api/neighbors/{node_id:path}")
async def api_neighbors(node_id: str):
    """1-hop subgraph — delegates to graph/node. Kept for backwards compat."""
    db = get_session()
    try:
        store = _get_store(db)
        result = store.neighbors(node_id, depth=1)
        # Return in Cytoscape format expected by old frontend code
        cy_nodes = [{"data": n} for n in result["nodes"]]
        cy_edges = [{"data": e} for e in result["edges"]]
        return JSONResponse(content={"nodes": cy_nodes, "edges": cy_edges})
    finally:
        db.close()


# ── API: multi-hop attack chains ──────────────────────────────────────────────

def _chain_step_to_dict(s) -> dict:
    return {
        "actor": s.actor, "actor_label": s.actor_label,
        "action": s.action, "target": s.target, "explanation": s.explanation,
    }


def _chain_to_dict(c) -> dict:
    return {
        "chain_id": c.chain_id, "severity": c.severity, "title": c.title,
        "principal_arn": c.principal_arn,
        "node_id": f"principal:{c.principal_arn}",
        "account_id": c.account_id, "outcome": c.outcome,
        "suppressed": c.suppressed, "suppress_reason": c.suppress_reason,
        "steps": [_chain_step_to_dict(s) for s in c.steps],
    }


@app.get("/api/chains")
async def api_chains(account_id: str | None = None, suppress_sso: bool = True):
    import asyncio
    db = get_session()
    try:
        acct = None
        if account_id:
            acct = db.query(Account).filter_by(account_id=account_id).first()
        loop = asyncio.get_event_loop()
        chains = await loop.run_in_executor(
            None,
            lambda: privilege_escalation.analyze_chains(db, acct, max_workers=4),
        )
        return JSONResponse(content=[
            _chain_to_dict(c) for c in chains
            if not (suppress_sso and c.suppressed)
        ])
    finally:
        db.close()


# ── API: security findings (persisted) ────────────────────────────────────

def _sf_to_dict(f: SecurityFinding) -> dict:
    return {
        "id":                f.id,
        "account_id":        f.account.account_id if f.account else None,  # AWS acct ID string
        "entity_arn":        f.entity_arn,
        "entity_type":       f.entity_type,
        "entity_name":       f.entity_name,
        "category":          f.category,
        "path_id":           f.path_id,
        "severity":          f.severity,
        "original_severity": f.original_severity,
        "message":           f.message,
        "principal_detail":  f.principal_detail,
        "condition":         f.condition,
        "perm_risk":         f.perm_risk,
        "downgrade_note":    f.downgrade_note,
        "suppressed":        f.suppressed,
        "created_at":        str(f.created_at) if f.created_at else None,
    }


@app.get("/api/security-findings")
async def api_security_findings(
    account_id:   str | None = None,
    severity:     str | None = None,
    category:     str | None = None,
    entity_type:  str | None = None,
    suppressed:   bool = False,
):
    """
    Return persisted SecurityFinding rows with optional filters.
    Results must be pre-computed via `worst assess` or POST /api/security-findings/run.
    """
    db = get_session()
    try:
        query = db.query(SecurityFinding)
        if account_id:
            acct = db.query(Account).filter_by(account_id=account_id).first()
            if acct:
                query = query.filter(SecurityFinding.account_id == acct.id)
        if severity:
            query = query.filter(SecurityFinding.severity == severity.upper())
        if category:
            query = query.filter(SecurityFinding.category == category.upper())
        if entity_type:
            query = query.filter(SecurityFinding.entity_type == entity_type.lower())
        if not suppressed:
            query = query.filter(SecurityFinding.suppressed == False)  # noqa: E712
        findings = query.order_by(SecurityFinding.severity, SecurityFinding.category).all()
        return JSONResponse(content=[_sf_to_dict(f) for f in findings])
    finally:
        db.close()


@app.get("/api/security-findings/entity/{entity_arn:path}")
async def api_security_findings_entity(entity_arn: str):
    """All persisted findings for a specific entity ARN."""
    db = get_session()
    try:
        findings = (
            db.query(SecurityFinding)
            .filter_by(entity_arn=entity_arn)
            .order_by(SecurityFinding.severity)
            .all()
        )
        return JSONResponse(content=[_sf_to_dict(f) for f in findings])
    finally:
        db.close()


@app.post("/api/security-findings/run")
async def api_security_findings_run(
    body: dict = Body(default={}),
):
    """
    Trigger a security assessment run and return the persisted findings.
    Body (optional JSON): {"account_id": str, "min_severity": str}
    CPU-intensive — runs in a thread executor.
    """
    import asyncio
    from worstassume.core.security_assessment import assess, SeverityConfig

    body = body or {}
    account_id   = body.get("account_id")
    min_severity = body.get("min_severity", "HIGH").upper()

    db = get_session()
    try:
        account = None
        if account_id:
            account = db.query(Account).filter_by(account_id=account_id).first()

        loop = asyncio.get_event_loop()
        findings = await loop.run_in_executor(
            None,
            lambda: assess(db, account=account, min_severity=min_severity),
        )
        return JSONResponse(content={
            "status": "ok",
            "count": len(findings),
            "findings": [_sf_to_dict(f) for f in findings],
        })
    finally:
        db.close()


# ── API: cross-account links ──────────────────────────────────────────────────

@app.get("/api/cross-account-links")
async def api_cross_account_links():
    db = get_session()
    try:
        links = db.query(CrossAccountLink).all()
        return JSONResponse(content=[
            {
                "source_account": link.source_account.account_id if link.source_account else None,
                "target_account": link.target_account.account_id if link.target_account else None,
                "role_arn": link.role_arn,
                "trust_principal_arn": link.trust_principal_arn,
                "is_wildcard": link.is_wildcard,
                "link_type": link.link_type,
            }
            for link in links
        ])
    finally:
        db.close()


# ── API: principal search ─────────────────────────────────────────────────────

@app.get("/api/principals")
async def api_principals(q: str = ""):
    from worstassume.core.resource_graph import _normalize_assumed_role_arn
    db = get_session()
    try:
        query = db.query(Principal).filter(
            Principal.principal_type.in_(["user", "role"])
        )
        assumed_resolved = None
        if q and ":assumed-role/" in q:
            resolved_arn = _normalize_assumed_role_arn(q, db)
            if resolved_arn:
                p = db.query(Principal).filter_by(arn=resolved_arn).first()
                if p:
                    assumed_resolved = {
                        "node_id": f"principal:{p.arn}", "arn": p.arn,
                        "name": p.name, "principal_type": p.principal_type,
                        "account_id": p.account.account_id if p.account else None,
                        "resolved_from": q,
                    }

        if q and ":assumed-role/" not in q:
            q_lower = q.lower()
            principals = [
                p for p in query.all()
                if q_lower in p.name.lower() or q_lower in p.arn.lower()
            ]
        else:
            principals = query.order_by(Principal.name).limit(80).all()

        result = [
            {
                "node_id": f"principal:{p.arn}", "arn": p.arn,
                "name": p.name, "principal_type": p.principal_type,
                "account_id": p.account.account_id if p.account else None,
            }
            for p in principals
        ]
        if assumed_resolved:
            result = [assumed_resolved] + [r for r in result if r["arn"] != assumed_resolved["arn"]]

        return JSONResponse(content=result)
    finally:
        db.close()


# ── GraphStore-based viz helpers (used by /api/path and /api/path-privesc) ──────────

_TRAVERSABLE_EDGES = {"can_assume", "cross_account", "execution_role"}

_EDGE_EXPLANATIONS = {
    "can_assume":     "Can call sts:AssumeRole on this role (trust policy allows it)",
    "cross_account":  "Has a cross-account trust link — can assume a role in the target account",
    "execution_role": "This resource runs as the role — attacker who controls the resource inherits its permissions",
}

_EDGE_ICONS = {
    "can_assume":     "→ assume",
    "cross_account":  "→ cross-account",
    "execution_role": "→ exec as",
}


def _build_attack_digraph(store: GraphStore) -> nx.DiGraph:
    """Build a NetworkX DiGraph with only traversable attack edges, from GraphStore data."""
    AG = nx.DiGraph()
    for nid, attrs in store.nodes.items():
        AG.add_node(nid, **attrs.to_dict())
    for (src, dst), edge in store.edges.items():
        if edge.edge_type in _TRAVERSABLE_EDGES:
            AG.add_edge(src, dst, **edge.to_dict())
    return AG


def _explain_hop(store: GraphStore, AG: nx.DiGraph, src: str, dst: str) -> dict:
    src_attrs  = store.nodes.get(src)
    dst_attrs  = store.nodes.get(dst)
    edge_data  = AG.edges.get((src, dst), {})
    et = edge_data.get("edge_type", "")
    explanation = _EDGE_EXPLANATIONS.get(et, f"Connected via '{et}'")
    extras = []
    if edge_data.get("is_wildcard"):
        extras.append("wildcard trust — any principal can assume this role")
    if edge_data.get("condition"):
        extras.append(f"condition: {edge_data['condition']}")
    if extras:
        explanation += f" ({', '.join(extras)})"
    return {
        "from_id":    src,
        "from_label": src_attrs.label if src_attrs else src,
        "from_type":  (src_attrs.principal_type or src_attrs.node_type) if src_attrs else "",
        "to_id":      dst,
        "to_label":   dst_attrs.label if dst_attrs else dst,
        "to_type":    (dst_attrs.principal_type or dst_attrs.node_type) if dst_attrs else "",
        "edge_type":  et,
        "edge_icon":  _EDGE_ICONS.get(et, "→"),
        "explanation": explanation,
        "is_reversed": False,
        "trust_principal_arn": edge_data.get("trust_principal_arn"),
    }


def _path_to_response(store: GraphStore, AG: nx.DiGraph, path: list[str]) -> dict:
    """Build the full path response dict including nodes, edges, and hop explanations."""
    hops = [_explain_hop(store, AG, path[i], path[i + 1]) for i in range(len(path) - 1)]
    path_set = set(path)
    nodes = [store.nodes[n].to_dict() for n in path if n in store.nodes]
    edges = [
        e.to_dict()
        for (src, dst), e in store.edges.items()
        if src in path_set and dst in path_set
        and e.edge_type in _TRAVERSABLE_EDGES
    ]
    return {
        "found": True, "nodes": nodes, "edges": edges,
        "hops": hops, "path": path,
    }


# ── API: shortest attack path ─────────────────────────────────────────────────

@app.get("/api/path")
async def api_path(from_id: str, to_id: str):
    """Shortest directed attack path between two nodes (traversable edges only)."""
    db = get_session()
    try:
        store = _get_store(db)
        AG = _build_attack_digraph(store)

        if from_id not in AG or to_id not in AG:
            return JSONResponse(content={"found": False, "nodes": [], "edges": [], "hops": []})

        try:
            path = nx.shortest_path(AG, from_id, to_id)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return JSONResponse(content={"found": False, "nodes": [], "edges": [], "hops": []})

        return JSONResponse(content=_path_to_response(store, AG, path))
    finally:
        db.close()


# ── API: privilege-escalation-aware path ──────────────────────────────────────

@app.get("/api/path-privesc")
async def api_path_privesc(from_id: str, to_id: str):
    """
    Finds a path combining direct graph traversal with privilege escalation chains.
    Returns path_type: "direct" | "chain" | "none".
    """
    db = get_session()
    try:
        store = _get_store(db)
        AG = _build_attack_digraph(store)

        # 1. Try direct path first
        if from_id in AG and to_id in AG:
            try:
                path = nx.shortest_path(AG, from_id, to_id)
                result = _path_to_response(store, AG, path)
                result["path_type"] = "direct"
                return JSONResponse(content=result)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                pass

        # 2. Fall back to chain analysis
        attacker_arn = from_id[len("principal:"):] if from_id.startswith("principal:") else None
        target_arn   = to_id[len("principal:"):]   if to_id.startswith("principal:")   else None

        if not attacker_arn:
            return JSONResponse(content={
                "found": False, "path_type": "none",
                "nodes": [], "edges": [], "hops": [],
                "reason": "Source node is not a principal.",
            })

        attacker_account_id: str | None = None
        p = db.query(Principal).filter_by(arn=attacker_arn).first()
        if p and p.account:
            attacker_account_id = p.account.account_id

        target_account_id: str | None = None
        if target_arn:
            tp = db.query(Principal).filter_by(arn=target_arn).first()
            if tp and tp.account:
                target_account_id = tp.account.account_id

        target_is_admin = False
        if target_arn:
            tp = db.query(Principal).filter_by(arn=target_arn).first()
            if tp:
                from worstassume.core.privilege_escalation import _collect_allowed_actions, _is_dangerous_action_set
                target_is_admin = _is_dangerous_action_set(frozenset(_collect_allowed_actions(tp)))

        all_chains = privilege_escalation.analyze_chains(db)
        sev_order  = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
        matching_chains = []

        for c in all_chains:
            if c.principal_arn != attacker_arn or c.suppressed:
                continue
            relevance: str | None = None
            for step in c.steps:
                if target_arn and (target_arn in step.target or target_arn in step.actor):
                    relevance = f"Chain step directly involves target '{target_arn}'"
                    break
            if not relevance and target_is_admin and target_account_id == attacker_account_id:
                relevance = (
                    f"Chain grants admin-level access in account '{attacker_account_id}', "
                    f"which includes control over target '{target_arn}'"
                )
            if not relevance and "admin" in c.outcome.lower() and target_arn == attacker_arn:
                relevance = "Chain is a self-escalation path for the selected identity"

            if relevance:
                matching_chains.append({
                    "chain_id": c.chain_id, "severity": c.severity,
                    "title": c.title, "outcome": c.outcome, "relevance": relevance,
                    "steps": [_chain_step_to_dict(s) for s in c.steps],
                })

        if not matching_chains:
            return JSONResponse(content={
                "found": False, "path_type": "none",
                "nodes": [], "edges": [], "hops": [],
                "reason": f"No direct path or privilege escalation chain found from '{attacker_arn}'.",
            })

        matching_chains.sort(key=lambda c: sev_order.get(c["severity"], 99))
        return JSONResponse(content={
            "found": True, "path_type": "chain",
            "nodes": [], "edges": [], "hops": [],
            "chains": matching_chains,
            "from_id": from_id, "to_id": to_id,
            "attacker_arn": attacker_arn, "target_arn": target_arn,
        })
    finally:
        db.close()


# ── API: findings reachable from an identity ──────────────────────────────────

@app.get("/api/privesc-from/{node_id:path}")
async def api_privesc_from(node_id: str):
    """All privesc findings and chain findings reachable from a given identity."""
    db = get_session()
    try:
        all_findings = privilege_escalation.analyze(db)
        all_chains   = privilege_escalation.analyze_chains(db)

        identity_arn = node_id[len("principal:"):] if node_id.startswith("principal:") else None
        identity_account_id: str | None = None
        if identity_arn:
            p = db.query(Principal).filter_by(arn=identity_arn).first()
            if p and p.account:
                identity_account_id = p.account.account_id

        if not identity_account_id:
            return JSONResponse(content=[])

        cross_account_arns: set[str] = set()
        account_obj = db.query(Account).filter_by(account_id=identity_account_id).first()
        if account_obj:
            for link in db.query(CrossAccountLink).filter_by(source_account_id=account_obj.id).all():
                if link.role_arn:
                    cross_account_arns.add(link.role_arn)

        def in_scope(arn: str, acct_id: str) -> tuple[bool, str]:
            if arn == identity_arn:
                return True, "This is your own identity"
            if acct_id == identity_account_id:
                return True, "Principal is in your account"
            if arn in cross_account_arns:
                return True, "Reachable via cross-account trust link"
            return False, ""

        matched = []
        for f in all_findings:
            ok, reason = in_scope(f.principal_arn, f.account_id)
            if not ok:
                continue
            matched.append({
                "result_type": "finding", "severity": f.severity, "path": f.path,
                "principal_arn": f.principal_arn, "node_id": f"principal:{f.principal_arn}",
                "account_id": f.account_id, "description": f.description,
                "details": f.details, "suppressed": f.suppressed,
                "is_self": f.principal_arn == identity_arn,
                "reachable_because": reason,
            })

        seen_chains: set[str] = set()
        for c in all_chains:
            ok, reason = in_scope(c.principal_arn, c.account_id)
            if not ok or c.suppressed:
                continue
            key = f"{c.chain_id}:{c.principal_arn}"
            if key in seen_chains:
                continue
            seen_chains.add(key)
            matched.append({
                "result_type": "chain", "severity": c.severity, "path": c.chain_id,
                "principal_arn": c.principal_arn, "node_id": f"principal:{c.principal_arn}",
                "account_id": c.account_id, "description": c.title,
                "details": {"outcome": c.outcome, "steps": [_chain_step_to_dict(s) for s in c.steps]},
                "suppressed": False, "is_self": c.principal_arn == identity_arn,
                "reachable_because": reason,
            })

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
        matched.sort(key=lambda x: sev_order.get(x["severity"], 99))
        return JSONResponse(content=matched)
    finally:
        db.close()


# ── API: node detail ──────────────────────────────────────────────────────────

@app.get("/api/node/{node_id:path}")
async def api_node_detail(node_id: str):
    """Full detail for a single node including enriched policy/action data."""
    db = get_session()
    try:
        store = _get_store(db)
        if node_id not in store.nodes:
            return JSONResponse(content={"error": "not found"}, status_code=404)

        data = dict(store.nodes[node_id].to_dict())

        if node_id.startswith("principal:"):
            arn = node_id[len("principal:"):]
            principal = db.query(Principal).filter_by(arn=arn).first()
            if principal:
                policies_out = []
                all_actions: set[str] = set()
                for pol in principal.policies:
                    doc = pol.document
                    actions: list[str] = []
                    if doc:
                        stmts = doc.get("Statement", [])
                        if isinstance(stmts, dict):
                            stmts = [stmts]
                        for stmt in stmts:
                            if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
                                continue
                            a = stmt.get("Action", [])
                            if isinstance(a, str):
                                a = [a]
                            actions.extend(a)
                    all_actions.update(actions)
                    policies_out.append({
                        "name": pol.name, "arn": pol.arn,
                        "type": pol.policy_type, "actions": sorted(set(actions)),
                    })
                data["policies"]        = policies_out
                data["all_actions"]     = sorted(all_actions)
                data["trust_principals"] = _extract_trust_principals(principal)

        if node_id.startswith("policy:"):
            arn = node_id[len("policy:"):]
            pol = db.query(Policy).filter_by(arn=arn).first()
            if pol:
                doc = pol.document
                actions: list[str] = []
                if doc:
                    stmts = doc.get("Statement", [])
                    if isinstance(stmts, dict):
                        stmts = [stmts]
                    for stmt in stmts:
                        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
                            continue
                        a = stmt.get("Action", [])
                        if isinstance(a, str):
                            a = [a]
                        actions.extend(a)
                data["policies"] = [{
                    "name": pol.name, "arn": pol.arn,
                    "type": pol.policy_type, "actions": sorted(set(actions)),
                }]
                data["all_actions"] = sorted(set(actions))
                data["attached_principals"] = [p.arn for p in pol.principals]
                if pol.document:
                    data["policy_document"] = json.dumps(pol.document, indent=2)

        return JSONResponse(content=data)
    finally:
        db.close()


# ── API: attack paths (Phase 6) ───────────────────────────────────────────────

from worstassume.db.models import AttackPath, AttackPathStep  # noqa: E402


def _ap_summary(ap: AttackPath) -> dict:
    return {
        "id":                 ap.id,
        "from_principal_arn": ap.from_principal_arn,
        "objective_type":     ap.objective_type,
        "objective_value":    ap.objective_value,
        "severity":           ap.severity,
        "total_hops":         ap.total_hops,
        "summary":            ap.summary,
        "created_at":         str(ap.created_at) if ap.created_at else None,
    }


def _ap_step(s: AttackPathStep) -> dict:
    return {
        "step_index":  s.step_index,
        "actor_arn":   s.actor_arn,
        "action":      s.action,
        "target_arn":  s.target_arn,
        "explanation": s.explanation,
        "edge_type":   s.edge_type,
    }


@app.get("/api/attack-paths")
async def api_attack_paths(
    from_arn:       str | None = None,
    severity:       str | None = None,
    objective_type: str | None = None,
    account_id:     str | None = None,
):
    """
    Return persisted AttackPath rows with optional filters.

    Query params:
        from_arn        – filter by starting identity ARN
        severity        – CRITICAL / HIGH / MEDIUM
        objective_type  – permission / resource / principal
        account_id      – AWS account ID string
    """
    db = get_session()
    try:
        query = db.query(AttackPath)
        if account_id:
            acct = db.query(Account).filter_by(account_id=account_id).first()
            if acct:
                query = query.filter(AttackPath.account_id == acct.id)
        if from_arn:
            query = query.filter(AttackPath.from_principal_arn == from_arn)
        if severity:
            query = query.filter(AttackPath.severity == severity.upper())
        if objective_type:
            query = query.filter(AttackPath.objective_type == objective_type.lower())
        paths = query.order_by(AttackPath.severity, AttackPath.total_hops).all()
        return JSONResponse(content=[_ap_summary(ap) for ap in paths])
    finally:
        db.close()


@app.get("/api/attack-paths/{path_id}")
async def api_attack_path_detail(path_id: int):
    """
    Full detail for a single AttackPath including all steps.
    Returns 404 if path_id is not found.
    """
    db = get_session()
    try:
        from sqlalchemy.orm import joinedload as _jl
        ap = (
            db.query(AttackPath)
            .options(_jl(AttackPath.steps))
            .filter(AttackPath.id == path_id)
            .first()
        )
        if ap is None:
            return JSONResponse(content={"error": "not found"}, status_code=404)
        result = _ap_summary(ap)
        result["steps"] = [_ap_step(s) for s in ap.steps]
        return JSONResponse(content=result)
    finally:
        db.close()


@app.post("/api/attack-paths/run")
async def api_attack_paths_run(body: dict = Body(default={})):
    """
    Build the attack graph, find paths, persist, and return results.

    Delegates to privilege_escalation.analyze_attack_paths() — the canonical
    orchestrator that owns all engine imports (attack_graph, attack_path).

    Body (JSON):
        from_arn    : str  – REQUIRED starting identity ARN
        objective   : str? – e.g. "permission:*:*" (optional)
        max_hops    : int? – default 10
        account_id  : str? – restrict to one AWS account ID

    Returns list[AttackPathSummary].
    CPU-intensive — runs in a thread executor.
    """
    import asyncio
    from worstassume.core.privilege_escalation import analyze_attack_paths

    body       = body or {}
    from_arn   = body.get("from_arn", "")
    objective  = body.get("objective")
    max_hops   = int(body.get("max_hops", 10))
    account_id = body.get("account_id")

    if not from_arn:
        return JSONResponse(
            content={"error": "from_arn is required"},
            status_code=422,
        )

    def _run():
        db = get_session()
        try:
            account = None
            if account_id:
                account = db.query(Account).filter_by(account_id=account_id).first()

            # All orchestration lives in privilege_escalation.analyze_attack_paths()
            analyze_attack_paths(
                db,
                from_arn=from_arn,
                objective=objective,
                max_hops=max_hops,
                account=account,
                persist_paths=True,
            )
            # Return the freshly persisted rows
            orms = (
                db.query(AttackPath)
                .filter_by(from_principal_arn=from_arn)
                .order_by(AttackPath.severity, AttackPath.total_hops)
                .all()
            )
            return [_ap_summary(ap) for ap in orms]
        finally:
            db.close()

    loop    = asyncio.get_event_loop()
    results = await loop.run_in_executor(None, _run)
    return JSONResponse(content=results)
