"""FastAPI visualization server — serves the React graph builder UI."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
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


# ── ReverseIndexCache — process-level reverse engine for the Threat Model ────

class ReverseIndexCache:
    """Holds a NeighborContext + ReverseIndex, rebuilt when the SQLite file changes.

    The Threat Model page expands one node at a time, so every click hits this.
    Loading the context and normalizing every principal's policy statements is
    the expensive part and is entirely DB-state dependent, so it is done once
    per DB change and shared across requests.
    """

    def __init__(self) -> None:
        self._index = None
        self._built_at: float = 0.0
        self._lock = threading.Lock()

    def get(self, db, db_path: str | None = None):
        from worstassume.core.attack_graph import NeighborContext
        from worstassume.core.reverse_index import ReverseIndex
        with self._lock:
            stale = self._index is None
            if not stale and db_path:
                try:
                    stale = os.path.getmtime(db_path) > self._built_at
                except OSError:
                    stale = True
            if stale:
                log.info("[reverse_index_cache] building reverse index…")
                started = time.time()
                ctx = NeighborContext(db)
                known = {a.account_id for a in db.query(Account).all()}
                self._index = ReverseIndex(ctx, known_accounts=known or None)
                self._built_at = time.time()
                log.info(
                    "[reverse_index_cache] ready in %.2fs: %d principals, %d resources",
                    self._built_at - started, len(ctx.principals), len(ctx.resources),
                )
        return self._index


_REVERSE_CACHE = ReverseIndexCache()


def _get_reverse_index(db):
    return _REVERSE_CACHE.get(db, _db_path())


def _prewarm_cache() -> None:
    """Build the GraphStore + entity index once at startup so first requests are instant."""
    db = get_session()
    try:
        _CACHE.get(db, _db_path())
    except Exception as exc:
        log.warning("[graph_cache] pre-warm failed (non-fatal): %s", exc)
    finally:
        db.close()
    db = get_session()
    try:
        _ENTITY_CACHE.get(db, _db_path())
    except Exception as exc:
        log.warning("[entity_index] pre-warm failed (non-fatal): %s", exc)
    finally:
        db.close()
    db = get_session()
    try:
        _get_reverse_index(db)
    except Exception as exc:
        log.warning("[reverse_index] pre-warm failed (non-fatal): %s", exc)
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
            "roles":      db.query(Principal).filter_by(principal_type="role").count(),
            "users":      db.query(Principal).filter_by(principal_type="user").count(),
            "groups":     db.query(Principal).filter_by(principal_type="group").count(),
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


# ── Entity catalogue index (cached, filterable, paginated) ────────────────────
#
# The entity catalogue is expensive to assemble for large orgs (10k+ principals,
# each requiring policy-document parsing).  We build it ONCE into a process-level
# index and invalidate it on SQLite mtime change (same strategy as GraphCache).
# All filtering / sorting / pagination then runs over the in-memory index.

_RISK_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "CLEAN": 4}


def _compute_entity_risk(actions: list[str], trusts: list[str], severities: set[str]) -> str:
    """Server-side mirror of the frontend computeRisk() heuristic."""
    if "CRITICAL" in severities:
        return "CRITICAL"
    if "HIGH" in severities:
        return "HIGH"
    if any(a == "*" or a == "iam:*" for a in actions):
        return "CRITICAL"
    if any(a.startswith("iam:") or a.startswith("sts:") for a in actions):
        return "HIGH"
    if any(a.startswith(("lambda:", "ec2:", "s3:")) for a in actions):
        return "MEDIUM"
    if any("*" in p for p in trusts):
        return "HIGH"
    if actions:
        return "LOW"
    return "CLEAN"


def _entity_is_aws_managed(item: dict) -> bool:
    """Server-side mirror of the frontend isAwsManaged() heuristic."""
    arn = item.get("arn") or ""
    label = item.get("label") or ""
    typ = item.get("principal_type") or item.get("node_type")
    if typ == "role":
        if "/aws-service-role/" in arn:
            return True
        if label.startswith("AWSServiceRole"):
            return True
        if "/AWSReservedSSO_" in arn:
            return True
        if "/aws-reserved/sso.amazonaws.com/" in arn:
            return True
    if item.get("node_type") == "policy":
        if item.get("policy_type") == "aws_managed":
            return True
        if ":aws:policy/" in arn:
            return True
    return False


def _permission_matches(actions_lc: list[str], query: str) -> bool:
    """IAM-style prefix match: 'iam:*' / 'iam:Assume' → startswith after stripping '*'."""
    q = query.lower().rstrip("*")
    if not q:
        return False
    return any(a.startswith(q) for a in actions_lc)


class EntityIndex:
    """
    Pre-built, cached catalogue of all entities with derived risk/paths/managed
    flags.  Supports server-side filtering, sorting and pagination.
    """

    def __init__(self) -> None:
        self.entries: list[dict] = []      # each: {"public": dict, filter fields...}
        # arn -> {"risk", "paths"}; lets other endpoints colour a node without
        # rescanning the catalogue.
        self.risk_by_arn: dict[str, dict] = {}
        self.type_counts: dict[str, int] = {}
        self.accounts: list[dict] = []     # [{"id","name"}]
        self.actions_vocab: list[str] = []
        self.built_at: float = 0.0

    # ── Build ────────────────────────────────────────────────────────────────
    @classmethod
    def build(cls, db) -> "EntityIndex":
        from sqlalchemy.orm import joinedload as jl

        idx = cls()
        principals = (
            db.query(Principal)
            .options(jl(Principal.policies), jl(Principal.account))
            .all()
        )
        policies = (
            db.query(Policy)
            .options(jl(Policy.account), jl(Policy.principals))
            .all()
        )
        resources = (
            db.query(Resource)
            .options(
                jl(Resource.account),
                jl(Resource.execution_role).joinedload(Principal.policies),
            )
            .all()
        )
        accounts = db.query(Account).all()

        # Non-suppressed finding severities per entity ARN
        sev_map: dict[str, set[str]] = {}
        path_count: dict[str, int] = {}
        for f in db.query(SecurityFinding).all():
            if f.suppressed:
                continue
            sev_map.setdefault(f.entity_arn, set()).add(f.severity)
            path_count[f.entity_arn] = path_count.get(f.entity_arn, 0) + 1

        vocab: set[str] = set()
        acct_names: dict[str, str] = {a.account_id: (a.account_name or a.account_id) for a in accounts}

        def _add(public: dict, type_key: str, actions: list[str], trusts: list[str]) -> None:
            arn = public.get("arn") or ""
            severities = sev_map.get(arn, set())
            risk = _compute_entity_risk(actions, trusts, severities)
            paths = path_count.get(arn, 0)
            public["risk"] = risk
            public["paths"] = paths
            if arn:
                idx.risk_by_arn[arn] = {"risk": risk, "paths": paths}
            managed = _entity_is_aws_managed(public)
            for a in actions:
                if isinstance(a, str):
                    vocab.add(a)
            acct = public.get("account_id")
            search = " ".join(
                x for x in (public.get("label"), arn, acct) if x
            ).lower()
            idx.entries.append({
                "public": public,
                "type_key": type_key,
                "account_id": acct,
                "service": public.get("service"),
                "managed": managed,
                "risk": risk,
                "risk_rank": _RISK_RANK.get(risk, 5),
                "search": search,
                "actions_lc": [a.lower() for a in actions if isinstance(a, str)],
            })

        for a in accounts:
            _add({
                "node_id": f"account:{a.account_id}",
                "label": a.account_name or a.account_id,
                "account_id": a.account_id,
                "node_type": "account",
            }, "account", [], [])

        for p in principals:
            actions = _collect_principal_actions(p)
            trusts = _extract_trust_principals(p)
            _add({
                "node_id": f"principal:{p.arn}",
                "label": p.name,
                "arn": p.arn,
                "principal_type": p.principal_type,
                "account_id": p.account.account_id if p.account else None,
                "node_type": "principal",
                "actions": actions,
                "trust_principals": trusts,
                "policies": [
                    {"name": pol.name, "arn": pol.arn, "type": pol.policy_type}
                    for pol in p.policies
                ],
            }, p.principal_type or "role", actions, trusts)

        for pol in policies:
            actions = _collect_policy_actions(pol)
            _add({
                "node_id": f"policy:{pol.arn}",
                "label": pol.name,
                "arn": pol.arn,
                "policy_type": pol.policy_type,
                "account_id": pol.account.account_id if pol.account else None,
                "node_type": "policy",
                "actions": actions,
                "attached_principals": [
                    {"name": pr.name, "arn": pr.arn, "type": pr.principal_type}
                    for pr in pol.principals
                ],
            }, "policy", actions, [])

        for r in resources:
            actions = _collect_principal_actions(r.execution_role) if r.execution_role else []
            _add({
                "node_id": f"resource:{r.arn}",
                "label": r.name or r.arn,
                "arn": r.arn,
                "service": r.service,
                "resource_type": r.resource_type,
                "region": r.region,
                "account_id": r.account.account_id if r.account else None,
                "node_type": "resource",
                "execution_role": {
                    "name": r.execution_role.name,
                    "arn": r.execution_role.arn,
                } if r.execution_role else None,
                "actions": actions,
                # Service-specific detail (IMDS, IPs, VPC/subnet/SG, etc.)
                "metadata": r.extra,
            }, "resource", actions, [])

        idx.type_counts = {
            "All": len(idx.entries),
            "role": sum(1 for e in idx.entries if e["type_key"] == "role"),
            "user": sum(1 for e in idx.entries if e["type_key"] == "user"),
            "group": sum(1 for e in idx.entries if e["type_key"] == "group"),
            "policy": sum(1 for e in idx.entries if e["type_key"] == "policy"),
            "resource": sum(1 for e in idx.entries if e["type_key"] == "resource"),
        }
        idx.accounts = [{"id": aid, "name": name} for aid, name in sorted(acct_names.items())]
        idx.actions_vocab = sorted(vocab)
        idx.built_at = time.time()
        log.info("[entity_index] built — %d entries, %d actions", len(idx.entries), len(idx.actions_vocab))
        return idx

    def is_stale(self, db_path: str | None) -> bool:
        if not self.built_at:
            return True
        if not db_path:
            return False
        try:
            return os.path.getmtime(db_path) > self.built_at
        except OSError:
            return True

    # ── Query ────────────────────────────────────────────────────────────────
    def query(
        self,
        *,
        type_key: str = "",
        risk: str = "",
        q: str = "",
        service: str = "",
        permissions: list[str] | None = None,
        account_id: str = "",
        managed: str = "all",
        page: int = 1,
        page_size: int = 50,
    ) -> dict:
        permissions = permissions or []
        q = (q or "").strip().lower()
        rows = self.entries

        if type_key == "principal":
            # Pseudo-key: everything that can act. The Threat Model asset picker
            # wants "principals vs resources", not one IAM type at a time.
            rows = [e for e in rows if e["type_key"] in ("role", "user", "group")]
        elif type_key:
            rows = [e for e in rows if e["type_key"] == type_key]
        if risk:
            ru = risk.upper()
            rows = [e for e in rows if e["risk"] == ru]
        if q:
            rows = [e for e in rows if q in e["search"]]
        if service and service != "All":
            rows = [e for e in rows if e["service"] == service]
        if account_id:
            rows = [e for e in rows if e["account_id"] == account_id]
        if permissions:
            rows = [
                e for e in rows
                if e["actions_lc"]
                and all(_permission_matches(e["actions_lc"], p) for p in permissions)
            ]
        if managed == "only":
            rows = [e for e in rows if e["managed"]]
        elif managed == "exclude":
            rows = [e for e in rows if not e["managed"]]
        elif managed == "none":
            rows = []

        rows = sorted(rows, key=lambda e: e["risk_rank"])
        total = len(rows)
        if page_size > 0:
            start = max(0, (page - 1) * page_size)
            rows = rows[start:start + page_size]
        return {
            "items": [e["public"] for e in rows],
            "total": total,
            "page": page,
            "page_size": page_size,
        }

    def grouped(self) -> dict:
        """Legacy full-dump shape: {accounts, principals, policies, resources, total}."""
        out = {"accounts": [], "principals": [], "policies": [], "resources": []}
        for e in self.entries:
            nt = e["public"].get("node_type")
            if nt == "account":
                out["accounts"].append(e["public"])
            elif nt == "principal":
                out["principals"].append(e["public"])
            elif nt == "policy":
                out["policies"].append(e["public"])
            elif nt == "resource":
                out["resources"].append(e["public"])
        out["total"] = len(self.entries)
        return out


class _EntityIndexCache:
    def __init__(self) -> None:
        self._idx: EntityIndex | None = None
        self._lock = threading.Lock()

    def get(self, db, db_path: str | None) -> EntityIndex:
        with self._lock:
            if self._idx is None or self._idx.is_stale(db_path):
                log.info("[entity_index] building…")
                self._idx = EntityIndex.build(db)
        return self._idx


_ENTITY_CACHE = _EntityIndexCache()


def _get_entity_index(db) -> EntityIndex:
    return _ENTITY_CACHE.get(db, _db_path())


# ── API: entity catalogue (paginated, filtered) ──────────────────────────────

@app.get("/api/entities")
async def api_entities(
    page: int = 1,
    page_size: int = 0,
    type: str = "",
    risk: str = "",
    q: str = "",
    service: str = "",
    permissions: str = "",
    account_id: str = "",
    managed: str = "all",
):
    """
    Entity catalogue with server-side filtering, sorting and pagination.

    page_size=0 (default) returns the legacy full grouped dump
    ({accounts, principals, policies, resources, total}) for backwards compat
    (report export, graph enrichment).  page_size>0 returns
    {items, total, page, page_size}.
    """
    db = get_session()
    try:
        idx = _get_entity_index(db)
        if page_size <= 0:
            return JSONResponse(content=idx.grouped())
        perms = [p.strip() for p in permissions.split(",") if p.strip()]
        result = idx.query(
            type_key=type,
            risk=risk,
            q=q,
            service=service,
            permissions=perms,
            account_id=account_id,
            managed=managed,
            page=page,
            page_size=page_size,
        )
        return JSONResponse(content=result)
    finally:
        db.close()


@app.get("/api/entities/meta")
async def api_entities_meta():
    """Lightweight facets for the Entities filter UI: type counts, accounts, action vocab."""
    db = get_session()
    try:
        idx = _get_entity_index(db)
        return JSONResponse(content={
            "counts": idx.type_counts,
            "accounts": idx.accounts,
            "actions": idx.actions_vocab,
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
    min_severity = body.get("min_severity", "INFO").upper()

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
                        # The document is what the sidebar's Permissions tab
                        # shows; the ORM object is already loaded here, so this
                        # costs no extra query.
                        "document": doc,
                    })
                data["policies"]        = policies_out
                data["all_actions"]     = sorted(all_actions)
                data["trust_principals"] = _extract_trust_principals(principal)
                data["metadata"]        = principal.extra

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

        if node_id.startswith("resource:"):
            arn = node_id[len("resource:"):]
            res = db.query(Resource).filter_by(arn=arn).first()
            if res:
                data["metadata"] = res.extra
                if res.execution_role:
                    data["execution_role"] = {
                        "name": res.execution_role.name,
                        "arn": res.execution_role.arn,
                    }
                    data["actions"] = _collect_principal_actions(res.execution_role)

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
    involves_arn:   str | None = None,
    severity:       str | None = None,
    objective_type: str | None = None,
    account_id:     str | None = None,
    limit:          int = 0,
):
    """
    Return persisted AttackPath rows with optional filters.

    Query params:
        from_arn        – filter by starting identity ARN
        involves_arn    – ARN appearing anywhere in the path (start, any step
                          actor, or any step target)
        severity        – CRITICAL / HIGH / MEDIUM
        objective_type  – permission / resource / principal
        account_id      – AWS account ID string
        limit           – cap the number of rows (0 = no cap). A busy identity
                          can sit on thousands of paths, which no sidebar wants
                          to render; callers that page ask for limit+1 to detect
                          that there are more.

    `from_arn` alone only matches paths that *start* at the ARN, which is rarely
    what you want when inspecting an entity — a path can traverse or terminate at
    it. `involves_arn` joins the step table for that. It has no index, but the
    table is small enough that a scan is not worth one.
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
        if involves_arn:
            from sqlalchemy import or_ as _or
            from worstassume.db.models import AttackPathStep as _Step
            query = (query.outerjoin(_Step)
                     .filter(_or(AttackPath.from_principal_arn == involves_arn,
                                 _Step.actor_arn == involves_arn,
                                 _Step.target_arn == involves_arn))
                     .distinct())
        if severity:
            query = query.filter(AttackPath.severity == severity.upper())
        if objective_type:
            query = query.filter(AttackPath.objective_type == objective_type.lower())
        query = query.order_by(AttackPath.severity, AttackPath.total_hops)
        if limit > 0:
            query = query.limit(limit)
        return JSONResponse(content=[_ap_summary(ap) for ap in query.all()])
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


# ── API: threat model — interactive inbound access graph ─────────────────────
#
# The page walks the access graph backwards one hop at a time: pick an asset,
# see everything that can reach it, expand one of those, repeat. So the API is
# a cheap per-node neighbour lookup plus CRUD for saving the graph the analyst
# builds — not a batch scan.

from dataclasses import asdict  # noqa: E402
from datetime import datetime  # noqa: E402

from worstassume.core.reverse_index import DEFAULT_LIMIT, FAMILIES  # noqa: E402
from worstassume.db.models import ThreatModelGraph  # noqa: E402

_NODE_ID_PREFIXES = ("principal", "resource", "policy", "account", "external")

#: Hard ceiling on one expansion, whatever the client asks for.
_MAX_NEIGHBOR_LIMIT = 500

#: Multi-hop auto-expand is bounded separately: each visited node costs one
#: inbound_page(), so without a ceiling a single request could occupy a worker
#: for minutes. These keep the worst case in the tens of seconds.
_MAX_HOPS = 5
_MULTIHOP_PER_NODE_LIMIT = 50
_MULTIHOP_NODE_BUDGET = 150

#: A saved graph is analyst-authored, so it is small in practice; the cap only
#: stops a malformed or runaway client filling the DB with one row.
_MAX_GRAPH_JSON_BYTES = 4 * 1024 * 1024
_MAX_NOTES_CHARS = 4000


def _strip_prefix(raw: str) -> str:
    head, _, rest = raw.partition(":")
    return rest if head in _NODE_ID_PREFIXES and rest else raw


def _enrich_node(node: dict, risk_by_arn: dict) -> dict:
    """Attach the catalogue's risk label / finding count to a graph node."""
    extra = risk_by_arn.get(node.get("arn")) or {}
    node["risk"] = extra.get("risk")
    node["findings"] = extra.get("paths", 0)
    return node


def _parse_families(raw: str) -> tuple[str, ...]:
    if not raw:
        return FAMILIES
    picked = tuple(f.strip() for f in raw.split(",") if f.strip() in FAMILIES)
    return picked or FAMILIES


@app.get("/api/threat-model/neighbors")
async def api_threat_model_neighbors(
    arn: str = "",
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
    families: str = "",
    hops: int = 1,
):
    """Everything that can reach *arn* in one inbound hop, ranked and paged.

    Query params:
        arn      : target ARN (a prefixed graph node id is also accepted)
        limit    : page size, capped at 500 (0 = no cap, still capped at 500)
        offset   : page offset into the ranked list
        families : comma-separated subset of identity_policy,resource_policy,abuse
        hops     : >1 auto-expands breadth-first and returns one page per node

    Response: {node, neighbors[], total_found, returned, truncated} for a single
    hop, or {pages: [...]} when hops > 1.
    """
    target = _strip_prefix(arn or "")
    if not target:
        return JSONResponse(content={"error": "arn is required"}, status_code=422)

    limit = _MAX_NEIGHBOR_LIMIT if limit <= 0 else min(limit, _MAX_NEIGHBOR_LIMIT)
    offset = max(0, offset)
    fams = _parse_families(families)

    def _run() -> dict:
        db = get_session()
        try:
            index = _get_reverse_index(db)
            risk_by_arn = _get_entity_index(db).risk_by_arn

            def _pack(page) -> dict:
                out = asdict(page)
                _enrich_node(out["node"], risk_by_arn)
                for n in out["neighbors"]:
                    _enrich_node(n, risk_by_arn)
                return out

            if hops > 1:
                pages = index.expand_hops(
                    target, hops=min(hops, _MAX_HOPS), families=fams,
                    per_node_limit=min(limit, _MULTIHOP_PER_NODE_LIMIT),
                    node_budget=_MULTIHOP_NODE_BUDGET,
                )
                return {"pages": [_pack(p) for p in pages]}

            return _pack(
                index.inbound_page(target, families=fams, limit=limit, offset=offset)
            )
        finally:
            db.close()

    # Expansion is CPU-bound; keep it off the event loop so one deep auto-expand
    # cannot stall every other request.
    import asyncio
    loop = asyncio.get_event_loop()
    return JSONResponse(content=await loop.run_in_executor(None, _run))


# ── API: saved threat-model graphs ───────────────────────────────────────────

def _tmg_summary(g: ThreatModelGraph) -> dict:
    return {
        "id":         g.id,
        "name":       g.name,
        "root_arn":   g.root_arn,
        "account_id": g.account_id,
        "node_count": g.node_count,
        "edge_count": g.edge_count,
        "notes":      g.notes,
        "created_at": str(g.created_at) if g.created_at else None,
        "updated_at": str(g.updated_at) if g.updated_at else None,
    }


def _tmg_full(g: ThreatModelGraph) -> dict:
    d = _tmg_summary(g)
    d["graph"] = g.graph or {"nodes": [], "edges": [], "expanded": [], "removed": []}
    return d


def _apply_graph_payload(g: ThreatModelGraph, body: dict) -> None:
    """Apply a create/update payload. Only fields present in *body* are touched.

    In particular a rename must not clobber the canvas, so the graph blob is
    replaced only when the caller actually sends one.
    """
    def _text(key, current, limit):
        """A string field from the body, or the current value. Type-checked so a
        non-string reaches the caller as a 422 rather than blowing up on slice."""
        if key not in body:
            return current
        v = body[key]
        if v is None:
            return current
        if not isinstance(v, str):
            raise ValueError(f"{key} must be a string")
        return v[:limit]

    g.name = _text("name", g.name, 256) or "Untitled graph"
    g.root_arn = _strip_prefix(_text("root_arn", g.root_arn, 2048) or "") or None
    g.account_id = _text("account_id", g.account_id, 32)
    g.notes = _text("notes", g.notes, _MAX_NOTES_CHARS)
    if "graph" in body:
        graph = body.get("graph") or {}
        if not isinstance(graph, dict):
            raise ValueError("graph must be an object")
        try:
            blob = json.dumps(graph)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"graph is not serialisable: {exc}") from exc
        if len(blob.encode("utf-8")) > _MAX_GRAPH_JSON_BYTES:
            raise ValueError("graph is too large to save")
        g.node_count = len(graph.get("nodes") or [])
        g.edge_count = len(graph.get("edges") or [])
        g.graph_json = blob


@app.post("/api/threat-model/graphs")
async def api_tmg_create(body: dict = Body(default={})):
    """Save a new threat-model graph.

    Body: {name, root_arn?, account_id?, notes?, graph: {nodes, edges,
    expanded, removed}}. The graph blob is stored verbatim.
    """
    name = body.get("name")
    if not isinstance(name, str) or not name.strip():
        return JSONResponse(content={"error": "name is required"}, status_code=422)
    db = get_session()
    try:
        g = ThreatModelGraph()
        try:
            _apply_graph_payload(g, body)
        except ValueError as exc:
            return JSONResponse(content={"error": str(exc)}, status_code=422)
        db.add(g)
        db.commit()
        return JSONResponse(content=_tmg_full(g))
    finally:
        db.close()


@app.get("/api/threat-model/graphs")
async def api_tmg_list():
    """List saved threat-model graphs, most recently updated first."""
    db = get_session()
    try:
        rows = (db.query(ThreatModelGraph)
                .order_by(ThreatModelGraph.updated_at.desc()).all())
        return JSONResponse(content=[_tmg_summary(g) for g in rows])
    finally:
        db.close()


@app.get("/api/threat-model/graphs/{graph_id}")
async def api_tmg_detail(graph_id: int):
    db = get_session()
    try:
        g = db.get(ThreatModelGraph, graph_id)
        if g is None:
            return JSONResponse(content={"error": "not found"}, status_code=404)
        return JSONResponse(content=_tmg_full(g))
    finally:
        db.close()


@app.put("/api/threat-model/graphs/{graph_id}")
async def api_tmg_update(graph_id: int, body: dict = Body(default={})):
    """Overwrite a saved graph (rename and/or replace the canvas)."""
    db = get_session()
    try:
        g = db.get(ThreatModelGraph, graph_id)
        if g is None:
            return JSONResponse(content={"error": "not found"}, status_code=404)
        try:
            _apply_graph_payload(g, body)
        except ValueError as exc:
            return JSONResponse(content={"error": str(exc)}, status_code=422)
        g.updated_at = datetime.utcnow()
        db.commit()
        return JSONResponse(content=_tmg_full(g))
    finally:
        db.close()


@app.delete("/api/threat-model/graphs/{graph_id}")
async def api_tmg_delete(graph_id: int):
    db = get_session()
    try:
        g = db.get(ThreatModelGraph, graph_id)
        if g is not None:
            db.delete(g)
            db.commit()
        return JSONResponse(content={"ok": True})
    finally:
        db.close()
