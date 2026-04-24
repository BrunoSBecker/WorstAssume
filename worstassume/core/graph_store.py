"""
Graph store — pre-indexed, memory-lean graph for the visualization server.

Public surface:
  GraphStore.build(db)            -- build from a SQLAlchemy session
  store.neighbors(node_id, depth) -- local + neighbor node/edge dicts
  store.shortest_path(src, dst)   -- list of node IDs (uses nx internally)
  store.export()                  -- graphology-compatible JSON dict
  store.is_stale(db_path)         -- True when DB file is newer than build
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field

import networkx as nx
from sqlalchemy.orm import Session, joinedload

from worstassume.db.models import Account, CrossAccountLink, Policy, Principal, Resource

log = logging.getLogger(__name__)


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class NodeAttrs:
    node_id: str
    node_type: str
    label: str
    arn: str | None = None
    principal_type: str | None = None
    policy_type: str | None = None
    service: str | None = None
    resource_type: str | None = None
    account_id: str | None = None
    trust_policy: dict | None = None
    # Extra display fields (populated for principals)
    actions: list[str] = field(default_factory=list)
    trust_principals: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {
            "id":         self.node_id,
            "node_type":  self.node_type,
            "label":      self.label,
        }
        for k in ("arn", "principal_type", "policy_type", "service",
                  "resource_type", "account_id"):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        if self.actions:
            d["actions"] = self.actions
        if self.trust_principals:
            d["trust_principals"] = self.trust_principals
        if self.trust_policy:
            d["trust_policy"] = json.dumps(self.trust_policy)
        return d


@dataclass
class EdgeAttrs:
    source: str
    target: str
    edge_type: str
    # Optional metadata
    trust_principal_arn: str | None = None
    condition: str | None = None
    explanation: str | None = None
    is_wildcard: bool = False
    role_arn: str | None = None
    link_type: str | None = None

    @property
    def edge_id(self) -> str:
        return f"{self.source}--{self.edge_type}--{self.target}"

    def to_dict(self) -> dict:
        d = {
            "id":        self.edge_id,
            "source":    self.source,
            "target":    self.target,
            "edge_type": self.edge_type,
        }
        for k in ("trust_principal_arn", "condition", "explanation",
                  "role_arn", "link_type"):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        if self.is_wildcard:
            d["is_wildcard"] = True
        return d


# ── GraphStore ─────────────────────────────────────────────────────────────────

class GraphStore:
    """
    Pre-indexed, memory-lean graph for fast read access.

    After build(), the NetworkX DiGraph is discarded. Only flat Python dicts
    remain in memory:
      - nodes:       node_id  → NodeAttrs
      - successors:  node_id  → [successor node_ids]
      - predecessors: node_id → [predecessor node_ids]
      - edges:       (src, dst) → EdgeAttrs
      - built_at:    Unix timestamp of the build
    """

    def __init__(self) -> None:
        self.nodes:        dict[str, NodeAttrs] = {}
        self.successors:   dict[str, list[str]] = {}
        self.predecessors: dict[str, list[str]] = {}
        self.edges:        dict[tuple[str, str], EdgeAttrs] = {}
        self.built_at:     float = 0.0
        # nx graph is temporarily stored for shortest_path, then cleared
        self._nx: nx.DiGraph | None = None

    # ── Build ─────────────────────────────────────────────────────────────────

    @classmethod
    def build(cls, db: Session) -> "GraphStore":
        """Build a GraphStore from the current DB state."""
        t0 = time.perf_counter()
        store = cls()
        store._build_internal(db)
        store.built_at = time.time()
        elapsed = time.perf_counter() - t0
        log.info(
            "[graph_store] built in %.2fs — %d nodes, %d edges",
            elapsed, len(store.nodes), len(store.edges),
        )
        return store

    def _build_internal(self, db: Session) -> None:
        # ── 1. Load all data in bulk (5 queries, no lazy loading) ─────────────
        t = time.perf_counter()
        accounts    = db.query(Account).all()
        principals  = (
            db.query(Principal)
            .options(joinedload(Principal.account), joinedload(Principal.policies))
            .all()
        )
        policies    = (
            db.query(Policy)
            .options(joinedload(Policy.account))
            .all()
        )
        resources   = (
            db.query(Resource)
            .options(joinedload(Resource.account), joinedload(Resource.execution_role))
            .all()
        )
        cross_links = (
            db.query(CrossAccountLink)
            .options(
                joinedload(CrossAccountLink.source_account),
                joinedload(CrossAccountLink.target_account),
            )
            .all()
        )
        log.debug(
            "[graph_store] DB queries: %.2fs  "
            "(%d accounts, %d principals, %d policies, %d resources, %d links)",
            time.perf_counter() - t,
            len(accounts), len(principals), len(policies), len(resources), len(cross_links),
        )

        # ── 2. Build NetworkX graph (for path algorithms) ─────────────────────
        t = time.perf_counter()
        G = _build_nx_graph(accounts, principals, policies, resources, cross_links)
        self._nx = G
        log.debug("[graph_store] NX graph built: %.2fs", time.perf_counter() - t)

        # ── 3. Extract allowed actions per principal (for display) ────────────
        t = time.perf_counter()
        actions_map: dict[str, list[str]] = {}
        for p in principals:
            acts: set[str] = set()
            for pol in p.policies:
                doc = pol.document
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
                    acts.update(a)
            actions_map[p.arn] = sorted(acts)

        # Extract trust principals per role
        trust_map: dict[str, list[str]] = {}
        for p in principals:
            if p.principal_type != "role" or not p.trust_policy:
                continue
            result: set[str] = set()
            for stmt in p.trust_policy.get("Statement", []):
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
            trust_map[p.arn] = sorted(result)
        log.debug("[graph_store] actions/trust extracted: %.2fs", time.perf_counter() - t)

        # ── 4. Populate flat dicts from G ─────────────────────────────────────
        t = time.perf_counter()
        for node_id, data in G.nodes(data=True):
            arn = data.get("arn")
            attrs = NodeAttrs(
                node_id=node_id,
                node_type=data.get("node_type", ""),
                label=data.get("label", node_id),
                arn=arn,
                principal_type=data.get("principal_type"),
                policy_type=data.get("policy_type"),
                service=data.get("service"),
                resource_type=data.get("resource_type"),
                account_id=data.get("account_id"),
                trust_policy=data.get("trust_policy"),
                actions=actions_map.get(arn, []) if arn else [],
                trust_principals=trust_map.get(arn, []) if arn else [],
            )
            self.nodes[node_id] = attrs
            self.successors[node_id] = []
            self.predecessors[node_id] = []

        for src, dst, data in G.edges(data=True):
            edge = EdgeAttrs(
                source=src,
                target=dst,
                edge_type=data.get("edge_type", ""),
                trust_principal_arn=data.get("trust_principal_arn"),
                condition=str(data["condition"]) if data.get("condition") else None,
                explanation=data.get("explanation"),
                is_wildcard=bool(data.get("is_wildcard", False)),
                role_arn=data.get("role_arn"),
                link_type=data.get("link_type"),
            )
            self.edges[(src, dst)] = edge
            if src in self.successors:
                self.successors[src].append(dst)
            if dst in self.predecessors:
                self.predecessors[dst].append(src)
        log.debug("[graph_store] index built: %.2fs", time.perf_counter() - t)

    # ── Query ─────────────────────────────────────────────────────────────────

    def neighbors(self, node_id: str, depth: int = 1) -> dict:
        """
        Return node data + all neighbors up to `depth` hops as
        {nodes: [NodeAttrs.to_dict()], edges: [EdgeAttrs.to_dict()]}.
        """
        if node_id not in self.nodes:
            return {"nodes": [], "edges": []}

        visited_nodes: set[str] = {node_id}
        visited_edges: set[tuple[str, str]] = set()
        frontier = {node_id}

        for _ in range(depth):
            next_frontier: set[str] = set()
            for nid in frontier:
                for nb in self.successors.get(nid, []):
                    visited_nodes.add(nb)
                    visited_edges.add((nid, nb))
                    if nb not in visited_nodes or nb == nb:
                        next_frontier.add(nb)
                for nb in self.predecessors.get(nid, []):
                    visited_nodes.add(nb)
                    visited_edges.add((nb, nid))
                    next_frontier.add(nb)
            frontier = next_frontier - visited_nodes | frontier
            visited_nodes.update(next_frontier)

        nodes_out = [self.nodes[n].to_dict() for n in visited_nodes if n in self.nodes]
        edges_out = [
            self.edges[e].to_dict()
            for e in visited_edges
            if e in self.edges
        ]
        return {"nodes": nodes_out, "edges": edges_out}

    def shortest_path(self, src: str, dst: str) -> list[str]:
        """Return shortest directed path between two node IDs."""
        G = self._nx
        if G is None or src not in G or dst not in G:
            return []
        try:
            return nx.shortest_path(G, src, dst)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    def export(self) -> dict:
        """
        Export to graphology-compatible JSON.
        Format: {nodes: [{key, attributes}], edges: [{key, source, target, attributes}]}
        """
        nodes = [
            {"key": nid, "attributes": attrs.to_dict()}
            for nid, attrs in self.nodes.items()
        ]
        edges = [
            {
                "key":        e.edge_id,
                "source":     e.source,
                "target":     e.target,
                "attributes": e.to_dict(),
            }
            for e in self.edges.values()
        ]
        return {"nodes": nodes, "edges": edges}

    def cytoscape(self) -> dict:
        """
        Export to Cytoscape.js format (used by CLI graph export command).
        Format: {nodes: [{data}], edges: [{data}]}
        """
        nodes = [{"data": attrs.to_dict()} for attrs in self.nodes.values()]
        edges = [{"data": e.to_dict()} for e in self.edges.values()]
        return {"nodes": nodes, "edges": edges}

    def is_stale(self, db_path: str) -> bool:
        """Return True when the SQLite file is newer than this store was built."""
        if not self.built_at:
            return True
        try:
            mtime = os.path.getmtime(db_path)
            return mtime > self.built_at
        except OSError:
            return True


# ── Internal NetworkX builder (used only during build()) ──────────────────────

def _build_nx_graph(
    accounts: list,
    principals: list,
    policies: list,
    resources: list,
    cross_links: list,
) -> nx.DiGraph:
    """
    Build a NetworkX DiGraph from pre-fetched ORM objects.
    All relationships are already loaded — no lazy queries here.
    """
    G = nx.DiGraph()

    # Accounts
    for a in accounts:
        G.add_node(
            f"account:{a.account_id}",
            node_type="account",
            label=a.account_name or a.account_id,
            account_id=a.account_id,
        )

    # Principals + account membership edges
    for p in principals:
        nid = f"principal:{p.arn}"
        G.add_node(
            nid,
            node_type="principal",
            principal_type=p.principal_type,
            label=p.name,
            arn=p.arn,
            account_id=p.account.account_id if p.account else None,
            trust_policy=p.trust_policy,
        )
        if p.account:
            G.add_edge(
                f"account:{p.account.account_id}", nid,
                edge_type="has_principal",
            )

    # Policies + principal→policy edges
    for pol in policies:
        pid = f"policy:{pol.arn}"
        G.add_node(
            pid,
            node_type="policy",
            policy_type=pol.policy_type,
            label=pol.name,
            arn=pol.arn,
            account_id=pol.account.account_id if pol.account else None,
        )
        for principal in pol.principals:
            G.add_edge(
                f"principal:{principal.arn}", pid,
                edge_type="has_policy",
            )

    # Resources + account membership + execution_role edges
    for res in resources:
        rid = f"resource:{res.arn}"
        G.add_node(
            rid,
            node_type="resource",
            service=res.service,
            resource_type=res.resource_type,
            label=res.name or res.arn,
            arn=res.arn,
            account_id=res.account.account_id if res.account else None,
        )
        if res.account:
            G.add_edge(
                f"account:{res.account.account_id}", rid,
                edge_type="has_resource",
            )
        if res.execution_role:
            G.add_edge(
                rid, f"principal:{res.execution_role.arn}",
                edge_type="execution_role",
            )

    # Cross-account trust links
    for link in cross_links:
        src = link.source_account.account_id if link.source_account else None
        tgt = link.target_account.account_id if link.target_account else None
        if src and tgt:
            G.add_edge(
                f"account:{src}", f"account:{tgt}",
                edge_type="cross_account",
                role_arn=link.role_arn,
                trust_principal_arn=link.trust_principal_arn,
                is_wildcard=link.is_wildcard,
                link_type=link.link_type,
            )

    # Trust policy → can_assume edges (single pass, reuses loaded data)
    _add_trust_edges(G, principals)

    log.info("[graph_store] nx graph: %d nodes, %d edges", G.number_of_nodes(), G.number_of_edges())
    return G


def _add_trust_edges(G: nx.DiGraph, principals: list) -> None:
    """Parse trust policies and add can_assume edges. Uses pre-loaded principals list."""
    # Build ARN → node_id index from loaded graph
    arn_index: dict[str, str] = {}
    for node_id, data in G.nodes(data=True):
        arn = data.get("arn")
        if arn:
            arn_index[arn] = node_id
        if data.get("node_type") == "account":
            arn_index[f"account:{data['account_id']}"] = node_id

    for p in principals:
        if p.principal_type != "role" or not p.trust_policy:
            continue
        role_node = f"principal:{p.arn}"
        if role_node not in G:
            continue

        stmts = p.trust_policy.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]

        for stmt in stmts:
            if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            if not any("AssumeRole" in a for a in actions):
                continue

            principal_val = stmt.get("Principal", {})
            cond = stmt.get("Condition")

            if principal_val == "*":
                G.add_edge(
                    "__wildcard__", role_node,
                    edge_type="can_assume",
                    explanation="Wildcard — ANY principal can assume this role ⚠",
                    is_wildcard=True,
                )
                continue

            aws_list = principal_val.get("AWS", []) if isinstance(principal_val, dict) else [principal_val]
            if isinstance(aws_list, str):
                aws_list = [aws_list]

            for trust_arn in aws_list:
                src_node = arn_index.get(trust_arn)

                # Handle account-root ARNs
                if src_node is None and trust_arn.endswith(":root"):
                    try:
                        acct_id = trust_arn.split(":")[4]
                        src_node = arn_index.get(f"account:{acct_id}")
                    except IndexError:
                        pass

                # External/unresolved principal
                if src_node is None:
                    src_node = f"external:{trust_arn}"
                    if src_node not in G:
                        G.add_node(
                            src_node,
                            node_type="external",
                            label=trust_arn.split("/")[-1] or trust_arn,
                            arn=trust_arn,
                        )

                G.add_edge(
                    src_node, role_node,
                    edge_type="can_assume",
                    trust_principal_arn=trust_arn,
                    condition=str(cond) if cond else None,
                    explanation="Can assume this role via trust policy"
                    + (f" (condition: {cond})" if cond else ""),
                )


def build_graph(db: Session) -> nx.DiGraph:
    """Build and return a NetworkX DiGraph. Delegates to GraphStore internally."""
    store = GraphStore.build(db)
    # Return the internal nx graph for path algorithms / CLI export
    return store._nx  # type: ignore[return-value]


def graph_to_cytoscape(G: nx.DiGraph) -> dict:
    """Convert a NetworkX graph to Cytoscape.js format. Used by CLI graph export."""
    nodes = []
    edges = []
    for node_id, data in G.nodes(data=True):
        d = {"id": node_id, **{k: v for k, v in data.items() if v is not None and not isinstance(v, dict)}}
        if data.get("trust_policy"):
            d["trust_policy"] = json.dumps(data["trust_policy"])
        nodes.append({"data": d})
    for src, dst, data in G.edges(data=True):
        edge_id = f"{src}--{data.get('edge_type', 'edge')}--{dst}"
        edges.append({"data": {"id": edge_id, "source": src, "target": dst,
                                **{k: v for k, v in data.items() if v is not None}}})
    return {"nodes": nodes, "edges": edges}
