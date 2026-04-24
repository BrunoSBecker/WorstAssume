"""
Tests for worstassume.core.graph_store — GraphStore builder and query methods.

Pure DB logic; no AWS calls.
"""

from __future__ import annotations

import time

import pytest

from worstassume.core.graph_store import GraphStore, build_graph, graph_to_cytoscape
from worstassume.db.store import (
    get_or_create_account,
    upsert_principal,
    upsert_policy,
    upsert_resource,
    link_principal_policy,
    upsert_cross_account_link,
)


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def store_empty(db_session):
    return GraphStore.build(db_session)


@pytest.fixture
def account_a(db_session):
    acct = get_or_create_account(db_session, "111111111111", account_name="alpha")
    db_session.commit()
    return acct


@pytest.fixture
def account_b(db_session):
    acct = get_or_create_account(db_session, "222222222222", account_name="beta")
    db_session.commit()
    return acct


@pytest.fixture
def role(db_session, account_a):
    trust = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Principal": {"AWS": "arn:aws:iam::111111111111:user/alice"},
        }]
    }
    p = upsert_principal(
        db_session, account_a,
        arn="arn:aws:iam::111111111111:role/target-role",
        name="target-role", principal_type="role",
        trust_policy=trust,
    )
    db_session.commit()
    return p


@pytest.fixture
def user(db_session, account_a):
    p = upsert_principal(
        db_session, account_a,
        arn="arn:aws:iam::111111111111:user/alice",
        name="alice", principal_type="user",
    )
    db_session.commit()
    return p


# ── GraphStore.build() ─────────────────────────────────────────────────────────

class TestBuild:
    def test_empty_db(self, store_empty):
        assert len(store_empty.nodes) == 0
        assert len(store_empty.edges) == 0

    def test_built_at_set(self, store_empty):
        assert store_empty.built_at > 0

    def test_account_node(self, db_session, account_a):
        store = GraphStore.build(db_session)
        assert f"account:{account_a.account_id}" in store.nodes

    def test_principal_node(self, db_session, account_a, user):
        store = GraphStore.build(db_session)
        nid = f"principal:{user.arn}"
        assert nid in store.nodes
        assert store.nodes[nid].principal_type == "user"

    def test_role_node(self, db_session, account_a, role):
        store = GraphStore.build(db_session)
        nid = f"principal:{role.arn}"
        assert nid in store.nodes
        assert store.nodes[nid].principal_type == "role"

    def test_account_to_principal_edge(self, db_session, account_a, user):
        store = GraphStore.build(db_session)
        acct_nid = f"account:{account_a.account_id}"
        user_nid = f"principal:{user.arn}"
        assert user_nid in store.successors.get(acct_nid, [])
        edge = store.edges.get((acct_nid, user_nid))
        assert edge is not None
        assert edge.edge_type == "has_principal"

    def test_trust_edge_created(self, db_session, account_a, user, role):
        store = GraphStore.build(db_session)
        user_nid = f"principal:{user.arn}"
        role_nid = f"principal:{role.arn}"
        assert role_nid in store.successors.get(user_nid, [])
        edge = store.edges.get((user_nid, role_nid))
        assert edge is not None
        assert edge.edge_type == "can_assume"

    def test_resource_node(self, db_session, account_a):
        res = upsert_resource(
            db_session, account_a,
            arn="arn:aws:s3:::my-bucket",
            service="s3", resource_type="bucket", name="my-bucket",
        )
        db_session.commit()
        store = GraphStore.build(db_session)
        assert "resource:arn:aws:s3:::my-bucket" in store.nodes

    def test_policy_node(self, db_session, account_a, user):
        pol = upsert_policy(
            db_session, account_a,
            arn="arn:aws:iam::111111111111:policy/MyPolicy",
            name="MyPolicy", policy_type="customer_managed",
        )
        link_principal_policy(db_session, user, pol)
        db_session.commit()
        store = GraphStore.build(db_session)
        assert "policy:arn:aws:iam::111111111111:policy/MyPolicy" in store.nodes

    def test_cross_account_edge(self, db_session, account_a, account_b):
        upsert_cross_account_link(
            db_session, account_a, account_b,
            role_arn="arn:aws:iam::222222222222:role/cross-role",
            trust_principal_arn="arn:aws:iam::111111111111:role/source-role",
        )
        db_session.commit()
        store = GraphStore.build(db_session)
        src = f"account:{account_a.account_id}"
        dst = f"account:{account_b.account_id}"
        edge = store.edges.get((src, dst))
        assert edge is not None
        assert edge.edge_type == "cross_account"


# ── GraphStore.neighbors() ────────────────────────────────────────────────────

class TestNeighbors:
    def test_missing_node_returns_empty(self, store_empty):
        result = store_empty.neighbors("principal:does-not-exist")
        assert result == {"nodes": [], "edges": []}

    def test_returns_node_and_neighbors(self, db_session, account_a, user, role):
        store = GraphStore.build(db_session)
        user_nid = f"principal:{user.arn}"
        result = store.neighbors(user_nid, depth=1)
        node_ids = [n["id"] for n in result["nodes"]]
        assert user_nid in node_ids
        role_nid = f"principal:{role.arn}"
        assert role_nid in node_ids

    def test_edge_returned(self, db_session, account_a, user, role):
        store = GraphStore.build(db_session)
        user_nid = f"principal:{user.arn}"
        result = store.neighbors(user_nid, depth=1)
        edge_types = [e["edge_type"] for e in result["edges"]]
        assert "can_assume" in edge_types


# ── GraphStore.shortest_path() ────────────────────────────────────────────────

class TestShortestPath:
    def test_no_path_returns_empty(self, db_session, account_a, user):
        store = GraphStore.build(db_session)
        # No path from user to non-existent node
        result = store.shortest_path("principal:arn:aws:iam::111111111111:user/alice", "principal:ghost")
        assert result == []

    def test_known_path(self, db_session, account_a, user, role):
        store = GraphStore.build(db_session)
        src = f"principal:{user.arn}"
        dst = f"principal:{role.arn}"
        path = store.shortest_path(src, dst)
        assert src in path
        assert dst in path
        assert path.index(src) < path.index(dst)


# ── GraphStore.export() ───────────────────────────────────────────────────────

class TestExport:
    def test_export_structure(self, db_session, account_a, user):
        store = GraphStore.build(db_session)
        exp = store.export()
        assert "nodes" in exp and "edges" in exp
        assert isinstance(exp["nodes"], list)
        assert any(n["key"] == f"principal:{user.arn}" for n in exp["nodes"])

    def test_cytoscape_format(self, db_session, account_a, user):
        store = GraphStore.build(db_session)
        cy = store.cytoscape()
        assert "nodes" in cy and "edges" in cy
        assert any(n["data"]["id"] == f"principal:{user.arn}" for n in cy["nodes"])


# ── GraphStore.is_stale() ─────────────────────────────────────────────────────

class TestIsStale:
    def test_fresh_is_not_stale(self, db_session, tmp_path):
        db_file = tmp_path / "test.db"
        db_file.touch()
        store = GraphStore.build(db_session)
        store.built_at = time.time() + 10  # future build time
        assert not store.is_stale(str(db_file))

    def test_old_build_is_stale(self, db_session, tmp_path):
        db_file = tmp_path / "test.db"
        db_file.touch()
        store = GraphStore.build(db_session)
        store.built_at = 0  # epoch — always stale
        assert store.is_stale(str(db_file))

    def test_missing_file_is_stale(self, db_session, tmp_path):
        store = GraphStore.build(db_session)
        assert store.is_stale(str(tmp_path / "ghost.db"))


# ── Shim compatibility (build_graph, graph_to_cytoscape) ─────────────────────

class TestShims:
    def test_build_graph_returns_digraph(self, db_session):
        import networkx as nx
        G = build_graph(db_session)
        assert isinstance(G, nx.DiGraph)

    def test_build_graph_empty(self, db_session):
        import networkx as nx
        G = build_graph(db_session)
        assert G.number_of_nodes() == 0

    def test_build_graph_account_node(self, db_session, account_a):
        G = build_graph(db_session)
        assert f"account:{account_a.account_id}" in G.nodes

    def test_graph_to_cytoscape_structure(self, db_session, account_a, user):
        import networkx as nx
        G = build_graph(db_session)
        cy = graph_to_cytoscape(G)
        assert "nodes" in cy and "edges" in cy
        node_ids = [n["data"]["id"] for n in cy["nodes"]]
        assert f"principal:{user.arn}" in node_ids
