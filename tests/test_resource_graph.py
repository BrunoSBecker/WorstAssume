"""
Tests for worstassume.core.resource_graph — graph builder and Cytoscape.js exporter.

Pure DB logic; no AWS calls.
"""

from __future__ import annotations

import pytest
import networkx as nx

from worstassume.core.resource_graph import build_graph, graph_to_cytoscape
from worstassume.db.store import (
    get_or_create_account,
    upsert_principal,
    upsert_policy,
    upsert_resource,
    link_principal_policy,
    upsert_cross_account_link,
)


class TestBuildGraph:
    def test_empty_db_produces_empty_graph(self, db_session):
        G = build_graph(db_session)
        assert G.number_of_nodes() == 0
        assert G.number_of_edges() == 0

    def test_account_node_added(self, db_session, account_a):
        G = build_graph(db_session)
        assert f"account:{account_a.account_id}" in G.nodes

    def test_principal_node_added(self, db_session, account_a):
        upsert_principal(
            db_session, account_a,
            arn="arn:aws:iam::111111111111:role/my-role",
            name="my-role",
            principal_type="role",
        )
        db_session.commit()
        G = build_graph(db_session)
        assert "principal:arn:aws:iam::111111111111:role/my-role" in G.nodes

    def test_account_to_principal_edge(self, db_session, account_a):
        upsert_principal(
            db_session, account_a,
            arn="arn:aws:iam::111111111111:user/alice",
            name="alice",
            principal_type="user",
        )
        db_session.commit()
        G = build_graph(db_session)
        src = f"account:{account_a.account_id}"
        dst = "principal:arn:aws:iam::111111111111:user/alice"
        assert G.has_edge(src, dst)
        assert G[src][dst]["edge_type"] == "has_principal"

    def test_resource_node_added(self, db_session, account_a):
        upsert_resource(
            db_session, account_a,
            arn="arn:aws:s3:::my-bucket",
            service="s3",
            resource_type="bucket",
            name="my-bucket",
        )
        db_session.commit()
        G = build_graph(db_session)
        assert "resource:arn:aws:s3:::my-bucket" in G.nodes

    def test_execution_role_edge(self, db_session, account_a):
        role = upsert_principal(
            db_session, account_a,
            arn="arn:aws:iam::111111111111:role/fn-role",
            name="fn-role",
            principal_type="role",
        )
        res = upsert_resource(
            db_session, account_a,
            arn="arn:aws:lambda:us-east-1:111111111111:function/fn",
            service="lambda",
            resource_type="function",
            name="fn",
            execution_role=role,
        )
        db_session.commit()
        G = build_graph(db_session)
        res_node = "resource:arn:aws:lambda:us-east-1:111111111111:function/fn"
        role_node = "principal:arn:aws:iam::111111111111:role/fn-role"
        assert G.has_edge(res_node, role_node)
        assert G[res_node][role_node]["edge_type"] == "execution_role"

    def test_cross_account_edge(self, db_session, account_a, account_b):
        upsert_cross_account_link(
            db_session,
            source_account=account_a,
            target_account=account_b,
            role_arn="arn:aws:iam::222222222222:role/CrossRole",
            trust_principal_arn="arn:aws:iam::111111111111:role/source",
        )
        db_session.commit()
        G = build_graph(db_session)
        src = f"account:{account_a.account_id}"
        tgt = f"account:{account_b.account_id}"
        assert G.has_edge(src, tgt)
        assert G[src][tgt]["edge_type"] == "cross_account"

    def test_policy_edge(self, db_session, account_a):
        p = upsert_principal(
            db_session, account_a,
            arn="arn:aws:iam::111111111111:role/r",
            name="r",
            principal_type="role",
        )
        pol = upsert_policy(
            db_session, account_a,
            arn="arn:aws:iam::111111111111:policy/P",
            name="P",
            policy_type="managed",
        )
        link_principal_policy(db_session, p, pol)
        db_session.commit()
        G = build_graph(db_session)
        p_node = "principal:arn:aws:iam::111111111111:role/r"
        pol_node = "policy:arn:aws:iam::111111111111:policy/P"
        assert G.has_edge(p_node, pol_node)
        assert G[p_node][pol_node]["edge_type"] == "has_policy"

    def test_graph_is_directed(self, db_session, account_a):
        G = build_graph(db_session)
        assert isinstance(G, nx.DiGraph)


class TestGraphToCytoscape:
    def test_returns_nodes_and_edges_keys(self, db_session, account_a):
        G = build_graph(db_session)
        result = graph_to_cytoscape(G)
        assert "nodes" in result
        assert "edges" in result

    def test_node_has_data_field(self, db_session, account_a):
        G = build_graph(db_session)
        result = graph_to_cytoscape(G)
        for node in result["nodes"]:
            assert "data" in node
            assert "id" in node["data"]

    def test_edge_has_source_and_target(self, db_session, account_a):
        upsert_principal(
            db_session, account_a,
            arn="arn:aws:iam::111111111111:user/alice",
            name="alice",
            principal_type="user",
        )
        db_session.commit()
        G = build_graph(db_session)
        result = graph_to_cytoscape(G)
        for edge in result["edges"]:
            assert "source" in edge["data"]
            assert "target" in edge["data"]

    def test_node_count_matches_graph(self, db_session, account_a, account_b):
        G = build_graph(db_session)
        result = graph_to_cytoscape(G)
        assert len(result["nodes"]) == G.number_of_nodes()

    def test_edge_count_matches_graph(self, db_session, account_a):
        upsert_principal(
            db_session, account_a,
            arn="arn:aws:iam::111111111111:user/alice",
            name="alice",
            principal_type="user",
        )
        db_session.commit()
        G = build_graph(db_session)
        result = graph_to_cytoscape(G)
        assert len(result["edges"]) == G.number_of_edges()
