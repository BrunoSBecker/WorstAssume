"""
tests/test_threat_model_api.py — Threat Model HTTP handlers.

Exercises the endpoint coroutines directly against a temporary SQLite file.
starlette's TestClient needs httpx, which is not a dependency of this project,
so routing is not covered here — only the handler contracts (status codes,
JSON shapes, persistence).

All fixtures use clearly fictitious ARNs and account IDs.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from worstassume.db.store import (
    get_or_create_account,
    link_principal_policy,
    upsert_policy,
    upsert_principal,
    upsert_resource,
)

ACCOUNT_ID = "111111111111"


def _call(coro):
    return asyncio.run(coro)


def _body(response):
    """Decode a JSONResponse body."""
    return json.loads(response.body)


@pytest.fixture()
def api(tmp_path, monkeypatch):
    """A server module wired to a throwaway DB with a small fixture estate."""
    from worstassume.db import engine as engine_mod

    db_file = tmp_path / "worst.db"
    monkeypatch.setenv("WORST_DB", str(db_file))
    engine_mod.init_db(db_file)

    from worstassume.viz import server

    # Caches are process-level singletons; reset them for each test DB.
    server._REVERSE_CACHE = server.ReverseIndexCache()
    server._ENTITY_CACHE = server._EntityIndexCache()

    db = engine_mod.get_session()
    account = get_or_create_account(db, account_id=ACCOUNT_ID, account_name="Test")
    db.commit()

    bucket_arn = "arn:aws:s3:::crown-jewels"
    upsert_resource(db, account, arn=bucket_arn,
                    service="s3", resource_type="bucket",
                    name="crown-jewels", region="us-east-1")
    reader_arn = f"arn:aws:iam::{ACCOUNT_ID}:role/Reader"
    reader = upsert_principal(db, account, arn=reader_arn, name="Reader",
                              principal_type="role")
    pol = upsert_policy(db, account, arn=f"{reader_arn}:inline/p", name="p",
                        policy_type="inline", document={
                            "Version": "2012-10-17", "Statement": [
                                {"Effect": "Allow", "Action": "s3:GetObject",
                                 "Resource": "*"}]})
    link_principal_policy(db, reader, pol)
    db.commit()
    db.close()

    yield server, {"bucket_arn": bucket_arn, "reader_arn": reader_arn}

    server._REVERSE_CACHE = server.ReverseIndexCache()
    server._ENTITY_CACHE = server._EntityIndexCache()


# ─────────────────────────────────────────────────────────────────────────────
# /api/threat-model/neighbors
# ─────────────────────────────────────────────────────────────────────────────

class TestNeighborsEndpoint:
    def test_missing_arn_is_422(self, api):
        server, _ = api
        resp = _call(server.api_threat_model_neighbors(arn=""))
        assert resp.status_code == 422
        assert _body(resp)["error"] == "arn is required"

    def test_returns_ranked_inbound_neighbours(self, api):
        server, f = api
        resp = _call(server.api_threat_model_neighbors(arn=f["bucket_arn"]))
        data = _body(resp)

        assert data["node"]["arn"] == f["bucket_arn"]
        assert data["node"]["node_type"] == "resource"
        assert f["reader_arn"] in {n["arn"] for n in data["neighbors"]}
        assert data["total_found"] == len(data["neighbors"])
        assert data["truncated"] is False

    def test_accepts_a_prefixed_node_id(self, api):
        server, f = api
        resp = _call(server.api_threat_model_neighbors(
            arn=f"resource:{f['bucket_arn']}"))
        assert _body(resp)["node"]["arn"] == f["bucket_arn"]

    def test_nodes_carry_risk_and_finding_counts(self, api):
        server, f = api
        data = _body(_call(server.api_threat_model_neighbors(arn=f["bucket_arn"])))
        for node in [data["node"], *data["neighbors"]]:
            assert "risk" in node
            assert "findings" in node

    def test_family_filter_is_honoured(self, api):
        server, f = api
        data = _body(_call(server.api_threat_model_neighbors(
            arn=f["bucket_arn"], families="abuse")))
        families = {e["family"] for n in data["neighbors"] for e in n["edges"]}
        assert families <= {"abuse"}

    def test_unknown_family_falls_back_to_all(self, api):
        server, f = api
        data = _body(_call(server.api_threat_model_neighbors(
            arn=f["bucket_arn"], families="nonsense")))
        assert f["reader_arn"] in {n["arn"] for n in data["neighbors"]}

    def test_limit_is_capped(self, api):
        server, f = api
        data = _body(_call(server.api_threat_model_neighbors(
            arn=f["bucket_arn"], limit=100000)))
        assert data["returned"] <= server._MAX_NEIGHBOR_LIMIT

    def test_multi_hop_returns_pages(self, api):
        server, f = api
        data = _body(_call(server.api_threat_model_neighbors(
            arn=f["bucket_arn"], hops=2)))
        assert "pages" in data
        assert data["pages"][0]["node"]["arn"] == f["bucket_arn"]

    def test_multi_hop_is_bounded(self, api):
        """hops and per-request work are capped regardless of what is asked."""
        server, f = api
        data = _body(_call(server.api_threat_model_neighbors(
            arn=f["bucket_arn"], hops=99, limit=100000)))
        seen = {p["node"]["arn"] for p in data["pages"]}
        seen |= {n["arn"] for p in data["pages"] for n in p["neighbors"]}
        assert len(seen) <= server._MULTIHOP_NODE_BUDGET

    def test_unknown_arn_is_handled_gracefully(self, api):
        """An ARN with no DB record still resolves — identity policies scoped to
        Resource "*" legitimately grant access to it — but it is not a known node."""
        server, _ = api
        data = _body(_call(server.api_threat_model_neighbors(
            arn="arn:aws:dynamodb:us-east-1:111111111111:table/no-such-table")))
        assert data["node"]["node_type"] == "external"
        assert data["neighbors"] == []
        assert data["total_found"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# /api/threat-model/graphs
# ─────────────────────────────────────────────────────────────────────────────

def _sample_graph(bucket_arn, reader_arn):
    return {
        "nodes": [
            {"arn": bucket_arn, "label": "crown-jewels", "node_type": "resource",
             "x": 10.5, "y": -20.0},
            {"arn": reader_arn, "label": "Reader", "node_type": "principal",
             "x": 100.0, "y": 40.0},
        ],
        "edges": [
            {"source": reader_arn, "target": bucket_arn,
             "family": "identity_policy", "edge_type": "identity_policy",
             "action": "s3:GetObject", "severity": "MEDIUM"},
        ],
        "expanded": [bucket_arn],
        "removed": [],
    }


class TestSavedGraphs:
    def test_create_requires_a_name(self, api):
        server, _ = api
        resp = _call(server.api_tmg_create(body={"graph": {}}))
        assert resp.status_code == 422

    def test_crud_round_trip(self, api):
        server, f = api
        graph = _sample_graph(f["bucket_arn"], f["reader_arn"])

        created = _body(_call(server.api_tmg_create(body={
            "name": "S3 exposure", "root_arn": f["bucket_arn"],
            "account_id": ACCOUNT_ID, "notes": "first pass", "graph": graph,
        })))
        gid = created["id"]
        assert created["name"] == "S3 exposure"
        assert created["node_count"] == 2
        assert created["edge_count"] == 1

        listed = _body(_call(server.api_tmg_list()))
        assert [g["id"] for g in listed] == [gid]
        assert "graph" not in listed[0]  # list view stays light

        fetched = _body(_call(server.api_tmg_detail(gid)))
        assert fetched["graph"] == graph  # blob survives verbatim, positions included

        updated = _body(_call(server.api_tmg_update(gid, body={
            "name": "S3 exposure (reviewed)", "graph": graph,
        })))
        assert updated["name"] == "S3 exposure (reviewed)"
        assert updated["root_arn"] == f["bucket_arn"]  # preserved when omitted

        assert _body(_call(server.api_tmg_delete(gid)))["ok"] is True
        assert _body(_call(server.api_tmg_list())) == []

    def test_rename_does_not_clobber_the_canvas(self, api):
        """A PUT that only carries a name must leave the saved graph intact."""
        server, f = api
        graph = _sample_graph(f["bucket_arn"], f["reader_arn"])
        created = _body(_call(server.api_tmg_create(body={
            "name": "before", "graph": graph})))

        _call(server.api_tmg_update(created["id"], body={"name": "after"}))

        fetched = _body(_call(server.api_tmg_detail(created["id"])))
        assert fetched["name"] == "after"
        assert fetched["node_count"] == 2
        assert fetched["graph"] == graph

    def test_oversized_graph_is_rejected(self, api):
        """The blob cap keeps one runaway client from filling the DB."""
        server, _ = api
        huge = {"nodes": [{"arn": f"arn:aws:s3:::b{i}", "label": "x" * 512}
                          for i in range(12000)], "edges": []}
        resp = _call(server.api_tmg_create(body={"name": "huge", "graph": huge}))
        assert resp.status_code == 422
        assert "too large" in _body(resp)["error"]
        assert _body(_call(server.api_tmg_list())) == []

    def test_notes_are_truncated(self, api):
        server, _ = api
        created = _body(_call(server.api_tmg_create(body={
            "name": "notes", "notes": "n" * 9999})))
        assert len(created["notes"]) == server._MAX_NOTES_CHARS

    def test_malformed_fields_are_422_not_500(self, api):
        """A non-string name used to blow up on the length slice."""
        server, _ = api
        for body in ({"name": {"nope": 1}},
                     {"name": "ok", "root_arn": 12345},
                     {"name": "ok", "graph": "not-an-object"}):
            resp = _call(server.api_tmg_create(body=body))
            assert resp.status_code == 422, body

    def test_root_arn_is_truncated_to_its_column(self, api):
        server, _ = api
        created = _body(_call(server.api_tmg_create(body={
            "name": "long", "root_arn": "arn:aws:s3:::" + "x" * 4000})))
        assert len(created["root_arn"]) <= 2048

    def test_detail_404_on_unknown_id(self, api):
        server, _ = api
        resp = _call(server.api_tmg_detail(9999))
        assert resp.status_code == 404
        assert _body(resp)["error"] == "not found"

    def test_update_404_on_unknown_id(self, api):
        server, _ = api
        resp = _call(server.api_tmg_update(9999, body={"name": "x"}))
        assert resp.status_code == 404

    def test_delete_is_idempotent(self, api):
        server, _ = api
        assert _body(_call(server.api_tmg_delete(9999)))["ok"] is True

    def test_root_arn_prefix_is_stripped(self, api):
        server, f = api
        created = _body(_call(server.api_tmg_create(body={
            "name": "prefixed", "root_arn": f"resource:{f['bucket_arn']}",
            "graph": {"nodes": [], "edges": []},
        })))
        assert created["root_arn"] == f["bucket_arn"]

    def test_empty_graph_reads_back_as_empty_shape(self, api):
        server, _ = api
        created = _body(_call(server.api_tmg_create(body={"name": "empty"})))
        fetched = _body(_call(server.api_tmg_detail(created["id"])))
        assert fetched["graph"] == {"nodes": [], "edges": [],
                                    "expanded": [], "removed": []}


class TestCrossAccountVisibility:
    def test_hidden_count_is_reported_to_the_client(self, api, tmp_path):
        """The gate must not hide silently — the UI needs the count to show it."""
        server, f = api
        from worstassume.db import engine as engine_mod
        from worstassume.db.store import (get_or_create_account, link_principal_policy,
                                          upsert_policy, upsert_principal)

        db = engine_mod.get_session()
        other = get_or_create_account(db, account_id="222222222222", account_name="Other")
        db.commit()
        arn = "arn:aws:iam::222222222222:role/ForeignAdmin"
        p = upsert_principal(db, other, arn=arn, name="ForeignAdmin",
                             principal_type="role")
        pol = upsert_policy(db, other, arn=f"{arn}:inline/p", name="p",
                            policy_type="inline", document={
                                "Version": "2012-10-17", "Statement": [
                                    {"Effect": "Allow", "Action": "*", "Resource": "*"}]})
        link_principal_policy(db, p, pol)
        db.commit()
        db.close()

        server._REVERSE_CACHE = server.ReverseIndexCache()
        server._ENTITY_CACHE = server._EntityIndexCache()

        data = _body(_call(server.api_threat_model_neighbors(arn=f["bucket_arn"])))
        assert arn not in {n["arn"] for n in data["neighbors"]}
        assert data["filtered_cross_account"] >= 1
