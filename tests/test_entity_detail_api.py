"""
tests/test_entity_detail_api.py — the endpoints backing the entity sidebar.

Exercises the handler coroutines directly against a temporary SQLite file (the
project has no HTTP test client dependency).

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
ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/AppRole"
DOC = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"],
                   "Resource": "*"}],
}
TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}


def _call(coro):
    return asyncio.run(coro)


def _body(response):
    return json.loads(response.body)


@pytest.fixture()
def api(tmp_path, monkeypatch):
    from worstassume.db import engine as engine_mod

    db_file = tmp_path / "worst.db"
    monkeypatch.setenv("WORST_DB", str(db_file))
    engine_mod.init_db(db_file)

    from worstassume.viz import server
    server._CACHE = server.GraphCache()
    server._ENTITY_CACHE = server._EntityIndexCache()
    server._REVERSE_CACHE = server.ReverseIndexCache()

    db = engine_mod.get_session()
    account = get_or_create_account(db, account_id=ACCOUNT_ID, account_name="Test")
    db.commit()
    role = upsert_principal(db, account, arn=ROLE_ARN, name="AppRole",
                            principal_type="role", trust_policy=TRUST)
    pol = upsert_policy(db, account, arn=f"{ROLE_ARN}:inline/p", name="AppPolicy",
                        policy_type="inline", document=DOC)
    link_principal_policy(db, role, pol)
    upsert_resource(db, account, arn="arn:aws:s3:::app-bucket", service="s3",
                    resource_type="bucket", name="app-bucket", region="us-east-1",
                    metadata={"policy": {"Version": "2012-10-17", "Statement": []}})
    db.commit()
    db.close()

    yield server

    server._CACHE = server.GraphCache()
    server._ENTITY_CACHE = server._EntityIndexCache()
    server._REVERSE_CACHE = server.ReverseIndexCache()


class TestNodeDetail:
    def test_principal_carries_policy_documents(self, api):
        """The Permissions tab needs the document, not just a flattened action list."""
        data = _body(_call(api.api_node_detail(f"principal:{ROLE_ARN}")))
        assert len(data["policies"]) == 1
        pol = data["policies"][0]
        assert pol["name"] == "AppPolicy"
        assert pol["document"] == DOC
        assert pol["actions"] == ["s3:GetObject", "s3:PutObject"]

    def test_principal_carries_trust_policy(self, api):
        data = _body(_call(api.api_node_detail(f"principal:{ROLE_ARN}")))
        # NodeAttrs ships it as a JSON string; the Trust tab parses it.
        assert json.loads(data["trust_policy"]) == TRUST
        assert "lambda.amazonaws.com" in data["trust_principals"]

    def test_principal_carries_metadata_key(self, api):
        data = _body(_call(api.api_node_detail(f"principal:{ROLE_ARN}")))
        assert "metadata" in data

    def test_resource_carries_resource_policy(self, api):
        data = _body(_call(api.api_node_detail("resource:arn:aws:s3:::app-bucket")))
        assert data["metadata"]["policy"]["Version"] == "2012-10-17"

    def test_unknown_node_is_404(self, api):
        resp = _call(api.api_node_detail("principal:arn:aws:iam::111111111111:role/None"))
        assert resp.status_code == 404


class TestAttackPathsInvolvesArn:
    """`from_arn` only matches paths that *start* at an ARN. The sidebar needs
    paths that merely traverse or terminate at it."""

    def _make_path(self, api, from_arn, steps):
        from worstassume.db import engine as engine_mod
        from worstassume.db.models import AttackPath, AttackPathStep

        from worstassume.db.models import Account

        db = engine_mod.get_session()
        acct = db.query(Account).filter_by(account_id=ACCOUNT_ID).first()
        ap = AttackPath(account_id=acct.id,
                        from_principal_arn=from_arn, objective_type="principal",
                        objective_value=steps[-1][1], severity="HIGH",
                        total_hops=len(steps), summary="test path")
        db.add(ap)
        db.flush()
        for i, (actor, target) in enumerate(steps):
            db.add(AttackPathStep(path_id=ap.id, step_index=i, actor_arn=actor,
                                  action="sts:AssumeRole", target_arn=target,
                                  explanation="assumes the role",
                                  edge_type="assume_role"))
        db.commit()
        pid = ap.id
        db.close()
        return pid

    def test_matches_a_mid_path_target(self, api):
        start = f"arn:aws:iam::{ACCOUNT_ID}:role/Start"
        mid = f"arn:aws:iam::{ACCOUNT_ID}:role/Middle"
        end = f"arn:aws:iam::{ACCOUNT_ID}:role/End"
        pid = self._make_path(api, start, [(start, mid), (mid, end)])

        # `from_arn` finds it only from the start...
        assert [p["id"] for p in _body(_call(api.api_attack_paths(from_arn=start)))] == [pid]
        assert _body(_call(api.api_attack_paths(from_arn=mid))) == []
        # ...`involves_arn` finds it from anywhere along the path.
        for arn in (start, mid, end):
            got = _body(_call(api.api_attack_paths(involves_arn=arn)))
            assert [p["id"] for p in got] == [pid], f"involves_arn={arn}"

    def test_no_match_returns_empty(self, api):
        self._make_path(api, f"arn:aws:iam::{ACCOUNT_ID}:role/A",
                        [(f"arn:aws:iam::{ACCOUNT_ID}:role/A",
                          f"arn:aws:iam::{ACCOUNT_ID}:role/B")])
        assert _body(_call(api.api_attack_paths(
            involves_arn=f"arn:aws:iam::{ACCOUNT_ID}:role/Unrelated"))) == []

    def test_results_are_deduplicated(self, api):
        """A path whose ARN appears in several steps must be returned once."""
        a = f"arn:aws:iam::{ACCOUNT_ID}:role/Loop"
        b = f"arn:aws:iam::{ACCOUNT_ID}:role/Other"
        pid = self._make_path(api, a, [(a, b), (b, a), (a, b)])
        got = _body(_call(api.api_attack_paths(involves_arn=a)))
        assert [p["id"] for p in got] == [pid]

    def test_limit_caps_results(self, api):
        base = f"arn:aws:iam::{ACCOUNT_ID}:role/Hub"
        for i in range(5):
            self._make_path(api, f"arn:aws:iam::{ACCOUNT_ID}:role/S{i}",
                            [(f"arn:aws:iam::{ACCOUNT_ID}:role/S{i}", base)])
        assert len(_body(_call(api.api_attack_paths(involves_arn=base)))) == 5
        assert len(_body(_call(api.api_attack_paths(involves_arn=base, limit=2)))) == 2
        # limit=0 keeps the old unbounded behaviour PrivEscPage relies on
        assert len(_body(_call(api.api_attack_paths(involves_arn=base, limit=0)))) == 5
