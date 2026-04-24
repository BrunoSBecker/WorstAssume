"""
Tests for worstassume.db.store — idempotent upsert helpers.

Uses an in-memory SQLite DB (via conftest.py fixtures).
No AWS calls, no moto required.
"""

from __future__ import annotations

import json

import pytest

from worstassume.db.store import (
    finish_run,
    get_or_create_account,
    link_principal_policy,
    start_run,
    touch_account,
    upsert_cross_account_link,
    upsert_policy,
    upsert_principal,
    upsert_resource,
)
from worstassume.db.models import Account, CrossAccountLink, EnumerationRun, Policy, Principal, Resource


# ─── Account ──────────────────────────────────────────────────────────────────

class TestGetOrCreateAccount:
    def test_creates_new_account(self, db_session):
        acct = get_or_create_account(db_session, "123456789012", account_name="Test")
        db_session.commit()
        assert acct.id is not None
        assert acct.account_id == "123456789012"
        assert acct.account_name == "Test"

    def test_returns_existing_account(self, db_session):
        a1 = get_or_create_account(db_session, "123456789012")
        db_session.commit()
        a2 = get_or_create_account(db_session, "123456789012", account_name="Updated")
        db_session.commit()
        # Same row, name updated
        assert a1.id == a2.id
        assert a2.account_name == "Updated"

    def test_no_duplicate_rows(self, db_session):
        get_or_create_account(db_session, "123456789012")
        get_or_create_account(db_session, "123456789012")
        db_session.commit()
        count = db_session.query(Account).filter_by(account_id="123456789012").count()
        assert count == 1

    def test_touch_account_sets_timestamp(self, db_session, account_a):
        assert account_a.last_enumerated_at is None
        touch_account(db_session, account_a)
        db_session.commit()
        assert account_a.last_enumerated_at is not None


# ─── Principal ────────────────────────────────────────────────────────────────

class TestUpsertPrincipal:
    def test_creates_principal(self, db_session, account_a):
        p = upsert_principal(
            db_session, account_a,
            arn="arn:aws:iam::111111111111:user/alice",
            name="alice",
            principal_type="user",
        )
        db_session.commit()
        assert p.id is not None
        assert p.name == "alice"
        assert p.principal_type == "user"

    def test_upsert_updates_existing(self, db_session, account_a):
        upsert_principal(
            db_session, account_a,
            arn="arn:aws:iam::111111111111:user/alice",
            name="alice",
            principal_type="user",
        )
        db_session.commit()
        p2 = upsert_principal(
            db_session, account_a,
            arn="arn:aws:iam::111111111111:user/alice",
            name="alice-renamed",
            principal_type="user",
        )
        db_session.commit()
        count = db_session.query(Principal).filter_by(
            account_id=account_a.id,
            arn="arn:aws:iam::111111111111:user/alice",
        ).count()
        assert count == 1
        assert p2.name == "alice-renamed"

    def test_stores_trust_policy(self, db_session, account_a):
        trust = {
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]
        }
        p = upsert_principal(
            db_session, account_a,
            arn="arn:aws:iam::111111111111:role/my-role",
            name="my-role",
            principal_type="role",
            trust_policy=trust,
        )
        db_session.commit()
        assert p.trust_policy == trust

    def test_metadata_is_serialised(self, db_session, account_a):
        p = upsert_principal(
            db_session, account_a,
            arn="arn:aws:iam::111111111111:user/bob",
            name="bob",
            principal_type="user",
            metadata={"create_date": "2024-01-01"},
        )
        db_session.commit()
        assert json.loads(p.metadata_json) == {"create_date": "2024-01-01"}


# ─── Policy ───────────────────────────────────────────────────────────────────

class TestUpsertPolicy:
    def test_creates_policy(self, db_session, account_a):
        pol = upsert_policy(
            db_session, account_a,
            arn="arn:aws:iam::111111111111:policy/MyPolicy",
            name="MyPolicy",
            policy_type="managed",
            document={"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]},
        )
        db_session.commit()
        assert pol.id is not None
        assert pol.name == "MyPolicy"

    def test_upsert_is_idempotent(self, db_session, account_a):
        for _ in range(3):
            upsert_policy(
                db_session, account_a,
                arn="arn:aws:iam::111111111111:policy/MyPolicy",
                name="MyPolicy",
                policy_type="managed",
            )
        db_session.commit()
        count = db_session.query(Policy).filter_by(account_id=account_a.id).count()
        assert count == 1

    def test_policy_document_property(self, db_session, account_a):
        doc = {"Statement": [{"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": "*"}]}
        pol = upsert_policy(
            db_session, account_a,
            arn="arn:aws:iam::111111111111:policy/P",
            name="P",
            policy_type="managed",
            document=doc,
        )
        db_session.commit()
        assert pol.document == doc


# ─── Principal ↔ Policy link ──────────────────────────────────────────────────

class TestLinkPrincipalPolicy:
    def test_links_policy_to_principal(self, db_session, account_a):
        p = upsert_principal(
            db_session, account_a,
            arn="arn:aws:iam::111111111111:user/alice", name="alice", principal_type="user",
        )
        pol = upsert_policy(
            db_session, account_a,
            arn="arn:aws:iam::111111111111:policy/P", name="P", policy_type="managed",
        )
        link_principal_policy(db_session, p, pol)
        db_session.commit()
        assert pol in p.policies

    def test_no_duplicate_links(self, db_session, account_a):
        p = upsert_principal(
            db_session, account_a,
            arn="arn:aws:iam::111111111111:user/alice", name="alice", principal_type="user",
        )
        pol = upsert_policy(
            db_session, account_a,
            arn="arn:aws:iam::111111111111:policy/P", name="P", policy_type="managed",
        )
        link_principal_policy(db_session, p, pol)
        link_principal_policy(db_session, p, pol)  # Should be idempotent
        db_session.commit()
        assert p.policies.count(pol) == 1


# ─── Resource ─────────────────────────────────────────────────────────────────

class TestUpsertResource:
    def test_creates_resource(self, db_session, account_a):
        res = upsert_resource(
            db_session, account_a,
            arn="arn:aws:ec2:us-east-1:111111111111:instance/i-abc",
            service="ec2",
            resource_type="instance",
            name="my-server",
            region="us-east-1",
        )
        db_session.commit()
        assert res.id is not None
        assert res.service == "ec2"
        assert res.name == "my-server"

    def test_upsert_updates_existing(self, db_session, account_a):
        arn = "arn:aws:ec2:us-east-1:111111111111:instance/i-abc"
        upsert_resource(db_session, account_a, arn=arn, service="ec2", resource_type="instance", name="old-name")
        db_session.commit()
        r2 = upsert_resource(db_session, account_a, arn=arn, service="ec2", resource_type="instance", name="new-name")
        db_session.commit()
        count = db_session.query(Resource).filter_by(account_id=account_a.id, arn=arn).count()
        assert count == 1
        assert r2.name == "new-name"

    def test_links_execution_role(self, db_session, account_a):
        role = upsert_principal(
            db_session, account_a,
            arn="arn:aws:iam::111111111111:role/lambda-exec",
            name="lambda-exec",
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
        assert res.execution_role == role


# ─── CrossAccountLink ─────────────────────────────────────────────────────────

class TestUpsertCrossAccountLink:
    def test_creates_link(self, db_session, account_a, account_b):
        link = upsert_cross_account_link(
            db_session,
            source_account=account_a,
            target_account=account_b,
            role_arn="arn:aws:iam::222222222222:role/CrossRole",
            trust_principal_arn="arn:aws:iam::111111111111:role/source-role",
        )
        db_session.commit()
        assert link.id is not None
        assert link.is_wildcard is False

    def test_idempotent_upsert(self, db_session, account_a, account_b):
        kwargs = dict(
            source_account=account_a,
            target_account=account_b,
            role_arn="arn:aws:iam::222222222222:role/CrossRole",
            trust_principal_arn="arn:aws:iam::111111111111:role/source-role",
        )
        upsert_cross_account_link(db_session, **kwargs)
        upsert_cross_account_link(db_session, **kwargs)
        db_session.commit()
        count = db_session.query(CrossAccountLink).count()
        assert count == 1

    def test_wildcard_flag(self, db_session, account_a, account_b):
        link = upsert_cross_account_link(
            db_session,
            source_account=account_a,
            target_account=account_b,
            role_arn="arn:aws:iam::222222222222:role/CrossRole",
            trust_principal_arn="*",
            is_wildcard=True,
        )
        db_session.commit()
        assert link.is_wildcard is True


# ─── EnumerationRun ───────────────────────────────────────────────────────────

class TestEnumerationRun:
    def test_start_and_finish_run(self, db_session, account_a):
        run = start_run(db_session, account_a)
        db_session.commit()
        assert run.id is not None
        assert run.started_at is not None
        assert run.finished_at is None

        finish_run(db_session, run, capabilities={"ec2_instances": True}, success=True)
        db_session.commit()
        assert run.finished_at is not None
        assert run.success is True
        assert run.capabilities == {"ec2_instances": True}

    def test_failed_run(self, db_session, account_a):
        run = start_run(db_session, account_a)
        finish_run(db_session, run, success=False, error_message="Access denied")
        db_session.commit()
        assert run.success is False
        assert run.error_message == "Access denied"
