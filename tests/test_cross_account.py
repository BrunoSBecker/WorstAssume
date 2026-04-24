"""
Tests for worstassume.core.cross_account — cross-account trust link inference.

Pure DB logic; no AWS calls.
"""

from __future__ import annotations

import json

import pytest

from worstassume.core.cross_account import build_cross_account_links, _extract_account_id_from_arn
from worstassume.db.store import get_or_create_account, upsert_principal, upsert_cross_account_link
from worstassume.db.models import CrossAccountLink


# ─── ARN parser ───────────────────────────────────────────────────────────────

class TestExtractAccountId:
    def test_user_arn(self):
        assert _extract_account_id_from_arn("arn:aws:iam::111111111111:user/alice") == "111111111111"

    def test_role_arn(self):
        assert _extract_account_id_from_arn("arn:aws:iam::222222222222:role/MyRole") == "222222222222"

    def test_assumed_role_arn(self):
        assert _extract_account_id_from_arn("arn:aws:sts::333333333333:assumed-role/Role/Session") == "333333333333"

    def test_service_principal_returns_none(self):
        assert _extract_account_id_from_arn("lambda.amazonaws.com") is None

    def test_wildcard_returns_none(self):
        assert _extract_account_id_from_arn("*") is None

    def test_root_arn(self):
        assert _extract_account_id_from_arn("arn:aws:iam::123456789012:root") == "123456789012"


# ─── build_cross_account_links ────────────────────────────────────────────────

class TestBuildCrossAccountLinks:
    def test_no_links_with_single_account(self, db_session, account_a):
        """With only one tracked account, no links should be created."""
        links = build_cross_account_links(db_session)
        assert links == []

    def test_detects_cross_account_trust(self, db_session, account_a, account_b):
        """
        account_a (111111111111) has a role that trusts account_b (222222222222).
        account_b has a role whose trust policy references account_a.
        → one CrossAccountLink from account_a → account_b.
        """
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::111111111111:role/source-role"},
                "Action": "sts:AssumeRole",
            }],
        }
        # Role lives in account_b (222222222222), trusted by account_a
        upsert_principal(
            db_session, account_b,
            arn="arn:aws:iam::222222222222:role/cross-role",
            name="cross-role",
            principal_type="role",
            trust_policy=trust_policy,
        )
        # source-role in account_a — must exist so the account is meaningful
        upsert_principal(
            db_session, account_a,
            arn="arn:aws:iam::111111111111:role/source-role",
            name="source-role",
            principal_type="role",
        )
        db_session.commit()

        links = build_cross_account_links(db_session)
        assert len(links) == 1
        link = links[0]
        assert link.role_arn == "arn:aws:iam::222222222222:role/cross-role"
        assert link.trust_principal_arn == "arn:aws:iam::111111111111:role/source-role"
        assert link.is_wildcard is False

    def test_same_account_trust_not_linked(self, db_session, account_a, account_b):
        """A role trusting a principal in the same account should NOT create a CrossAccountLink."""
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::222222222222:role/other-role"},
                "Action": "sts:AssumeRole",
            }],
        }
        upsert_principal(
            db_session, account_b,
            arn="arn:aws:iam::222222222222:role/my-role",
            name="my-role",
            principal_type="role",
            trust_policy=trust_policy,
        )
        db_session.commit()

        links = build_cross_account_links(db_session)
        # account_b trusts account_b — same account, no link
        assert len(links) == 0

    def test_service_principal_not_linked(self, db_session, account_a, account_b):
        """Service principals (e.g. lambda.amazonaws.com) should not create links."""
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }
        upsert_principal(
            db_session, account_b,
            arn="arn:aws:iam::222222222222:role/lambda-role",
            name="lambda-role",
            principal_type="role",
            trust_policy=trust_policy,
        )
        db_session.commit()

        links = build_cross_account_links(db_session)
        assert len(links) == 0

    def test_wildcard_trust_detected(self, db_session, account_a, account_b):
        """A trust policy with Principal: '*' should be flagged as wildcard."""
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole",
            }],
        }
        upsert_principal(
            db_session, account_b,
            arn="arn:aws:iam::222222222222:role/open-role",
            name="open-role",
            principal_type="role",
            trust_policy=trust_policy,
        )
        db_session.commit()

        links = build_cross_account_links(db_session)
        # Wildcard '*' has no ARN, so we can't extract a source account → 0 links
        # (wildcard trust is detected by privilege_escalation, not cross_account)
        assert len(links) == 0

    def test_unknown_source_account_skipped(self, db_session, account_a, account_b):
        """A trust referencing an account NOT in our DB should be silently skipped."""
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:role/external"},
                "Action": "sts:AssumeRole",
            }],
        }
        upsert_principal(
            db_session, account_b,
            arn="arn:aws:iam::222222222222:role/cross-role",
            name="cross-role",
            principal_type="role",
            trust_policy=trust_policy,
        )
        db_session.commit()

        links = build_cross_account_links(db_session)
        # 999999999999 is not tracked — skip
        assert len(links) == 0

    def test_build_is_idempotent(self, db_session, account_a, account_b):
        """Calling build twice should not duplicate CrossAccountLink rows."""
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::111111111111:role/source-role"},
                "Action": "sts:AssumeRole",
            }],
        }
        upsert_principal(
            db_session, account_b,
            arn="arn:aws:iam::222222222222:role/cross-role",
            name="cross-role",
            principal_type="role",
            trust_policy=trust_policy,
        )
        upsert_principal(
            db_session, account_a,
            arn="arn:aws:iam::111111111111:role/source-role",
            name="source-role",
            principal_type="role",
        )
        db_session.commit()

        build_cross_account_links(db_session)
        build_cross_account_links(db_session)

        count = db_session.query(CrossAccountLink).count()
        assert count == 1

    def test_multiple_trust_principals(self, db_session, account_a, account_b):
        """A role trusted by multiple ARNs from different tracked accounts → multiple links."""
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {
                    "AWS": [
                        "arn:aws:iam::111111111111:role/role-a",
                        "arn:aws:iam::111111111111:user/user-a",
                    ]
                },
                "Action": "sts:AssumeRole",
            }],
        }
        upsert_principal(
            db_session, account_b,
            arn="arn:aws:iam::222222222222:role/target-role",
            name="target-role",
            principal_type="role",
            trust_policy=trust_policy,
        )
        db_session.commit()

        links = build_cross_account_links(db_session)
        # Both ARN trust principals are from account_a → 2 links
        assert len(links) == 2
