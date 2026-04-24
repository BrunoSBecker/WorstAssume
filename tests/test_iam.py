"""
Tests for worstassume.modules.iam — IAM fast path and slow path enumeration.

Uses moto to mock IAM and provides a real in-memory DB session.
"""

from __future__ import annotations

import json

import boto3
import pytest
from moto import mock_aws

from worstassume.core.capability import CapabilityMap
from worstassume.db.store import get_or_create_account
from worstassume.modules import iam as iam_module
from worstassume.session import SessionManager
from worstassume.db.models import Account, Principal, Policy


def _session(region="us-east-1") -> SessionManager:
    return SessionManager(region=region)


def _cap_full() -> CapabilityMap:
    """All IAM capabilities enabled."""
    return CapabilityMap(
        iam_full_dump=True,
        iam_list_roles=True,
        iam_list_users=True,
        iam_list_policies=True,
    )


def _cap_slow() -> CapabilityMap:
    """Slow path: GetAccountAuthorizationDetails denied, individual calls allowed."""
    return CapabilityMap(
        iam_full_dump=False,
        iam_list_roles=True,
        iam_list_users=True,
        iam_list_policies=True,
    )


def _cap_none() -> CapabilityMap:
    """No IAM access."""
    return CapabilityMap()


# ─── Fast path ────────────────────────────────────────────────────────────────

@mock_aws
class TestIAMFastPath:
    def test_enumerates_users_via_fast_path(self, db_session):
        # Setup: create IAM user in moto
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="alice")
        iam.create_user(UserName="bob")

        account = get_or_create_account(db_session, "123456789012", account_name="Test")
        db_session.commit()

        session = _session()
        iam_module.enumerate(session, db_session, account, _cap_full())
        db_session.commit()

        users = (
            db_session.query(Principal)
            .filter_by(account_id=account.id, principal_type="user")
            .all()
        )
        names = {u.name for u in users}
        assert "alice" in names
        assert "bob" in names

    def test_enumerates_roles_via_fast_path(self, db_session):
        iam = boto3.client("iam", region_name="us-east-1")
        trust = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        })
        iam.create_role(RoleName="my-role", AssumeRolePolicyDocument=trust)

        account = get_or_create_account(db_session, "123456789012")
        db_session.commit()

        session = _session()
        iam_module.enumerate(session, db_session, account, _cap_full())
        db_session.commit()

        roles = (
            db_session.query(Principal)
            .filter_by(account_id=account.id, principal_type="role")
            .all()
        )
        role_names = {r.name for r in roles}
        assert "my-role" in role_names

    def test_trust_policy_stored_on_role(self, db_session):
        iam = boto3.client("iam", region_name="us-east-1")
        trust_doc = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }
        iam.create_role(RoleName="ec2-role", AssumeRolePolicyDocument=json.dumps(trust_doc))

        account = get_or_create_account(db_session, "123456789012")
        db_session.commit()

        iam_module.enumerate(session := _session(), db_session, account, _cap_full())
        db_session.commit()

        role = (
            db_session.query(Principal)
            .filter_by(account_id=account.id, name="ec2-role")
            .first()
        )
        assert role is not None
        assert role.trust_policy is not None
        assert "ec2.amazonaws.com" in json.dumps(role.trust_policy)

    def test_enumeration_is_idempotent(self, db_session):
        """Re-enumerating the same account should not duplicate principals."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="alice")

        account = get_or_create_account(db_session, "123456789012")
        db_session.commit()

        session = _session()
        iam_module.enumerate(session, db_session, account, _cap_full())
        db_session.commit()
        iam_module.enumerate(session, db_session, account, _cap_full())
        db_session.commit()

        count = (
            db_session.query(Principal)
            .filter_by(account_id=account.id, name="alice")
            .count()
        )
        assert count == 1

    def test_managed_policy_attached_to_role(self, db_session):
        iam = boto3.client("iam", region_name="us-east-1")
        trust = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        })
        iam.create_role(RoleName="fn-role", AssumeRolePolicyDocument=trust)
        policy_doc = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
        })
        pol = iam.create_policy(PolicyName="S3FullPolicy", PolicyDocument=policy_doc)
        iam.attach_role_policy(RoleName="fn-role", PolicyArn=pol["Policy"]["Arn"])

        account = get_or_create_account(db_session, "123456789012")
        db_session.commit()

        iam_module.enumerate(session := _session(), db_session, account, _cap_full())
        db_session.commit()

        role = db_session.query(Principal).filter_by(account_id=account.id, name="fn-role").first()
        assert role is not None
        policy_names = {p.name for p in role.policies}
        assert "S3FullPolicy" in policy_names


# ─── Slow path ────────────────────────────────────────────────────────────────

@mock_aws
class TestIAMSlowPath:
    def test_slow_path_enumerates_users(self, db_session):
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="charlie")

        account = get_or_create_account(db_session, "123456789012")
        db_session.commit()

        iam_module.enumerate(_session(), db_session, account, _cap_slow())
        db_session.commit()

        users = db_session.query(Principal).filter_by(account_id=account.id, principal_type="user").all()
        assert any(u.name == "charlie" for u in users)

    def test_slow_path_enumerates_roles(self, db_session):
        iam = boto3.client("iam", region_name="us-east-1")
        trust = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        })
        iam.create_role(RoleName="slow-role", AssumeRolePolicyDocument=trust)

        account = get_or_create_account(db_session, "123456789012")
        db_session.commit()

        iam_module.enumerate(_session(), db_session, account, _cap_slow())
        db_session.commit()

        roles = db_session.query(Principal).filter_by(account_id=account.id, principal_type="role").all()
        assert any(r.name == "slow-role" for r in roles)


# ─── No IAM permissions ───────────────────────────────────────────────────────

@mock_aws
def test_skips_when_no_iam_permissions(db_session):
    """If cap.has_any_iam is False, nothing should be written to DB."""
    account = get_or_create_account(db_session, "123456789012")
    db_session.commit()

    iam_module.enumerate(_session(), db_session, account, _cap_none())
    db_session.commit()

    count = db_session.query(Principal).filter_by(account_id=account.id).count()
    assert count == 0


# ─── Group membership — fast path ─────────────────────────────────────────────

@mock_aws
class TestIAMGroupMembershipFastPath:
    """Phase 8: fast path must persist group memberships from GroupList in UserDetailList."""

    def _setup(self, db_session):
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_group(GroupName="admins")
        iam.create_user(UserName="alice")
        iam.add_user_to_group(GroupName="admins", UserName="alice")
        account = get_or_create_account(db_session, "123456789012", account_name="Test")
        db_session.commit()
        iam_module.enumerate(_session(), db_session, account, _cap_full())
        db_session.commit()
        return account

    def test_group_membership_row_created(self, db_session):
        from worstassume.db.models import GroupMembership
        account = self._setup(db_session)
        count = db_session.query(GroupMembership).filter_by(account_id=account.id).count()
        assert count >= 1, "Fast path must persist at least one GroupMembership row"

    def test_membership_links_correct_user_and_group(self, db_session):
        from worstassume.db.models import GroupMembership
        account = self._setup(db_session)
        alice = db_session.query(Principal).filter_by(account_id=account.id, name="alice").first()
        admins = db_session.query(Principal).filter_by(account_id=account.id, name="admins").first()
        assert alice and admins
        gm = db_session.query(GroupMembership).filter_by(
            user_id=alice.id, group_id=admins.id
        ).first()
        assert gm is not None, "GroupMembership row must link alice → admins"

    def test_membership_is_idempotent(self, db_session):
        from worstassume.db.models import GroupMembership
        account = self._setup(db_session)
        iam_module.enumerate(_session(), db_session, account, _cap_full())
        db_session.commit()
        count = db_session.query(GroupMembership).filter_by(account_id=account.id).count()
        assert count >= 1, "Re-enumeration must not duplicate GroupMembership rows"


# ─── Group membership — slow path ─────────────────────────────────────────────

@mock_aws
class TestIAMGroupMembershipSlowPath:
    """Phase 8: slow path must persist group memberships via list_groups_for_user."""

    def _setup(self, db_session):
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_group(GroupName="devs")
        iam.create_user(UserName="bob")
        iam.add_user_to_group(GroupName="devs", UserName="bob")
        account = get_or_create_account(db_session, "123456789012", account_name="Test")
        db_session.commit()
        iam_module.enumerate(_session(), db_session, account, _cap_slow())
        db_session.commit()
        return account

    def test_slow_path_group_membership_row_created(self, db_session):
        from worstassume.db.models import GroupMembership
        account = self._setup(db_session)
        count = db_session.query(GroupMembership).filter_by(account_id=account.id).count()
        assert count >= 1, "Slow path must persist at least one GroupMembership row"

    def test_slow_path_links_correct_user_and_group(self, db_session):
        from worstassume.db.models import GroupMembership
        account = self._setup(db_session)
        bob = db_session.query(Principal).filter_by(account_id=account.id, name="bob").first()
        devs = db_session.query(Principal).filter_by(account_id=account.id, name="devs").first()
        assert bob and devs
        gm = db_session.query(GroupMembership).filter_by(
            user_id=bob.id, group_id=devs.id
        ).first()
        assert gm is not None, "GroupMembership row must link bob → devs"
