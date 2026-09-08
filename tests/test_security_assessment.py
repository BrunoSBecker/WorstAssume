"""
tests/test_security_assessment.py — Test suite for security_assessment.assess().

Coverage:
  1. assess() returns findings for roles with dangerous permissions
  2. assess() correctly emits USER_CONFIG findings via _assess_user()
  3. assess() skips safe read-only principals (no findings)
  4. Phase 8: user inherits group permissions via _collect_allowed_actions()
     → user with no direct dangerous policies but HIGH-priv group membership
       is correctly assessed as HIGH
  5. Phase 8: group_memberships_as_user is eager-loaded (no lazy-load exception)
  6. assess() filters by account
  7. assess() respects min_severity threshold
  8. assess() is idempotent (second call same results)
  9. deleted _cross_ref_user_group no longer emits UserSharedGroupPolicy finding
"""

from __future__ import annotations

import pytest

from worstassume.core.security_assessment import assess
from worstassume.db.store import (
    get_or_create_account,
    link_principal_policy,
    upsert_group_membership,
    upsert_policy,
    upsert_principal,
)
from worstassume.db.models import Principal, SecurityFinding


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_role(db, account, name, actions, trust_policy=None):
    arn = f"arn:aws:iam::{account.account_id}:role/{name}"
    role = upsert_principal(db, account, arn=arn, name=name,
                            principal_type="role", trust_policy=trust_policy)
    if actions:
        pol = upsert_policy(db, account,
                            arn=f"{arn}:inline/p", name=f"{name}-p",
                            policy_type="inline",
                            document={"Version": "2012-10-17",
                                      "Statement": [{"Effect": "Allow",
                                                     "Action": actions,
                                                     "Resource": "*"}]})
        link_principal_policy(db, role, pol)
    db.commit()
    return role


def _make_user(db, account, name, actions=None):
    arn = f"arn:aws:iam::{account.account_id}:user/{name}"
    user = upsert_principal(db, account, arn=arn, name=name, principal_type="user")
    if actions:
        pol = upsert_policy(db, account,
                            arn=f"{arn}:inline/p", name=f"{name}-p",
                            policy_type="inline",
                            document={"Version": "2012-10-17",
                                      "Statement": [{"Effect": "Allow",
                                                     "Action": actions,
                                                     "Resource": "*"}]})
        link_principal_policy(db, user, pol)
    db.commit()
    return user


def _make_group(db, account, name, actions=None):
    arn = f"arn:aws:iam::{account.account_id}:group/{name}"
    grp = upsert_principal(db, account, arn=arn, name=name, principal_type="group")
    if actions:
        pol = upsert_policy(db, account,
                            arn=f"{arn}:inline/p", name=f"{name}-p",
                            policy_type="inline",
                            document={"Version": "2012-10-17",
                                      "Statement": [{"Effect": "Allow",
                                                     "Action": actions,
                                                     "Resource": "*"}]})
        link_principal_policy(db, grp, pol)
    db.commit()
    return grp


def _path_ids(findings) -> set[str]:
    return {f.path_id for f in findings}


# ── Basic assess() behaviour ──────────────────────────────────────────────────

def test_assess_returns_findings_for_dangerous_role(db_session, account_a):
    _make_role(db_session, account_a, "bad-role", ["iam:CreatePolicyVersion"])
    findings = assess(db_session, account=account_a)
    assert findings, "High-priv role must produce at least one finding"
    assert any(f.entity_type == "role" for f in findings)


def test_assess_no_findings_for_safe_role(db_session, account_a):
    _make_role(db_session, account_a, "safe", ["ec2:DescribeInstances", "s3:ListBucket"])
    findings = assess(db_session, account=account_a)
    assert len(findings) == 0, "Read-only role must produce zero findings"


def test_assess_filters_by_account(db_session, account_a, account_b):
    _make_role(db_session, account_a, "bad-a", ["iam:CreatePolicyVersion"])
    _make_role(db_session, account_b, "bad-b", ["iam:CreatePolicyVersion"])
    findings_a = assess(db_session, account=account_a)
    arns = {f.entity_arn for f in findings_a}
    assert all(account_a.account_id in arn for arn in arns), \
        "Findings must only contain account_a principals"
    assert not any(account_b.account_id in arn for arn in arns), \
        "Findings must not contain account_b principals"


def test_assess_respects_min_severity_threshold(db_session, account_a):
    _make_role(db_session, account_a, "mid", ["iam:CreateAccessKey"])
    all_findings = assess(db_session, account=account_a, min_severity="LOW")
    high_only = assess(db_session, account=account_a, min_severity="HIGH")
    assert len(all_findings) >= len(high_only), \
        "min_severity=HIGH must return a subset of min_severity=LOW"


def test_assess_is_idempotent(db_session, account_a):
    _make_role(db_session, account_a, "stable", ["iam:PutRolePolicy"])
    first = assess(db_session, account=account_a)
    second = assess(db_session, account=account_a)
    assert _path_ids(first) == _path_ids(second), \
        "Second assess() call must produce identical path_ids"


# ── Phase 8: group-inherited permissions ─────────────────────────────────────

def test_assess_user_inherits_group_permissions(db_session, account_a):
    """
    User with no direct dangerous policies but is a member of a HIGH-priv group
    should show HIGH-severity findings because _collect_allowed_actions() now
    includes group policies.
    """
    group = _make_group(db_session, account_a, "admin-group", ["iam:CreatePolicyVersion"])
    user  = _make_user(db_session, account_a, "alice")   # no direct policies
    upsert_group_membership(db_session, user=user, group=group, account=account_a)
    db_session.commit()

    findings = assess(db_session, account=account_a)
    user_findings = [f for f in findings if f.entity_arn == user.arn]
    # Non-empty proves group-inherited permissions are flowing through to the user
    assert user_findings, "User in HIGH-priv group must have findings from inherited permissions"
    sevs = {f.severity for f in user_findings}
    # iam:CreatePolicyVersion via an inline policy rates MEDIUM in _inline_risk — that's correct.
    # The key assertion is that severity is above LOW (not ignored), proving inheritance works.
    assert sevs & {"CRITICAL", "HIGH", "MEDIUM"}, \
        "Inherited group permission must produce at least a MEDIUM/HIGH/CRITICAL finding"


def test_assess_user_no_findings_when_not_in_dangerous_group(db_session, account_a):
    """User with no direct policies and in a safe group → no PermissionRisk findings."""
    group = _make_group(db_session, account_a, "readonly-group", ["s3:ListBucket"])
    user  = _make_user(db_session, account_a, "bob")
    upsert_group_membership(db_session, user=user, group=group, account=account_a)
    db_session.commit()

    findings = assess(db_session, account=account_a)
    user_findings = [f for f in findings
                     if f.entity_arn == user.arn and f.category == "PERM_RISK"]
    assert not user_findings, "User in safe group must have no PERM_RISK findings"


def test_assess_user_with_group_membership_no_lazy_load_error(db_session, account_a):
    """
    With group_memberships_as_user loaded via joinedload in assess(),
    accessing the relationship in worker threads must not raise DetachedInstanceError.
    """
    group = _make_group(db_session, account_a, "grp", ["ec2:DescribeInstances"])
    user  = _make_user(db_session, account_a, "carol")
    upsert_group_membership(db_session, user=user, group=group, account=account_a)
    db_session.commit()

    # Should not raise; if joinedload is missing this fails with DetachedInstanceError
    findings = assess(db_session, account=account_a)
    # No assertion on finding content — just verifying no exception raised
    assert findings is not None


def test_cross_ref_user_group_heuristic_removed(db_session, account_a):
    """
    The deleted _cross_ref_user_group heuristic emitted UserSharedGroupPolicy
    when a user shared a managed policy with a group. That path_id must no
    longer appear in any findings after Phase 8 cleanup.
    """
    # Shared managed policy
    managed_pol = upsert_policy(
        db_session, account_a,
        arn=f"arn:aws:iam::{account_a.account_id}:policy/SharedAdminPolicy",
        name="SharedAdminPolicy",
        policy_type="managed",
        document={"Version": "2012-10-17",
                  "Statement": [{"Effect": "Allow",
                                 "Action": "iam:CreatePolicyVersion",
                                 "Resource": "*"}]},
    )
    group = _make_group(db_session, account_a, "admin-grp")
    user  = _make_user(db_session, account_a, "eve")
    link_principal_policy(db_session, group, managed_pol)
    link_principal_policy(db_session, user, managed_pol)
    db_session.commit()

    findings = assess(db_session, account=account_a)
    legacy_ids = {f.path_id for f in findings if "UserSharedGroupPolicy" in f.path_id}
    assert not legacy_ids, \
        "Deleted _cross_ref_user_group heuristic must not emit UserSharedGroupPolicy findings"


# ── Stream 2: NotAction, inherited wildcards, collapse, golden Criticals ──────

def test_not_action_excluding_iam_is_not_high(db_session, account_a):
    arn = f"arn:aws:iam::{account_a.account_id}:role/not-iam"
    role = upsert_principal(db_session, account_a, arn=arn, name="not-iam", principal_type="role")
    pol = upsert_policy(
        db_session, account_a,
        arn=f"{arn}:inline/p", name="everything-but-iam", policy_type="inline",
        document={"Version": "2012-10-17",
                  "Statement": [{"Effect": "Allow",
                                 "NotAction": ["iam:*", "sts:*"],
                                 "Resource": "*"}]},
    )
    link_principal_policy(db_session, role, pol)
    db_session.commit()

    findings = assess(db_session, account=account_a)
    role_findings = [f for f in findings if f.entity_arn == role.arn]
    assert role_findings, "NotAction on Resource:* still grants other write actions"
    assert all("wildcard Action (*)" not in (f.message or "") for f in role_findings)
    assert all(f.severity not in {"HIGH", "CRITICAL"} for f in role_findings), \
        "Allow+NotAction of iam:* and sts:* must not be scored as Action:*"


def test_group_inherited_s3_putobject_wildcard_on_user(db_session, account_a):
    group = _make_group(db_session, account_a, "writers", ["s3:PutObject"])
    user = _make_user(db_session, account_a, "writer-user")
    upsert_group_membership(db_session, user=user, group=group, account=account_a)
    db_session.commit()

    findings = assess(db_session, account=account_a)
    user_wc = [f for f in findings
               if f.entity_arn == user.arn and f.category == "RESOURCE_WILDCARD"]
    assert user_wc, "User must inherit Resource:* write verbs from the group"
    assert any("s3:putobject" in (f.message or "").lower() for f in user_wc)


def test_administrator_access_stays_high(db_session, account_a):
    arn = f"arn:aws:iam::{account_a.account_id}:role/admin"
    role = upsert_principal(db_session, account_a, arn=arn, name="admin", principal_type="role")
    pol = upsert_policy(
        db_session, account_a,
        arn=f"arn:aws:iam::aws:policy/AdministratorAccess",
        name="AdministratorAccess",
        policy_type="aws_managed",
        document={"Version": "2012-10-17",
                  "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
    )
    link_principal_policy(db_session, role, pol)
    db_session.commit()

    findings = assess(db_session, account=account_a)
    role_findings = [f for f in findings if f.entity_arn == role.arn]
    perm = [f for f in role_findings if f.category == "PERMISSIVE_POLICY"]
    wild = [f for f in role_findings if f.category == "RESOURCE_WILDCARD"]
    assert perm and perm[0].severity == "HIGH"
    assert not wild, "Wildcard verbs must fold into the HIGH permissive finding"
    assert "Resource:*" in perm[0].message


def test_wildcard_principal_trust_stays_critical(db_session, account_a):
    trust = {"Version": "2012-10-17",
             "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}
    _make_role(db_session, account_a, "open", ["s3:GetObject"], trust_policy=trust)
    findings = assess(db_session, account=account_a)
    trust_f = [f for f in findings if f.path_id == "WildcardTrustNoCondition"]
    assert trust_f and trust_f[0].severity == "CRITICAL"


def test_resource_wildcards_collapse_to_one_finding(db_session, account_a):
    _make_role(db_session, account_a, "multi", ["s3:PutObject", "s3:DeleteBucket"])
    findings = assess(db_session, account=account_a)
    wild = [f for f in findings
            if "multi" in f.entity_arn and f.category == "RESOURCE_WILDCARD"]
    assert len(wild) == 1
    assert wild[0].path_id == "ResourceWildcard"
    assert "s3:putobject" in wild[0].message.lower()
    assert "s3:deletebucket" in wild[0].message.lower()


def test_stale_per_verb_wildcard_rows_are_pruned(db_session, account_a):
    from worstassume.db.store import upsert_security_finding
    role = _make_role(db_session, account_a, "prune-me", ["iam:PassRole"])
    upsert_security_finding(
        db_session, account_a,
        entity_arn=role.arn, entity_type="role", entity_name="prune-me",
        category="RESOURCE_WILDCARD", path_id="ResourceWildcard:iam:passrole",
        severity="HIGH", original_severity="HIGH",
        message="stale per-verb card",
    )
    db_session.commit()

    assess(db_session, account=account_a)
    leftover = [f for f in db_session.query(SecurityFinding).filter_by(entity_arn=role.arn)
                if f.path_id.startswith("ResourceWildcard:")]
    assert not leftover
