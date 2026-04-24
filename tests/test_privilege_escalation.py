"""
Tests for worstassume.core.privilege_escalation — comprehensive priv-esc path detection.

Covers all 6 attack families:
  A — IAM Policy Manipulation
  B — Role Trust / Assumption Manipulation
  C — Compute: PassRole + Resource Abuse
  D — Credential / Key Exfiltration via Data Plane
  E — Service-Specific Escalation
  F — Trust Condition Bypass / Weak Conditions

Pure DB logic; no AWS calls needed.
"""

from __future__ import annotations

import json
import pytest

from worstassume.core.privilege_escalation import (
    CATEGORY_ADMIN_ACCESS,
    CATEGORY_MISCONFIGURATION,
    CATEGORY_RISK_PERMISSION,
    CATEGORY_WILDCARD_TRUST,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    _can_do,
    _collect_allowed_actions,
    _has_wildcard,
    analyze,
)
from worstassume.db.models import Principal, Resource
from worstassume.db.store import (
    get_or_create_account,
    link_principal_policy,
    upsert_cross_account_link,
    upsert_policy,
    upsert_principal,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_role(db_session, account, name, actions, trust_policy=None):
    """Create a role with an attached inline policy granting given actions."""
    arn = f"arn:aws:iam::{account.account_id}:role/{name}"
    role = upsert_principal(
        db_session, account,
        arn=arn, name=name, principal_type="role",
        trust_policy=trust_policy,
    )
    if actions:
        doc = {"Version": "2012-10-17",
               "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}
        pol = upsert_policy(
            db_session, account,
            arn=f"{arn}:inline/policy", name=f"{name}-policy",
            policy_type="inline", document=doc,
        )
        link_principal_policy(db_session, role, pol)
    db_session.commit()
    return role


def _make_user(db_session, account, name, actions):
    """Create a user with an attached inline policy."""
    arn = f"arn:aws:iam::{account.account_id}:user/{name}"
    user = upsert_principal(
        db_session, account,
        arn=arn, name=name, principal_type="user",
    )
    if actions:
        doc = {"Version": "2012-10-17",
               "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}
        pol = upsert_policy(
            db_session, account,
            arn=f"{arn}:inline/policy", name=f"{name}-policy",
            policy_type="inline", document=doc,
        )
        link_principal_policy(db_session, user, pol)
    db_session.commit()
    return user


def _make_ec2_resource(db_session, account, name, role=None, http_tokens="optional"):
    """Create an EC2 instance resource with optional attached role and IMDS config."""
    from worstassume.db.store import upsert_resource
    import json
    arn = f"arn:aws:ec2:us-east-1:{account.account_id}:instance/{name}"
    metadata = {"MetadataOptions": {"HttpTokens": http_tokens}}
    r = upsert_resource(
        db_session, account,
        arn=arn, service="ec2", resource_type="instance",
        name=name, region="us-east-1",
        execution_role=role,
        metadata=metadata,
    )
    db_session.commit()
    return r


def _paths(findings) -> set[str]:
    return {f.path for f in findings}


# ─────────────────────────────────────────────────────────────────────────────
# _can_do helper
# ─────────────────────────────────────────────────────────────────────────────

class TestCanDo:
    def test_exact_match(self):
        assert _can_do({"iam:PassRole"}, "iam:PassRole")

    def test_global_wildcard(self):
        assert _can_do({"*"}, "iam:PassRole")

    def test_service_wildcard(self):
        assert _can_do({"iam:*"}, "iam:PassRole")

    def test_prefix_wildcard(self):
        assert _can_do({"iam:Pass*"}, "iam:PassRole")
        assert _can_do({"lambda:*"}, "lambda:CreateFunction")

    def test_no_match(self):
        assert not _can_do({"s3:GetObject"}, "iam:PassRole")

    def test_wrong_service_wildcard(self):
        assert not _can_do({"s3:*"}, "iam:PassRole")


# ─────────────────────────────────────────────────────────────────────────────
# _collect_allowed_actions
# ─────────────────────────────────────────────────────────────────────────────

class TestCollectAllowedActions:
    def test_collects_single_action(self, db_session, account_a):
        role = _make_role(db_session, account_a, "r1", ["s3:GetObject"])
        assert "s3:GetObject" in _collect_allowed_actions(role)

    def test_collects_multiple_actions(self, db_session, account_a):
        role = _make_role(db_session, account_a, "r2", ["s3:*", "ec2:Describe*"])
        actions = _collect_allowed_actions(role)
        assert "s3:*" in actions and "ec2:Describe*" in actions

    def test_ignores_deny_statements(self, db_session, account_a):
        arn = "arn:aws:iam::111111111111:role/deny-role"
        role = upsert_principal(db_session, account_a, arn=arn, name="deny-role", principal_type="role")
        doc = {"Version": "2012-10-17",
               "Statement": [{"Effect": "Deny", "Action": ["iam:*"], "Resource": "*"}]}
        pol = upsert_policy(db_session, account_a, arn=f"{arn}:inline/p", name="deny-pol",
                            policy_type="inline", document=doc)
        link_principal_policy(db_session, role, pol)
        db_session.commit()
        assert "iam:*" not in _collect_allowed_actions(role)

    def test_handles_string_action(self, db_session, account_a):
        arn = "arn:aws:iam::111111111111:role/str-role"
        role = upsert_principal(db_session, account_a, arn=arn, name="str-role", principal_type="role")
        doc = {"Version": "2012-10-17",
               "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]}
        pol = upsert_policy(db_session, account_a, arn=f"{arn}:inline/p", name="p",
                            policy_type="inline", document=doc)
        link_principal_policy(db_session, role, pol)
        db_session.commit()
        assert "iam:PassRole" in _collect_allowed_actions(role)

    def test_empty_when_no_policies(self, db_session, account_a):
        arn = "arn:aws:iam::111111111111:role/empty-role"
        role = upsert_principal(db_session, account_a, arn=arn, name="empty-role", principal_type="role")
        db_session.commit()
        assert _collect_allowed_actions(role) == set()


# ─────────────────────────────────────────────────────────────────────────────
# Baseline
# ─────────────────────────────────────────────────────────────────────────────

class TestBaseline:
    def test_no_findings_for_safe_role(self, db_session, account_a):
        """A role with only read-only, non-sensitive actions produces zero findings."""
        _make_role(db_session, account_a, "safe", [
            "ec2:DescribeInstances",
            "ec2:DescribeVpcs",
            "ec2:DescribeSecurityGroups",
            "s3:ListBucket",
            "s3:ListAllMyBuckets",
            "cloudwatch:GetMetricData",
            "cloudwatch:ListMetrics",
        ])
        assert len(analyze(db_session)) == 0

    def test_findings_sorted_critical_first(self, db_session, account_a):
        _make_role(db_session, account_a, "r1", ["iam:PassRole", "lambda:UpdateFunctionCode"])
        _make_role(db_session, account_a, "r2", ["iam:CreatePolicyVersion"])
        severities = [f.severity for f in analyze(db_session)]
        seen_high = False
        for sev in severities:
            if sev == SEVERITY_HIGH:
                seen_high = True
            if seen_high and sev == SEVERITY_CRITICAL:
                pytest.fail(f"CRITICAL after HIGH: {severities}")

    def test_findings_are_deduplicated(self, db_session, account_a):
        _make_role(db_session, account_a, "r1", ["iam:CreatePolicyVersion"])
        findings = analyze(db_session)
        assert len([f for f in findings if f.path == "CreatePolicyVersion"]) == 1

    def test_groups_not_analyzed(self, db_session, account_a):
        arn = "arn:aws:iam::111111111111:group/admins"
        grp = upsert_principal(db_session, account_a, arn=arn, name="admins", principal_type="group")
        doc = {"Version": "2012-10-17",
               "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}
        pol = upsert_policy(db_session, account_a, arn=f"{arn}:inline/p", name="p",
                            policy_type="inline", document=doc)
        link_principal_policy(db_session, grp, pol)
        db_session.commit()
        findings = analyze(db_session)
        assert all(f.principal_arn != arn for f in findings)

    def test_filter_by_account(self, db_session, account_a, account_b):
        _make_role(db_session, account_a, "bad-a", ["iam:CreatePolicyVersion"])
        _make_role(db_session, account_b, "bad-b", ["iam:CreatePolicyVersion"])
        findings_a = analyze(db_session, account=account_a)
        arns = {f.principal_arn for f in findings_a}
        assert all("111111111111" in arn for arn in arns)
        assert not any("222222222222" in arn for arn in arns)

    def test_admin_access_detected(self, db_session, account_a):
        _make_role(db_session, account_a, "admin", ["*"])
        findings = analyze(db_session)
        assert "AdministratorAccess" in _paths(findings)
        assert any(f.category == CATEGORY_ADMIN_ACCESS for f in findings)

    def test_iam_wildcard_triggers_multiple_paths(self, db_session, account_a):
        _make_role(db_session, account_a, "admin", ["iam:*"])
        paths = _paths(analyze(db_session))
        assert "CreatePolicyVersion" in paths
        assert "AttachUserPolicy" in paths
        assert "PutRolePolicy" in paths
        assert "UpdateAssumeRolePolicy" in paths


# ─────────────────────────────────────────────────────────────────────────────
# Family A — IAM Policy Manipulation
# ─────────────────────────────────────────────────────────────────────────────

class TestFamilyA:
    def test_create_policy_version(self, db_session, account_a):
        _make_role(db_session, account_a, "r", ["iam:CreatePolicyVersion"])
        assert "CreatePolicyVersion" in _paths(analyze(db_session))

    def test_set_default_policy_version(self, db_session, account_a):
        _make_role(db_session, account_a, "r", ["iam:SetDefaultPolicyVersion"])
        findings = analyze(db_session)
        assert "SetDefaultPolicyVersion" in _paths(findings)
        assert any(f.severity == SEVERITY_CRITICAL for f in findings
                   if f.path == "SetDefaultPolicyVersion")

    def test_attach_user_policy(self, db_session, account_a):
        _make_role(db_session, account_a, "r", ["iam:AttachUserPolicy"])
        assert "AttachUserPolicy" in _paths(analyze(db_session))

    def test_attach_role_policy(self, db_session, account_a):
        _make_role(db_session, account_a, "r", ["iam:AttachRolePolicy"])
        assert "AttachRolePolicy" in _paths(analyze(db_session))

    def test_attach_group_policy(self, db_session, account_a):
        _make_role(db_session, account_a, "r", ["iam:AttachGroupPolicy"])
        findings = analyze(db_session)
        assert "AttachGroupPolicy" in _paths(findings)
        assert any(f.severity == SEVERITY_CRITICAL for f in findings
                   if f.path == "AttachGroupPolicy")

    def test_put_user_policy(self, db_session, account_a):
        _make_role(db_session, account_a, "r", ["iam:PutUserPolicy"])
        assert "PutUserPolicy" in _paths(analyze(db_session))

    def test_put_role_policy(self, db_session, account_a):
        _make_role(db_session, account_a, "r", ["iam:PutRolePolicy"])
        findings = analyze(db_session)
        assert "PutRolePolicy" in _paths(findings)
        assert any(f.severity == SEVERITY_CRITICAL for f in findings
                   if f.path == "PutRolePolicy")

    def test_put_group_policy(self, db_session, account_a):
        _make_role(db_session, account_a, "r", ["iam:PutGroupPolicy"])
        assert "PutGroupPolicy" in _paths(analyze(db_session))

    def test_create_policy(self, db_session, account_a):
        _make_role(db_session, account_a, "r", ["iam:CreatePolicy"])
        findings = analyze(db_session)
        assert "CreatePolicy" in _paths(findings)
        assert any(f.severity == SEVERITY_HIGH for f in findings if f.path == "CreatePolicy")

    def test_add_user_to_group(self, db_session, account_a):
        _make_role(db_session, account_a, "r", ["iam:AddUserToGroup"])
        findings = analyze(db_session)
        assert "AddUserToGroup" in _paths(findings)
        assert any(f.severity == SEVERITY_HIGH for f in findings if f.path == "AddUserToGroup")


# ─────────────────────────────────────────────────────────────────────────────
# Family B — Role Trust / Assumption Manipulation
# ─────────────────────────────────────────────────────────────────────────────

class TestFamilyB:
    def test_update_assume_role_policy(self, db_session, account_a):
        _make_role(db_session, account_a, "r", ["iam:UpdateAssumeRolePolicy"])
        findings = analyze(db_session)
        assert "UpdateAssumeRolePolicy" in _paths(findings)
        assert any(f.severity == SEVERITY_CRITICAL for f in findings
                   if f.path == "UpdateAssumeRolePolicy")

    def test_assume_role_wildcard_resource(self, db_session, account_a):
        _make_role(db_session, account_a, "r", ["sts:AssumeRole"])
        assert "AssumeRoleWildcardResource" in _paths(analyze(db_session))

    def test_wildcard_trust_principal(self, db_session, account_a):
        trust = {"Version": "2012-10-17",
                 "Statement": [{"Effect": "Allow", "Principal": "*",
                                "Action": "sts:AssumeRole"}]}
        _make_role(db_session, account_a, "open", [], trust_policy=trust)
        findings = analyze(db_session)
        assert "WildcardTrustPrincipal" in _paths(findings)
        assert any(f.category == CATEGORY_WILDCARD_TRUST for f in findings
                   if f.path == "WildcardTrustPrincipal")

    def test_cross_account_wildcard_trust(self, db_session, account_a, account_b):
        upsert_cross_account_link(
            db_session,
            source_account=account_a, target_account=account_b,
            role_arn="arn:aws:iam::222222222222:role/WildRole",
            trust_principal_arn="*", is_wildcard=True,
        )
        db_session.commit()
        assert "CrossAccountWildcardTrust" in _paths(analyze(db_session))


# ─────────────────────────────────────────────────────────────────────────────
# Family C — Compute: PassRole + Resource Abuse
# ─────────────────────────────────────────────────────────────────────────────

class TestFamilyC:
    def test_passrole_lambda_create(self, db_session, account_a):
        _make_role(db_session, account_a, "r", ["iam:PassRole", "lambda:CreateFunction"])
        assert "PassRole+Lambda:CreateFunction" in _paths(analyze(db_session))

    def test_passrole_lambda_update(self, db_session, account_a):
        _make_role(db_session, account_a, "r", ["iam:PassRole", "lambda:UpdateFunctionCode"])
        findings = analyze(db_session)
        assert "PassRole+Lambda:UpdateFunctionCode" in _paths(findings)
        assert any(f.severity == SEVERITY_HIGH for f in findings
                   if f.path == "PassRole+Lambda:UpdateFunctionCode")

    def test_passrole_ec2_run(self, db_session, account_a):
        _make_role(db_session, account_a, "r", ["iam:PassRole", "ec2:RunInstances"])
        assert "PassRole+EC2:RunInstances" in _paths(analyze(db_session))

    def test_passrole_ecs_register_task(self, db_session, account_a):
        _make_role(db_session, account_a, "r",
                   ["iam:PassRole", "ecs:RegisterTaskDefinition"])
        assert "PassRole+ECS:RegisterTaskDefinition" in _paths(analyze(db_session))

    def test_passrole_ecs_update_service(self, db_session, account_a):
        _make_role(db_session, account_a, "r",
                   ["iam:PassRole", "ecs:UpdateService"])
        assert "PassRole+ECS:UpdateService" in _paths(analyze(db_session))

    def test_passrole_cloudformation_create(self, db_session, account_a):
        _make_role(db_session, account_a, "r",
                   ["iam:PassRole", "cloudformation:CreateStack"])
        findings = analyze(db_session)
        assert "PassRole+CloudFormation:CreateStack" in _paths(findings)
        assert any(f.severity == SEVERITY_CRITICAL for f in findings
                   if f.path == "PassRole+CloudFormation:CreateStack")

    def test_passrole_cloudformation_update(self, db_session, account_a):
        _make_role(db_session, account_a, "r",
                   ["iam:PassRole", "cloudformation:UpdateStack"])
        assert "PassRole+CloudFormation:UpdateStack" in _paths(analyze(db_session))

    def test_passrole_glue_create(self, db_session, account_a):
        _make_role(db_session, account_a, "r",
                   ["iam:PassRole", "glue:CreateJob"])
        assert "PassRole+Glue:CreateJob" in _paths(analyze(db_session))

    def test_passrole_sagemaker(self, db_session, account_a):
        _make_role(db_session, account_a, "r",
                   ["iam:PassRole", "sagemaker:CreateTrainingJob"])
        assert "PassRole+SageMaker:CreateTrainingJob" in _paths(analyze(db_session))

    def test_passrole_codebuild(self, db_session, account_a):
        _make_role(db_session, account_a, "r",
                   ["iam:PassRole", "codebuild:CreateProject"])
        assert "PassRole+CodeBuild:CreateProject" in _paths(analyze(db_session))

    def test_passrole_datapipeline(self, db_session, account_a):
        _make_role(db_session, account_a, "r",
                   ["iam:PassRole", "datapipeline:CreatePipeline"])
        findings = analyze(db_session)
        assert "PassRole+DataPipeline" in _paths(findings)
        assert any(f.severity == SEVERITY_MEDIUM for f in findings
                   if f.path == "PassRole+DataPipeline")

    def test_passrole_ssm_send_command(self, db_session, account_a):
        _make_role(db_session, account_a, "r",
                   ["iam:PassRole", "ssm:SendCommand"])
        assert "PassRole+SSM:SendCommand" in _paths(analyze(db_session))

    def test_no_passrole_no_combo_findings(self, db_session, account_a):
        """Without iam:PassRole, none of the combo paths should fire."""
        _make_role(db_session, account_a, "r",
                   ["lambda:CreateFunction", "ec2:RunInstances", "ecs:UpdateService"])
        combo_paths = {
            "PassRole+Lambda:CreateFunction", "PassRole+EC2:RunInstances",
            "PassRole+ECS:UpdateService",
        }
        assert not combo_paths.intersection(_paths(analyze(db_session)))


# ─────────────────────────────────────────────────────────────────────────────
# Family D — Credential / Key Exfiltration
# ─────────────────────────────────────────────────────────────────────────────

class TestFamilyD:
    def test_ec2_modify_instance_attribute(self, db_session, account_a):
        _make_role(db_session, account_a, "r", ["ec2:ModifyInstanceAttribute"])
        findings = analyze(db_session)
        assert "EC2:ModifyInstanceAttribute" in _paths(findings)
        assert any(f.severity == SEVERITY_HIGH for f in findings
                   if f.path == "EC2:ModifyInstanceAttribute")

    def test_ssm_send_command(self, db_session, account_a):
        _make_role(db_session, account_a, "r", ["ssm:SendCommand"])
        assert "SSM:SendCommand" in _paths(analyze(db_session))

    def test_secrets_manager_get(self, db_session, account_a):
        _make_role(db_session, account_a, "r", ["secretsmanager:GetSecretValue"])
        findings = analyze(db_session)
        assert "SecretsManager:GetSecretValue" in _paths(findings)
        assert any(f.severity == SEVERITY_HIGH for f in findings
                   if f.path == "SecretsManager:GetSecretValue")

    def test_ssm_get_parameter(self, db_session, account_a):
        _make_role(db_session, account_a, "r", ["ssm:GetParameter"])
        findings = analyze(db_session)
        assert "SSM:GetParameter" in _paths(findings)
        assert any(f.severity == SEVERITY_MEDIUM for f in findings
                   if f.path == "SSM:GetParameter")

    def test_ssm_get_parameters_also_detected(self, db_session, account_a):
        """ssm:GetParameters (plural) should also trigger the finding."""
        _make_role(db_session, account_a, "r", ["ssm:GetParameters"])
        assert "SSM:GetParameter" in _paths(analyze(db_session))

    def test_lambda_get_function(self, db_session, account_a):
        _make_role(db_session, account_a, "r", ["lambda:GetFunction"])
        findings = analyze(db_session)
        assert "Lambda:GetFunction" in _paths(findings)
        assert any(f.severity == SEVERITY_MEDIUM for f in findings
                   if f.path == "Lambda:GetFunction")

    def test_s3_get_object_wildcard(self, db_session, account_a):
        _make_role(db_session, account_a, "r", ["s3:GetObject"])
        findings = analyze(db_session)
        assert "S3:GetObject:Wildcard" in _paths(findings)
        assert any(f.severity == SEVERITY_MEDIUM for f in findings
                   if f.path == "S3:GetObject:Wildcard")


# ─────────────────────────────────────────────────────────────────────────────
# Family E — Service-Specific Escalation
# ─────────────────────────────────────────────────────────────────────────────

class TestFamilyE:
    def test_update_login_profile(self, db_session, account_a):
        _make_role(db_session, account_a, "r", ["iam:UpdateLoginProfile"])
        findings = analyze(db_session)
        assert "UpdateLoginProfile" in _paths(findings)
        assert any(f.severity == SEVERITY_CRITICAL for f in findings
                   if f.path == "UpdateLoginProfile")

    def test_create_login_profile(self, db_session, account_a):
        _make_role(db_session, account_a, "r", ["iam:CreateLoginProfile"])
        findings = analyze(db_session)
        assert "CreateLoginProfile" in _paths(findings)
        assert any(f.severity == SEVERITY_HIGH for f in findings
                   if f.path == "CreateLoginProfile")

    def test_create_access_key(self, db_session, account_a):
        _make_role(db_session, account_a, "r", ["iam:CreateAccessKey"])
        findings = analyze(db_session)
        assert "CreateAccessKey" in _paths(findings)
        assert any(f.severity == SEVERITY_CRITICAL for f in findings
                   if f.path == "CreateAccessKey")

    def test_update_access_key(self, db_session, account_a):
        _make_role(db_session, account_a, "r", ["iam:UpdateAccessKey"])
        findings = analyze(db_session)
        assert "UpdateAccessKey" in _paths(findings)
        assert any(f.severity == SEVERITY_MEDIUM for f in findings
                   if f.path == "UpdateAccessKey")

    def test_mfa_bypass_deactivate(self, db_session, account_a):
        _make_role(db_session, account_a, "r", ["iam:DeactivateMFADevice"])
        findings = analyze(db_session)
        assert "MFABypass" in _paths(findings)
        assert any(f.severity == SEVERITY_HIGH for f in findings if f.path == "MFABypass")

    def test_mfa_bypass_delete(self, db_session, account_a):
        _make_role(db_session, account_a, "r", ["iam:DeleteVirtualMFADevice"])
        assert "MFABypass" in _paths(analyze(db_session))


# ─────────────────────────────────────────────────────────────────────────────
# Family F — Trust Condition Bypass / Weak Conditions
# ─────────────────────────────────────────────────────────────────────────────

class TestFamilyF:
    def _cross_trust(self, source_acct_id: str, conditions: dict | None):
        """Build a trust policy trusting a specific account."""
        stmt = {
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{source_acct_id}:root"},
            "Action": "sts:AssumeRole",
        }
        if conditions is not None:
            stmt["Condition"] = conditions
        return {"Version": "2012-10-17", "Statement": [stmt]}

    def test_no_condition_at_all(self, db_session, account_a, account_b):
        """Cross-account trust with zero Condition block → TrustPolicyNoCondition."""
        trust = self._cross_trust(account_a.account_id, conditions=None)
        _make_role(db_session, account_b, "r", [], trust_policy=trust)
        findings = analyze(db_session)
        assert "TrustPolicyNoCondition" in _paths(findings)
        assert any(f.severity == SEVERITY_HIGH for f in findings
                   if f.path == "TrustPolicyNoCondition")
        assert any(f.category == CATEGORY_MISCONFIGURATION for f in findings
                   if f.path == "TrustPolicyNoCondition")

    def test_no_external_id(self, db_session, account_a, account_b):
        """Cross-account trust with a condition but no ExternalId → TrustPolicyNoExternalId."""
        trust = self._cross_trust(account_a.account_id,
                                  conditions={"StringEquals": {"aws:RequestedRegion": "us-east-1"}})
        _make_role(db_session, account_b, "r", [], trust_policy=trust)
        findings = analyze(db_session)
        assert "TrustPolicyNoExternalId" in _paths(findings)

    def test_with_external_id_no_finding(self, db_session, account_a, account_b):
        """Cross-account trust with ExternalId → no TrustPolicyNoExternalId."""
        trust = self._cross_trust(account_a.account_id,
                                  conditions={"StringEquals": {"sts:ExternalId": "secret-id"}})
        _make_role(db_session, account_b, "r", [], trust_policy=trust)
        findings = analyze(db_session)
        assert "TrustPolicyNoExternalId" not in _paths(findings)

    def test_no_mfa_required(self, db_session, account_a, account_b):
        """Cross-account trust without MFA condition → TrustPolicyNoMFARequired."""
        trust = self._cross_trust(account_a.account_id,
                                  conditions={"StringEquals": {"sts:ExternalId": "abc"}})
        _make_role(db_session, account_b, "r", [], trust_policy=trust)
        findings = analyze(db_session)
        assert "TrustPolicyNoMFARequired" in _paths(findings)
        assert any(f.severity == SEVERITY_MEDIUM for f in findings
                   if f.path == "TrustPolicyNoMFARequired")

    def test_with_mfa_condition_no_mfa_finding(self, db_session, account_a, account_b):
        """Cross-account trust with MFA condition → no TrustPolicyNoMFARequired."""
        trust = self._cross_trust(account_a.account_id, conditions={
            "StringEquals": {"sts:ExternalId": "abc"},
            "Bool": {"aws:MultiFactorAuthPresent": "true"},
        })
        _make_role(db_session, account_b, "r", [], trust_policy=trust)
        findings = analyze(db_session)
        assert "TrustPolicyNoMFARequired" not in _paths(findings)

    def test_same_account_trust_ignored(self, db_session, account_a):
        """Trust from SAME account should not trigger cross-account condition checks."""
        trust = self._cross_trust(account_a.account_id, conditions=None)
        _make_role(db_session, account_a, "self-trust-role", [], trust_policy=trust)
        findings = analyze(db_session)
        assert "TrustPolicyNoCondition" not in _paths(findings)


# ─────────────────────────────────────────────────────────────────────────────
# EC2 IMDSv1 (Resource-aware)
# ─────────────────────────────────────────────────────────────────────────────

class TestIMDSv1:
    def test_imdsv1_optional_flagged(self, db_session, account_a):
        """Instance with HttpTokens=optional should be flagged."""
        _make_ec2_resource(db_session, account_a, "i-001", http_tokens="optional")
        findings = analyze(db_session)
        assert "EC2IMDSv1Enabled" in _paths(findings)
        assert any(f.severity == SEVERITY_MEDIUM for f in findings
                   if f.path == "EC2IMDSv1Enabled")
        assert any(f.category == CATEGORY_MISCONFIGURATION for f in findings
                   if f.path == "EC2IMDSv1Enabled")

    def test_imdsv2_required_not_flagged(self, db_session, account_a):
        """Instance with HttpTokens=required should NOT be flagged."""
        _make_ec2_resource(db_session, account_a, "i-002", http_tokens="required")
        assert "EC2IMDSv1Enabled" not in _paths(analyze(db_session))


# ─────────────────────────────────────────────────────────────────────────────
# Cross-account PrivEsc path
# ─────────────────────────────────────────────────────────────────────────────

class TestCrossAccountPrivEsc:
    def test_cross_account_priv_esc_path(self, db_session, account_a, account_b):
        role_arn = f"arn:aws:iam::{account_b.account_id}:role/HiPrivRole"
        _make_role(db_session, account_b, "HiPrivRole", ["iam:CreatePolicyVersion"])
        upsert_cross_account_link(
            db_session,
            source_account=account_a, target_account=account_b,
            role_arn=role_arn, trust_principal_arn=f"arn:aws:iam::{account_a.account_id}:root",
            is_wildcard=False,
        )
        db_session.commit()
        findings = analyze(db_session)
        assert "CrossAccountPrivEscPath" in _paths(findings)

    def test_cross_account_safe_role_no_priv_esc_path(self, db_session, account_a, account_b):
        role_arn = f"arn:aws:iam::{account_b.account_id}:role/SafeRole"
        _make_role(db_session, account_b, "SafeRole", ["s3:GetObject"])
        upsert_cross_account_link(
            db_session,
            source_account=account_a, target_account=account_b,
            role_arn=role_arn, trust_principal_arn=f"arn:aws:iam::{account_a.account_id}:root",
            is_wildcard=False,
        )
        db_session.commit()
        assert "CrossAccountPrivEscPath" not in _paths(analyze(db_session))


# ─────────────────────────────────────────────────────────────────────────────
# Backward-compat
# ─────────────────────────────────────────────────────────────────────────────

class TestBackwardCompat:
    def test_has_wildcard_global(self):
        assert _has_wildcard({"*"}, "")
        assert _has_wildcard({"*"}, "iam:")

    def test_has_wildcard_service(self):
        assert _has_wildcard({"iam:*"}, "iam:")
        assert not _has_wildcard({"s3:*"}, "iam:")


# ─────────────────────────────────────────────────────────────────────────────
# NotAction support — PR 1
# ─────────────────────────────────────────────────────────────────────────────

class TestNotAction:
    """
    Verify that Allow+NotAction statements are parsed correctly.

    IAM semantics: multiple Allow statements union additively.
    NotAction limits only what that statement contributes; a later Action
    statement can re-grant actions the NotAction excluded.
    """

    def _make_principal_with_policy(self, db_session, account, name, doc):
        """Helper: create a role principal with a single inline policy doc."""
        arn = f"arn:aws:iam::{account.account_id}:role/{name}"
        role = upsert_principal(db_session, account, arn=arn,
                                name=name, principal_type="role")
        pol = upsert_policy(db_session, account,
                            arn=f"{arn}/inline-0",
                            name=f"{name}-policy",
                            policy_type="inline",
                            document=doc)
        link_principal_policy(db_session, role, pol)
        db_session.commit()
        return role

    # ------------------------------------------------------------------
    # 1. NotAction-only policy: exclude iam:* — compute actions are allowed
    # ------------------------------------------------------------------
    def test_notaction_excludes_iam_wildcard(self, db_session, account_a):
        """NotAction: [iam:*] must NOT yield any iam: actions."""
        doc = {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            "NotAction": ["iam:*"],
            "Resource": "*",
        }]}
        role = self._make_principal_with_policy(db_session, account_a, "r-na1", doc)
        actions = _collect_allowed_actions(role)
        # iam:PassRole is excluded by iam:* — assert via _can_do (semantic check)
        assert not _can_do(actions, "iam:PassRole")
        assert not _can_do(actions, "iam:CreatePolicyVersion")
        # compute-service actions are NOT excluded
        assert _can_do(actions, "ec2:RunInstances")
        assert _can_do(actions, "lambda:CreateFunction")
        assert _can_do(actions, "sts:AssumeRole")

    # ------------------------------------------------------------------
    # 2. Real-world case: NotAction + explicit Action re-grants some iam:
    # ------------------------------------------------------------------
    def test_notaction_plus_explicit_action_regrant(self, db_session, account_a):
        """
        Statement 1: NotAction:[iam:*, orgs:*, account:*], Allow, Resource:*
        Statement 2: Action:[iam:PassRole, iam:List*, iam:Get*, ...], Allow, Resource:*

        Expected: ec2:RunInstances IN (from stmt1), iam:PassRole IN (from stmt2),
                  iam:CreatePolicyVersion NOT IN (excluded by stmt1, not re-granted).
        """
        doc = {"Version": "2012-10-17", "Statement": [
            {
                "Effect": "Allow",
                "NotAction": ["organizations:*", "iam:*", "account:*"],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": [
                    "organizations:DescribeOrganization",
                    "iam:PassRole",
                    "iam:ListRoles", "iam:ListPolicies", "iam:List*",
                    "iam:GetRole", "iam:Get*",
                    "iam:DeleteServiceLinkedRole", "iam:CreateServiceLinkedRole",
                    "account:ListRegions", "account:GetPrimaryEmail",
                    "account:GetAccountInformation",
                ],
                "Resource": "*",
            },
        ]}
        role = self._make_principal_with_policy(db_session, account_a, "r-na2", doc)
        actions = _collect_allowed_actions(role)

        # From statement 1 (NotAction excludes iam:*)
        assert _can_do(actions, "ec2:RunInstances")
        assert _can_do(actions, "lambda:CreateFunction")
        assert _can_do(actions, "sts:AssumeRole")
        assert _can_do(actions, "secretsmanager:GetSecretValue")

        # From statement 2 (explicit re-grant overrides NotAction exclusion)
        assert _can_do(actions, "iam:PassRole")

        # iam:CreatePolicyVersion is excluded by iam:* and NOT re-granted
        assert not _can_do(actions, "iam:CreatePolicyVersion")
        assert not _can_do(actions, "iam:AttachUserPolicy")

    # ------------------------------------------------------------------
    # 3. Deny Effect with NotAction must be ignored
    # ------------------------------------------------------------------
    def test_deny_notaction_is_ignored(self, db_session, account_a):
        """Deny+NotAction statements must NOT contribute any actions."""
        doc = {"Version": "2012-10-17", "Statement": [{
            "Effect": "Deny",
            "NotAction": ["iam:*"],
            "Resource": "*",
        }]}
        role = self._make_principal_with_policy(db_session, account_a, "r-na3", doc)
        actions = _collect_allowed_actions(role)
        assert len(actions) == 0

    # ------------------------------------------------------------------
    # 4. NotAction with a string (not list) value
    # ------------------------------------------------------------------
    def test_notaction_string_value(self, db_session, account_a):
        """NotAction can be a bare string instead of a list — must be handled."""
        doc = {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            "NotAction": "iam:*",   # string, not list
            "Resource": "*",
        }]}
        role = self._make_principal_with_policy(db_session, account_a, "r-na4", doc)
        actions = _collect_allowed_actions(role)
        assert not _can_do(actions, "iam:PassRole")
        assert _can_do(actions, "ec2:RunInstances")

    # ------------------------------------------------------------------
    # 5. Narrow NotAction — excludes only s3:* → iam actions still blocked
    #    (only non-s3 tracked actions should appear)
    # ------------------------------------------------------------------
    def test_notaction_narrow_exclusion(self, db_session, account_a):
        """NotAction: [s3:*] should still exclude s3: actions only."""
        doc = {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            "NotAction": ["s3:*"],
            "Resource": "*",
        }]}
        role = self._make_principal_with_policy(db_session, account_a, "r-na5", doc)
        actions = _collect_allowed_actions(role)
        # s3 actions excluded
        assert not _can_do(actions, "s3:GetObject")
        assert not _can_do(actions, "s3:PutBucketPolicy")
        # iam actions NOT excluded → dangerous!
        assert _can_do(actions, "iam:PassRole")
        assert _can_do(actions, "iam:CreatePolicyVersion")
        assert _can_do(actions, "ec2:RunInstances")
