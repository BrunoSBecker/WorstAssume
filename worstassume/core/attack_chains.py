"""
Multi-hop attack chain detection engine.

Families covered:
  I   — IAM Self-Modification
  II  — PassRole + Compute Service
  III — Compute Credential Theft
  IV  — Secret Exfiltration → Credential Reuse
  V   — Account Takeover
  VI  — Group Membership
  VII — Cross-Account Lateral Movement
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from worstassume.core.iam_actions import (
    _can_do,
    _is_dangerous,
)

if TYPE_CHECKING:
    from worstassume.db.models import CrossAccountLink, Principal, Resource

log = logging.getLogger(__name__)

# ── Severity constants ────────────────────────────────────────────────────────
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"


# ── Chain data classes ────────────────────────────────────────────────────────

@dataclass
class ChainStep:
    actor: str         # node_id of acting entity (e.g. 'principal:arn:...')
    actor_label: str
    action: str        # e.g. 'cloudformation:CreateStack'
    target: str        # ARN, service principal, or descriptive target
    explanation: str


@dataclass
class PrivEscChain:
    chain_id: str
    severity: str
    title: str
    principal_arn: str
    account_id: str
    outcome: str
    steps: list[ChainStep] = field(default_factory=list)
    suppressed: bool = False
    suppress_reason: str = ""



# ── Node helpers ──────────────────────────────────────────────────────────────

def _p_node(p: Principal) -> str:
    return f"principal:{p.arn}"


def _p_label(p: Principal) -> str:
    return p.name


# ── Deduplication ─────────────────────────────────────────────────────────────

def _dedup_chains(chains: list[PrivEscChain]) -> list[PrivEscChain]:
    seen: set[str] = set()
    unique: list[PrivEscChain] = []
    for c in chains:
        key = f"{c.chain_id}:{c.principal_arn}"
        if key not in seen:
            seen.add(key)
            unique.append(c)
    order = {SEVERITY_CRITICAL: 0, SEVERITY_HIGH: 1, SEVERITY_MEDIUM: 2}
    unique.sort(key=lambda c: order.get(c.severity, 99))
    return unique


# ── Role/resource pre-filtering helpers ───────────────────────────────────────

def _roles_trusting_service(
    all_principals: list[Principal],
    service_principal: str,
    action_cache: dict[str, frozenset[str]] | None = None,
) -> list[tuple[Principal, frozenset[str]]]:
    """Return (role, actions) pairs for roles whose trust policy includes service_principal."""
    result = []
    for role in all_principals:
        if role.principal_type != "role":
            continue
        trust = role.trust_policy
        if not trust:
            continue
        for stmt in trust.get("Statement", []):
            if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            services = principal.get("Service", []) if isinstance(principal, dict) else []
            if isinstance(services, str):
                services = [services]
            if any(service_principal in svc for svc in services):
                acts = (
                    action_cache.get(role.arn, frozenset())
                    if action_cache is not None
                    else frozenset()
                )
                result.append((role, acts))
                break
    return result


def _resources_with_high_priv_role(
    all_resources: list[Resource],
    all_principals: list[Principal],
    action_cache: dict[str, frozenset[str]] | None = None,
) -> list[tuple[Resource, Principal]]:
    """Return (resource, execution_role) pairs where the role has dangerous actions."""
    dangerous_arns = {
        p.arn for p in all_principals
        if _is_dangerous(action_cache.get(p.arn, frozenset()) if action_cache else frozenset())
    }
    return [
        (r, r.execution_role)
        for r in all_resources
        if r.execution_role and r.execution_role.arn in dangerous_arns
    ]


# ── PassRole service chain table ──────────────────────────────────────────────

_PASSROLE_SERVICE_CHAINS = [
    ("cloudformation:CreateStack", "cloudformation.amazonaws.com",
     "PassRole+CFN→IAMUser", SEVERITY_CRITICAL,
     "PassRole + CloudFormation → Create IAM Admin User",
     "CFN template creates a new IAM user with AdministratorAccess.",
     "Attacker creates a CloudFormation stack passing a role that trusts CloudFormation. "
     "The template includes IAM::User + AttachUserPolicy resources creating an admin user."),

    ("cloudformation:UpdateStack", "cloudformation.amazonaws.com",
     "PassRole+CFN→UpdateStack", SEVERITY_HIGH,
     "PassRole + CloudFormation UpdateStack → Execute as Service Role",
     "Stack update executes arbitrary resource changes under the service role.",
     "Attacker updates an existing stack with a service role that has high privileges, "
     "injecting new IAM or compute resources."),

    ("lambda:CreateFunction", "lambda.amazonaws.com",
     "PassRole+Lambda→StealRole", SEVERITY_CRITICAL,
     "PassRole + Lambda CreateFunction → Steal Execution Role Credentials",
     "Lambda function runs as the passed role and exfiltrates its credentials.",
     "Attacker creates a Lambda function with a high-privilege execution role. "
     "The function code exfiltrates the role's temporary credentials via env vars or HTTP."),

    ("lambda:UpdateFunctionCode", "lambda.amazonaws.com",
     "PassRole+Lambda→UpdateCode", SEVERITY_HIGH,
     "PassRole + Lambda UpdateFunctionCode → Inherit Execution Role",
     "Overwriting existing Lambda code to run under its high-privilege execution role.",
     "Attacker overwrites an existing Lambda function's code; the function already has "
     "a high-privilege execution role, so the new code inherits full role permissions."),

    ("ec2:RunInstances", "ec2.amazonaws.com",
     "PassRole+EC2→IMDSSteal", SEVERITY_HIGH,
     "PassRole + EC2 RunInstances → Steal Instance Profile via IMDS",
     "New EC2 instance has high-priv instance profile; attacker steals creds from IMDS.",
     "Attacker launches an EC2 instance with a high-privilege instance profile. "
     "Via SSH or SSM, the attacker retrieves credentials from http://169.254.169.254/."),

    ("ecs:RegisterTaskDefinition", "ecs-tasks.amazonaws.com",
     "PassRole+ECS→StealTaskRole", SEVERITY_HIGH,
     "PassRole + ECS RegisterTaskDefinition → Steal Task Role",
     "Malicious task definition runs container code under a high-privilege task role.",
     "Attacker registers a new ECS task definition with a high-priv task execution role. "
     "The malicious container exfiltrates the role's environment credentials."),

    ("ecs:UpdateService", "ecs-tasks.amazonaws.com",
     "PassRole+ECS→UpdateService", SEVERITY_HIGH,
     "PassRole + ECS UpdateService → Inject Malicious Task Into Existing Service",
     "Updating existing ECS service to run malicious task under current task role.",
     "Attacker creates a new malicious task definition and updates an existing ECS service "
     "to use it. The service's high-privilege task role is inherited by the new tasks."),

    ("glue:CreateJob", "glue.amazonaws.com",
     "PassRole+Glue→CodeExec", SEVERITY_HIGH,
     "PassRole + Glue CreateJob → Arbitrary Code Execution as Role",
     "Glue job executes arbitrary Python/Scala as the passed service role.",
     "Attacker creates a Glue job with a high-privilege service role. "
     "The job script executes arbitrary code (credential exfiltration, IAM calls)."),

    ("sagemaker:CreateTrainingJob", "sagemaker.amazonaws.com",
     "PassRole+SageMaker→CodeExec", SEVERITY_HIGH,
     "PassRole + SageMaker CreateTrainingJob → Arbitrary Container Execution",
     "Training container runs attacker code under a high-privilege SageMaker role.",
     "Attacker launches a SageMaker Training Job with a custom Docker container and "
     "a high-privilege execution role. The container runs arbitrary code as that role."),

    ("codebuild:CreateProject", "codebuild.amazonaws.com",
     "PassRole+CodeBuild→ShellExec", SEVERITY_HIGH,
     "PassRole + CodeBuild CreateProject → Shell Execution as Service Role",
     "CodeBuild buildspec executes shell commands as the service role.",
     "Attacker creates a CodeBuild project with a high-priv service role. "
     "The buildspec.yml runs arbitrary shell commands with role credentials in env."),

    ("datapipeline:CreatePipeline", "datapipeline.amazonaws.com",
     "PassRole+DataPipeline→ShellActivity", SEVERITY_MEDIUM,
     "PassRole + Data Pipeline → Shell Activity Execution as Role",
     "Shell command activity in pipeline runs as the passed role.",
     "Attacker creates a Data Pipeline with a high-privilege role and a ShellCommandActivity. "
     "The pipeline executes arbitrary commands under that role's identity."),
]


# =============================================================================
# Public API
# =============================================================================

def detect_chains(
    attacker: Principal,
    actions: frozenset[str],
    acct_id: str,
    sso: bool,
    all_principals: list[Principal],
    all_resources: list[Resource],
    cross_links: list[CrossAccountLink],
    action_cache: dict[str, frozenset[str]],
) -> list[PrivEscChain]:
    """
    Run all chain-detection families for a single attacker principal.
    Returns a list of detected PrivEscChain objects (not deduped — caller dedupes).
    """
    local: list[PrivEscChain] = []

    log.debug("[chains] %s: starting detection families", attacker.arn)

    # Family I — IAM self-modification
    _chain_create_policy_attach_user(attacker, actions, acct_id, sso, local)
    _chain_create_policy_attach_role(attacker, actions, acct_id, all_principals,
                                     action_cache, sso, local)
    log.debug("[chains] %s: family I done (%d chains)", attacker.arn, len(local))

    # Family II — PassRole + compute service
    if _can_do(actions, "iam:PassRole"):
        _chain_passrole_service(attacker, actions, acct_id, sso,
                                all_principals, action_cache, local)
    log.debug("[chains] %s: family II done (%d chains)", attacker.arn, len(local))

    # Family III — Compute credential theft (no PassRole)
    _chain_compute_theft(attacker, actions, acct_id, sso,
                         all_resources, all_principals, action_cache, local)
    log.debug("[chains] %s: family III done (%d chains)", attacker.arn, len(local))

    # Family IV — Secret exfiltration → credential reuse
    _chain_secret_exfil(attacker, actions, acct_id, sso, all_principals, action_cache, local)
    log.debug("[chains] %s: family IV done (%d chains)", attacker.arn, len(local))

    # Family V — Account takeover
    _chain_account_takeover(attacker, actions, acct_id, sso, all_principals, action_cache, local)
    log.debug("[chains] %s: family V done (%d chains)", attacker.arn, len(local))

    # Family VI — Group membership
    _chain_group_membership(attacker, actions, acct_id, sso, all_principals, action_cache, local)
    log.debug("[chains] %s: family VI done (%d chains)", attacker.arn, len(local))

    # Family VII — Cross-account
    _chain_cross_account(attacker, actions, acct_id, sso,
                         cross_links, all_principals, action_cache, local)
    log.debug("[chains] %s: all families done, total=%d", attacker.arn, len(local))

    return local


# =============================================================================
# Family I — IAM Self-Modification
# =============================================================================

def _chain_create_policy_attach_user(
    attacker: Principal, actions: frozenset[str], acct_id: str, sso: bool,
    chains: list[PrivEscChain],
) -> None:
    if not (_can_do(actions, "iam:CreatePolicy") and _can_do(actions, "iam:AttachUserPolicy")):
        return
    chains.append(PrivEscChain(
        chain_id="CreatePolicy+AttachUserPolicy",
        severity=SEVERITY_CRITICAL,
        title="CreatePolicy + AttachUserPolicy → Self Admin Escalation",
        principal_arn=attacker.arn,
        account_id=acct_id,
        suppressed=sso,
        suppress_reason="AWS SSO managed role" if sso else "",
        outcome="Full administrator access on self or any user",
        steps=[
            ChainStep(_p_node(attacker), _p_label(attacker),
                      "iam:CreatePolicy",
                      "New managed policy (Action: *, Resource: *)",
                      "Attacker creates a new managed policy granting full admin access."),
            ChainStep(_p_node(attacker), _p_label(attacker),
                      "iam:AttachUserPolicy",
                      attacker.arn,
                      "Attacker attaches the new admin policy to themselves (or any IAM user)."),
        ],
    ))


def _chain_create_policy_attach_role(
    attacker: Principal, actions: frozenset[str], acct_id: str,
    all_principals: list[Principal],
    action_cache: dict[str, frozenset[str]],
    sso: bool,
    chains: list[PrivEscChain],
) -> None:
    if not (_can_do(actions, "iam:CreatePolicy") and _can_do(actions, "iam:AttachRolePolicy")):
        return
    chains.append(PrivEscChain(
        chain_id="CreatePolicy+AttachRolePolicy",
        severity=SEVERITY_CRITICAL,
        title="CreatePolicy + AttachRolePolicy → Role Privilege Escalation",
        principal_arn=attacker.arn,
        account_id=acct_id,
        suppressed=sso,
        suppress_reason="AWS SSO managed role" if sso else "",
        outcome="Full admin access via any assumable role",
        steps=[
            ChainStep(_p_node(attacker), _p_label(attacker),
                      "iam:CreatePolicy",
                      "New managed policy (Action: *, Resource: *)",
                      "Attacker creates an admin managed policy."),
            ChainStep(_p_node(attacker), _p_label(attacker),
                      "iam:AttachRolePolicy",
                      "Any IAM role",
                      "Attacker attaches admin policy to a role they can assume, "
                      "then assumes that role."),
        ],
    ))


# =============================================================================
# Family II — PassRole + Compute Service
# =============================================================================

def _chain_passrole_service(
    attacker: Principal, actions: frozenset[str], acct_id: str, sso: bool,
    all_principals: list[Principal],
    action_cache: dict[str, frozenset[str]],
    chains: list[PrivEscChain],
) -> None:
    for (svc_action, svc_principal, chain_id, severity,
         title, step2_explanation, step3_explanation) in _PASSROLE_SERVICE_CHAINS:
        if not _can_do(actions, svc_action):
            continue

        trusted_roles = _roles_trusting_service(all_principals, svc_principal, action_cache)
        if not trusted_roles:
            chains.append(PrivEscChain(
                chain_id=chain_id,
                severity=SEVERITY_HIGH if severity == SEVERITY_CRITICAL else severity,
                title=title,
                principal_arn=attacker.arn,
                account_id=acct_id,
                suppressed=sso,
                suppress_reason="AWS SSO managed role" if sso else "",
                outcome=step2_explanation,
                steps=[
                    ChainStep(_p_node(attacker), _p_label(attacker),
                              "iam:PassRole", svc_principal,
                              f"Attacker can pass any role to {svc_principal}."),
                    ChainStep(_p_node(attacker), _p_label(attacker),
                              svc_action, svc_principal,
                              step3_explanation),
                ],
            ))
            continue

        for role, role_actions in trusted_roles:
            if not _is_dangerous(role_actions):
                continue
            chains.append(PrivEscChain(
                chain_id=chain_id,
                severity=severity,
                title=title,
                principal_arn=attacker.arn,
                account_id=acct_id,
                suppressed=sso,
                suppress_reason="AWS SSO managed role" if sso else "",
                outcome=step2_explanation,
                steps=[
                    ChainStep(_p_node(attacker), _p_label(attacker),
                              "iam:PassRole", role.arn,
                              f"Attacker passes role '{role.name}' (which has dangerous "
                              f"permissions) to {svc_principal}."),
                    ChainStep(_p_node(attacker), _p_label(attacker),
                              svc_action, svc_principal,
                              step3_explanation),
                    ChainStep(f"service:{svc_principal}", svc_principal,
                              "executes as", role.arn,
                              f"The AWS service executes with '{role.name}' credentials, "
                              "giving attacker full control of that role's permissions."),
                ],
            ))


# =============================================================================
# Family III — Compute Credential Theft
# =============================================================================

def _chain_compute_theft(
    attacker: Principal, actions: frozenset[str], acct_id: str, sso: bool,
    all_resources: list[Resource], all_principals: list[Principal],
    action_cache: dict[str, frozenset[str]],
    chains: list[PrivEscChain],
) -> None:
    high_priv_pairs = _resources_with_high_priv_role(all_resources, all_principals, action_cache)

    if _can_do(actions, "ssm:SendCommand"):
        ec2_pairs = [(r, p) for r, p in high_priv_pairs
                     if r.service == "ec2" and r.resource_type == "instance"]
        for resource, role in ec2_pairs:
            chains.append(PrivEscChain(
                chain_id="SSMSendCommand→StealInstanceRole",
                severity=SEVERITY_HIGH,
                title="SSM SendCommand → Steal EC2 Instance Profile Credentials",
                principal_arn=attacker.arn, account_id=acct_id,
                suppressed=sso, suppress_reason="AWS SSO managed role" if sso else "",
                outcome=f"Credentials of role '{role.name}' stolen via IMDS",
                steps=[
                    ChainStep(_p_node(attacker), _p_label(attacker),
                              "ssm:SendCommand", resource.arn,
                              "Attacker sends an SSM RunCommand document to the EC2 instance."),
                    ChainStep(f"resource:{resource.arn}", resource.name or resource.arn,
                              "executes", "curl http://169.254.169.254/latest/meta-data/iam/",
                              f"Command requests IMDS credentials for instance profile '{role.name}'."),
                    ChainStep(_p_node(role), _p_label(role),
                              "credential reuse", "attacker",
                              f"Attacker receives temporary credentials for '{role.name}' "
                              "and uses them to perform privileged actions."),
                ],
            ))
            break

    if (_can_do(actions, "ec2:ModifyInstanceAttribute")
            and (_can_do(actions, "ec2:StopInstances") or _can_do(actions, "ec2:StartInstances"))):
        ec2_pairs = [(r, p) for r, p in high_priv_pairs
                     if r.service == "ec2" and r.resource_type == "instance"]
        for resource, role in ec2_pairs:
            chains.append(PrivEscChain(
                chain_id="EC2ModifyUserData→StealRole",
                severity=SEVERITY_HIGH,
                title="EC2 ModifyInstanceAttribute → Inject UserData → Steal Instance Profile",
                principal_arn=attacker.arn, account_id=acct_id,
                suppressed=sso, suppress_reason="AWS SSO managed role" if sso else "",
                outcome=f"Credentials of role '{role.name}' stolen after instance restart",
                steps=[
                    ChainStep(_p_node(attacker), _p_label(attacker),
                              "ec2:StopInstances", resource.arn,
                              "Attacker stops the target EC2 instance."),
                    ChainStep(_p_node(attacker), _p_label(attacker),
                              "ec2:ModifyInstanceAttribute (UserData)", resource.arn,
                              "Attacker replaces UserData with a script that "
                              "exfiltrates IMDS credentials on boot."),
                    ChainStep(_p_node(attacker), _p_label(attacker),
                              "ec2:StartInstances", resource.arn,
                              "On restart, the malicious UserData script runs as root "
                              f"and exfiltrates '{role.name}' credentials."),
                ],
            ))
            break

    if _can_do(actions, "lambda:UpdateFunctionCode"):
        lambda_pairs = [(r, p) for r, p in high_priv_pairs
                        if r.service == "lambda" and r.resource_type == "function"]
        for resource, role in lambda_pairs:
            chains.append(PrivEscChain(
                chain_id="Lambda:UpdateCode→StealExecRole",
                severity=SEVERITY_HIGH,
                title="Lambda UpdateFunctionCode → Steal Execution Role Credentials",
                principal_arn=attacker.arn, account_id=acct_id,
                suppressed=sso, suppress_reason="AWS SSO managed role" if sso else "",
                outcome=f"Credentials of role '{role.name}' stolen via Lambda env",
                steps=[
                    ChainStep(_p_node(attacker), _p_label(attacker),
                              "lambda:UpdateFunctionCode", resource.arn,
                              f"Attacker overwrites function '{resource.name or resource.arn}' "
                              "with code that exfiltrates environment credentials."),
                    ChainStep(f"resource:{resource.arn}", resource.name or resource.arn,
                              "exposes", role.arn,
                              f"Lambda execution role '{role.name}' credentials are "
                              "available as env vars (AWS_ACCESS_KEY_ID, etc.)."),
                ],
            ))
            break

    if (_can_do(actions, "ecs:UpdateService") and _can_do(actions, "ecs:RegisterTaskDefinition")):
        ecs_pairs = [(r, p) for r, p in high_priv_pairs if r.service == "ecs"]
        for resource, role in ecs_pairs:
            chains.append(PrivEscChain(
                chain_id="ECS:UpdateService→StealTaskRole",
                severity=SEVERITY_HIGH,
                title="ECS UpdateService → Inject Malicious Task → Steal Task Role",
                principal_arn=attacker.arn, account_id=acct_id,
                suppressed=sso, suppress_reason="AWS SSO managed role" if sso else "",
                outcome=f"Credentials of role '{role.name}' stolen via ECS task",
                steps=[
                    ChainStep(_p_node(attacker), _p_label(attacker),
                              "ecs:RegisterTaskDefinition",
                              f"ecs-tasks.amazonaws.com / {role.arn}",
                              "Attacker registers a new task definition with a malicious "
                              "container image and the existing high-privilege task role."),
                    ChainStep(_p_node(attacker), _p_label(attacker),
                              "ecs:UpdateService", resource.arn,
                              "Attacker updates the existing ECS service to use "
                              "the new malicious task definition."),
                    ChainStep(f"resource:{resource.arn}", resource.name or resource.arn,
                              "container credential exfil", role.arn,
                              f"New container runs as '{role.name}', "
                              "exfiltrating credentials from the task metadata endpoint."),
                ],
            ))
            break


# =============================================================================
# Family IV — Secret Exfiltration → Credential Reuse
# =============================================================================

def _chain_secret_exfil(
    attacker: Principal, actions: frozenset[str], acct_id: str, sso: bool,
    all_principals: list[Principal],
    action_cache: dict[str, frozenset[str]],
    chains: list[PrivEscChain],
) -> None:
    has_dangerous_role = any(
        _is_dangerous(action_cache.get(p.arn, frozenset()))
        for p in all_principals
        if p.account and (p.account.account_id == acct_id)
    )
    severity = SEVERITY_HIGH if has_dangerous_role else SEVERITY_MEDIUM

    if _can_do(actions, "secretsmanager:GetSecretValue"):
        chains.append(PrivEscChain(
            chain_id="SecretsManager→IAMKeyReuse",
            severity=severity,
            title="SecretsManager GetSecretValue → IAM Credential Reuse",
            principal_arn=attacker.arn, account_id=acct_id,
            suppressed=sso, suppress_reason="AWS SSO managed role" if sso else "",
            outcome="Attacker reuses IAM keys found in secrets to act as a higher-privilege identity",
            steps=[
                ChainStep(_p_node(attacker), _p_label(attacker),
                          "secretsmanager:GetSecretValue", "arn:aws:secretsmanager:*",
                          "Attacker reads all secrets. Secrets frequently store IAM access keys, "
                          "database passwords, or third-party API tokens."),
                ChainStep("secret_store", "AWS Secrets Manager",
                          "returns", "IAM AccessKeyId + SecretAccessKey",
                          "If any secret contains IAM credentials, attacker can call AWS APIs "
                          "as the associated higher-privilege identity."),
            ],
        ))

    if _can_do(actions, "ssm:GetParameter") or _can_do(actions, "ssm:GetParameters"):
        chains.append(PrivEscChain(
            chain_id="SSMParameter→IAMKeyReuse",
            severity=severity,
            title="SSM GetParameter → IAM Credential Reuse via SecureString",
            principal_arn=attacker.arn, account_id=acct_id,
            suppressed=sso, suppress_reason="AWS SSO managed role" if sso else "",
            outcome="IAM keys or passwords stored in SecureString parameters reused for escalation",
            steps=[
                ChainStep(_p_node(attacker), _p_label(attacker),
                          "ssm:GetParameter", "arn:aws:ssm:*:*:parameter/*",
                          "Attacker reads SecureString SSM parameters, which commonly "
                          "store IAM access keys, database passwords, or API tokens."),
                ChainStep("param_store", "AWS SSM Parameter Store",
                          "returns", "Credential value",
                          "If any SecureString contains IAM credentials, attacker "
                          "uses them to authenticate as a higher-privilege identity."),
            ],
        ))

    if _can_do(actions, "lambda:GetFunction"):
        chains.append(PrivEscChain(
            chain_id="Lambda:GetFunction→EnvSecrets",
            severity=SEVERITY_MEDIUM,
            title="Lambda GetFunction → Harvest Hardcoded Credentials from Env Vars",
            principal_arn=attacker.arn, account_id=acct_id,
            suppressed=sso, suppress_reason="AWS SSO managed role" if sso else "",
            outcome="Hardcoded IAM keys or DB passwords found in Lambda env vars reused",
            steps=[
                ChainStep(_p_node(attacker), _p_label(attacker),
                          "lambda:GetFunction", "arn:aws:lambda:*",
                          "Attacker retrieves Lambda function configuration, including "
                          "all environment variables."),
                ChainStep("lambda_config", "Lambda Function Config",
                          "exposes", "Environment Variables",
                          "Environment variables frequently contain hardcoded IAM keys, "
                          "DB connection strings, and API tokens that can be reused."),
            ],
        ))

    if _can_do(actions, "s3:GetObject"):
        chains.append(PrivEscChain(
            chain_id="S3:GetObject→CredFile",
            severity=SEVERITY_MEDIUM,
            title="S3 GetObject (Wildcard) → Credential File Exfiltration",
            principal_arn=attacker.arn, account_id=acct_id,
            suppressed=sso, suppress_reason="AWS SSO managed role" if sso else "",
            outcome="IAM credentials, SSH keys, or Terraform state files found in S3 reused",
            steps=[
                ChainStep(_p_node(attacker), _p_label(attacker),
                          "s3:GetObject", "arn:aws:s3:::*",
                          "Attacker reads objects from all accessible S3 buckets. "
                          "Common targets include .aws/credentials, id_rsa, terraform.tfstate."),
                ChainStep("s3_bucket", "S3 Bucket",
                          "returns", "Credential artifacts",
                          "Any found IAM keys, SSH private keys, or cloud credentials "
                          "are used to authenticate as a higher-privilege identity."),
            ],
        ))


# =============================================================================
# Family V — Account Takeover
# =============================================================================

def _chain_account_takeover(
    attacker: Principal, actions: frozenset[str], acct_id: str, sso: bool,
    all_principals: list[Principal],
    action_cache: dict[str, frozenset[str]],
    chains: list[PrivEscChain],
) -> None:
    admin_users = [
        p for p in all_principals
        if p.principal_type == "user"
        and _is_dangerous(action_cache.get(p.arn, frozenset()))
        and p.arn != attacker.arn
    ]
    target_user  = admin_users[0] if admin_users else None
    target_label = target_user.name if target_user else "any admin IAM user"
    target_arn   = target_user.arn  if target_user else "arn:aws:iam::*:user/admin"

    if _can_do(actions, "iam:UpdateLoginProfile"):
        chains.append(PrivEscChain(
            chain_id="UpdateLoginProfile→ConsoleTakeover",
            severity=SEVERITY_CRITICAL,
            title="UpdateLoginProfile → Console Takeover of Admin User",
            principal_arn=attacker.arn, account_id=acct_id,
            suppressed=sso, suppress_reason="AWS SSO managed role" if sso else "",
            outcome=f"Full AWS Console access as '{target_label}'",
            steps=[
                ChainStep(_p_node(attacker), _p_label(attacker),
                          "iam:UpdateLoginProfile", target_arn,
                          f"Attacker changes the console password for '{target_label}'."),
                ChainStep("aws_console", "AWS Management Console",
                          "login as", target_arn,
                          "Attacker logs into the AWS Console using the new password, "
                          "gaining full access to all services the admin user can access."),
            ],
        ))

    if (_can_do(actions, "iam:DeactivateMFADevice")
            and _can_do(actions, "iam:UpdateLoginProfile")):
        chains.append(PrivEscChain(
            chain_id="MFABypass+UpdateLogin→Takeover",
            severity=SEVERITY_CRITICAL,
            title="MFA Bypass + UpdateLoginProfile → Admin Console Takeover Without MFA",
            principal_arn=attacker.arn, account_id=acct_id,
            suppressed=sso, suppress_reason="AWS SSO managed role" if sso else "",
            outcome=f"Console access as '{target_label}' with MFA removed",
            steps=[
                ChainStep(_p_node(attacker), _p_label(attacker),
                          "iam:DeactivateMFADevice", target_arn,
                          f"Attacker deactivates MFA for '{target_label}'."),
                ChainStep(_p_node(attacker), _p_label(attacker),
                          "iam:UpdateLoginProfile", target_arn,
                          "Attacker sets a new console password."),
                ChainStep("aws_console", "AWS Management Console",
                          "login as", target_arn,
                          "Attacker logs in without MFA prompt — full console access."),
            ],
        ))

    if _can_do(actions, "iam:CreateAccessKey"):
        chains.append(PrivEscChain(
            chain_id="CreateAccessKey→PersistentAdmin",
            severity=SEVERITY_CRITICAL,
            title="CreateAccessKey → Persistent Programmatic Admin Access",
            principal_arn=attacker.arn, account_id=acct_id,
            suppressed=sso, suppress_reason="AWS SSO managed role" if sso else "",
            outcome=f"Persistent AWS CLI/SDK access as '{target_label}'",
            steps=[
                ChainStep(_p_node(attacker), _p_label(attacker),
                          "iam:CreateAccessKey", target_arn,
                          f"Attacker generates a new access key pair for '{target_label}'."),
                ChainStep("aws_api", "AWS API",
                          "authenticate as", target_arn,
                          "Attacker uses the new key pair to authenticate as the admin user. "
                          "Access persists until the key is manually revoked."),
            ],
        ))

    if _can_do(actions, "iam:UpdateAssumeRolePolicy") and _can_do(actions, "sts:AssumeRole"):
        high_priv_roles = [
            p for p in all_principals
            if p.principal_type == "role"
            and _is_dangerous(action_cache.get(p.arn, frozenset()))
            and p.arn != attacker.arn
        ]
        target_role    = high_priv_roles[0] if high_priv_roles else None
        target_r_arn   = target_role.arn  if target_role else "arn:aws:iam::*:role/admin"
        target_r_label = target_role.name if target_role else "any high-priv role"
        chains.append(PrivEscChain(
            chain_id="UpdateAssumeRole+AssumeRole→Takeover",
            severity=SEVERITY_CRITICAL,
            title="UpdateAssumeRolePolicy + AssumeRole → High-Privilege Role Takeover",
            principal_arn=attacker.arn, account_id=acct_id,
            suppressed=sso, suppress_reason="AWS SSO managed role" if sso else "",
            outcome=f"Assumes role '{target_r_label}' with full privileges",
            steps=[
                ChainStep(_p_node(attacker), _p_label(attacker),
                          "iam:UpdateAssumeRolePolicy", target_r_arn,
                          f"Attacker modifies the trust policy of '{target_r_label}' "
                          "to add attacker's own ARN as a trusted principal."),
                ChainStep(_p_node(attacker), _p_label(attacker),
                          "sts:AssumeRole", target_r_arn,
                          f"Attacker assumes '{target_r_label}', gaining all its permissions."),
            ],
        ))


# =============================================================================
# Family VI — Group Membership
# =============================================================================

def _chain_group_membership(
    attacker: Principal, actions: frozenset[str], acct_id: str, sso: bool,
    all_principals: list[Principal],
    action_cache: dict[str, frozenset[str]],
    chains: list[PrivEscChain],
) -> None:
    if _can_do(actions, "iam:AddUserToGroup"):
        chains.append(PrivEscChain(
            chain_id="AddUserToGroup→GroupPrivEsc",
            severity=SEVERITY_HIGH,
            title="AddUserToGroup → Join High-Privilege Group",
            principal_arn=attacker.arn, account_id=acct_id,
            suppressed=sso, suppress_reason="AWS SSO managed role" if sso else "",
            outcome="Inherits all permissions of a highly-privileged IAM group",
            steps=[
                ChainStep(_p_node(attacker), _p_label(attacker),
                          "iam:AddUserToGroup", "Any privileged IAM group",
                          "Attacker adds their own IAM user to any group with AdministratorAccess "
                          "or other high-privilege policies attached."),
                ChainStep("iam_group", "Privileged IAM Group",
                          "grants", "Group's policy permissions",
                          "Attacker immediately inherits all the group's permission policies."),
            ],
        ))

    if _can_do(actions, "iam:PutGroupPolicy") and _can_do(actions, "iam:AddUserToGroup"):
        chains.append(PrivEscChain(
            chain_id="PutGroupPolicy+AddUser→SelfEscalation",
            severity=SEVERITY_CRITICAL,
            title="PutGroupPolicy + AddUserToGroup → Self-Escalation via Group",
            principal_arn=attacker.arn, account_id=acct_id,
            suppressed=sso, suppress_reason="AWS SSO managed role" if sso else "",
            outcome="Full admin access via attacker-controlled group",
            steps=[
                ChainStep(_p_node(attacker), _p_label(attacker),
                          "iam:PutGroupPolicy", "Any IAM group",
                          "Attacker writes an inline policy granting full admin access (*) "
                          "to any IAM group."),
                ChainStep(_p_node(attacker), _p_label(attacker),
                          "iam:AddUserToGroup", "That group",
                          "Attacker adds themselves to the modified group, "
                          "inheriting the newly injected admin policy."),
            ],
        ))


# =============================================================================
# Family VII — Cross-Account Lateral Movement
# =============================================================================

def _chain_cross_account(
    attacker: Principal, actions: frozenset[str], acct_id: str, sso: bool,
    cross_links: list[CrossAccountLink], all_principals: list[Principal],
    action_cache: dict[str, frozenset[str]],
    chains: list[PrivEscChain],
) -> None:
    principal_map = {p.arn: p for p in all_principals}

    for link in cross_links:
        src_acct = link.source_account.account_id if link.source_account else None
        if src_acct != acct_id:
            continue

        role = principal_map.get(link.role_arn)
        if not role:
            continue

        role_actions = action_cache.get(role.arn, frozenset())
        if not _is_dangerous(role_actions):
            continue

        tgt_acct_id = link.target_account.account_id if link.target_account else "?"
        if link.is_wildcard:
            chains.append(PrivEscChain(
                chain_id="WildcardTrust→AnyPrincipalAssume",
                severity=SEVERITY_CRITICAL,
                title="Wildcard Trust → Any Principal Assumes High-Privilege Cross-Account Role",
                principal_arn=attacker.arn, account_id=acct_id,
                suppressed=sso, suppress_reason="AWS SSO managed role" if sso else "",
                outcome=f"Attacker assumes '{role.name}' in account {tgt_acct_id}",
                steps=[
                    ChainStep(_p_node(attacker), _p_label(attacker),
                              "sts:AssumeRole", link.role_arn,
                              f"Role '{role.name}' has Principal: * in its trust policy — "
                              "any AWS principal can assume it."),
                    ChainStep(_p_node(role), _p_label(role),
                              "grants", "Dangerous permissions",
                              f"'{role.name}' has dangerous permissions: "
                              + ", ".join(list(role_actions)[:5])),
                ],
            ))
        else:
            chains.append(PrivEscChain(
                chain_id="CrossAccount→DangerousRole",
                severity=SEVERITY_CRITICAL,
                title="Cross-Account Trust to High-Privilege Role → Lateral Movement + Escalation",
                principal_arn=attacker.arn, account_id=acct_id,
                suppressed=sso, suppress_reason="AWS SSO managed role" if sso else "",
                outcome=f"Lateral movement into account {tgt_acct_id} "
                        f"with role '{role.name}' privileges",
                steps=[
                    ChainStep(_p_node(attacker), _p_label(attacker),
                              "sts:AssumeRole", link.role_arn,
                              f"Cross-account trust link allows principals from account "
                              f"'{acct_id}' to assume role '{role.name}' in another account."),
                    ChainStep(_p_node(role), _p_label(role),
                              "grants", "Dangerous permissions",
                              f"'{role.name}' has dangerous permissions enabling further "
                              "escalation within the target account."),
                ],
            ))


# =============================================================================
# PRIV-ESC FINDINGS — single-hop detection (PrivEscFinding dataclass + checkers)
# =============================================================================

from dataclasses import dataclass as _dataclass, field as _field

# ── Categories ────────────────────────────────────────────────────────────────
CATEGORY_PRIV_ESC_PATH    = "PRIV_ESC_PATH"
CATEGORY_RISK_PERMISSION  = "RISK_PERMISSION"
CATEGORY_WILDCARD_TRUST   = "WILDCARD_TRUST"
CATEGORY_ADMIN_ACCESS     = "ADMIN_ACCESS"
CATEGORY_MISCONFIGURATION = "MISCONFIGURATION"


@_dataclass
class PrivEscFinding:
    severity: str
    path: str
    principal_arn: str
    account_id: str
    description: str
    category: str = CATEGORY_RISK_PERMISSION
    details: dict = _field(default_factory=dict)
    suppressed: bool = False
    suppress_reason: str = ""


# ── Internal helpers ──────────────────────────────────────────────────────────

def _emit(findings: list, f: PrivEscFinding) -> None:
    findings.append(f)


def _sort_and_dedup(findings: list) -> list:
    order = {SEVERITY_CRITICAL: 0, SEVERITY_HIGH: 1, SEVERITY_MEDIUM: 2}
    seen: set = set()
    unique = []
    for f in findings:
        key = f"{f.path}:{f.principal_arn}"
        if key not in seen:
            seen.add(key)
            unique.append(f)
    unique.sort(key=lambda f: order.get(f.severity, 99))
    return unique


def _simple(
    findings: list,
    p,
    acct_id: str,
    sso: bool,
    actions,
    *,
    required: list,
    path: str,
    severity: str,
    description: str,
    category: str = CATEGORY_RISK_PERMISSION,
) -> None:
    """Emit a PrivEscFinding if ALL required actions are accessible."""
    if all(_can_do(actions, a) for a in required):
        _emit(findings, PrivEscFinding(
            severity=severity, path=path,
            principal_arn=p.arn, account_id=acct_id,
            description=description, category=category,
            details={"permissions": required},
            suppressed=sso,
            suppress_reason="AWS SSO managed role" if sso else "",
        ))


def _combo(
    findings: list,
    p,
    acct_id: str,
    sso: bool,
    actions,
    *,
    path: str,
    severity: str,
    required_extra: list,
    description: str,
    extra_detail: dict | None = None,
    require_all: bool = True,
) -> None:
    """Emit a PassRole-combo PrivEscFinding."""
    match = (
        all(_can_do(actions, a) for a in required_extra)
        if require_all
        else any(_can_do(actions, a) for a in required_extra)
    )
    if match:
        detail: dict = {"permissions": ["iam:PassRole"] + required_extra}
        if extra_detail:
            detail.update(extra_detail)
        _emit(findings, PrivEscFinding(
            severity=severity, path=path,
            principal_arn=p.arn, account_id=acct_id,
            description=description,
            category=CATEGORY_RISK_PERMISSION,
            details=detail,
            suppressed=sso,
            suppress_reason="AWS SSO managed role" if sso else "",
        ))


def _check_wildcard_trust(p, findings: list) -> None:
    """Emit WILDCARD_TRUST finding if the role trusts Principal: '*'."""
    from worstassume.core.iam_actions import is_sso_managed
    if p.principal_type != "role":
        return
    trust = p.trust_policy
    if not trust:
        return
    stmts = trust.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for stmt in stmts:
        if not isinstance(stmt, dict):
            continue
        principal_val = stmt.get("Principal")
        is_wildcard = (
            principal_val == "*"
            or (isinstance(principal_val, dict) and principal_val.get("AWS") == "*")
        )
        if is_wildcard and stmt.get("Effect") == "Allow":
            acct_id = p.account.account_id if p.account else ""
            sso = is_sso_managed(p.arn)
            _emit(findings, PrivEscFinding(
                severity=SEVERITY_CRITICAL,
                path="WildcardTrustPrincipal",
                principal_arn=p.arn,
                account_id=acct_id,
                description=(
                    "This role's trust policy allows any principal (*) to assume it. "
                    "Any AWS principal in any account can call sts:AssumeRole on this role."
                ),
                category=CATEGORY_WILDCARD_TRUST,
                details={"action": stmt.get("Action", "sts:AssumeRole")},
                suppressed=sso,
                suppress_reason="AWS SSO managed role" if sso else "",
            ))
            return


# ── Family checkers ───────────────────────────────────────────────────────────

def _check_admin_access(p, actions, acct_id: str, sso: bool, findings: list) -> None:
    is_admin = (
        _can_do(actions, "*")
        or any("AdministratorAccess" in (pol.name or "") for pol in p.policies)
    )
    if is_admin:
        _emit(findings, PrivEscFinding(
            severity=SEVERITY_CRITICAL,
            path="AdministratorAccess",
            principal_arn=p.arn,
            account_id=acct_id,
            description=(
                "Principal has full administrator access (* on all resources). "
                "If this is an AWS SSO managed role, this may be intentional."
            ),
            category=CATEGORY_ADMIN_ACCESS,
            details={"is_sso_managed": sso},
            suppressed=sso,
            suppress_reason="AWS SSO managed role — admin access is expected" if sso else "",
        ))


def _check_finding_family_a(p, actions, acct_id: str, sso: bool, findings: list) -> None:
    """Family A — IAM Policy Manipulation."""
    _simple(findings, p, acct_id, sso, actions,
        required=["iam:CreatePolicyVersion"], path="CreatePolicyVersion",
        severity=SEVERITY_CRITICAL,
        description=(
            "Principal can create a new managed policy version with AdministratorAccess "
            "on any managed policy it can access."
        ),
    )
    _simple(findings, p, acct_id, sso, actions,
        required=["iam:SetDefaultPolicyVersion"], path="SetDefaultPolicyVersion",
        severity=SEVERITY_CRITICAL,
        description=(
            "Principal can activate any existing (dormant) policy version. If a "
            "higher-privilege version exists, activating it escalates permissions."
        ),
    )
    _simple(findings, p, acct_id, sso, actions,
        required=["iam:AttachUserPolicy"], path="AttachUserPolicy",
        severity=SEVERITY_CRITICAL,
        description=(
            "Principal can attach arbitrary managed policies (including AdministratorAccess) "
            "to any IAM user, including itself."
        ),
    )
    _simple(findings, p, acct_id, sso, actions,
        required=["iam:AttachRolePolicy"], path="AttachRolePolicy",
        severity=SEVERITY_CRITICAL,
        description=(
            "Principal can attach arbitrary managed policies (including AdministratorAccess) "
            "to any IAM role."
        ),
    )
    _simple(findings, p, acct_id, sso, actions,
        required=["iam:AttachGroupPolicy"], path="AttachGroupPolicy",
        severity=SEVERITY_CRITICAL,
        description=(
            "Principal can attach arbitrary managed policies to any IAM group. "
            "If the attacker is a member of a target group, this grants self-escalation."
        ),
    )
    _simple(findings, p, acct_id, sso, actions,
        required=["iam:PutUserPolicy"], path="PutUserPolicy",
        severity=SEVERITY_CRITICAL,
        description=(
            "Principal can write an inline policy directly to any IAM user, "
            "including granting that user full administrator access."
        ),
    )
    _simple(findings, p, acct_id, sso, actions,
        required=["iam:PutRolePolicy"], path="PutRolePolicy",
        severity=SEVERITY_CRITICAL,
        description=(
            "Principal can write an inline policy directly to any IAM role, "
            "granting that role arbitrary permissions — including AdministratorAccess."
        ),
    )
    _simple(findings, p, acct_id, sso, actions,
        required=["iam:PutGroupPolicy"], path="PutGroupPolicy",
        severity=SEVERITY_CRITICAL,
        description=(
            "Principal can write an inline policy directly to any IAM group. "
            "Combined with group membership, this enables self-escalation."
        ),
    )
    _simple(findings, p, acct_id, sso, actions,
        required=["iam:CreatePolicy"], path="CreatePolicy",
        severity=SEVERITY_HIGH,
        description=(
            "Principal can create new managed policies. Combined with any attach-policy "
            "permission, this enables full administrator access."
        ),
    )
    _simple(findings, p, acct_id, sso, actions,
        required=["iam:AddUserToGroup"], path="AddUserToGroup",
        severity=SEVERITY_HIGH,
        description=(
            "Principal can add any user to any IAM group. Adding itself to a "
            "highly-privileged group is a direct privilege escalation."
        ),
    )


def _check_finding_family_b(p, actions, acct_id: str, sso: bool, findings: list) -> None:
    """Family B — Role Trust / Assumption Manipulation."""
    _simple(findings, p, acct_id, sso, actions,
        required=["iam:UpdateAssumeRolePolicy"], path="UpdateAssumeRolePolicy",
        severity=SEVERITY_CRITICAL,
        description=(
            "Principal can modify any role's trust policy. An attacker adds themselves "
            "as a trusted principal on a high-privilege role, then immediately assumes it."
        ),
    )
    _check_wildcard_trust(p, findings)
    if _can_do(actions, "sts:AssumeRole"):
        _emit(findings, PrivEscFinding(
            severity=SEVERITY_HIGH,
            path="AssumeRoleWildcardResource",
            principal_arn=p.arn, account_id=acct_id,
            description=(
                "Principal has sts:AssumeRole (potentially on Resource: *), enabling "
                "attempts to assume any role whose trust policy permits it. Combined with "
                "UpdateAssumeRolePolicy, this is a full escalation path."
            ),
            category=CATEGORY_RISK_PERMISSION,
            details={"permission": "sts:AssumeRole"},
            suppressed=sso, suppress_reason="AWS SSO managed role" if sso else "",
        ))


def _check_finding_family_c(p, actions, acct_id: str, sso: bool, findings: list) -> None:
    """Family C — Compute: PassRole + Resource Abuse."""
    if not _can_do(actions, "iam:PassRole"):
        return
    _combo(findings, p, acct_id, sso, actions,
        path="PassRole+Lambda:CreateFunction", severity=SEVERITY_CRITICAL,
        required_extra=["lambda:CreateFunction"],
        description=(
            "Principal can create a Lambda function with a high-privilege execution role "
            "and invoke it to steal credentials or perform privileged actions."
        ),
        extra_detail={"trigger": "lambda:InvokeFunction (optional — EventBridge can trigger)"},
    )
    _combo(findings, p, acct_id, sso, actions,
        path="PassRole+Lambda:UpdateFunctionCode", severity=SEVERITY_HIGH,
        required_extra=["lambda:UpdateFunctionCode"],
        description=(
            "Principal can overwrite existing Lambda function code to inherit "
            "its execution role's permissions."
        ),
    )
    _combo(findings, p, acct_id, sso, actions,
        path="PassRole+EC2:RunInstances", severity=SEVERITY_HIGH,
        required_extra=["ec2:RunInstances"],
        description=(
            "Principal can launch an EC2 instance with an instance profile (role) "
            "attached and access credentials from the instance metadata service."
        ),
    )
    _combo(findings, p, acct_id, sso, actions,
        path="PassRole+ECS:RegisterTaskDefinition", severity=SEVERITY_HIGH,
        required_extra=["ecs:RegisterTaskDefinition", "ecs:RunTask"],
        description=(
            "Principal can register a new ECS task definition with a high-privilege "
            "task role and run it to exfiltrate credentials."
        ),
        require_all=False,
    )
    _combo(findings, p, acct_id, sso, actions,
        path="PassRole+ECS:UpdateService", severity=SEVERITY_HIGH,
        required_extra=["ecs:UpdateService"],
        description=(
            "Principal can update an existing ECS service's task definition to inject "
            "malicious code running under a high-privilege task role."
        ),
    )
    _combo(findings, p, acct_id, sso, actions,
        path="PassRole+CloudFormation:CreateStack", severity=SEVERITY_CRITICAL,
        required_extra=["cloudformation:CreateStack"],
        description=(
            "Principal can create a CloudFormation stack with a service role that has "
            "broad permissions. CloudFormation acts as the role, enabling arbitrary "
            "resource creation (including IAM policies)."
        ),
    )
    _combo(findings, p, acct_id, sso, actions,
        path="PassRole+CloudFormation:UpdateStack", severity=SEVERITY_HIGH,
        required_extra=["cloudformation:UpdateStack"],
        description=(
            "Principal can update an existing CloudFormation stack with a new service "
            "role, redirecting stack operations through a high-privilege role."
        ),
    )
    _combo(findings, p, acct_id, sso, actions,
        path="PassRole+Glue:CreateJob", severity=SEVERITY_HIGH,
        required_extra=["glue:CreateJob", "glue:StartJobRun"],
        description=(
            "Principal can create an AWS Glue job with a high-privilege service role "
            "and run arbitrary Python/Scala code under that role's identity."
        ),
        require_all=False,
    )
    _combo(findings, p, acct_id, sso, actions,
        path="PassRole+SageMaker:CreateTrainingJob", severity=SEVERITY_HIGH,
        required_extra=["sagemaker:CreateTrainingJob"],
        description=(
            "Principal can launch a SageMaker Training Job under a high-privilege "
            "execution role, with arbitrary code in the training container."
        ),
    )
    _combo(findings, p, acct_id, sso, actions,
        path="PassRole+CodeBuild:CreateProject", severity=SEVERITY_HIGH,
        required_extra=["codebuild:CreateProject", "codebuild:StartBuild"],
        description=(
            "Principal can create a CodeBuild project with a service role and start a "
            "build that executes arbitrary commands in the role's context."
        ),
        require_all=False,
    )
    _combo(findings, p, acct_id, sso, actions,
        path="PassRole+DataPipeline", severity=SEVERITY_MEDIUM,
        required_extra=["datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition"],
        description=(
            "Principal can create an AWS Data Pipeline with a high-privilege role and "
            "define a shell command activity to exfiltrate credentials."
        ),
        require_all=False,
    )
    _combo(findings, p, acct_id, sso, actions,
        path="PassRole+SSM:SendCommand", severity=SEVERITY_HIGH,
        required_extra=["ssm:SendCommand"],
        description=(
            "Principal can send an SSM Run Command to EC2 instances that have an IAM "
            "instance profile attached, executing arbitrary commands under that role."
        ),
    )


def _check_finding_family_d(p, actions, acct_id: str, sso: bool, findings: list) -> None:
    """Family D — Credential / Key Exfiltration via Data Plane."""
    _simple(findings, p, acct_id, sso, actions,
        required=["ec2:ModifyInstanceAttribute"], path="EC2:ModifyInstanceAttribute",
        severity=SEVERITY_HIGH,
        description=(
            "Principal can modify EC2 instance UserData. After stopping and starting "
            "the instance, arbitrary commands run as root — enabling credential theft "
            "from any attached instance profile."
        ),
    )
    _simple(findings, p, acct_id, sso, actions,
        required=["ssm:SendCommand"], path="SSM:SendCommand",
        severity=SEVERITY_HIGH,
        description=(
            "Principal can send SSM Run Command documents to managed EC2 instances. "
            "This allows arbitrary command execution under the instance's IAM role, "
            "enabling credential theft or lateral movement."
        ),
    )
    _simple(findings, p, acct_id, sso, actions,
        required=["secretsmanager:GetSecretValue"], path="SecretsManager:GetSecretValue",
        severity=SEVERITY_HIGH,
        description=(
            "Principal can retrieve all secrets from AWS Secrets Manager. "
            "Stored database credentials, API keys, or IAM access keys may enable "
            "further privilege escalation."
        ),
    )
    if _can_do(actions, "ssm:GetParameter") or _can_do(actions, "ssm:GetParameters"):
        _emit(findings, PrivEscFinding(
            severity=SEVERITY_MEDIUM, path="SSM:GetParameter",
            principal_arn=p.arn, account_id=acct_id,
            description=(
                "Principal can read SSM Parameter Store values (including SecureString), "
                "which commonly store database passwords, access keys, or API tokens."
            ),
            category=CATEGORY_RISK_PERMISSION,
            details={"permissions": ["ssm:GetParameter", "ssm:GetParameters"]},
            suppressed=sso, suppress_reason="AWS SSO managed role" if sso else "",
        ))
    _simple(findings, p, acct_id, sso, actions,
        required=["lambda:GetFunction"], path="Lambda:GetFunction",
        severity=SEVERITY_MEDIUM,
        description=(
            "Principal can retrieve Lambda function configuration, including environment "
            "variables which frequently contain hardcoded credentials, API keys, or "
            "database passwords."
        ),
    )
    _simple(findings, p, acct_id, sso, actions,
        required=["s3:GetObject"], path="S3:GetObject:Wildcard",
        severity=SEVERITY_MEDIUM,
        description=(
            "Principal has s3:GetObject (potentially on Resource: *). Credential files, "
            "private keys, and configuration files stored in S3 buckets may enable "
            "further privilege escalation."
        ),
    )


def _check_finding_family_e(p, actions, acct_id: str, sso: bool, findings: list) -> None:
    """Family E — Service-Specific Escalation."""
    _simple(findings, p, acct_id, sso, actions,
        required=["iam:UpdateLoginProfile"], path="UpdateLoginProfile",
        severity=SEVERITY_CRITICAL,
        description=(
            "Principal can change the AWS console login profile of any IAM user, "
            "including administrators — enabling full account takeover."
        ),
    )
    _simple(findings, p, acct_id, sso, actions,
        required=["iam:CreateLoginProfile"], path="CreateLoginProfile",
        severity=SEVERITY_HIGH,
        description=(
            "Principal can create a console login for any IAM user that doesn't have one, "
            "enabling console access to high-privilege users."
        ),
    )
    _simple(findings, p, acct_id, sso, actions,
        required=["iam:CreateAccessKey"], path="CreateAccessKey",
        severity=SEVERITY_CRITICAL,
        description=(
            "Principal can generate a new programmatic access key for any IAM user, "
            "including administrators — enabling persistent credential theft."
        ),
    )
    _simple(findings, p, acct_id, sso, actions,
        required=["iam:UpdateAccessKey"], path="UpdateAccessKey",
        severity=SEVERITY_MEDIUM,
        description=(
            "Principal can reactivate disabled access keys for any IAM user, "
            "potentially reactivating previously-revoked administrative credentials."
        ),
    )
    if _can_do(actions, "iam:DeactivateMFADevice") or _can_do(actions, "iam:DeleteVirtualMFADevice"):
        _emit(findings, PrivEscFinding(
            severity=SEVERITY_HIGH, path="MFABypass",
            principal_arn=p.arn, account_id=acct_id,
            description=(
                "Principal can deactivate or delete MFA devices for IAM users. "
                "If combined with UpdateLoginProfile, this allows full console takeover "
                "by removing the MFA requirement from a target user."
            ),
            category=CATEGORY_RISK_PERMISSION,
            details={"permissions": ["iam:DeactivateMFADevice", "iam:DeleteVirtualMFADevice"]},
            suppressed=sso, suppress_reason="AWS SSO managed role" if sso else "",
        ))


def _check_finding_family_f(p, acct_id: str, findings: list) -> None:
    """Family F — Trust Condition Bypass / Weak Conditions."""
    from worstassume.core.iam_actions import _flatten_condition_keys
    if p.principal_type != "role":
        return
    trust = p.trust_policy
    if not trust:
        return
    stmts = trust.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for stmt in stmts:
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue
        principal_val = stmt.get("Principal", {})
        condition = stmt.get("Condition", {})
        is_wildcard_principal = (
            principal_val == "*"
            or (isinstance(principal_val, dict) and principal_val.get("AWS") == "*")
        )
        if is_wildcard_principal:
            continue
        account_arns: list = []
        if isinstance(principal_val, dict):
            aws_val = principal_val.get("AWS", [])
            if isinstance(aws_val, str):
                aws_val = [aws_val]
            account_arns.extend(aws_val)
        elif isinstance(principal_val, str):
            account_arns = [principal_val]
        is_cross_account = any(
            "arn:aws:iam::" in arn and acct_id not in arn
            for arn in account_arns
        )
        if not is_cross_account:
            continue
        if not condition:
            _emit(findings, PrivEscFinding(
                severity=SEVERITY_HIGH, path="TrustPolicyNoCondition",
                principal_arn=p.arn, account_id=acct_id,
                description=(
                    "This role's trust policy allows a cross-account principal to assume "
                    "it without any Condition. There is no ExternalId, MFA, or IP "
                    "restriction — widening the attack surface."
                ),
                category=CATEGORY_MISCONFIGURATION,
                details={"trusted_principals": account_arns},
            ))
            continue
        has_external_id = any(
            "sts:ExternalId" in str(k) for k in _flatten_condition_keys(condition)
        )
        if not has_external_id:
            _emit(findings, PrivEscFinding(
                severity=SEVERITY_HIGH, path="TrustPolicyNoExternalId",
                principal_arn=p.arn, account_id=acct_id,
                description=(
                    "Cross-account role trust is missing sts:ExternalId. Without an "
                    "ExternalId, any principal in the trusted account can assume this role "
                    "(confused deputy attack)."
                ),
                category=CATEGORY_MISCONFIGURATION,
                details={"trusted_principals": account_arns},
            ))
        has_mfa_condition = any(
            "MultiFactorAuthPresent" in str(k) or "MultiFactorAuthAge" in str(k)
            for k in _flatten_condition_keys(condition)
        )
        if not has_mfa_condition:
            _emit(findings, PrivEscFinding(
                severity=SEVERITY_MEDIUM, path="TrustPolicyNoMFARequired",
                principal_arn=p.arn, account_id=acct_id,
                description=(
                    "Cross-account role trust does not require MFA "
                    "(aws:MultiFactorAuthPresent). The role can be assumed without MFA, "
                    "reducing the security bar for assumption."
                ),
                category=CATEGORY_MISCONFIGURATION,
                details={"trusted_principals": account_arns},
            ))


def _check_ec2_imdsv1(resources: list, findings: list) -> None:
    """Flag EC2 instances still allowing IMDSv1 (HttpTokens != 'required')."""
    for r in resources:
        if r.service != "ec2" or r.resource_type != "instance":
            continue
        extra = r.extra or {}
        metadata_options = extra.get("MetadataOptions", {})
        http_tokens = metadata_options.get("HttpTokens", "optional")
        if http_tokens != "required":
            acct_id = r.account.account_id if r.account else "unknown"
            _emit(findings, PrivEscFinding(
                severity=SEVERITY_MEDIUM,
                path="EC2IMDSv1Enabled",
                principal_arn=r.arn,
                account_id=acct_id,
                description=(
                    f"EC2 instance '{r.name or r.arn}' allows IMDSv1 "
                    f"(HttpTokens={http_tokens!r}). An SSRF vulnerability or "
                    "privilege on this instance can be used to steal the attached "
                    "IAM role credentials via http://169.254.169.254/."
                ),
                category=CATEGORY_MISCONFIGURATION,
                details={
                    "instance_arn": r.arn,
                    "instance_name": r.name,
                    "http_tokens": http_tokens,
                    "execution_role_arn": r.execution_role.arn if r.execution_role else None,
                },
            ))


# ── Unified entry point for privilege_escalation.analyze() ────────────────────

def check_all_findings(
    p,
    actions,
    acct_id: str,
    sso: bool,
    findings: list,
) -> None:
    """
    Run all single-hop family checkers (A–F) for one principal.
    Called once per principal inside privilege_escalation.analyze().
    """
    _check_admin_access(p, actions, acct_id, sso, findings)
    _check_finding_family_a(p, actions, acct_id, sso, findings)
    _check_finding_family_b(p, actions, acct_id, sso, findings)
    _check_finding_family_c(p, actions, acct_id, sso, findings)
    _check_finding_family_d(p, actions, acct_id, sso, findings)
    _check_finding_family_e(p, actions, acct_id, sso, findings)
    _check_finding_family_f(p, acct_id, findings)
