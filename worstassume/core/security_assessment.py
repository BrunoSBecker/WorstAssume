"""
Security Assessment Engine — detects IAM misconfigurations and persists findings.

Analysis categories:
  WEAK_TRUST        — Overly permissive trust policies on roles
  PERMISSIVE_POLICY — High-privilege managed/inline policies
  RESOURCE_WILDCARD — Write/admin actions on Resource: *
  USER_CONFIG       — IAM user hygiene (MFA, stale keys, privilege)
  GROUP_CONFIG      — Dangerous group-level permissions
"""

from __future__ import annotations

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from worstassume.db.models import Account, Principal, SecurityFinding
from worstassume.db.store import upsert_security_finding

log = logging.getLogger(__name__)

# ─── Severity helpers ──────────────────────────────────────────────────────────

SEV_ORDER: dict[str, int] = {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4,
}

_SEV_DOWNGRADE_ONE: dict[str, str] = {
    "CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW",
}

# Trust × permission-risk downgrade matrix
_TRUST_DOWNGRADE: dict[tuple[str, str], str] = {
    ("CRITICAL", "MEDIUM"): "HIGH",
    ("CRITICAL", "LOW"):    "MEDIUM",
    ("HIGH",     "LOW"):    "MEDIUM",
}

# ─── Trust policy constants ────────────────────────────────────────────────────

PRINCIPAL_RESTRICTING_KEYS: frozenset[str] = frozenset({
    "aws:principalorgid",
    "aws:principalorgpaths",
    "aws:principalaccount",
    "aws:principalarn",
    "aws:principaltag",
    "sts:externalid",
    "aws:principaltype",
    "aws:userid",
})

# Broad service principals and their default severity + rationale
BROAD_SERVICES: dict[str, tuple[str, str]] = {
    "sts.amazonaws.com":          ("CRITICAL", "STS itself can assume this role — any identity with sts:AssumeRole can leverage this"),
    "ssm.amazonaws.com":          ("HIGH",     "SSM can assume this role — enables lateral movement via Run Command and Session Manager"),
    "ec2.amazonaws.com":          ("MEDIUM",   "All EC2 instance profiles can assume this role"),
    "lambda.amazonaws.com":       ("MEDIUM",   "All Lambda functions can assume this role"),
    "ecs-tasks.amazonaws.com":    ("MEDIUM",   "All ECS tasks can assume this role"),
    "sagemaker.amazonaws.com":    ("MEDIUM",   "All SageMaker jobs can assume this role"),
    "glue.amazonaws.com":         ("MEDIUM",   "All Glue jobs can assume this role"),
    "states.amazonaws.com":       ("MEDIUM",   "All Step Functions state machines can assume this role"),
    "datapipeline.amazonaws.com": ("MEDIUM",   "All DataPipeline pipelines can assume this role"),
}

# ─── Permission risk constants ─────────────────────────────────────────────────

DANGEROUS_MANAGED: frozenset[str] = frozenset({
    "AdministratorAccess", "PowerUserAccess", "IAMFullAccess",
    "AWSAccountManagementFullAccess", "AWSOrganizationsFullAccess",
})

ELEVATED_MANAGED: frozenset[str] = frozenset({
    "AmazonEC2FullAccess", "AmazonS3FullAccess", "AWSLambda_FullAccess",
    "AWSLambdaFullAccess", "AmazonRDSFullAccess", "AmazonDynamoDBFullAccess",
    "AmazonSQSFullAccess", "AmazonSNSFullAccess", "AWSCodePipelineFullAccess",
    "AWSCodeBuildAdminAccess", "AmazonEKSClusterPolicy", "AmazonSSMFullAccess",
    "SecretsManagerReadWrite", "AWSCloudFormationFullAccess",
    "AWSStepFunctionsFullAccess", "AmazonCognitoPowerUser",
})

# Write/admin verbs that, when allowed on Resource:*, indicate excessive scope
DEFAULT_WRITE_VERBS: frozenset[str] = frozenset({
    # IAM manipulation
    "iam:passrole", "iam:createpolicy", "iam:putrolepolicy",
    "iam:attachuserpolicy", "iam:attachrolepolicy", "iam:attachgrouppolicy",
    "iam:createpolicyversion", "iam:setroledefaultpolicyversion",
    "iam:updateassumerolepolicy",
    # Compute / code execution
    "lambda:invokefunction", "lambda:createfunction", "lambda:updatefunctioncode",
    "lambda:updatefunctionconfiguration", "lambda:addpermission",
    "ec2:runinstances", "glue:createjob", "glue:updatejob",
    "sagemaker:createnotebookinstance", "sagemaker:updatenotebookinstance",
    # Data exfiltration helpers
    "s3:putobject", "s3:deletebucket", "s3:putbucketpolicy",
    "secretsmanager:getsecretvalue",
    "ssm:sendcommand", "ssm:startautomationexecution",
    # Privilege maintenance
    "sts:assumerole",
    # Defensive blinding
    "cloudtrail:stoptail", "cloudtrail:deletetrail",
    "guardduty:deletedetector", "config:deleteconfigrule",
})

# ─── SeverityConfig ───────────────────────────────────────────────────────────


@dataclass
class SeverityConfig:
    """Per-rule severity overrides. Missing keys fall back to the engine default."""

    overrides: dict[str, str] = field(default_factory=dict)

    def resolve(self, path_id: str, default: str) -> str:
        return self.overrides.get(path_id, default)

    @classmethod
    def from_json(cls, path: str) -> "SeverityConfig":
        import json
        with open(path) as f:
            return cls(overrides=json.load(f))

    @classmethod
    def default(cls) -> "SeverityConfig":
        return cls()


# ─── Internal finding dataclass ────────────────────────────────────────────────


@dataclass
class _RawFinding:
    entity_arn:        str
    entity_type:       str   # role / user / group
    entity_name:       str
    category:          str   # WEAK_TRUST / PERMISSIVE_POLICY / RESOURCE_WILDCARD / USER_CONFIG / GROUP_CONFIG
    path_id:           str
    severity:          str
    original_severity: str
    message:           str
    principal_detail:  str | None = None
    condition:         dict | None = None
    perm_risk:         str | None = None
    downgrade_note:    str | None = None
    suppressed:        bool = False


# ─── Utility helpers ───────────────────────────────────────────────────────────


def _normalize_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _is_service_linked_role(p: Principal) -> bool:
    path = p.path or "/"
    return "/aws-service-role/" in path or p.name.startswith("AWSServiceRole")


def _is_restricting_condition(condition: dict | None) -> bool:
    if not condition:
        return False
    for _op, key_values in condition.items():
        if isinstance(key_values, dict):
            for key in key_values:
                if key.lower() in PRINCIPAL_RESTRICTING_KEYS:
                    return True
    return False


def _has_oidc_sub_condition(condition: dict | None) -> bool:
    if not condition:
        return False
    for _op, kvs in condition.items():
        if isinstance(kvs, dict):
            for key in kvs:
                if ":sub" in key.lower() or ":aud" in key.lower():
                    return True
    return False


# ─── Trust policy analysis ────────────────────────────────────────────────────


def _check_principal(
    ptype: str, pvalue: str, condition: dict | None, own_account: str, cfg: SeverityConfig
) -> list[tuple[str, str, str, str | None]]:
    """
    Returns list of (path_id, severity, message, principal_detail).
    """
    results: list[tuple[str, str, str, str | None]] = []
    restricting = _is_restricting_condition(condition)
    pd = f"{ptype}: {pvalue}"

    # 1. Wildcard principal
    if pvalue == "*":
        if not condition:
            pid = "WildcardTrustNoCondition"
            sev = cfg.resolve(pid, "CRITICAL")
            results.append((pid, sev,
                "Wildcard principal '*' with NO condition — anyone on the internet can attempt to assume this role",
                pd))
        elif restricting:
            pid = "WildcardTrustRestrictingCondition"
            sev = cfg.resolve(pid, "MEDIUM")
            results.append((pid, sev,
                "Wildcard principal '*' with principal-restricting condition — verify the condition is sufficiently tight",
                pd))
        else:
            pid = "WildcardTrustNonPrincipalCondition"
            sev = cfg.resolve(pid, "HIGH")
            results.append((pid, sev,
                "Wildcard principal '*' with non-principal condition — condition limits behavior, NOT who can assume the role",
                pd))

    # 2. AWS account / ARN
    elif ptype == "AWS":
        account_root_re = re.compile(r"arn:aws:iam::(\d+):root$")
        specific_re     = re.compile(r"arn:aws:iam::(\d+):(role|user|group)/(.+)$")
        bare_acct_re    = re.compile(r"^\d{12}$")

        m_root     = account_root_re.match(pvalue)
        m_specific = specific_re.match(pvalue)

        if m_root:
            acct = m_root.group(1)
            if acct == own_account:
                pid = "OwnAccountRootTrust"
                sev = cfg.resolve(pid, "INFO" if restricting else "HIGH")
                results.append((pid, sev,
                    f"Own account root trusted: every identity in account {acct} can assume this role "
                    f"{'(condition present)' if condition else '(no condition)'}",
                    pd))
            else:
                pid = "ExternalAccountRootTrust"
                sev = cfg.resolve(pid, "HIGH" if restricting else "CRITICAL")
                results.append((pid, sev,
                    f"External account root trusted: {acct} — entire external account can assume this role "
                    f"{'(condition present)' if condition else '(no condition)'}",
                    pd))

        elif m_specific:
            acct        = m_specific.group(1)
            entity_type = m_specific.group(2)
            entity_name = m_specific.group(3)
            if acct == own_account:
                pid = "OwnAccountSpecificTrust"
                sev = cfg.resolve(pid, "INFO")
                results.append((pid, sev,
                    f"Own-account {entity_type} trusted: {entity_name}",
                    pd))
            else:
                pid = "ExternalAccountSpecificTrust"
                sev = cfg.resolve(pid, "MEDIUM" if restricting else "HIGH")
                results.append((pid, sev,
                    f"External account {entity_type} trusted: {entity_name} in {acct} "
                    f"{'(condition present)' if condition else '(no condition)'}",
                    pd))

        elif bare_acct_re.match(pvalue):
            pid = "BareAccountNumberTrust"
            sev = cfg.resolve(pid, "HIGH")
            results.append((pid, sev,
                f"Bare account number as principal: {pvalue} — equivalent to trusting the entire account",
                pd))

    # 3. Service principals
    elif ptype == "Service":
        if "*" in pvalue:
            pid = "WildcardServicePrincipal"
            sev = cfg.resolve(pid, "CRITICAL")
            results.append((pid, sev, f"Wildcard service principal '{pvalue}'", pd))
        elif pvalue in BROAD_SERVICES:
            default_sev, msg = BROAD_SERVICES[pvalue]
            pid = f"BroadServicePrincipal:{pvalue}"
            if restricting:
                default_sev = _SEV_DOWNGRADE_ONE.get(default_sev, default_sev)
                sev = cfg.resolve(pid, default_sev)
                results.append((pid, sev, f"Service '{pvalue}': {msg} (condition present — downgraded)", pd))
            else:
                sev = cfg.resolve(pid, default_sev)
                results.append((pid, sev, f"Service '{pvalue}': {msg}", pd))

    # 4. Federated principals
    elif ptype == "Federated":
        if pvalue == "*":
            pid = "WildcardFederatedPrincipal"
            sev = cfg.resolve(pid, "CRITICAL")
            results.append((pid, sev,
                "Wildcard federated principal — any federated identity can assume this role", pd))

        elif "cognito-identity.amazonaws.com" in pvalue:
            if not restricting:
                pid = "CognitoTrustNoCondition"
                sev = cfg.resolve(pid, "HIGH")
                results.append((pid, sev,
                    "Cognito federated trust WITHOUT restricting condition — any Cognito identity pool user can assume this role",
                    pd))
            else:
                pid = "CognitoTrustWithCondition"
                sev = cfg.resolve(pid, "MEDIUM")
                results.append((pid, sev,
                    "Cognito federated principal — condition present; verify it restricts sub/aud", pd))

        elif "token.actions.githubusercontent.com" in pvalue:
            if not _has_oidc_sub_condition(condition):
                pid = "GitHubOIDCNoSubCondition"
                sev = cfg.resolve(pid, "HIGH")
                results.append((pid, sev,
                    "GitHub Actions OIDC trust without 'sub'/'aud' condition — any GitHub Actions workflow may assume this role",
                    pd))
            else:
                pid = "GitHubOIDCWithSubCondition"
                sev = cfg.resolve(pid, "INFO")
                results.append((pid, sev,
                    "GitHub Actions OIDC trust — sub/aud condition present; verify it restricts to expected repos/branches",
                    pd))

        elif "oidc-provider" in pvalue or ".amazonaws.com" not in pvalue:
            if not _has_oidc_sub_condition(condition):
                pid = "OIDCTrustNoSubCondition"
                sev = cfg.resolve(pid, "MEDIUM")
                results.append((pid, sev,
                    f"OIDC/Federated principal '{pvalue}' without sub/aud condition — ensure identity is scoped correctly",
                    pd))
            else:
                pid = "OIDCTrustWithSubCondition"
                sev = cfg.resolve(pid, "INFO")
                results.append((pid, sev,
                    f"OIDC/Federated principal '{pvalue}' with sub/aud condition", pd))

    return results


def _check_trust_policy(
    p: Principal, own_account: str, cfg: SeverityConfig
) -> list[_RawFinding]:
    findings: list[_RawFinding] = []
    trust = p.trust_policy
    if not trust:
        return findings
    for stmt in _normalize_list(trust.get("Statement", [])):
        if stmt.get("Effect", "Allow") != "Allow":
            continue
        condition = stmt.get("Condition") or {}
        raw_p = stmt.get("Principal", {})
        if raw_p == "*":
            pairs = [("Wildcard", "*")]
        elif isinstance(raw_p, str):
            pairs = [("Unknown", raw_p)]
        else:
            pairs = []
            for ptype, pvalues in raw_p.items():
                for v in _normalize_list(pvalues):
                    pairs.append((ptype, v))

        for ptype, pvalue in pairs:
            for path_id, sev, msg, pd in _check_principal(ptype, pvalue, condition, own_account, cfg):
                findings.append(_RawFinding(
                    entity_arn=p.arn, entity_type=p.principal_type, entity_name=p.name,
                    category="WEAK_TRUST", path_id=path_id,
                    severity=sev, original_severity=sev,
                    message=msg, principal_detail=pd,
                    condition=condition if condition else None,
                ))
    return findings


# ─── Permission risk assessment ────────────────────────────────────────────────


def _inline_risk(policies) -> tuple[str, str]:
    """Assess inline policies. Returns (risk_level, reason)."""
    risk, reason = "LOW", "read-only or tightly scoped policies"
    for pol in policies:
        doc = pol.document
        if not doc:
            continue
        for stmt in _normalize_list(doc.get("Statement", [])):
            if stmt.get("Effect") != "Allow":
                continue
            actions   = _normalize_list(stmt.get("Action", []))
            resources = _normalize_list(stmt.get("Resource", []))
            if "*" in actions or actions == ["*"]:
                return "HIGH", "wildcard Action (*) in inline policy"
            low = [a.lower() for a in actions]
            if any(a in ("iam:*", "sts:*", "sts:assumerole") for a in low):
                if "*" in resources:
                    return "HIGH", "iam:* or sts:AssumeRole on Resource: *"
            write_kw = ["put", "create", "delete", "update", "invoke",
                        "passrole", "full", "write", "start", "stop"]
            action_str = " ".join(low)
            if "*" in resources and any(kw in action_str for kw in write_kw):
                risk, reason = "MEDIUM", "write actions on wildcard resources (inline)"
    return risk, reason


def _assess_permissions(p: Principal) -> tuple[str, str]:
    """Returns (perm_risk, perm_reason) for a principal's effective policies.

    For users, effective policies include those inherited from group memberships
    (via group_memberships_as_user), consistent with _collect_allowed_actions().
    """
    # Build effective policy list: direct + group-inherited (for users)
    effective_policies = list(p.policies)
    for gm in getattr(p, "group_memberships_as_user", []):
        if gm.group:
            effective_policies.extend(gm.group.policies)

    attached_names = [
        pol.name for pol in effective_policies if pol.policy_type in ("managed", "aws_managed")
    ]
    inline_policies = [pol for pol in effective_policies if pol.policy_type == "inline"]

    for name in attached_names:
        if name in DANGEROUS_MANAGED:
            return "HIGH", f"attached managed policy: {name}"
    for name in attached_names:
        if name in ELEVATED_MANAGED:
            return "MEDIUM", f"attached managed policy: {name}"

    if not effective_policies:
        return "LOW", "no policies attached"

    return _inline_risk(inline_policies)


def _permissive_findings(
    p: Principal, cfg: SeverityConfig
) -> tuple[list[_RawFinding], str, str]:
    """Emit PERMISSIVE_POLICY findings if the principal has HIGH/MEDIUM permission risk.

    Returns:
        (findings, perm_risk, perm_reason) so callers can reuse risk without re-computing.
    """
    perm_risk, perm_reason = _assess_permissions(p)
    findings: list[_RawFinding] = []
    if perm_risk in ("HIGH", "MEDIUM"):
        pid = f"PermissivePolicy:{perm_risk}"
        sev = cfg.resolve(pid, perm_risk)
        findings.append(_RawFinding(
            entity_arn=p.arn, entity_type=p.principal_type, entity_name=p.name,
            category="PERMISSIVE_POLICY", path_id=pid,
            severity=sev, original_severity=sev,
            message=f"Principal has {perm_risk.lower()}-privilege permissions — {perm_reason}",
            perm_risk=perm_risk,
        ))
    return findings, perm_risk, perm_reason


# ─── Resource wildcard detection ────────────────────────────────────────────────


def _check_resource_wildcards(p: Principal, cfg: SeverityConfig) -> list[_RawFinding]:
    """Detect write/admin actions allowed on Resource: * in any attached policy."""
    findings: list[_RawFinding] = []
    seen: set[str] = set()
    for pol in p.policies:
        doc = pol.document
        if not doc:
            continue
        for stmt in _normalize_list(doc.get("Statement", [])):
            if stmt.get("Effect") != "Allow":
                continue
            resources = _normalize_list(stmt.get("Resource", []))
            if "*" not in resources:
                continue
            actions = [a.lower() for a in _normalize_list(stmt.get("Action", []))]
            matched = [a for a in actions if a in DEFAULT_WRITE_VERBS]
            for action in matched:
                path_id = f"ResourceWildcard:{action}"
                if path_id in seen:
                    continue  # one finding per unique action per principal
                seen.add(path_id)
                sev = cfg.resolve(path_id, "MEDIUM")
                findings.append(_RawFinding(
                    entity_arn=p.arn, entity_type=p.principal_type, entity_name=p.name,
                    category="RESOURCE_WILDCARD", path_id=path_id,
                    severity=sev, original_severity=sev,
                    message=f"Policy grants '{action}' on Resource: * — no resource scoping (policy: {pol.name})",
                ))
    return findings


# ─── Per-entity assessors ──────────────────────────────────────────────────────


def _assess_role(p: Principal, own_account: str, cfg: SeverityConfig) -> list[_RawFinding]:
    if _is_service_linked_role(p):
        return []

    trust_findings = _check_trust_policy(p, own_account, cfg)

    # Apply permission-risk downgrade to trust findings
    perm_risk, perm_reason = _assess_permissions(p)
    for f in trust_findings:
        new_sev = _TRUST_DOWNGRADE.get((f.severity, perm_risk), f.severity)
        if new_sev != f.severity:
            f.downgrade_note = (
                f"Downgraded {f.severity}→{new_sev}: role has {perm_risk.lower()} "
                f"permission risk ({perm_reason})"
            )
            f.severity = new_sev
        f.perm_risk = perm_risk

    wildcard_findings = _check_resource_wildcards(p, cfg)
    perm_findings, _, _ = _permissive_findings(p, cfg)

    return trust_findings + wildcard_findings + perm_findings


def _assess_user(p: Principal, cfg: SeverityConfig) -> list[_RawFinding]:
    findings: list[_RawFinding] = []
    perm_risk, perm_reason = _assess_permissions(p)

    # Privilege findings
    if perm_risk in ("HIGH", "MEDIUM"):
        pid = f"UserPrivilege:{perm_risk}"
        sev = cfg.resolve(pid, perm_risk)
        findings.append(_RawFinding(
            entity_arn=p.arn, entity_type="user", entity_name=p.name,
            category="USER_CONFIG", path_id=pid,
            severity=sev, original_severity=sev,
            message=f"User has {perm_risk.lower()}-privilege permissions — {perm_reason}",
            perm_risk=perm_risk,
        ))

    meta = p.extra or {}

    # Console access without MFA
    has_console = bool(meta.get("has_console_access") or meta.get("LoginProfile"))
    has_mfa = bool(meta.get("mfa_enabled") or meta.get("MFADevices"))
    if has_console and not has_mfa:
        pid = "UserConsolNoMFA"
        sev = cfg.resolve(pid, "HIGH" if perm_risk == "HIGH" else "MEDIUM")
        findings.append(_RawFinding(
            entity_arn=p.arn, entity_type="user", entity_name=p.name,
            category="USER_CONFIG", path_id=pid,
            severity=sev, original_severity=sev,
            message="Console access enabled with NO MFA device — account takeover risk",
            perm_risk=perm_risk,
        ))

    # Stale access keys
    for key in _normalize_list(meta.get("AccessKeyMetadata") or meta.get("access_keys") or []):
        if key.get("Status") != "Active":
            continue
        created = key.get("CreateDate", "")
        try:
            dt = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - dt).days
            if age > 365:
                pid = "UserStaleKey365"
                sev = cfg.resolve(pid, "HIGH")
                findings.append(_RawFinding(
                    entity_arn=p.arn, entity_type="user", entity_name=p.name,
                    category="USER_CONFIG", path_id=pid,
                    severity=sev, original_severity=sev,
                    message=f"Access key active for {age} days (>365) — rotate immediately",
                    perm_risk=perm_risk,
                    principal_detail=f"Key ID: {key.get('AccessKeyId', '?')}",
                ))
            elif age > 90:
                pid = "UserStaleKey90"
                sev = cfg.resolve(pid, "MEDIUM")
                findings.append(_RawFinding(
                    entity_arn=p.arn, entity_type="user", entity_name=p.name,
                    category="USER_CONFIG", path_id=pid,
                    severity=sev, original_severity=sev,
                    message=f"Access key active for {age} days (>90) — consider rotation",
                    perm_risk=perm_risk,
                    principal_detail=f"Key ID: {key.get('AccessKeyId', '?')}",
                ))
        except (ValueError, TypeError):
            pass

    # Resource wildcard checks on users too
    findings += _check_resource_wildcards(p, cfg)
    return findings


def _assess_group(p: Principal, cfg: SeverityConfig) -> list[_RawFinding]:
    findings: list[_RawFinding] = []
    perm_risk, perm_reason = _assess_permissions(p)
    if perm_risk in ("HIGH", "MEDIUM"):
        pid = f"GroupPrivilege:{perm_risk}"
        sev = cfg.resolve(pid, perm_risk)
        findings.append(_RawFinding(
            entity_arn=p.arn, entity_type="group", entity_name=p.name,
            category="GROUP_CONFIG", path_id=pid,
            severity=sev, original_severity=sev,
            message=f"Group grants {perm_risk.lower()}-privilege permissions to all its members — {perm_reason}",
            perm_risk=perm_risk,
        ))
    findings += _check_resource_wildcards(p, cfg)
    return findings


# ─── Persistence ───────────────────────────────────────────────────────────────


def _persist(db: Session, account: Account, raw: _RawFinding) -> SecurityFinding:
    return upsert_security_finding(
        session=db,
        account=account,
        entity_arn=raw.entity_arn,
        entity_type=raw.entity_type,
        entity_name=raw.entity_name,
        category=raw.category,
        path_id=raw.path_id,
        severity=raw.severity,
        original_severity=raw.original_severity,
        message=raw.message,
        principal_detail=raw.principal_detail,
        condition=raw.condition,
        perm_risk=raw.perm_risk,
        downgrade_note=raw.downgrade_note,
        suppressed=raw.suppressed,
    )


# ─── Public API ────────────────────────────────────────────────────────────────


def assess(
    db: Session,
    account: Account | None = None,
    min_severity: str = "INFO",
    severity_config: SeverityConfig | None = None,
    max_workers: int = 8,
) -> list[SecurityFinding]:
    """
    Scan all enumerated IAM principals for misconfigurations, persist findings,
    and return the upserted SecurityFinding ORM rows.

    Args:
        db:              Active SQLAlchemy session.
        account:         Limit analysis to a single Account. None = all accounts.
        min_severity:    Minimum severity to persist (CRITICAL/HIGH/MEDIUM/LOW/INFO).
        severity_config: Optional per-rule severity overrides.
        max_workers:     Thread pool size for concurrent analysis.

    Returns:
        List of persisted SecurityFinding ORM objects (only those >= min_severity).
    """
    cfg = severity_config or SeverityConfig.default()
    threshold = SEV_ORDER.get(min_severity, 4)

    # ── Load principals ───────────────────────────────────────────────────────
    from sqlalchemy.orm import joinedload
    from worstassume.db.models import GroupMembership
    query = db.query(Principal).options(
        joinedload(Principal.policies),
        joinedload(Principal.account),
        # Eagerly load group memberships → group → group policies so that
        # _assess_permissions() and _collect_allowed_actions() can traverse
        # inherited policies in worker threads without lazy-load errors.
        joinedload(Principal.group_memberships_as_user)
            .joinedload(GroupMembership.group)
            .joinedload(Principal.policies),
    )
    if account:
        query = query.filter(Principal.account_id == account.id)
    principals: list[Principal] = query.all()

    # ── Account ID lookup (for trust analysis) ────────────────────────────────
    # own_account_id keyed by account.id → account.account_id
    acct_id_map: dict[int, str] = {}
    for p in principals:
        if p.account_id not in acct_id_map and p.account:
            acct_id_map[p.account_id] = p.account.account_id

    # ── Per-principal analysis worker ─────────────────────────────────────────
    def _analyze_principal(p: Principal) -> list[_RawFinding]:
        own_account = acct_id_map.get(p.account_id, "unknown")
        try:
            if p.principal_type == "role":
                raw = _assess_role(p, own_account, cfg)
            elif p.principal_type == "user":
                raw = _assess_user(p, cfg)
            elif p.principal_type == "group":
                raw = _assess_group(p, cfg)
            else:
                raw = []
        except Exception as exc:
            log.warning("[assess] error analyzing %s: %s", p.arn, exc)
            raw = []
        # Apply severity threshold filter
        return [f for f in raw if SEV_ORDER.get(f.severity, 99) <= threshold]

    # ── Thread pool ───────────────────────────────────────────────────────────
    all_raw: list[_RawFinding] = []
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="assess") as pool:
        futures = {pool.submit(_analyze_principal, p): p for p in principals}
        for fut in as_completed(futures):
            try:
                all_raw.extend(fut.result())
            except Exception as exc:
                log.warning("[assess] future error: %s", exc)

    log.info("[assess] %d raw findings (threshold=%s) — persisting…", len(all_raw), min_severity)

    # ── Persist (single-threaded — SQLAlchemy session is not thread-safe) ─────
    results: list[SecurityFinding] = []
    account_map: dict[int, Account] = {}

    for raw in all_raw:
        # Resolve account for the upsert helper (cached)
        p_match = next((p for p in principals if p.arn == raw.entity_arn), None)
        if p_match is None:
            continue
        acct_obj = account_map.get(p_match.account_id)
        if acct_obj is None:
            acct_obj = p_match.account
            account_map[p_match.account_id] = acct_obj
        sf = _persist(db, acct_obj, raw)
        results.append(sf)

    db.commit()
    log.info("[assess] %d findings persisted.", len(results))
    return results
