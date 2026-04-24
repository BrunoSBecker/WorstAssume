from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from worstassume.db.models import Principal

# ── High-risk actions that alone constitute a privilege escalation risk ────────

DANGEROUS_ACTIONS: list[str] = [
    "*", "iam:*",
    "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
    "iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:AttachGroupPolicy",
    "iam:PutUserPolicy", "iam:PutRolePolicy", "iam:PutGroupPolicy",
    "iam:UpdateAssumeRolePolicy",
    "iam:CreateAccessKey", "iam:UpdateLoginProfile", "iam:CreateLoginProfile",
    "iam:CreateUser", "iam:AddUserToGroup",
]

# Maps a service action to the service principal used in trust policies.
# None means the service reuses the instance profile path (no service trust).
SERVICE_TRUST_MAP: dict[str, str | None] = {
    "lambda:CreateFunction":          "lambda.amazonaws.com",
    "lambda:UpdateFunctionCode":      "lambda.amazonaws.com",
    "cloudformation:CreateStack":     "cloudformation.amazonaws.com",
    "cloudformation:UpdateStack":     "cloudformation.amazonaws.com",
    "ec2:RunInstances":               "ec2.amazonaws.com",
    "ecs:RegisterTaskDefinition":     "ecs-tasks.amazonaws.com",
    "ecs:UpdateService":              "ecs-tasks.amazonaws.com",
    "glue:CreateJob":                 "glue.amazonaws.com",
    "sagemaker:CreateTrainingJob":    "sagemaker.amazonaws.com",
    "codebuild:CreateProject":        "codebuild.amazonaws.com",
    "datapipeline:CreatePipeline":    "datapipeline.amazonaws.com",
    "ssm:SendCommand":                None,
}

# Full set of actions the engine tracks for analysis purposes.
# Used to enumerate what an Allow+NotAction statement actually permits:
# any tracked action NOT covered by the NotAction exclusion list is permitted.
_ALL_TRACKED_ACTIONS: frozenset[str] = frozenset(
    set(DANGEROUS_ACTIONS) | set(SERVICE_TRUST_MAP.keys()) | {
        # PassRole — enables all compute-service escalation chains
        "iam:PassRole",
        # AssumeRole + credential theft paths
        "sts:AssumeRole",
        # EC2 UserData injection
        "ec2:ModifyInstanceAttribute", "ec2:StopInstances", "ec2:StartInstances",
        # Secret / credential exfiltration
        "ssm:GetParameter", "ssm:GetParameters",
        "secretsmanager:GetSecretValue",
        "s3:GetObject", "s3:PutBucketPolicy",
        # Lambda code / config overwrite
        "lambda:GetFunction", "lambda:UpdateFunctionCode",
        "lambda:UpdateFunctionConfiguration", "lambda:CreateEventSourceMapping",
        # Glue / SageMaker abuse
        "glue:UpdateDevEndpoint", "glue:CreateDevEndpoint",
        "sagemaker:CreateNotebookInstance",
        "sagemaker:CreatePresignedNotebookInstanceUrl",
        # ECS lateral movement
        "ecs:UpdateService",
        # Instance Connect
        "ec2-instance-connect:SendSSHPublicKey",
        # CodeBuild / DataPipeline passrole targets
        "codebuild:CreateProject", "datapipeline:CreatePipeline",
        # CodeStar
        "codestar:CreateProject",
        # Monitoring blind
        "cloudtrail:StopLogging", "guardduty:DeleteDetector",
    }
)


# ── Identity helpers ──────────────────────────────────────────────────────────

def is_sso_managed(arn: str) -> bool:
    """Return True for AWS-managed SSO permission-set roles."""
    return (
        "/AWSReservedSSO_" in arn
        or "/aws-reserved/sso.amazonaws.com/" in arn
    )


# ── Action matching ───────────────────────────────────────────────────────────

def _can_do(actions: frozenset[str] | set[str], action: str) -> bool:
    """
    Return True if *actions* grants *action* via:
      - exact match          (iam:PassRole)
      - service wildcard     (iam:*)
      - global wildcard      (*)
      - prefix wildcard      (iam:Pass*)
    """
    if "*" in actions:
        return True
    if action in actions:
        return True
    service, _, _ = action.partition(":")
    for a in actions:
        if not isinstance(a, str):
            continue
        if a == f"{service}:*":
            return True
        if a.endswith("*") and not a.endswith(":*"):
            prefix = a[:-1]
            if action.startswith(prefix):
                return True
    return False


def _has_wildcard(actions: frozenset[str] | set[str], prefix: str) -> bool:
    """Deprecated — use _can_do() instead. Kept for test backward-compatibility."""
    if "*" in actions:
        return True
    for a in actions:
        if not isinstance(a, str):
            continue
        if prefix:
            if a.lower().startswith(prefix.lower()) and a.endswith("*"):
                return True
        else:
            if a.endswith(":*") or a == "*":
                return True
    return False


# ── Policy document parsing ───────────────────────────────────────────────────

def _collect_allowed_actions(principal: "Principal") -> set[str]:
    """Aggregate all 'Allow' actions from a principal's effective policies.

    Handles both `Action` and `NotAction` statements correctly:
    - `Action`:    adds the listed actions directly (standard case).
    - `NotAction`: for each action the engine tracks, adds it if NOT covered
                   by the exclusion list. Multiple statements union additively,
                   so a second `Action` statement can re-grant what `NotAction`
                   excluded — no cross-statement coordination is needed.

    For IAM users, group-inherited policies are included automatically.
    """
    actions: set[str] = set()

    def _extract(policies) -> None:
        for policy in policies:
            doc = policy.document
            if not doc:
                continue
            stmts = doc.get("Statement", [])
            if isinstance(stmts, dict):
                stmts = [stmts]
            for stmt in stmts:
                if not isinstance(stmt, dict):
                    continue
                if stmt.get("Effect") != "Allow":
                    continue

                # Standard Allow+Action statement
                if "Action" in stmt:
                    a = stmt["Action"]
                    if isinstance(a, str):
                        a = [a]
                    actions.update(a)

                # Allow+NotAction: enumerate which tracked actions are permitted.
                # An action is permitted if the exclusion list does NOT cover it.
                elif "NotAction" in stmt:
                    excluded = stmt["NotAction"]
                    if isinstance(excluded, str):
                        excluded = [excluded]
                    excluded_set = set(excluded)
                    for candidate in _ALL_TRACKED_ACTIONS:
                        # Skip wildcards — they are matching patterns, not concrete
                        # AWS actions. A NotAction statement never "grants *".
                        if "*" in candidate:
                            continue
                        if not _can_do(excluded_set, candidate):
                            actions.add(candidate)

    # Direct policies (all principal types)
    _extract(principal.policies)

    # Group-inherited policies (users only)
    for gm in getattr(principal, "group_memberships_as_user", []):
        if gm.group:
            _extract(gm.group.policies)

    return actions


def _build_action_cache(
    principals: list["Principal"],
) -> dict[str, frozenset[str]]:
    """
    Build a {principal_arn: frozenset[allowed_actions]} mapping once.
    Calling _collect_allowed_actions() inside nested loops is O(N²) in
    policy-JSON re-parsing; pre-building once is O(N).
    """
    return {p.arn: frozenset(_collect_allowed_actions(p)) for p in principals}


# ── Resource-scoped PassRole helpers ─────────────────────────────────────────

def _resource_matches(target_arn: str, patterns: list[str]) -> bool:
    """Return True if target_arn satisfies at least one resource pattern.

    Supports:
      - Exact ARN match    (arn:aws:iam::123:role/app)
      - Wildcard (*) glob  (arn:aws:iam::123:role/app-*)  via fnmatch
      - Global wildcard    (*) always matches
    """
    import fnmatch
    for pattern in patterns:
        if pattern == "*":
            return True
        if fnmatch.fnmatch(target_arn, pattern):
            return True
    return False


def _collect_passrole_resources(principal: "Principal") -> list[str]:
    """Return the union of Resource patterns from all Allow+PassRole statements.

    IAM semantics: effective PassRole resource scope = union of all Allow
    statements that grant iam:PassRole (whether via Action or NotAction).
    Returns ['*'] if PassRole is allowed on all resources.
    """
    from worstassume.db.models import Principal as _P  # noqa: F401
    resource_patterns: list[str] = []

    def _scan(policies) -> None:
        for policy in policies:
            doc = policy.document
            if not doc:
                continue
            stmts = doc.get("Statement", [])
            if isinstance(stmts, dict):
                stmts = [stmts]
            for stmt in stmts:
                if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
                    continue

                # Action statement: check if PassRole is explicitly listed
                if "Action" in stmt:
                    action_val = stmt["Action"]
                    if isinstance(action_val, str):
                        action_val = [action_val]
                    if _can_do(set(action_val), "iam:PassRole"):
                        res = stmt.get("Resource", "*")
                        if isinstance(res, str):
                            res = [res]
                        resource_patterns.extend(res)

                # NotAction statement: PassRole is permitted if NOT excluded
                elif "NotAction" in stmt:
                    excluded = stmt["NotAction"]
                    if isinstance(excluded, str):
                        excluded = [excluded]
                    if not _can_do(set(excluded), "iam:PassRole"):
                        # PassRole not excluded — applies to all resources in this stmt
                        res = stmt.get("Resource", "*")
                        if isinstance(res, str):
                            res = [res]
                        resource_patterns.extend(res)

    _scan(principal.policies)
    for gm in getattr(principal, "group_memberships_as_user", []):
        if gm.group:
            _scan(gm.group.policies)

    # If '*' appears anywhere the scope is unrestricted; keep minimal list
    if "*" in resource_patterns:
        return ["*"]
    return resource_patterns or ["*"]  # no grant found — treat as unrestricted (fallback)


def _build_passrole_resource_map(
    principals: list["Principal"],
) -> dict[str, list[str]]:
    """
    Build {principal_arn: [resource_patterns]} for iam:PassRole once.
    Consumed by attack_graph._add_passrole_edges() to skip targets outside
    the attacker's actual PassRole resource scope.
    """
    return {p.arn: _collect_passrole_resources(p) for p in principals}


# ── Danger classification ─────────────────────────────────────────────────────

def _is_dangerous_action_set(actions: frozenset[str] | set[str]) -> bool:
    """True if an action set contains at least one dangerous permission."""
    return any(_can_do(actions, d) for d in DANGEROUS_ACTIONS)


# Alias used internally in chain builders
_is_dangerous = _is_dangerous_action_set


# ── Condition helpers ─────────────────────────────────────────────────────────

def _flatten_condition_keys(condition: dict) -> list[str]:
    """Return all leaf keys from a Condition block (e.g. 'sts:ExternalId')."""
    keys: list[str] = []
    for _op, kv in condition.items():
        if isinstance(kv, dict):
            keys.extend(kv.keys())
    return keys
