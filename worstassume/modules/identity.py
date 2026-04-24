"""Identity module — discovers the current AWS caller identity via sts:GetCallerIdentity."""

from __future__ import annotations

from dataclasses import dataclass

from botocore.exceptions import ClientError, NoCredentialsError

from worstassume.session import SessionManager


@dataclass
class IdentityResult:
    account_id: str
    arn: str
    user_id: str
    principal_type: str  # "user", "role", "assumed-role", "federated"
    principal_name: str


def get_caller_identity(session: SessionManager) -> IdentityResult:
    """Run sts:GetCallerIdentity and parse the result."""
    try:
        sts = session.client("sts")
        resp = sts.get_caller_identity()
    except (ClientError, NoCredentialsError) as e:
        raise RuntimeError(f"Cannot identify caller: {e}") from e

    account_id: str = resp["Account"]
    arn: str = resp["Arn"]
    user_id: str = resp["UserId"]

    # Parse principal type from ARN
    # arn:aws:iam::ACCOUNT:user/NAME
    # arn:aws:iam::ACCOUNT:role/NAME
    # arn:aws:sts::ACCOUNT:assumed-role/ROLE/SESSION
    # arn:aws:sts::ACCOUNT:federated-user/NAME
    parts = arn.split(":")
    resource = parts[-1] if parts else ""

    if resource.startswith("user/"):
        ptype = "user"
        pname = resource.split("/", 1)[1]
    elif resource.startswith("role/"):
        ptype = "role"
        pname = resource.split("/", 1)[1]
    elif resource.startswith("assumed-role/"):
        ptype = "assumed-role"
        # assumed-role/ROLE_NAME/SESSION_NAME
        pname = resource.split("/")[1]
    elif resource.startswith("federated-user/"):
        ptype = "federated"
        pname = resource.split("/", 1)[1]
    else:
        ptype = "unknown"
        pname = resource

    return IdentityResult(
        account_id=account_id,
        arn=arn,
        user_id=user_id,
        principal_type=ptype,
        principal_name=pname,
    )
