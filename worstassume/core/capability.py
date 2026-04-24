"""
Capability probe engine — determines which AWS services/actions the current
identity is allowed to call, using the lowest-noise strategy possible.

Strategy (waterfall):
  1. iam:GetAccountAuthorizationDetails — if allowed, covers all IAM
  2. iam:SimulatePrincipalPolicy         — if allowed, can test any action
  3. Service-level probes                — one list/describe call per service
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from botocore.exceptions import ClientError

from worstassume.session import SessionManager

log = logging.getLogger(__name__)

# Ordered probe list — (service_key, boto3_service_name, method, kwargs)
_PROBES: list[tuple[str, str, str, dict]] = [
    ("iam_full_dump",       "iam",    "get_account_authorization_details", {"Filter": ["User"]}),
    ("iam_list_roles",      "iam",    "list_roles",                        {"MaxItems": 1}),
    ("iam_list_users",      "iam",    "list_users",                        {"MaxItems": 1}),
    ("iam_list_policies",   "iam",    "list_policies",                     {"MaxItems": 1, "Scope": "Local"}),
    ("iam_simulate",        "iam",    "simulate_principal_policy",         {}),  # special-cased
    ("ec2_instances",       "ec2",    "describe_instances",                {"MaxResults": 5}),
    ("ec2_security_groups", "ec2",    "describe_security_groups",          {"MaxResults": 5}),
    ("ec2_vpcs",            "ec2",    "describe_vpcs",                     {}),
    ("s3_buckets",          "s3",     "list_buckets",                      {}),
    ("lambda_functions",    "lambda", "list_functions",                    {"MaxItems": 1}),
    ("ecs_clusters",        "ecs",    "list_clusters",                     {}),
    ("ecs_task_defs",       "ecs",    "list_task_definitions",             {"maxResults": 1}),
]


@dataclass
class CapabilityMap:
    """Boolean map of detected capabilities for the current identity."""

    # IAM
    iam_full_dump: bool = False       # GetAccountAuthorizationDetails
    iam_list_roles: bool = False
    iam_list_users: bool = False
    iam_list_policies: bool = False
    iam_simulate: bool = False        # SimulatePrincipalPolicy

    # Services
    ec2_instances: bool = False
    ec2_security_groups: bool = False
    ec2_vpcs: bool = False
    s3_buckets: bool = False
    lambda_functions: bool = False
    ecs_clusters: bool = False
    ecs_task_defs: bool = False

    # Derived helpers
    @property
    def has_any_iam(self) -> bool:
        return any([
            self.iam_full_dump, self.iam_list_roles, self.iam_list_users,
            self.iam_list_policies,
        ])

    @property
    def has_any_ec2(self) -> bool:
        return any([self.ec2_instances, self.ec2_security_groups, self.ec2_vpcs])

    def to_dict(self) -> dict[str, bool]:
        return {
            k: v for k, v in self.__dict__.items()
            if not k.startswith("_")
        }


def probe_capabilities(session: SessionManager, caller_arn: str) -> CapabilityMap:
    """
    Fire one probe per capability and build a CapabilityMap.

    Never raises — failures are logged as debug and marked as denied.
    """
    cap = CapabilityMap()

    for key, svc_name, method, kwargs in _PROBES:
        # simulate_principal_policy needs special args — skip probe, check separately
        if key == "iam_simulate":
            allowed = _probe_simulate(session, caller_arn)
            cap.iam_simulate = allowed
            continue

        try:
            client = session.client(svc_name)
            getattr(client, method)(**kwargs)
            setattr(cap, key, True)
            log.debug("[probe] ✓ %s", key)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
                        "AuthFailure", "InvalidClientTokenId"):
                log.debug("[probe] ✗ %s → %s", key, code)
            else:
                # Unexpected error (e.g. region issue) — still mark as allowed
                # because the action itself wasn't denied
                log.debug("[probe] ? %s → %s (non-auth error, marking allowed)", key, code)
                setattr(cap, key, True)
        except Exception as e:
            log.debug("[probe] ? %s → unexpected: %s", key, e)

    return cap


def _probe_simulate(session: SessionManager, caller_arn: str) -> bool:
    """Test iam:SimulatePrincipalPolicy with a minimal call."""
    try:
        iam = session.client("iam")
        iam.simulate_principal_policy(
            PolicySourceArn=caller_arn,
            ActionNames=["s3:ListBuckets"],
        )
        return True
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("AccessDenied", "AccessDeniedException"):
            return False
        # Other error — still allowed
        return True
    except Exception:
        return False
