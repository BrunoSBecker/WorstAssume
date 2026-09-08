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
from typing import Any

from botocore.exceptions import ClientError

from worstassume.session import SessionManager

log = logging.getLogger(__name__)

# One read-only inventory action per capability.  These are also fed to
# SimulatePrincipalPolicy, when available, so an explicit/implicit deny avoids
# a guaranteed AccessDenied call to the service itself.
# (capability key, boto3 service, boto3 method, probe kwargs)
_PROBES: list[tuple[str, str, str, dict]] = [
    ("iam_list_roles",      "iam",    "list_roles",                        {"MaxItems": 1}),
    ("iam_list_users",      "iam",    "list_users",                        {"MaxItems": 1}),
    ("iam_list_groups",     "iam",    "list_groups",                       {"MaxItems": 1}),
    ("iam_list_policies",   "iam",    "list_policies",                     {"MaxItems": 1, "Scope": "Local"}),
    ("ec2_instances",       "ec2",    "describe_instances",                {"MaxResults": 5}),
    ("ec2_security_groups", "ec2",    "describe_security_groups",          {"MaxResults": 5}),
    ("ec2_vpcs",            "ec2",    "describe_vpcs",                     {}),
    ("ec2_subnets",         "ec2",    "describe_subnets",                  {"MaxResults": 5}),
    ("ec2_internet_gateways", "ec2",  "describe_internet_gateways",        {"MaxResults": 5}),
    ("ec2_nat_gateways",    "ec2",    "describe_nat_gateways",             {"MaxResults": 5}),
    ("ec2_route_tables",    "ec2",    "describe_route_tables",             {"MaxResults": 5}),
    ("s3_buckets",          "s3",     "list_buckets",                      {}),
    ("lambda_functions",    "lambda", "list_functions",                    {"MaxItems": 1}),
    ("ecs_clusters",        "ecs",    "list_clusters",                     {"maxResults": 1}),
    ("ecs_task_defs",       "ecs",    "list_task_definitions",             {"maxResults": 1}),
]

_ACTION_BY_CAPABILITY: dict[str, str] = {
    "iam_list_roles": "iam:ListRoles",
    "iam_list_users": "iam:ListUsers",
    "iam_list_groups": "iam:ListGroups",
    "iam_list_policies": "iam:ListPolicies",
    "ec2_instances": "ec2:DescribeInstances",
    "ec2_security_groups": "ec2:DescribeSecurityGroups",
    "ec2_vpcs": "ec2:DescribeVpcs",
    "ec2_subnets": "ec2:DescribeSubnets",
    "ec2_internet_gateways": "ec2:DescribeInternetGateways",
    "ec2_nat_gateways": "ec2:DescribeNatGateways",
    "ec2_route_tables": "ec2:DescribeRouteTables",
    "s3_buckets": "s3:ListAllMyBuckets",
    "lambda_functions": "lambda:ListFunctions",
    "ecs_clusters": "ecs:ListClusters",
    "ecs_task_defs": "ecs:ListTaskDefinitions",
}

_AUTH_ERRORS = frozenset({
    "AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
    "AuthFailure", "InvalidClientTokenId",
})


@dataclass
class CapabilityMap:
    """Boolean map of detected capabilities for the current identity."""

    # IAM
    iam_full_dump: bool = False       # GetAccountAuthorizationDetails
    iam_list_roles: bool = False
    iam_list_users: bool = False
    iam_list_groups: bool = False
    iam_list_policies: bool = False
    iam_simulate: bool = False        # SimulatePrincipalPolicy

    # Services
    ec2_instances: bool = False
    ec2_security_groups: bool = False
    ec2_vpcs: bool = False
    ec2_subnets: bool = False
    ec2_internet_gateways: bool = False
    ec2_nat_gateways: bool = False
    ec2_route_tables: bool = False
    s3_buckets: bool = False
    lambda_functions: bool = False
    ecs_clusters: bool = False
    ecs_task_defs: bool = False

    # Internal probe evidence. These fields are deliberately excluded from
    # to_dict() so EnumerationRun.capabilities remains a bool-only payload.
    _status: dict[str, str] = field(default_factory=dict, repr=False)
    _iam_dump_first_page: dict[str, Any] | None = field(
        default=None, repr=False, compare=False
    )

    # Derived helpers
    @property
    def has_any_iam(self) -> bool:
        return any([
            self.iam_full_dump, self.iam_list_roles, self.iam_list_users,
            self.iam_list_groups, self.iam_list_policies,
        ])

    @property
    def has_any_ec2(self) -> bool:
        return any([
            self.ec2_instances, self.ec2_security_groups, self.ec2_vpcs,
            self.ec2_subnets, self.ec2_internet_gateways,
            self.ec2_nat_gateways, self.ec2_route_tables,
        ])

    @property
    def has_any_vpc(self) -> bool:
        return any([
            self.ec2_subnets, self.ec2_internet_gateways,
            self.ec2_nat_gateways, self.ec2_route_tables,
        ])

    def to_dict(self) -> dict[str, bool]:
        return {
            k: v for k, v in self.__dict__.items()
            if not k.startswith("_")
        }

    def status_groups(self) -> dict[str, list[str]]:
        """Return capability names grouped by allowed/denied/skipped evidence."""
        groups = {"allowed": [], "denied": [], "skipped": []}
        for key in self.to_dict():
            status = self._status.get(key, "skipped")
            groups.setdefault(status, []).append(key)
        return groups


def probe_capabilities(session: SessionManager, caller_arn: str) -> CapabilityMap:
    """
    Build a capability map using a low-noise waterfall.

    1. Try the IAM account authorization dump.
    2. If unavailable, try one SimulatePrincipalPolicy batch.
    3. Only when simulation itself is unavailable, make one residual read-only
       inventory probe per capability.

    A simulated deny is authoritative for this conservative scanner: the
    corresponding inventory API is not called. Never raises.
    """
    cap = CapabilityMap()

    # Fast IAM path. MaxItems keeps the permission check small; the first page
    # is retained so iam.enumerate can continue from its Marker without
    # repeating this API call.
    try:
        iam = session.client("iam")
        first_page = iam.get_account_authorization_details(MaxItems=1)
        cap.iam_full_dump = True
        cap._status["iam_full_dump"] = "allowed"
        cap._iam_dump_first_page = first_page
        for key in (
            "iam_list_roles", "iam_list_users",
            "iam_list_groups", "iam_list_policies",
        ):
            cap._status[key] = "skipped"
        log.debug("[probe] ✓ iam_full_dump (remaining IAM probes skipped)")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        cap._status["iam_full_dump"] = "denied" if code in _AUTH_ERRORS else "skipped"
        log.debug("[probe] ✗ iam_full_dump → %s", code)
    except Exception as exc:
        cap._status["iam_full_dump"] = "skipped"
        log.debug("[probe] ? iam_full_dump → %s", exc)

    # Simulation is useful only when the full IAM dump is unavailable. The
    # result covers every residual capability in one request.
    simulated = False
    if not cap.iam_full_dump:
        simulated = _simulate_capabilities(session, caller_arn, cap)
    else:
        cap._status["iam_simulate"] = "skipped"

    # Even a successful IAM dump does not prove service inventory access, so
    # service probes remain. A successful simulation, however, supplies direct
    # allow/deny evidence and suppresses all residual calls.
    for key, svc_name, method, kwargs in _PROBES:
        if key.startswith("iam_") and cap.iam_full_dump:
            continue
        if simulated:
            continue
        try:
            client = session.client(svc_name)
            getattr(client, method)(**kwargs)
            setattr(cap, key, True)
            cap._status[key] = "allowed"
            log.debug("[probe] ✓ %s", key)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in _AUTH_ERRORS:
                cap._status[key] = "denied"
                log.debug("[probe] ✗ %s → %s", key, code)
            else:
                # The request passed authorization and failed validation or
                # regional availability, so the action is callable.
                log.debug("[probe] ? %s → %s (non-auth error, marking allowed)", key, code)
                setattr(cap, key, True)
                cap._status[key] = "allowed"
        except Exception as exc:
            cap._status[key] = "skipped"
            log.debug("[probe] ? %s → unexpected: %s", key, exc)

    return cap


def normalize_policy_source_arn(caller_arn: str) -> str:
    """Convert an STS assumed-role ARN to the IAM role ARN required by Simulate."""
    parts = caller_arn.split(":", 5)
    if len(parts) != 6 or parts[2] != "sts":
        return caller_arn
    resource = parts[5]
    if not resource.startswith("assumed-role/"):
        return caller_arn
    role_name = resource.split("/", 2)[1]
    return f"arn:{parts[1]}:iam::{parts[4]}:role/{role_name}"


def _simulate_capabilities(
    session: SessionManager, caller_arn: str, cap: CapabilityMap
) -> bool:
    """Populate *cap* from one SimulatePrincipalPolicy request."""
    # Deliberately simulate inventory reads only. WorstAssume maps existing
    # infrastructure; it does not assess Create/Put capabilities during recon.
    action_names = sorted(set(_ACTION_BY_CAPABILITY.values()))
    # IAM currently accepts at most 100 ActionNames. Staying conservative is
    # preferable to silently issuing multiple calls under a "single batch"
    # promise.
    if len(action_names) > 100:
        log.warning("[probe] simulation catalogue has %d actions; using residual probes", len(action_names))
        cap._status["iam_simulate"] = "skipped"
        return False

    try:
        iam = session.client("iam")
        response = iam.simulate_principal_policy(
            PolicySourceArn=normalize_policy_source_arn(caller_arn),
            ActionNames=action_names,
        )
        cap.iam_simulate = True
        cap._status["iam_simulate"] = "allowed"
        decisions = {
            result.get("EvalActionName", "").lower(): result.get("EvalDecision", "").lower()
            for result in response.get("EvaluationResults", [])
        }
        for key, action in _ACTION_BY_CAPABILITY.items():
            allowed = decisions.get(action.lower()) == "allowed"
            setattr(cap, key, allowed)
            cap._status[key] = "allowed" if allowed else "denied"
        log.debug("[probe] ✓ iam_simulate (%d capabilities evaluated)", len(_ACTION_BY_CAPABILITY))
        return True
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        cap._status["iam_simulate"] = "denied" if code in _AUTH_ERRORS else "skipped"
        log.debug("[probe] ✗ iam_simulate → %s", code)
        return False
    except Exception as exc:
        cap._status["iam_simulate"] = "skipped"
        log.debug("[probe] ? iam_simulate → %s", exc)
        return False
