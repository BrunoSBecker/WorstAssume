"""EC2 enumeration — instances, security groups, VPCs, subnets, internet gateways."""

from __future__ import annotations

import logging

from botocore.exceptions import ClientError
from sqlalchemy.orm import Session

from worstassume.core.capability import CapabilityMap
from worstassume.db import store
from worstassume.db.models import Account, Principal
from worstassume.session import SessionManager

log = logging.getLogger(__name__)


def enumerate(
    session: SessionManager,
    db: Session,
    account: Account,
    cap: CapabilityMap,
) -> None:
    if not cap.has_any_ec2:
        log.info("[ec2] no EC2 permissions detected — skipping")
        return

    ec2 = session.client("ec2")
    region = session.region

    if cap.ec2_instances:
        _enumerate_instances(ec2, db, account, region)
    if cap.ec2_security_groups:
        _enumerate_security_groups(ec2, db, account, region)
    if cap.ec2_vpcs:
        _enumerate_vpcs(ec2, db, account, region)


def _get_role_by_arn(db: Session, account: Account, arn: str) -> "Principal | None":
    from worstassume.db.models import Principal as P
    return db.query(P).filter_by(account_id=account.id, arn=arn).first()


def _enumerate_instances(ec2, db: Session, account: Account, region: str) -> None:
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    iid = inst["InstanceId"]
                    name = next(
                        (t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"),
                        iid,
                    )
                    arn = f"arn:aws:ec2:{region}:{account.account_id}:instance/{iid}"

                    # Resolve attached IAM role if any
                    role_obj = None
                    profile = inst.get("IamInstanceProfile")
                    if profile:
                        role_arn = profile.get("Arn", "").replace(
                            ":instance-profile/", ":role/"
                        )
                        role_obj = _get_role_by_arn(db, account, role_arn)

                    store.upsert_resource(
                        db, account,
                        arn=arn,
                        service="ec2",
                        resource_type="instance",
                        name=name,
                        region=region,
                        execution_role=role_obj,
                        metadata={
                            "instance_id": iid,
                            "instance_type": inst.get("InstanceType"),
                            "state": inst.get("State", {}).get("Name"),
                            "private_ip": inst.get("PrivateIpAddress"),
                            "public_ip": inst.get("PublicIpAddress"),
                            "subnet_id": inst.get("SubnetId"),
                            "vpc_id": inst.get("VpcId"),
                            "security_groups": [sg["GroupId"] for sg in inst.get("SecurityGroups", [])],
                            "MetadataOptions": inst.get("MetadataOptions", {}),
                        },
                    )
    except ClientError as e:
        log.warning("[ec2] instances error: %s", e)


def _enumerate_security_groups(ec2, db: Session, account: Account, region: str) -> None:
    try:
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                arn = f"arn:aws:ec2:{region}:{account.account_id}:security-group/{sg['GroupId']}"
                store.upsert_resource(
                    db, account,
                    arn=arn,
                    service="ec2",
                    resource_type="security-group",
                    name=sg.get("GroupName"),
                    region=region,
                    metadata={
                        "group_id": sg["GroupId"],
                        "vpc_id": sg.get("VpcId"),
                        "description": sg.get("Description"),
                        "ingress_rules": len(sg.get("IpPermissions", [])),
                        "egress_rules": len(sg.get("IpPermissionsEgress", [])),
                    },
                )
    except ClientError as e:
        log.warning("[ec2] security-groups error: %s", e)


def _enumerate_vpcs(ec2, db: Session, account: Account, region: str) -> None:
    try:
        for vpc in ec2.describe_vpcs().get("Vpcs", []):
            vid = vpc["VpcId"]
            arn = f"arn:aws:ec2:{region}:{account.account_id}:vpc/{vid}"
            store.upsert_resource(
                db, account,
                arn=arn,
                service="ec2",
                resource_type="vpc",
                name=vid,
                region=region,
                metadata={
                    "vpc_id": vid,
                    "cidr": vpc.get("CidrBlock"),
                    "is_default": vpc.get("IsDefault"),
                    "state": vpc.get("State"),
                },
            )
    except ClientError as e:
        log.warning("[ec2] vpcs error: %s", e)
