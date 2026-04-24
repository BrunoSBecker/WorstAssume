"""VPC enumeration — subnets, internet gateways, NAT gateways, route tables."""

from __future__ import annotations

import logging

from botocore.exceptions import ClientError
from sqlalchemy.orm import Session

from worstassume.core.capability import CapabilityMap
from worstassume.db import store
from worstassume.db.models import Account
from worstassume.session import SessionManager

log = logging.getLogger(__name__)


def enumerate(
    session: SessionManager,
    db: Session,
    account: Account,
    cap: CapabilityMap,
) -> None:
    if not cap.ec2_vpcs:
        log.info("[vpc] no VPC permissions detected — skipping")
        return

    ec2 = session.client("ec2")
    region = session.region

    _enumerate_subnets(ec2, db, account, region)
    _enumerate_internet_gateways(ec2, db, account, region)
    _enumerate_nat_gateways(ec2, db, account, region)
    _enumerate_route_tables(ec2, db, account, region)


def _enumerate_subnets(ec2, db: Session, account: Account, region: str) -> None:
    try:
        paginator = ec2.get_paginator("describe_subnets")
        for page in paginator.paginate():
            for sn in page.get("Subnets", []):
                sid = sn["SubnetId"]
                arn = f"arn:aws:ec2:{region}:{account.account_id}:subnet/{sid}"
                name = next(
                    (t["Value"] for t in sn.get("Tags", []) if t["Key"] == "Name"), sid
                )
                store.upsert_resource(
                    db, account,
                    arn=arn,
                    service="vpc",
                    resource_type="subnet",
                    name=name,
                    region=region,
                    metadata={
                        "subnet_id": sid,
                        "vpc_id": sn.get("VpcId"),
                        "cidr": sn.get("CidrBlock"),
                        "availability_zone": sn.get("AvailabilityZone"),
                        "public": sn.get("MapPublicIpOnLaunch"),
                    },
                )
    except ClientError as e:
        log.warning("[vpc] subnets error: %s", e)


def _enumerate_internet_gateways(ec2, db: Session, account: Account, region: str) -> None:
    try:
        for igw in ec2.describe_internet_gateways().get("InternetGateways", []):
            igw_id = igw["InternetGatewayId"]
            arn = f"arn:aws:ec2:{region}:{account.account_id}:internet-gateway/{igw_id}"
            attached_vpcs = [att["VpcId"] for att in igw.get("Attachments", [])]
            store.upsert_resource(
                db, account,
                arn=arn,
                service="vpc",
                resource_type="internet-gateway",
                name=igw_id,
                region=region,
                metadata={"attaches_to_vpcs": attached_vpcs},
            )
    except ClientError as e:
        log.warning("[vpc] internet gateways error: %s", e)


def _enumerate_nat_gateways(ec2, db: Session, account: Account, region: str) -> None:
    try:
        paginator = ec2.get_paginator("describe_nat_gateways")
        for page in paginator.paginate():
            for nat in page.get("NatGateways", []):
                nat_id = nat["NatGatewayId"]
                arn = f"arn:aws:ec2:{region}:{account.account_id}:natgateway/{nat_id}"
                store.upsert_resource(
                    db, account,
                    arn=arn,
                    service="vpc",
                    resource_type="nat-gateway",
                    name=nat_id,
                    region=region,
                    metadata={
                        "vpc_id": nat.get("VpcId"),
                        "subnet_id": nat.get("SubnetId"),
                        "state": nat.get("State"),
                    },
                )
    except ClientError as e:
        log.warning("[vpc] nat gateways error: %s", e)


def _enumerate_route_tables(ec2, db: Session, account: Account, region: str) -> None:
    try:
        paginator = ec2.get_paginator("describe_route_tables")
        for page in paginator.paginate():
            for rt in page.get("RouteTables", []):
                rt_id = rt["RouteTableId"]
                arn = f"arn:aws:ec2:{region}:{account.account_id}:route-table/{rt_id}"
                store.upsert_resource(
                    db, account,
                    arn=arn,
                    service="vpc",
                    resource_type="route-table",
                    name=rt_id,
                    region=region,
                    metadata={
                        "vpc_id": rt.get("VpcId"),
                        "routes": len(rt.get("Routes", [])),
                        "associations": len(rt.get("Associations", [])),
                    },
                )
    except ClientError as e:
        log.warning("[vpc] route tables error: %s", e)
