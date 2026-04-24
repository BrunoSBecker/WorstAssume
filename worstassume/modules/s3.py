"""S3 enumeration — buckets, bucket policies, ACLs, and locations."""

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
    if not cap.s3_buckets:
        log.info("[s3] no S3 permissions detected — skipping")
        return

    s3 = session.client("s3")

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        log.warning("[s3] list_buckets error: %s", e)
        return

    log.info("[s3] found %d buckets", len(buckets))

    for bucket in buckets:
        name = bucket["Name"]
        arn = f"arn:aws:s3:::{name}"

        region = _get_bucket_region(s3, name)
        policy = _get_bucket_policy(s3, name)
        acl = _get_bucket_acl(s3, name)

        store.upsert_resource(
            db, account,
            arn=arn,
            service="s3",
            resource_type="bucket",
            name=name,
            region=region,
            metadata={
                "creation_date": str(bucket.get("CreationDate", "")),
                "region": region,
                "has_policy": policy is not None,
                "policy": policy,
                "acl_grants": len(acl) if acl else 0,
            },
        )


def _get_bucket_region(s3, name: str) -> str | None:
    try:
        loc = s3.get_bucket_location(Bucket=name)
        return loc.get("LocationConstraint") or "us-east-1"
    except ClientError:
        return None


def _get_bucket_policy(s3, name: str) -> dict | None:
    try:
        import json
        resp = s3.get_bucket_policy(Bucket=name)
        return json.loads(resp["Policy"])
    except ClientError:
        return None


def _get_bucket_acl(s3, name: str) -> list | None:
    try:
        resp = s3.get_bucket_acl(Bucket=name)
        return resp.get("Grants", [])
    except ClientError:
        return None
