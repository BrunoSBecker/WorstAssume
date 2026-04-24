"""Lambda enumeration — functions, resource-based policies, and execution roles."""

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
    if not cap.lambda_functions:
        log.info("[lambda] no Lambda permissions detected — skipping")
        return

    lmb = session.client("lambda")
    region = session.region

    try:
        paginator = lmb.get_paginator("list_functions")
        functions = []
        for page in paginator.paginate():
            functions.extend(page.get("Functions", []))
    except ClientError as e:
        log.warning("[lambda] list_functions error: %s", e)
        return

    log.info("[lambda] found %d functions", len(functions))

    for fn in functions:
        name = fn["FunctionName"]
        arn = fn["FunctionArn"]

        # Resolve execution role
        role_arn = fn.get("Role")
        role_obj = None
        if role_arn:
            from worstassume.db.models import Principal as P
            role_obj = db.query(P).filter_by(account_id=account.id, arn=role_arn).first()

        # Try to get resource policy
        policy = _get_function_policy(lmb, name)

        store.upsert_resource(
            db, account,
            arn=arn,
            service="lambda",
            resource_type="function",
            name=name,
            region=region,
            execution_role=role_obj,
            metadata={
                "runtime": fn.get("Runtime"),
                "handler": fn.get("Handler"),
                "memory": fn.get("MemorySize"),
                "timeout": fn.get("Timeout"),
                "last_modified": fn.get("LastModified"),
                "role_arn": role_arn,
                "resource_policy": policy,
            },
        )


def _get_function_policy(lmb, function_name: str) -> dict | None:
    try:
        import json
        resp = lmb.get_policy(FunctionName=function_name)
        return json.loads(resp["Policy"])
    except ClientError:
        return None
