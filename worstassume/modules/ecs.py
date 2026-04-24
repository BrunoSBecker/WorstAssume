"""ECS enumeration — clusters, services, tasks, and task definitions (with IAM roles)."""

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
    if not cap.ecs_clusters and not cap.ecs_task_defs:
        log.info("[ecs] no ECS permissions detected — skipping")
        return

    ecs = session.client("ecs")
    region = session.region

    if cap.ecs_clusters:
        _enumerate_clusters(ecs, db, account, region)
    if cap.ecs_task_defs:
        _enumerate_task_definitions(ecs, db, account, region)


def _enumerate_clusters(ecs, db: Session, account: Account, region: str) -> None:
    try:
        cluster_arns = []
        paginator = ecs.get_paginator("list_clusters")
        for page in paginator.paginate():
            cluster_arns.extend(page.get("clusterArns", []))

        if not cluster_arns:
            return

        # Describe in batches of 100
        for i in range(0, len(cluster_arns), 100):
            batch = cluster_arns[i:i + 100]
            try:
                clusters = ecs.describe_clusters(clusters=batch).get("clusters", [])
                for cl in clusters:
                    store.upsert_resource(
                        db, account,
                        arn=cl["clusterArn"],
                        service="ecs",
                        resource_type="cluster",
                        name=cl["clusterName"],
                        region=region,
                        metadata={
                            "status": cl.get("status"),
                            "running_tasks": cl.get("runningTasksCount"),
                            "pending_tasks": cl.get("pendingTasksCount"),
                            "active_services": cl.get("activeServicesCount"),
                        },
                    )
            except ClientError as e:
                log.warning("[ecs] describe_clusters error: %s", e)
    except ClientError as e:
        log.warning("[ecs] list_clusters error: %s", e)


def _enumerate_task_definitions(ecs, db: Session, account: Account, region: str) -> None:
    try:
        task_def_arns = []
        paginator = ecs.get_paginator("list_task_definitions")
        for page in paginator.paginate():
            task_def_arns.extend(page.get("taskDefinitionArns", []))

        log.info("[ecs] found %d task definitions", len(task_def_arns))

        for arn in task_def_arns:
            try:
                td = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]

                # Resolve execution role
                role_arn = td.get("taskRoleArn") or td.get("executionRoleArn")
                role_obj = None
                if role_arn:
                    from worstassume.db.models import Principal as P
                    role_obj = db.query(P).filter_by(account_id=account.id, arn=role_arn).first()

                store.upsert_resource(
                    db, account,
                    arn=arn,
                    service="ecs",
                    resource_type="task-definition",
                    name=td.get("family"),
                    region=region,
                    execution_role=role_obj,
                    metadata={
                        "family": td.get("family"),
                        "revision": td.get("revision"),
                        "status": td.get("status"),
                        "task_role_arn": td.get("taskRoleArn"),
                        "execution_role_arn": td.get("executionRoleArn"),
                        "network_mode": td.get("networkMode"),
                        "containers": [c.get("name") for c in td.get("containerDefinitions", [])],
                    },
                )
            except ClientError as e:
                log.debug("[ecs] describe task def error %s: %s", arn, e)
    except ClientError as e:
        log.warning("[ecs] list_task_definitions error: %s", e)
