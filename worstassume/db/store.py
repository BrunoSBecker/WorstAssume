"""DB read/write helpers — thin layer over SQLAlchemy sessions."""

from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy.orm import Session

from worstassume.db.models import (
    Account,
    AttackPath,
    AttackPathStep,
    CrossAccountLink,
    EnumerationRun,
    GroupMembership,
    Policy,
    Principal,
    Resource,
    SecurityFinding,
)


# ─── Account ──────────────────────────────────────────────────────────────────

def get_or_create_account(
    session: Session,
    account_id: str,
    account_name: str | None = None,
    org_id: str | None = None,
    profile: str | None = None,
) -> Account:
    obj = session.query(Account).filter_by(account_id=account_id).first()
    if obj is None:
        obj = Account(
            account_id=account_id,
            account_name=account_name,
            org_id=org_id,
            profile=profile,
        )
        session.add(obj)
        session.flush()
    else:
        if account_name:
            obj.account_name = account_name
        if org_id:
            obj.org_id = org_id
        if profile:
            obj.profile = profile
    return obj


def touch_account(session: Session, account: Account) -> None:
    account.last_enumerated_at = datetime.utcnow()


# ─── Principal ────────────────────────────────────────────────────────────────

def upsert_principal(
    session: Session,
    account: Account,
    arn: str,
    name: str,
    principal_type: str,
    path: str | None = None,
    trust_policy: dict | None = None,
    metadata: dict | None = None,
) -> Principal:
    obj = (
        session.query(Principal)
        .filter_by(account_id=account.id, arn=arn)
        .first()
    )
    if obj is None:
        obj = Principal(
            account_id=account.id,
            arn=arn,
            name=name,
            principal_type=principal_type,
        )
        session.add(obj)

    obj.name = name
    obj.path = path
    obj.trust_policy_json = json.dumps(trust_policy) if trust_policy else None
    obj.metadata_json = json.dumps(metadata) if metadata else None
    session.flush()
    return obj


# ─── Policy ───────────────────────────────────────────────────────────────────

def upsert_policy(
    session: Session,
    account: Account,
    arn: str,
    name: str,
    policy_type: str,
    document: dict | None = None,
) -> Policy:
    obj = (
        session.query(Policy)
        .filter_by(account_id=account.id, arn=arn)
        .first()
    )
    if obj is None:
        obj = Policy(account_id=account.id, arn=arn, name=name, policy_type=policy_type)
        session.add(obj)

    obj.name = name
    obj.policy_type = policy_type
    obj.document_json = json.dumps(document) if document else None
    session.flush()
    return obj


def link_principal_policy(session: Session, principal: Principal, policy: Policy) -> None:
    if policy not in principal.policies:
        principal.policies.append(policy)
    session.flush()


# ─── Resource ─────────────────────────────────────────────────────────────────

def upsert_resource(
    session: Session,
    account: Account,
    arn: str,
    service: str,
    resource_type: str,
    name: str | None = None,
    region: str | None = None,
    execution_role: Principal | None = None,
    metadata: dict | None = None,
) -> Resource:
    obj = (
        session.query(Resource)
        .filter_by(account_id=account.id, arn=arn)
        .first()
    )
    if obj is None:
        obj = Resource(
            account_id=account.id,
            arn=arn,
            service=service,
            resource_type=resource_type,
        )
        session.add(obj)

    obj.name = name
    obj.region = region
    obj.execution_role = execution_role
    obj.metadata_json = json.dumps(metadata, default=str) if metadata else None
    session.flush()
    return obj


# ─── CrossAccountLink ─────────────────────────────────────────────────────────

def upsert_cross_account_link(
    session: Session,
    source_account: Account,
    target_account: Account,
    role_arn: str,
    trust_principal_arn: str,
    link_type: str = "sts:AssumeRole",
    is_wildcard: bool = False,
    condition: dict | None = None,
    notes: str | None = None,
) -> CrossAccountLink:
    obj = (
        session.query(CrossAccountLink)
        .filter_by(
            source_account_id=source_account.id,
            target_account_id=target_account.id,
            role_arn=role_arn,
            trust_principal_arn=trust_principal_arn,
        )
        .first()
    )
    if obj is None:
        obj = CrossAccountLink(
            source_account_id=source_account.id,
            target_account_id=target_account.id,
            role_arn=role_arn,
            trust_principal_arn=trust_principal_arn,
        )
        session.add(obj)

    obj.link_type = link_type
    obj.is_wildcard = is_wildcard
    obj.condition_json = json.dumps(condition) if condition else None
    obj.notes = notes
    session.flush()
    return obj


# ─── EnumerationRun ───────────────────────────────────────────────────────────

def start_run(session: Session, account: Account) -> EnumerationRun:
    run = EnumerationRun(account_id=account.id, started_at=datetime.utcnow())
    session.add(run)
    session.flush()
    return run


def finish_run(
    session: Session,
    run: EnumerationRun,
    capabilities: dict | None = None,
    success: bool = True,
    error_message: str | None = None,
) -> None:
    run.finished_at = datetime.utcnow()
    run.success = success
    run.error_message = error_message
    run.capabilities_json = json.dumps(capabilities) if capabilities else None
    session.flush()


# ─── SecurityFinding ──────────────────────────────────────────────────────────

def upsert_security_finding(
    session: Session,
    account: Account,
    entity_arn: str,
    entity_type: str,
    entity_name: str,
    category: str,
    path_id: str,
    severity: str,
    original_severity: str,
    message: str,
    principal_detail: str | None = None,
    condition: dict | None = None,
    perm_risk: str | None = None,
    downgrade_note: str | None = None,
    suppressed: bool = False,
) -> SecurityFinding:
    """Insert or update a SecurityFinding row.

    Idempotent: uniqueness is enforced by (account_id, entity_arn, path_id).
    On conflict the existing row is updated with the latest assessment values.
    """
    obj = (
        session.query(SecurityFinding)
        .filter_by(account_id=account.id, entity_arn=entity_arn, path_id=path_id)
        .first()
    )
    if obj is None:
        obj = SecurityFinding(
            account_id=account.id,
            entity_arn=entity_arn,
            entity_type=entity_type,
            entity_name=entity_name,
            category=category,
            path_id=path_id,
        )
        session.add(obj)

    obj.entity_type = entity_type
    obj.entity_name = entity_name
    obj.category = category
    obj.severity = severity
    obj.original_severity = original_severity
    obj.message = message
    obj.principal_detail = principal_detail
    obj.condition_json = json.dumps(condition) if condition else None
    obj.perm_risk = perm_risk
    obj.downgrade_note = downgrade_note
    obj.suppressed = suppressed
    session.flush()
    return obj


# ─── AttackPath ──────────────────────────────────────────────────────────────────

def create_attack_path(
    session: Session,
    account: Account,
    from_principal_arn: str,
    severity: str,
    total_hops: int,
    summary: str,
    objective_type: str | None = None,
    objective_value: str | None = None,
) -> AttackPath:
    """Create a new AttackPath record. Each call creates a distinct path row."""
    obj = AttackPath(
        account_id=account.id,
        from_principal_arn=from_principal_arn,
        objective_type=objective_type,
        objective_value=objective_value,
        severity=severity,
        total_hops=total_hops,
        summary=summary,
    )
    session.add(obj)
    session.flush()
    return obj


def add_attack_path_step(
    session: Session,
    path: AttackPath,
    step_index: int,
    actor_arn: str,
    action: str,
    target_arn: str,
    explanation: str,
    edge_type: str,
) -> AttackPathStep:
    """Append a single hop to an existing AttackPath."""
    step = AttackPathStep(
        path_id=path.id,
        step_index=step_index,
        actor_arn=actor_arn,
        action=action,
        target_arn=target_arn,
        explanation=explanation,
        edge_type=edge_type,
    )
    session.add(step)
    session.flush()
    return step


# ─── GroupMembership (Phase 8) ─────────────────────────────────────────────────────

def upsert_group_membership(
    session: Session,
    user: Principal,
    group: Principal,
    account: Account,
) -> GroupMembership:
    """Insert a user→group membership row if it does not already exist (idempotent)."""
    obj = session.query(GroupMembership).filter_by(user_id=user.id, group_id=group.id).first()
    if obj:
        return obj
    obj = GroupMembership(user_id=user.id, group_id=group.id, account_id=account.id)
    session.add(obj)
    session.flush()
    return obj
