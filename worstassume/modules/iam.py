"""
IAM enumeration module.

Fast path: GetAccountAuthorizationDetails (one call = everything)
Slow path: enumerate users → groups → roles → policies individually
"""

from __future__ import annotations

import json
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
    """Entry point for IAM enumeration."""
    if not cap.has_any_iam:
        log.info("[iam] no IAM permissions detected — skipping")
        return

    if cap.iam_full_dump:
        log.info("[iam] using fast path: GetAccountAuthorizationDetails")
        _fast_path(session, db, account)
    else:
        log.info("[iam] using slow path: individual list/get calls")
        _slow_path(session, db, account, cap)


# ─── Fast path ────────────────────────────────────────────────────────────────

def _fast_path(session: SessionManager, db: Session, account: Account) -> None:
    iam = session.client("iam")
    paginator = iam.get_paginator("get_account_authorization_details")

    user_details = []
    group_details = []
    role_details = []
    policy_details = []

    for page in paginator.paginate():
        user_details.extend(page.get("UserDetailList", []))
        group_details.extend(page.get("GroupDetailList", []))
        role_details.extend(page.get("RoleDetailList", []))
        policy_details.extend(page.get("Policies", []))

    log.info(
        "[iam] found %d users, %d groups, %d roles, %d policies",
        len(user_details), len(group_details), len(role_details), len(policy_details),
    )

    # Upsert standalone managed policies first (so we can link them)
    policy_objects: dict[str, any] = {}
    for p in policy_details:
        arn = p["Arn"]
        # get latest version document
        doc = None
        for ver in p.get("PolicyVersionList", []):
            if ver.get("IsDefaultVersion"):
                doc = ver.get("Document")
                break
        obj = store.upsert_policy(
            db, account,
            arn=arn,
            name=p.get("PolicyName", p.get("Name", arn.split("/")[-1])),
            policy_type="aws_managed" if ":aws:policy/" in arn else "managed",
            document=doc,
        )
        policy_objects[arn] = obj

    # Users
    for u in user_details:
        principal = store.upsert_principal(
            db, account,
            arn=u["Arn"],
            name=u["UserName"],
            principal_type="user",
            path=u.get("Path"),
            metadata={"create_date": str(u.get("CreateDate", ""))},
        )
        # Inline policies
        for ip in u.get("UserPolicyList", []):
            pol = store.upsert_policy(
                db, account,
                arn=f"{u['Arn']}:inline/{ip['PolicyName']}",
                name=ip["PolicyName"],
                policy_type="inline",
                document=ip.get("PolicyDocument"),
            )
            store.link_principal_policy(db, principal, pol)
        # Attached managed policies
        for ap in u.get("AttachedManagedPolicies", []):
            pol = _resolve_or_fetch_policy(iam, db, account, ap, policy_objects)
            if pol:
                store.link_principal_policy(db, principal, pol)

    # Groups
    for g in group_details:
        principal = store.upsert_principal(
            db, account,
            arn=g["Arn"],
            name=g["GroupName"],
            principal_type="group",
            path=g.get("Path"),
        )
        for ip in g.get("GroupPolicyList", []):
            pol = store.upsert_policy(
                db, account,
                arn=f"{g['Arn']}:inline/{ip['PolicyName']}",
                name=ip["PolicyName"],
                policy_type="inline",
                document=ip.get("PolicyDocument"),
            )
            store.link_principal_policy(db, principal, pol)
        for ap in g.get("AttachedManagedPolicies", []):
            pol = _resolve_or_fetch_policy(iam, db, account, ap, policy_objects)
            if pol:
                store.link_principal_policy(db, principal, pol)

    # Roles
    for r in role_details:
        trust = r.get("AssumeRolePolicyDocument")
        principal = store.upsert_principal(
            db, account,
            arn=r["Arn"],
            name=r["RoleName"],
            principal_type="role",
            path=r.get("Path"),
            trust_policy=trust,
            metadata={"create_date": str(r.get("CreateDate", ""))},
        )
        for ip in r.get("RolePolicyList", []):
            pol = store.upsert_policy(
                db, account,
                arn=f"{r['Arn']}:inline/{ip['PolicyName']}",
                name=ip["PolicyName"],
                policy_type="inline",
                document=ip.get("PolicyDocument"),
            )
            store.link_principal_policy(db, principal, pol)
        for ap in r.get("AttachedManagedPolicies", []):
            pol = _resolve_or_fetch_policy(iam, db, account, ap, policy_objects)
            if pol:
                store.link_principal_policy(db, principal, pol)


    # ── Group memberships (fast path) ──────────────────────────────────────────
    # GetAccountAuthorizationDetails returns GroupList per user as a list of
    # group name strings. Map group names to ORM objects then persist each
    # user→group pair as a GroupMembership row (idempotent via upsert).
    from worstassume.db.store import upsert_group_membership
    from worstassume.db.models import Principal as _P

    group_by_name: dict[str, _P] = {
        g["GroupName"]: db.query(_P).filter_by(
            name=g["GroupName"], account_id=account.id, principal_type="group"
        ).first()
        for g in group_details
    }
    for u in user_details:
        user_obj = db.query(_P).filter_by(arn=u["Arn"], account_id=account.id).first()
        if not user_obj:
            continue
        for grp_name in u.get("GroupList", []):
            g_obj = group_by_name.get(grp_name)
            if g_obj:
                upsert_group_membership(db, user=user_obj, group=g_obj, account=account)


def _resolve_or_fetch_policy(iam, db, account, ap: dict, policy_objects: dict):
    """Return the Policy ORM object for an attached policy, fetching it from AWS if not cached."""
    arn = ap["PolicyArn"]
    if arn in policy_objects:
        return policy_objects[arn]
    # Not in the pre-built map — fetch inline
    try:
        meta = iam.get_policy(PolicyArn=arn)["Policy"]
        ver = iam.get_policy_version(PolicyArn=arn, VersionId=meta["DefaultVersionId"])
        doc = ver["PolicyVersion"]["Document"]
    except Exception:
        doc = None
    obj = store.upsert_policy(
        db, account,
        arn=arn,
        name=ap.get("PolicyName", arn.split("/")[-1]),
        policy_type="aws_managed" if ":aws:policy/" in arn else "managed",
        document=doc,
    )
    policy_objects[arn] = obj
    return obj


# ─── Slow path ────────────────────────────────────────────────────────────────

def _slow_path(
    session: SessionManager, db: Session, account: Account, cap: CapabilityMap
) -> None:
    iam = session.client("iam")

    # Groups must be enumerated BEFORE users so group rows exist when linking memberships
    if cap.iam_list_users:
        _enumerate_groups_for_slow_path(iam, db, account)
        _enumerate_users(iam, db, account)
    if cap.iam_list_roles:
        _enumerate_roles(iam, db, account)
    if cap.iam_list_policies:
        _enumerate_policies(iam, db, account)


def _enumerate_groups_for_slow_path(iam, db: Session, account: Account) -> None:
    """Persist IAM groups before users so group rows exist when linking memberships."""
    from worstassume.db.models import Principal as _P
    try:
        paginator = iam.get_paginator("list_groups")
        for page in paginator.paginate():
            for g in page["Groups"]:
                store.upsert_principal(
                    db, account,
                    arn=g["Arn"],
                    name=g["GroupName"],
                    principal_type="group",
                    path=g.get("Path"),
                )
    except ClientError:
        pass


def _enumerate_users(iam, db: Session, account: Account) -> None:
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for u in page["Users"]:
            principal = store.upsert_principal(
                db, account,
                arn=u["Arn"],
                name=u["UserName"],
                principal_type="user",
                path=u.get("Path"),
            )
            # Inline policies
            try:
                for pname in iam.list_user_policies(UserName=u["UserName"]).get("PolicyNames", []):
                    try:
                        doc = iam.get_user_policy(UserName=u["UserName"], PolicyName=pname)
                        pol = store.upsert_policy(
                            db, account,
                            arn=f"{u['Arn']}:inline/{pname}",
                            name=pname,
                            policy_type="inline",
                            document=doc.get("PolicyDocument"),
                        )
                        store.link_principal_policy(db, principal, pol)
                    except ClientError:
                        pass
            except ClientError:
                pass
            # Attached managed
            try:
                for ap in iam.list_attached_user_policies(UserName=u["UserName"]).get("AttachedPolicies", []):
                    try:
                        meta = iam.get_policy(PolicyArn=ap["PolicyArn"])["Policy"]
                        ver = iam.get_policy_version(
                            PolicyArn=ap["PolicyArn"],
                            VersionId=meta["DefaultVersionId"],
                        )
                        pol = store.upsert_policy(
                            db, account,
                            arn=ap["PolicyArn"],
                            name=ap["PolicyName"],
                            policy_type="managed",
                            document=ver["PolicyVersion"]["Document"],
                        )
                        store.link_principal_policy(db, principal, pol)
                    except ClientError:
                        pass
            except ClientError:
                pass
            # Group memberships (slow path) — list_groups_for_user provides group ARNs
            # so we can link memberships to the already-enumerated group rows.
            try:
                from worstassume.db.store import upsert_group_membership
                from worstassume.db.models import Principal as _P
                for grp in iam.list_groups_for_user(UserName=u["UserName"]).get("Groups", []):
                    g_obj = db.query(_P).filter_by(arn=grp["Arn"], account_id=account.id).first()
                    if g_obj:
                        upsert_group_membership(db, user=principal, group=g_obj, account=account)
            except ClientError:
                pass


def _enumerate_roles(iam, db: Session, account: Account) -> None:
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for r in page["Roles"]:
            principal = store.upsert_principal(
                db, account,
                arn=r["Arn"],
                name=r["RoleName"],
                principal_type="role",
                path=r.get("Path"),
                trust_policy=r.get("AssumeRolePolicyDocument"),
            )
            try:
                for pname in iam.list_role_policies(RoleName=r["RoleName"]).get("PolicyNames", []):
                    try:
                        doc = iam.get_role_policy(RoleName=r["RoleName"], PolicyName=pname)
                        pol = store.upsert_policy(
                            db, account,
                            arn=f"{r['Arn']}:inline/{pname}",
                            name=pname,
                            policy_type="inline",
                            document=doc.get("PolicyDocument"),
                        )
                        store.link_principal_policy(db, principal, pol)
                    except ClientError:
                        pass
            except ClientError:
                pass
            try:
                for ap in iam.list_attached_role_policies(RoleName=r["RoleName"]).get("AttachedPolicies", []):
                    try:
                        meta = iam.get_policy(PolicyArn=ap["PolicyArn"])["Policy"]
                        ver = iam.get_policy_version(
                            PolicyArn=ap["PolicyArn"],
                            VersionId=meta["DefaultVersionId"],
                        )
                        pol = store.upsert_policy(
                            db, account,
                            arn=ap["PolicyArn"],
                            name=ap["PolicyName"],
                            policy_type="managed",
                            document=ver["PolicyVersion"]["Document"],
                        )
                        store.link_principal_policy(db, principal, pol)
                    except ClientError:
                        pass
            except ClientError:
                pass


def _enumerate_policies(iam, db: Session, account: Account) -> None:
    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):
        for p in page["Policies"]:
            try:
                ver = iam.get_policy_version(
                    PolicyArn=p["Arn"],
                    VersionId=p["DefaultVersionId"],
                )
                store.upsert_policy(
                    db, account,
                    arn=p["Arn"],
                    name=p["PolicyName"],
                    policy_type="managed",
                    document=ver["PolicyVersion"]["Document"],
                )
            except ClientError:
                pass
