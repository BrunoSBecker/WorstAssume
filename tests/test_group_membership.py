"""
tests/test_group_membership.py — Phase 8 test suite

Tests:
  1. upsert_group_membership creates a row
  2. upsert_group_membership deduplicates
  3. _collect_allowed_actions includes group-inherited policies for users
  4. _collect_allowed_actions ignores groups for users with no memberships
  5. PATH-009: no edge added when user is already a member
  6. PATH-009: edge added when user has iam:AddUserToGroup and is not a member
"""

from __future__ import annotations

import networkx as nx
import pytest

from worstassume.db.models import GroupMembership, Principal
from worstassume.db.store import (
    get_or_create_account,
    upsert_group_membership,
    upsert_policy,
    upsert_principal,
    link_principal_policy,
)


# ── Shared helpers ────────────────────────────────────────────────────────────

def _make_user(db, account, name="alice", extra_arn=None):
    arn = extra_arn or f"arn:aws:iam::{account.account_id}:user/{name}"
    return upsert_principal(db, account, arn=arn, name=name, principal_type="user")


def _make_group(db, account, name="devs", extra_arn=None):
    arn = extra_arn or f"arn:aws:iam::{account.account_id}:group/{name}"
    return upsert_principal(db, account, arn=arn, name=name, principal_type="group")


def _make_policy(db, account, actions, ptype="inline", name=None, arn=None):
    pname = name or f"pol-{'-'.join(actions)}"
    return upsert_policy(
        db, account,
        arn=arn or f"arn:aws:iam::{account.account_id}:policy/{pname}",
        name=pname,
        policy_type=ptype,
        document={
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}],
        },
    )


# ── PR 8-A: upsert_group_membership ─────────────────────────────────────────

def test_upsert_creates_row(db_session, account_a):
    user  = _make_user(db_session, account_a)
    group = _make_group(db_session, account_a)
    upsert_group_membership(db_session, user=user, group=group, account=account_a)
    db_session.commit()
    assert db_session.query(GroupMembership).count() == 1


def test_upsert_deduplicates(db_session, account_a):
    user  = _make_user(db_session, account_a)
    group = _make_group(db_session, account_a)
    upsert_group_membership(db_session, user=user, group=group, account=account_a)
    upsert_group_membership(db_session, user=user, group=group, account=account_a)
    db_session.commit()
    assert db_session.query(GroupMembership).count() == 1


# ── PR 8-C: _collect_allowed_actions includes group policies ─────────────────

def test_collect_actions_includes_group_policies(db_session, account_a):
    from worstassume.core.iam_actions import _collect_allowed_actions
    from sqlalchemy.orm import joinedload

    user  = _make_user(db_session, account_a)
    group = _make_group(db_session, account_a)
    pol   = _make_policy(db_session, account_a, ["s3:GetObject"])
    link_principal_policy(db_session, group, pol)
    upsert_group_membership(db_session, user=user, group=group, account=account_a)
    db_session.commit()

    # Reload with relationships eager-loaded
    user = (
        db_session.query(Principal)
        .options(
            joinedload(Principal.policies),
            joinedload(Principal.group_memberships_as_user).joinedload(
                GroupMembership.group
            ).joinedload(Principal.policies),
        )
        .filter_by(id=user.id)
        .one()
    )

    actions = _collect_allowed_actions(user)
    assert "s3:GetObject" in actions


def test_collect_actions_no_group_policies_for_non_member(db_session, account_a):
    from worstassume.core.iam_actions import _collect_allowed_actions
    from sqlalchemy.orm import joinedload

    user  = _make_user(db_session, account_a)
    group = _make_group(db_session, account_a)
    pol   = _make_policy(db_session, account_a, ["s3:GetObject"])
    link_principal_policy(db_session, group, pol)
    # No upsert_group_membership — user is NOT in the group
    db_session.commit()

    user = (
        db_session.query(Principal)
        .options(
            joinedload(Principal.policies),
            joinedload(Principal.group_memberships_as_user),
        )
        .filter_by(id=user.id)
        .one()
    )

    actions = _collect_allowed_actions(user)
    assert "s3:GetObject" not in actions


# ── PR 8-D: PATH-009 group_membership edges ──────────────────────────────────

def _build_graph_from_principals(db_session, account_a):
    """Build an attack graph directly from pre-loaded principals."""
    from worstassume.core.iam_actions import _build_action_cache
    from worstassume.core.attack_graph import _build_nodes, _add_group_membership_edges
    from sqlalchemy.orm import joinedload

    principals = (
        db_session.query(Principal)
        .options(
            joinedload(Principal.policies),
            joinedload(Principal.account),
            joinedload(Principal.group_memberships_as_user),
        )
        .filter(Principal.account_id == account_a.id)
        .all()
    )
    G = nx.MultiDiGraph()
    action_cache = _build_action_cache(principals)
    _build_nodes(G, principals, [])
    _add_group_membership_edges(G, principals, action_cache)
    return G


def test_path009_no_edge_for_existing_member(db_session, account_a):
    user  = _make_user(db_session, account_a)
    group = _make_group(db_session, account_a)
    pol   = _make_policy(db_session, account_a, ["iam:AddUserToGroup"])
    link_principal_policy(db_session, user, pol)
    upsert_group_membership(db_session, user=user, group=group, account=account_a)
    db_session.commit()

    G = _build_graph_from_principals(db_session, account_a)

    # User is already a member — no edge should exist
    edges = list(G.edges(user.arn, data=True))
    group_membership_edges = [
        e for e in edges if e[2].get("edge_type") == "group_membership"
    ]
    assert len(group_membership_edges) == 0


def test_path009_edge_added_for_non_member(db_session, account_a):
    user  = _make_user(db_session, account_a)
    group = _make_group(db_session, account_a)
    pol   = _make_policy(db_session, account_a, ["iam:AddUserToGroup"])
    link_principal_policy(db_session, user, pol)
    # No upsert_group_membership — user is NOT in the group
    db_session.commit()

    G = _build_graph_from_principals(db_session, account_a)

    edges = list(G.edges(user.arn, data=True))
    group_membership_edges = [
        e for e in edges
        if e[1] == group.arn and e[2].get("edge_type") == "group_membership"
    ]
    assert len(group_membership_edges) == 1
    assert group_membership_edges[0][2]["path_id"] == "PATH-009"
