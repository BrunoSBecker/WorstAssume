"""
Tests for the cached, server-side EntityIndex that backs GET /api/entities.

Covers:
  - risk / managed / permission helper heuristics
  - index build (type counts, account facets, action vocabulary)
  - server-side filtering (type, risk, search, service, account, permission, managed)
  - pagination + risk-ordered sorting
  - non-suppressed finding-driven risk + path counts
  - legacy grouped() full-dump shape
"""

from __future__ import annotations

import json

import pytest

from worstassume.db.models import Policy, Principal, Resource, SecurityFinding
from worstassume.viz import server
from worstassume.viz.server import (
    EntityIndex,
    _compute_entity_risk,
    _entity_is_aws_managed,
    _permission_matches,
)


# ─── Helper heuristics ────────────────────────────────────────────────────────

def test_compute_entity_risk_matches_frontend_heuristic():
    assert _compute_entity_risk(["*"], [], set()) == "CRITICAL"
    assert _compute_entity_risk(["iam:*"], [], set()) == "CRITICAL"
    assert _compute_entity_risk([], [], {"CRITICAL"}) == "CRITICAL"
    assert _compute_entity_risk([], [], {"HIGH"}) == "HIGH"
    assert _compute_entity_risk(["iam:PassRole"], [], set()) == "HIGH"
    assert _compute_entity_risk(["sts:AssumeRole"], [], set()) == "HIGH"
    assert _compute_entity_risk(["s3:GetObject"], [], set()) == "MEDIUM"
    assert _compute_entity_risk(["ec2:DescribeInstances"], [], set()) == "MEDIUM"
    assert _compute_entity_risk([], ["arn:aws:iam::*:root"], set()) == "HIGH"
    assert _compute_entity_risk(["dynamodb:GetItem"], [], set()) == "LOW"
    assert _compute_entity_risk([], [], set()) == "CLEAN"


def test_finding_severity_beats_action_heuristic():
    # A CRITICAL finding upgrades even an otherwise-MEDIUM action set
    assert _compute_entity_risk(["s3:GetObject"], [], {"CRITICAL"}) == "CRITICAL"


def test_entity_is_aws_managed():
    assert _entity_is_aws_managed({
        "arn": "arn:aws:iam::111111111111:role/aws-service-role/foo.amazonaws.com/AWSServiceRoleForFoo",
        "label": "AWSServiceRoleForFoo",
        "principal_type": "role",
        "node_type": "principal",
    })
    assert _entity_is_aws_managed({
        "arn": "arn:aws:iam::123:role/AWSReservedSSO_Admin_abc/x",
        "label": "x",
        "principal_type": "role",
        "node_type": "principal",
    })
    assert _entity_is_aws_managed({
        "arn": "arn:aws:iam::aws:policy/PowerUserAccess",
        "label": "PowerUserAccess",
        "node_type": "policy",
        "policy_type": "aws_managed",
    })
    assert not _entity_is_aws_managed({
        "arn": "arn:aws:iam::111111111111:role/MyRole",
        "label": "MyRole",
        "principal_type": "role",
        "node_type": "principal",
    })


def test_permission_matches_is_prefix_based():
    assert _permission_matches(["iam:assumerole"], "iam:*")
    assert _permission_matches(["iam:assumerolewithsaml"], "iam:assume")
    assert _permission_matches(["s3:getobject"], "s3:GetObject")
    assert not _permission_matches(["s3:getobject"], "iam:PassRole")
    # A literal wildcard action does NOT prefix-match a concrete service query
    assert not _permission_matches(["*"], "s3:*")
    assert not _permission_matches([], "iam:*")


# ─── Index fixture ────────────────────────────────────────────────────────────

def _policy(db, account, name, ptype, actions):
    pol = Policy(
        account_id=account.id,
        arn=f"arn:aws:iam::{account.account_id}:policy/{name}"
        if ptype != "aws_managed"
        else f"arn:aws:iam::aws:policy/{name}",
        name=name,
        policy_type=ptype,
        document_json=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}],
        }),
    )
    db.add(pol)
    return pol


def _principal(db, account, name, ptype, policies=None, arn=None):
    p = Principal(
        account_id=account.id,
        arn=arn or f"arn:aws:iam::{account.account_id}:{ptype}/{name}",
        name=name,
        principal_type=ptype,
    )
    if policies:
        p.policies = policies
    db.add(p)
    return p


def _finding(db, account, entity_arn, name, severity, suppressed=False):
    db.add(SecurityFinding(
        account_id=account.id,
        entity_arn=entity_arn,
        entity_type="role",
        entity_name=name,
        category="TEST",
        path_id=f"TEST-{name}-{severity}",
        severity=severity,
        original_severity=severity,
        message="test finding",
        suppressed=suppressed,
    ))


@pytest.fixture()
def index(db_session, account_a, account_b):
    admin_pol = _policy(db_session, account_a, "AdminPolicy", "managed", ["*"])
    read_pol  = _policy(db_session, account_a, "ReadOnly", "inline", ["s3:GetObject"])
    aws_pol   = _policy(db_session, account_a, "PowerUserAccess", "aws_managed", ["ec2:*"])

    _principal(db_session, account_a, "AdminRole", "role", policies=[admin_pol])
    bob = _principal(db_session, account_a, "Bob", "user", policies=[read_pol])
    _principal(
        db_session, account_a, "AWSServiceRoleForFoo", "role",
        arn="arn:aws:iam::111111111111:role/aws-service-role/foo.amazonaws.com/AWSServiceRoleForFoo",
    )
    finder = _principal(db_session, account_b, "FinderRole", "role")

    db_session.flush()  # assign ids for execution_role FK

    db_session.add(Resource(
        account_id=account_a.id,
        arn="arn:aws:ec2:us-east-1:111111111111:instance/i-123",
        service="ec2",
        resource_type="instance",
        name="i-123",
        region="us-east-1",
        execution_role=bob,
        metadata_json=json.dumps({
            "instance_id": "i-123",
            "private_ip": "10.0.1.5",
            "vpc_id": "vpc-1",
            "MetadataOptions": {"HttpTokens": "optional"},
        }),
    ))
    db_session.add(Resource(
        account_id=account_a.id,
        arn="arn:aws:s3:::my-bucket",
        service="s3",
        resource_type="bucket",
        name="my-bucket",
    ))

    # Non-suppressed CRITICAL finding drives FinderRole risk + path count
    _finding(db_session, account_b, finder.arn, "FinderRole", "CRITICAL")
    # Suppressed finding on Bob must be ignored
    _finding(db_session, account_a, bob.arn, "Bob", "CRITICAL", suppressed=True)

    db_session.commit()
    return EntityIndex.build(db_session)


# ─── Build / facets ───────────────────────────────────────────────────────────

def test_type_counts(index):
    c = index.type_counts
    assert c["role"] == 3
    assert c["user"] == 1
    assert c["policy"] == 3
    assert c["resource"] == 2
    assert c["All"] == 11  # 3 roles + 1 user + 3 policies + 2 resources + 2 accounts


def test_account_facets(index):
    ids = [a["id"] for a in index.accounts]
    assert ids == ["111111111111", "222222222222"]
    assert {a["name"] for a in index.accounts} == {"Account-A", "Account-B"}


def test_action_vocabulary(index):
    assert index.actions_vocab == ["*", "ec2:*", "s3:GetObject"]


# ─── Filtering ────────────────────────────────────────────────────────────────

def test_filter_by_type(index):
    assert index.query(type_key="user", page_size=100)["total"] == 1
    assert index.query(type_key="role", page_size=100)["total"] == 3


def test_filter_by_risk(index):
    assert index.query(risk="CRITICAL", page_size=100)["total"] == 3
    assert index.query(risk="MEDIUM", page_size=100)["total"] == 4
    assert index.query(risk="CLEAN", page_size=100)["total"] == 4


def test_filter_by_service(index):
    res = index.query(service="ec2", page_size=100)
    assert res["total"] == 1
    assert res["items"][0]["arn"].endswith("instance/i-123")


def test_resource_metadata_surfaced(index):
    res = index.query(service="ec2", page_size=100)
    meta = res["items"][0]["metadata"]
    assert meta["private_ip"] == "10.0.1.5"
    assert meta["vpc_id"] == "vpc-1"
    assert meta["MetadataOptions"]["HttpTokens"] == "optional"


def test_filter_by_account(index):
    res = index.query(account_id="222222222222", page_size=100)
    arns = {i.get("node_id") for i in res["items"]}
    assert res["total"] == 2  # FinderRole + account node
    assert "account:222222222222" in arns


def test_filter_by_permission(index):
    # Everything with an s3 action (Bob, ReadOnly policy, ec2 instance via role)
    assert index.query(permissions=["s3:*"], page_size=100)["total"] == 3
    assert index.query(permissions=["iam:PassRole"], page_size=100)["total"] == 0


def test_filter_by_managed(index):
    assert index.query(managed="only", page_size=100)["total"] == 2  # SvcRole + aws policy
    assert index.query(managed="none", page_size=100)["total"] == 0
    assert index.query(managed="exclude", page_size=100)["total"] == 9


def test_search_query(index):
    res = index.query(q="bob", page_size=100)
    assert res["total"] == 1
    assert res["items"][0]["label"] == "Bob"


# ─── Findings-driven risk / paths ─────────────────────────────────────────────

def test_finding_drives_risk_and_paths(index):
    finder = next(i for i in index.query(type_key="role", page_size=100)["items"]
                  if i["label"] == "FinderRole")
    assert finder["risk"] == "CRITICAL"
    assert finder["paths"] == 1


def test_suppressed_finding_ignored(index):
    bob = next(i for i in index.query(type_key="user", page_size=100)["items"]
               if i["label"] == "Bob")
    assert bob["risk"] == "MEDIUM"   # not upgraded by suppressed CRITICAL
    assert bob["paths"] == 0


# ─── Pagination / sorting ─────────────────────────────────────────────────────

def test_pagination_and_risk_ordering(index):
    p1 = index.query(page=1, page_size=3)
    assert p1["total"] == 11
    assert len(p1["items"]) == 3
    # Sorted by risk rank → the first page is all CRITICAL
    assert all(i["risk"] == "CRITICAL" for i in p1["items"])

    p2 = index.query(page=2, page_size=3)
    assert len(p2["items"]) == 3
    # No overlap between pages
    ids1 = {i["node_id"] for i in p1["items"]}
    ids2 = {i["node_id"] for i in p2["items"]}
    assert ids1.isdisjoint(ids2)


def test_page_size_zero_returns_grouped_dump(index):
    grouped = index.grouped()
    assert set(grouped) == {"accounts", "principals", "policies", "resources", "total"}
    assert grouped["total"] == 11
    assert len(grouped["principals"]) == 4
    assert len(grouped["policies"]) == 3
    assert len(grouped["resources"]) == 2
    assert len(grouped["accounts"]) == 2


# ─── Combined filters ─────────────────────────────────────────────────────────

def test_combined_type_and_risk(index):
    # Roles that are CRITICAL: AdminRole (wildcard) + FinderRole (finding)
    res = index.query(type_key="role", risk="CRITICAL", page_size=100)
    assert res["total"] == 2
    assert {i["label"] for i in res["items"]} == {"AdminRole", "FinderRole"}
