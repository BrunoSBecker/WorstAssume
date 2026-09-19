"""
tests/test_attack_path_cross_account.py

Regression tests for the cross-account forward-privesc fix:

  * False positive: a dev-account principal with ``s3:PutBucketPolicy`` on ``*``
    must NOT get an edge to a prod-account bucket whose policy does not admit it.
  * False negative: the legitimate ``ci-runner -> bridge -> data-plane -> read
    PII`` chain must resolve to the bucket via an S3 read edge.

All fixtures use clearly fictitious ARNs and account IDs (111111111111 = dev,
222222222222 = prod). No real credentials or PII.
"""
from __future__ import annotations

from worstassume.core.attack_graph import NeighborContext
from worstassume.core.privilege_escalation import analyze_attack_paths
from worstassume.db.store import (
    link_principal_policy,
    upsert_policy,
    upsert_principal,
    upsert_resource,
)


# ── helpers ──────────────────────────────────────────────────────────────────

def _role(db, account, name, actions, trust_policy=None):
    arn = f"arn:aws:iam::{account.account_id}:role/{name}"
    role = upsert_principal(db, account, arn=arn, name=name,
                            principal_type="role", trust_policy=trust_policy)
    if actions:
        doc = {"Version": "2012-10-17",
               "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}
        pol = upsert_policy(db, account, arn=f"{arn}:inline/p", name=f"{name}-p",
                            policy_type="inline", document=doc)
        link_principal_policy(db, role, pol)
    db.commit()
    return role


def _user(db, account, name, actions):
    arn = f"arn:aws:iam::{account.account_id}:user/{name}"
    user = upsert_principal(db, account, arn=arn, name=name, principal_type="user")
    doc = {"Version": "2012-10-17",
           "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}
    pol = upsert_policy(db, account, arn=f"{arn}:inline/p", name=f"{name}-p",
                        policy_type="inline", document=doc)
    link_principal_policy(db, user, pol)
    db.commit()
    return user


def _bucket(db, account, name, policy=None):
    arn = f"arn:aws:s3:::{name}"
    meta = {"policy": policy} if policy else None
    r = upsert_resource(db, account, arn=arn, service="s3", resource_type="bucket",
                        name=name, region="us-east-1", metadata=meta)
    db.commit()
    return r


def _svc_trust(service):
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": service},
         "Action": "sts:AssumeRole"}]}


def _aws_trust(*arns):
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": list(arns)},
         "Action": "sts:AssumeRole"}]}


def _bucket_policy(principal_arn, actions):
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": principal_arn},
         "Action": actions, "Resource": "*"}]}


def _neighbor_edges(db, from_arn):
    """{(target_arn, edge_type)} reachable in one hop from from_arn."""
    ctx = NeighborContext(db)
    return {(t, d["edge_type"]) for t, d in ctx.get_neighbors(from_arn)}


# ── the reported bug ─────────────────────────────────────────────────────────

def _build_lab(db, dev, prod):
    """The demo-lab shape: dev ci-runner + lambda-exec, prod bridge/data-plane/PII."""
    ci = _user(db, dev, "ci-runner",
               ["sts:AssumeRole", "iam:PassRole", "lambda:CreateFunction",
                "lambda:UpdateFunctionCode"])
    lambda_exec = _role(db, dev, "lambda-exec", ["s3:PutBucketPolicy"],
                        trust_policy=_svc_trust("lambda.amazonaws.com"))
    # A dev Lambda whose execution role is lambda-exec — makes ci-runner able to
    # reach lambda-exec (passrole/create), the head of the old false path.
    upsert_resource(db, dev, arn=f"arn:aws:lambda:us-east-1:{dev.account_id}:function:proc",
                    service="lambda", resource_type="function", name="proc",
                    region="us-east-1", execution_role=lambda_exec)
    db.commit()

    bridge = _role(db, prod, "bridge", ["sts:AssumeRole"],
                   trust_policy=_aws_trust(ci.arn))
    data_plane = _role(db, prod, "data-plane", ["s3:GetObject", "s3:ListBucket"],
                       trust_policy=_aws_trust(bridge.arn))
    pii = _bucket(db, prod, "prod-pii",
                  policy=_bucket_policy(data_plane.arn, ["s3:GetObject", "s3:ListBucket"]))
    return ci, lambda_exec, bridge, data_plane, pii


def test_legit_cross_account_read_path_resolves(db_session, account_a, account_b):
    ci, _lx, _br, data_plane, pii = _build_lab(db_session, account_a, account_b)

    paths = analyze_attack_paths(db_session, from_arn=ci.arn,
                                 objective=f"resource:{pii.arn}", persist_paths=False)

    to_pii = [p for p in paths if p.to_arn == pii.arn]
    assert to_pii, "expected at least one path from ci-runner to the PII bucket"
    # The winning path ends with data-plane reading the bucket.
    read_paths = [
        p for p in to_pii
        if any(s["edge_type"] in ("s3_object_read", "s3_bucket_read")
               and s["actor"] == data_plane.arn for s in p.steps)
    ]
    assert read_paths, "expected a data-plane -> PII S3 read step"


def test_cross_account_putbucketpolicy_false_positive_is_gone(db_session, account_a, account_b):
    ci, lambda_exec, _br, _dp, pii = _build_lab(db_session, account_a, account_b)

    paths = analyze_attack_paths(db_session, from_arn=ci.arn,
                                 objective=f"resource:{pii.arn}", persist_paths=False)

    for p in paths:
        for s in p.steps:
            # No cross-account bucket-policy takeover of the prod bucket …
            assert not (s["edge_type"] == "s3_bucket_policy_abuse"
                        and s["target"] == pii.arn), \
                "cross-account s3_bucket_policy_abuse false positive resurfaced"
            # … and nothing reaches the bucket by routing through dev lambda-exec.
            assert not (s["actor"] == lambda_exec.arn and s["target"] == pii.arn), \
                "path to PII incorrectly routes through dev lambda-exec"


# ── focused gate unit tests on NeighborContext ───────────────────────────────

def test_cross_account_putbucketpolicy_dropped_without_bucket_policy(db_session, account_a, account_b):
    attacker = _user(db_session, account_a, "dev-writer", ["s3:PutBucketPolicy"])
    bucket = _bucket(db_session, account_b, "prod-bkt")  # no resource policy
    edges = _neighbor_edges(db_session, attacker.arn)
    assert (bucket.arn, "s3_bucket_policy_abuse") not in edges


def test_cross_account_putbucketpolicy_present_when_admitted(db_session, account_a, account_b):
    attacker = _user(db_session, account_a, "dev-writer", ["s3:PutBucketPolicy"])
    bucket = _bucket(db_session, account_b, "prod-bkt",
                     policy=_bucket_policy(attacker.arn, ["s3:PutBucketPolicy"]))
    edges = _neighbor_edges(db_session, attacker.arn)
    assert (bucket.arn, "s3_bucket_policy_abuse") in edges


def test_cross_account_read_dropped_without_bucket_policy(db_session, account_a, account_b):
    attacker = _user(db_session, account_a, "dev-reader", ["s3:GetObject"])
    bucket = _bucket(db_session, account_b, "prod-bkt")  # no resource policy
    edges = _neighbor_edges(db_session, attacker.arn)
    assert (bucket.arn, "s3_object_read") not in edges


def test_cross_account_read_present_when_admitted(db_session, account_a, account_b):
    attacker = _user(db_session, account_a, "dev-reader", ["s3:GetObject"])
    bucket = _bucket(db_session, account_b, "prod-bkt",
                     policy=_bucket_policy(attacker.arn, ["s3:GetObject"]))
    edges = _neighbor_edges(db_session, attacker.arn)
    assert (bucket.arn, "s3_object_read") in edges


def test_same_account_read_needs_no_resource_policy(db_session, account_a):
    attacker = _user(db_session, account_a, "reader", ["s3:GetObject"])
    bucket = _bucket(db_session, account_a, "same-acct-bkt")  # no resource policy
    edges = _neighbor_edges(db_session, attacker.arn)
    assert (bucket.arn, "s3_object_read") in edges


# ── resources are privesc path hops (runs_as) ────────────────────────────────

def _lambda_fn(db, account, name, exec_role):
    arn = f"arn:aws:lambda:us-east-1:{account.account_id}:function:{name}"
    r = upsert_resource(db, account, arn=arn, service="lambda", resource_type="function",
                        name=name, region="us-east-1", execution_role=exec_role)
    db.commit()
    return r


def test_lambda_function_is_a_reachable_privesc_target(db_session, account_a):
    exec_role = _role(db_session, account_a, "lambda-exec", ["iam:AttachUserPolicy"],
                      trust_policy=_svc_trust("lambda.amazonaws.com"))
    fn = _lambda_fn(db_session, account_a, "proc", exec_role)
    attacker = _user(db_session, account_a, "ci", ["lambda:UpdateFunctionCode"])

    paths = analyze_attack_paths(db_session, from_arn=attacker.arn,
                                 objective=f"resource:{fn.arn}", persist_paths=False)
    assert any(p.to_arn == fn.arn for p in paths), \
        "the compromised Lambda function must be a reachable target"
    assert any(s["edge_type"] in ("lambda_code_overwrite", "lambda_layer_inject")
               for p in paths for s in p.steps)


def test_function_runs_as_pivots_to_its_execution_role(db_session, account_a):
    exec_role = _role(db_session, account_a, "lambda-exec", ["iam:AttachUserPolicy"],
                      trust_policy=_svc_trust("lambda.amazonaws.com"))
    fn = _lambda_fn(db_session, account_a, "proc", exec_role)
    _user(db_session, account_a, "ci", ["lambda:UpdateFunctionCode"])

    ctx = NeighborContext(db_session)
    edges = {(t, d["edge_type"]) for t, d in ctx.get_neighbors(fn.arn)}
    assert (exec_role.arn, "runs_as") in edges, \
        "a resource must pivot to the execution role it runs as"
