"""
tests/test_reverse_index.py — ReverseIndex parity, scoping and ranking.

The parity suite is the important one: it asserts that reverse_neighbors()
returns exactly the in-edges of build_access_graph() for every node. As long as
it holds, the demand-driven engine and the forward graph cannot drift apart.

All fixtures use clearly fictitious ARNs and account IDs.
"""

from __future__ import annotations

import pytest

from worstassume.core.attack_graph import NeighborContext, build_access_graph
from worstassume.core.reverse_index import ReverseIndex
from worstassume.db.store import (
    link_principal_policy,
    upsert_cross_account_link,
    upsert_policy,
    upsert_principal,
    upsert_resource,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers (mirrors tests/test_attack_graph.py)
# ─────────────────────────────────────────────────────────────────────────────

def _make_role(db, account, name, actions, trust_policy=None):
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


def _make_user(db, account, name, actions):
    arn = f"arn:aws:iam::{account.account_id}:user/{name}"
    user = upsert_principal(db, account, arn=arn, name=name, principal_type="user")
    if actions:
        doc = {"Version": "2012-10-17",
               "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}
        pol = upsert_policy(db, account, arn=f"{arn}:inline/p", name=f"{name}-p",
                            policy_type="inline", document=doc)
        link_principal_policy(db, user, pol)
    db.commit()
    return user


def _make_resource(db, account, service, rtype, name, role=None, metadata=None):
    arn = f"arn:aws:{service}:us-east-1:{account.account_id}:{rtype}/{name}"
    r = upsert_resource(db, account, arn=arn, service=service, resource_type=rtype,
                        name=name, region="us-east-1", execution_role=role,
                        metadata=metadata)
    db.commit()
    return r


def _trust(*principal_arns):
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": list(principal_arns)},
         "Action": "sts:AssumeRole"},
    ]}


def _index(db, account=None):
    ctx = NeighborContext(db, account=account)
    return ctx, ReverseIndex(ctx)


def _forward_in_edges(G, arn):
    """Multiset of inbound (source, edge_type, action, severity) tuples."""
    out = []
    for u, v, d in G.in_edges(arn, data=True):
        out.append((u, d["edge_type"], d["action"], d["severity"]))
    return sorted(out)


def _reverse_in_edges(ridx, arn):
    return sorted(
        (src, d["edge_type"], d["action"], d["severity"])
        for src, d in ridx.reverse_neighbors(arn)
    )


def _assert_parity(db, account=None):
    """reverse_neighbors() must reproduce build_access_graph()'s in-edges."""
    G = build_access_graph(db, account=account)
    ctx, ridx = _index(db, account=account)
    checked = 0
    for node in G.nodes():
        fwd = _forward_in_edges(G, node)
        rev = _reverse_in_edges(ridx, node)
        # defensive_blind is a self-loop on the actor; the reverse engine drops
        # it deliberately, so exclude it from the forward side too.
        fwd = [e for e in fwd if e[1] != "defensive_blind"]
        assert rev == fwd, f"parity mismatch on {node}:\n forward={fwd}\n reverse={rev}"
        checked += 1
    assert checked > 0
    return G


# ─────────────────────────────────────────────────────────────────────────────
# Parity
# ─────────────────────────────────────────────────────────────────────────────

class TestReverseParity:
    def test_assume_role_chain(self, db_session, account_a):
        pivot = _make_role(db_session, account_a, "Pivot", ["s3:GetObject"])
        _make_role(db_session, account_a, "Attacker", ["sts:AssumeRole"],
                   trust_policy=None)
        attacker_arn = f"arn:aws:iam::{account_a.account_id}:role/Attacker"
        pivot.trust_policy_json = None
        # Rebuild Pivot with a trust policy naming the attacker
        _make_role(db_session, account_a, "Pivot", ["s3:GetObject"],
                   trust_policy=_trust(attacker_arn))
        _assert_parity(db_session, account_a)

    def test_account_root_trust_expands(self, db_session, account_a):
        _make_role(db_session, account_a, "Caller", ["sts:AssumeRole"])
        _make_user(db_session, account_a, "Human", ["sts:AssumeRole"])
        _make_role(db_session, account_a, "Wide", [],
                   trust_policy=_trust(f"arn:aws:iam::{account_a.account_id}:root"))
        G = _assert_parity(db_session, account_a)
        wide = f"arn:aws:iam::{account_a.account_id}:role/Wide"
        sources = {u for u, _v, d in G.in_edges(wide, data=True)
                   if d["edge_type"] == "assume_role"}
        assert sources == {
            f"arn:aws:iam::{account_a.account_id}:role/Caller",
            f"arn:aws:iam::{account_a.account_id}:user/Human",
        }

    def test_wildcard_trust_expands(self, db_session, account_a):
        _make_role(db_session, account_a, "Caller", ["sts:AssumeRole"])
        _make_role(db_session, account_a, "Open", [],
                   trust_policy={"Version": "2012-10-17", "Statement": [
                       {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]})
        _assert_parity(db_session, account_a)

    def test_cross_account_assume(self, db_session, account_a, account_b):
        caller = _make_role(db_session, account_a, "Caller", ["sts:AssumeRole"])
        _make_role(db_session, account_b, "Target", [], trust_policy=_trust(caller.arn))
        _assert_parity(db_session)

    def test_cross_account_link_table(self, db_session, account_a, account_b):
        caller = _make_role(db_session, account_a, "Caller", [])
        role_arn = f"arn:aws:iam::{account_b.account_id}:role/CrossRole"
        _make_role(db_session, account_b, "CrossRole", [])
        upsert_cross_account_link(db_session, source_account=account_a,
                                  target_account=account_b, role_arn=role_arn,
                                  trust_principal_arn=caller.arn, is_wildcard=True)
        db_session.commit()
        _assert_parity(db_session)

    def test_passrole_lambda(self, db_session, account_a):
        exec_role = _make_role(db_session, account_a, "LambdaExec", [], trust_policy={
            "Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                 "Action": "sts:AssumeRole"}]})
        _make_resource(db_session, account_a, "lambda", "function", "fn", role=exec_role)
        _make_role(db_session, account_a, "Deployer",
                   ["iam:PassRole", "lambda:CreateFunction"])
        _assert_parity(db_session, account_a)

    def test_passrole_scoped_by_resource_pattern(self, db_session, account_a):
        """A PassRole grant scoped to one role must not reach another."""
        trust = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
             "Action": "sts:AssumeRole"}]}
        allowed = _make_role(db_session, account_a, "AllowedExec", [], trust_policy=trust)
        other = _make_role(db_session, account_a, "OtherExec", [], trust_policy=trust)
        _make_resource(db_session, account_a, "lambda", "function", "a", role=allowed)
        _make_resource(db_session, account_a, "lambda", "function", "b", role=other)
        arn = f"arn:aws:iam::{account_a.account_id}:role/Scoped"
        principal = upsert_principal(db_session, account_a, arn=arn, name="Scoped",
                                     principal_type="role")
        doc = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": allowed.arn},
            {"Effect": "Allow", "Action": "lambda:CreateFunction", "Resource": "*"},
        ]}
        pol = upsert_policy(db_session, account_a, arn=f"{arn}:inline/p", name="p",
                            policy_type="inline", document=doc)
        link_principal_policy(db_session, principal, pol)
        db_session.commit()

        _assert_parity(db_session, account_a)
        _ctx, ridx = _index(db_session, account_a)
        assert any(src == arn for src, _d in ridx.reverse_neighbors(allowed.arn))
        assert not any(src == arn for src, _d in ridx.reverse_neighbors(other.arn))

    def test_resource_abuse_lambda(self, db_session, account_a):
        exec_role = _make_role(db_session, account_a, "FnRole", [])
        _make_resource(db_session, account_a, "lambda", "function", "fn", role=exec_role)
        _make_role(db_session, account_a, "Abuser", ["lambda:UpdateFunctionCode"])
        _assert_parity(db_session, account_a)

    def test_secret_harvest_and_ssm_lateral(self, db_session, account_a):
        inst_role = _make_role(db_session, account_a, "InstRole", [])
        _make_resource(db_session, account_a, "ec2", "instance", "i-1", role=inst_role,
                       metadata={"MetadataOptions": {"HttpTokens": "optional"}})
        _make_resource(db_session, account_a, "secretsmanager", "secret", "db-creds")
        _make_role(db_session, account_a, "Harvester",
                   ["ssm:SendCommand", "secretsmanager:GetSecretValue"])
        _assert_parity(db_session, account_a)

    def test_defensive_blind_is_not_a_self_neighbour(self, db_session, account_a):
        blinder = _make_role(db_session, account_a, "Blinder", ["cloudtrail:StopLogging"])
        _ctx, ridx = _index(db_session, account_a)
        assert not any(src == blinder.arn
                       for src, _d in ridx.reverse_neighbors(blinder.arn))

    def test_mixed_environment_parity(self, db_session, account_a, account_b):
        """Several families at once — the realistic case."""
        lam_trust = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
             "Action": "sts:AssumeRole"}]}
        exec_role = _make_role(db_session, account_a, "Exec", ["s3:GetObject"],
                               trust_policy=lam_trust)
        _make_resource(db_session, account_a, "lambda", "function", "fn", role=exec_role)
        _make_resource(db_session, account_a, "s3", "bucket", "pii")
        inst_role = _make_role(db_session, account_a, "InstRole", [])
        _make_resource(db_session, account_a, "ec2", "instance", "i-1", role=inst_role,
                       metadata={"MetadataOptions": {"HttpTokens": "optional"}})
        _make_resource(db_session, account_a, "secretsmanager", "secret", "s1")
        admin = _make_role(db_session, account_a, "Admin", ["*"])
        _make_user(db_session, account_a, "Dev",
                   ["sts:AssumeRole", "lambda:UpdateFunctionCode", "s3:PutBucketPolicy"])
        _make_role(db_session, account_b, "Partner", ["sts:AssumeRole"])
        _make_role(db_session, account_a, "Shared", [],
                   trust_policy=_trust(admin.arn,
                                       f"arn:aws:iam::{account_b.account_id}:root"))
        _assert_parity(db_session)


# ─────────────────────────────────────────────────────────────────────────────
# Scoping — the false-positive fan-out fixes
# ─────────────────────────────────────────────────────────────────────────────

class TestAbuseRuleScoping:
    def test_put_bucket_policy_only_targets_buckets(self, db_session, account_a):
        bucket = _make_resource(db_session, account_a, "s3", "bucket", "pii")
        table = _make_resource(db_session, account_a, "dynamodb", "table", "orders")
        abuser = _make_role(db_session, account_a, "Abuser", ["s3:PutBucketPolicy"])
        _ctx, ridx = _index(db_session, account_a)

        assert any(src == abuser.arn and d["edge_type"] == "s3_bucket_policy_abuse"
                   for src, d in ridx.reverse_neighbors(bucket.arn))
        assert not any(d["edge_type"] == "s3_bucket_policy_abuse"
                       for _src, d in ridx.reverse_neighbors(table.arn))

    def test_instance_connect_only_targets_instances(self, db_session, account_a):
        inst = _make_resource(db_session, account_a, "ec2", "instance", "i-1")
        bucket = _make_resource(db_session, account_a, "s3", "bucket", "logs")
        abuser = _make_role(db_session, account_a, "Abuser",
                            ["ec2-instance-connect:SendSSHPublicKey"])
        _ctx, ridx = _index(db_session, account_a)

        assert any(src == abuser.arn and d["edge_type"] == "ec2_instance_connect"
                   for src, d in ridx.reverse_neighbors(inst.arn))
        assert not any(d["edge_type"] == "ec2_instance_connect"
                       for _src, d in ridx.reverse_neighbors(bucket.arn))

    def test_imds_requires_a_landing_action(self, db_session, account_a):
        role = _make_role(db_session, account_a, "InstRole", [])
        _make_resource(db_session, account_a, "ec2", "instance", "i-1", role=role,
                       metadata={"MetadataOptions": {"HttpTokens": "optional"}})
        _make_role(db_session, account_a, "Bystander", ["s3:GetObject"])
        lander = _make_role(db_session, account_a, "Lander", ["ssm:SendCommand"])
        _ctx, ridx = _index(db_session, account_a)

        imds_sources = {src for src, d in ridx.reverse_neighbors(role.arn)
                        if d["edge_type"] == "imds_steal"}
        assert imds_sources == {lander.arn}


# ─────────────────────────────────────────────────────────────────────────────
# inbound_page — family union, ranking, paging
# ─────────────────────────────────────────────────────────────────────────────

def _bucket_with_policy(db, account, name, policy):
    arn = f"arn:aws:s3:::{name}"
    r = upsert_resource(db, account, arn=arn, service="s3", resource_type="bucket",
                        name=name, region="us-east-1",
                        metadata={"policy": policy})
    db.commit()
    return r


class TestInboundPage:
    def test_three_families_are_unioned(self, db_session, account_a):
        """One accessor per family must show up, each tagged correctly."""
        external_arn = "arn:aws:iam::999999999999:role/PartnerReader"
        bucket = _bucket_with_policy(db_session, account_a, "crown-jewels", {
            "Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Principal": {"AWS": external_arn},
                 "Action": "s3:GetObject", "Resource": "arn:aws:s3:::crown-jewels/*"},
            ]})
        reader = _make_role(db_session, account_a, "Reader", ["s3:GetObject"])
        abuser = _make_role(db_session, account_a, "Abuser", ["s3:PutBucketPolicy"])

        _ctx, ridx = _index(db_session, account_a)
        page = ridx.inbound_page(bucket.arn)
        by_arn = {n.arn: n for n in page.neighbors}

        assert {e.family for e in by_arn[reader.arn].edges} == {"identity_policy"}
        assert {e.family for e in by_arn[external_arn].edges} == {"resource_policy"}
        assert "abuse" in {e.family for e in by_arn[abuser.arn].edges}
        assert page.total_found == len(page.neighbors)
        assert page.truncated is False

    def test_family_filter_narrows_results(self, db_session, account_a):
        bucket = _make_resource(db_session, account_a, "s3", "bucket", "data")
        _make_role(db_session, account_a, "Reader", ["s3:GetObject"])
        abuser = _make_role(db_session, account_a, "Abuser", ["s3:PutBucketPolicy"])

        _ctx, ridx = _index(db_session, account_a)
        page = ridx.inbound_page(bucket.arn, families=("abuse",))
        assert {n.arn for n in page.neighbors} == {abuser.arn}
        assert all(e.family == "abuse" for n in page.neighbors for e in n.edges)

    def test_external_accessor_ranks_first(self, db_session, account_a):
        external_arn = "arn:aws:iam::999999999999:role/PartnerReader"
        bucket = _bucket_with_policy(db_session, account_a, "ranked", {
            "Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Principal": {"AWS": external_arn},
                 "Action": "s3:GetObject", "Resource": "arn:aws:s3:::ranked/*"}]})
        _make_role(db_session, account_a, "Reader", ["s3:GetObject"])

        _ctx, ridx = _index(db_session, account_a)
        page = ridx.inbound_page(bucket.arn)
        assert page.neighbors[0].arn == external_arn
        assert page.neighbors[0].external is True

    def test_public_wildcard_is_flagged_external(self, db_session, account_a):
        bucket = _bucket_with_policy(db_session, account_a, "public", {
            "Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                 "Resource": "arn:aws:s3:::public/*"}]})
        _ctx, ridx = _index(db_session, account_a)
        page = ridx.inbound_page(bucket.arn)
        star = next(n for n in page.neighbors if n.arn == "*")
        assert star.external is True
        assert star.node_type == "wildcard"

    def test_paging_is_stable_and_non_overlapping(self, db_session, account_a):
        bucket = _make_resource(db_session, account_a, "s3", "bucket", "many")
        for i in range(12):
            _make_role(db_session, account_a, f"Reader{i:02d}", ["s3:GetObject"])

        _ctx, ridx = _index(db_session, account_a)
        full = ridx.inbound_page(bucket.arn, limit=0)
        first = ridx.inbound_page(bucket.arn, limit=5, offset=0)
        second = ridx.inbound_page(bucket.arn, limit=5, offset=5)

        assert first.total_found == second.total_found == full.total_found == 12
        assert first.truncated is True
        assert [n.arn for n in first.neighbors] == [n.arn for n in full.neighbors[:5]]
        assert [n.arn for n in second.neighbors] == [n.arn for n in full.neighbors[5:10]]
        assert not set(n.arn for n in first.neighbors) & set(n.arn for n in second.neighbors)

    def test_target_is_never_its_own_neighbour(self, db_session, account_a):
        role = _make_role(db_session, account_a, "Selfy",
                          ["cloudtrail:StopLogging", "iam:PutRolePolicy"])
        _ctx, ridx = _index(db_session, account_a)
        page = ridx.inbound_page(role.arn)
        assert role.arn not in {n.arn for n in page.neighbors}

    def test_identity_accessors_match_the_reference_implementation(
            self, db_session, account_a):
        """The indexed fast path must agree with threat_model.direct_accessors."""
        from worstassume.core.threat_model import direct_accessors

        bucket = _make_resource(db_session, account_a, "s3", "bucket", "parity")
        _make_role(db_session, account_a, "Reader", ["s3:GetObject"])
        _make_role(db_session, account_a, "Admin", ["*"])
        _make_user(db_session, account_a, "Denied", ["s3:*"])
        _make_role(db_session, account_a, "Unrelated", ["dynamodb:GetItem"])

        ctx, ridx = _index(db_session, account_a)
        expected = direct_accessors(ctx, bucket.arn, "resource")
        actual = ridx.identity_accessors(bucket.arn, "resource")
        assert [(a.arn, a.actions) for a in actual] == \
               [(a.arn, a.actions) for a in expected]

    def test_deny_is_honoured_through_the_index(self, db_session, account_a):
        """A Deny in a bucket the service filter would skip must still apply."""
        bucket = _make_resource(db_session, account_a, "s3", "bucket", "denied")
        arn = f"arn:aws:iam::{account_a.account_id}:role/Blocked"
        p = upsert_principal(db_session, account_a, arn=arn, name="Blocked",
                             principal_type="role")
        doc = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
            {"Effect": "Deny", "Action": "*", "Resource": bucket.arn},
        ]}
        pol = upsert_policy(db_session, account_a, arn=f"{arn}:inline/p", name="p",
                            policy_type="inline", document=doc)
        link_principal_policy(db_session, p, pol)
        db_session.commit()

        _ctx, ridx = _index(db_session, account_a)
        assert arn not in {a.arn for a in ridx.identity_accessors(bucket.arn, "resource")}


class TestExpandHops:
    def test_two_hops_reaches_the_grandparent(self, db_session, account_a):
        bucket = _make_resource(db_session, account_a, "s3", "bucket", "target")
        reader = _make_role(db_session, account_a, "Reader", ["s3:GetObject"])
        pivot = _make_role(db_session, account_a, "Pivot", ["sts:AssumeRole"])
        # Reader trusts Pivot, so Pivot reaches the bucket in two hops.
        _make_role(db_session, account_a, "Reader", ["s3:GetObject"],
                   trust_policy=_trust(pivot.arn))

        _ctx, ridx = _index(db_session, account_a)
        pages = ridx.expand_hops(bucket.arn, hops=2)
        reached = {n.arn for page in pages for n in page.neighbors}
        assert reader.arn in reached
        assert pivot.arn in reached

    def test_node_budget_caps_expansion(self, db_session, account_a):
        bucket = _make_resource(db_session, account_a, "s3", "bucket", "wide")
        for i in range(20):
            _make_role(db_session, account_a, f"R{i:02d}", ["s3:GetObject"])

        _ctx, ridx = _index(db_session, account_a)
        pages = ridx.expand_hops(bucket.arn, hops=3, node_budget=5)
        reached = {n.arn for page in pages for n in page.neighbors}
        assert len(reached) <= 5


class TestReverseReachabilityEquivalence:
    def test_index_and_graph_paths_agree(self, db_session, account_a, account_b):
        """The indexed BFS must match the legacy nx.reverse BFS."""
        from worstassume.core.threat_model import reverse_reachability

        lam_trust = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
             "Action": "sts:AssumeRole"}]}
        exec_role = _make_role(db_session, account_a, "Exec", ["s3:GetObject"],
                               trust_policy=lam_trust)
        _make_resource(db_session, account_a, "lambda", "function", "fn", role=exec_role)
        deployer = _make_role(db_session, account_a, "Deployer",
                              ["iam:PassRole", "lambda:CreateFunction"])
        _make_role(db_session, account_a, "Pivot", ["sts:AssumeRole"])
        pivot_arn = f"arn:aws:iam::{account_a.account_id}:role/Pivot"
        _make_role(db_session, account_a, "Deployer",
                   ["iam:PassRole", "lambda:CreateFunction"],
                   trust_policy=_trust(pivot_arn))
        _make_role(db_session, account_b, "Partner", ["sts:AssumeRole"])

        seeds = {exec_role.arn}
        G = build_access_graph(db_session)
        _ctx, ridx = _index(db_session)

        via_graph = reverse_reachability(seeds, max_hops=5, graph=G)
        via_index = reverse_reachability(seeds, max_hops=5, index=ridx)

        assert {a.arn for a in via_index} == {a.arn for a in via_graph}
        assert {(a.arn, a.hops) for a in via_index} == \
               {(a.arn, a.hops) for a in via_graph}
        assert deployer.arn in {a.arn for a in via_index}
        assert pivot_arn in {a.arn for a in via_index}

    def test_hop_cap_is_respected(self, db_session, account_a):
        from worstassume.core.threat_model import reverse_reachability

        target = _make_role(db_session, account_a, "Target", [])
        mid = _make_role(db_session, account_a, "Mid", ["sts:AssumeRole"])
        _make_role(db_session, account_a, "Target", [], trust_policy=_trust(mid.arn))
        far = _make_role(db_session, account_a, "Far", ["sts:AssumeRole"])
        _make_role(db_session, account_a, "Mid", ["sts:AssumeRole"],
                   trust_policy=_trust(far.arn))

        _ctx, ridx = _index(db_session, account_a)
        one = reverse_reachability({target.arn}, max_hops=1, index=ridx)
        two = reverse_reachability({target.arn}, max_hops=2, index=ridx)
        assert {a.arn for a in one} == {mid.arn}
        assert {a.arn for a in two} == {mid.arn, far.arn}


# ─────────────────────────────────────────────────────────────────────────────
# Cross-account gating
#
# AWS evaluates cross-account access from both sides. An identity policy in
# account B granting s3:* on * says nothing about a bucket in account A unless
# the bucket policy also admits B. Every test here uses two fictitious accounts.
# ─────────────────────────────────────────────────────────────────────────────

def _bucket(db, account, name, policy=None):
    arn = f"arn:aws:s3:::{name}"
    r = upsert_resource(db, account, arn=arn, service="s3", resource_type="bucket",
                        name=name, region="us-east-1",
                        metadata={"policy": policy} if policy else None)
    db.commit()
    return r


def _allow_principal(principal_arn, action="s3:GetObject", resource="*"):
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": principal_arn},
         "Action": action, "Resource": resource}]}


class TestCrossAccountGate:
    def test_foreign_admin_is_not_an_accessor(self, db_session, account_a, account_b):
        """The reported bug: an admin role in another account with no bucket
        policy granting it access must not show up at all."""
        bucket = _bucket(db_session, account_a, "pii-a")
        local = _make_role(db_session, account_a, "LocalReader", ["s3:GetObject"])
        foreign = _make_role(db_session, account_b, "ForeignAdmin", ["*"])

        _ctx, ridx = _index(db_session)
        page = ridx.inbound_page(bucket.arn)
        arns = {n.arn for n in page.neighbors}

        assert local.arn in arns
        assert foreign.arn not in arns
        assert page.filtered_cross_account >= 1

    def test_root_grant_in_the_bucket_policy_admits_the_account(
            self, db_session, account_a, account_b):
        bucket = _bucket(db_session, account_a, "shared-a",
                         policy=_allow_principal(
                             f"arn:aws:iam::{account_b.account_id}:root"))
        foreign = _make_role(db_session, account_b, "ForeignAdmin", ["*"])

        _ctx, ridx = _index(db_session)
        page = ridx.inbound_page(bucket.arn)
        by_arn = {n.arn: n for n in page.neighbors}

        assert foreign.arn in by_arn
        assert "identity_policy" in {e.family for e in by_arn[foreign.arn].edges}
        assert page.filtered_cross_account == 0

    def test_exact_principal_grant_admits_only_that_principal(
            self, db_session, account_a, account_b):
        named_arn = f"arn:aws:iam::{account_b.account_id}:role/Named"
        bucket = _bucket(db_session, account_a, "narrow-a",
                         policy=_allow_principal(named_arn))
        _make_role(db_session, account_b, "Named", ["s3:GetObject"])
        other = _make_role(db_session, account_b, "Other", ["s3:GetObject"])

        _ctx, ridx = _index(db_session)
        arns = {n.arn for n in ridx.inbound_page(bucket.arn).neighbors}

        assert named_arn in arns
        assert other.arn not in arns

    def test_public_bucket_admits_everyone(self, db_session, account_a, account_b):
        bucket = _bucket(db_session, account_a, "public-a", policy={
            "Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                 "Resource": "arn:aws:s3:::public-a/*"}]})
        foreign = _make_role(db_session, account_b, "ForeignReader", ["s3:GetObject"])

        _ctx, ridx = _index(db_session)
        arns = {n.arn for n in ridx.inbound_page(bucket.arn).neighbors}
        assert foreign.arn in arns
        assert "*" in arns

    def test_same_account_needs_no_resource_policy(self, db_session, account_a):
        bucket = _bucket(db_session, account_a, "local-only")
        reader = _make_role(db_session, account_a, "Reader", ["s3:GetObject"])

        _ctx, ridx = _index(db_session, account_a)
        page = ridx.inbound_page(bucket.arn)
        assert reader.arn in {n.arn for n in page.neighbors}
        assert page.filtered_cross_account == 0

    def test_cross_account_assume_role_still_shows(self, db_session, account_a,
                                                   account_b):
        """Trust-policy-backed edges are exempt — the trust policy *is* the
        target-side grant."""
        caller = _make_role(db_session, account_b, "Caller", ["sts:AssumeRole"])
        target = _make_role(db_session, account_a, "Target", [],
                            trust_policy=_trust(caller.arn))

        _ctx, ridx = _index(db_session)
        by_arn = {n.arn: n for n in ridx.inbound_page(target.arn).neighbors}
        assert caller.arn in by_arn
        assert any(e.edge_type == "cross_account_assume"
                   for e in by_arn[caller.arn].edges)

    def test_cross_account_passrole_is_dropped(self, db_session, account_a,
                                               account_b):
        """iam:PassRole cannot pass a role in another account."""
        trust = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
             "Action": "sts:AssumeRole"}]}
        exec_role = _make_role(db_session, account_a, "Exec", [], trust_policy=trust)
        _make_resource(db_session, account_a, "lambda", "function", "fn",
                       role=exec_role)
        local = _make_role(db_session, account_a, "LocalDeployer",
                           ["iam:PassRole", "lambda:CreateFunction"])
        foreign = _make_role(db_session, account_b, "ForeignDeployer",
                             ["iam:PassRole", "lambda:CreateFunction"])

        _ctx, ridx = _index(db_session)
        arns = {n.arn for n in ridx.inbound_page(exec_role.arn).neighbors}
        assert local.arn in arns
        assert foreign.arn not in arns

    def test_unknown_target_account_is_not_gated(self, db_session, account_a,
                                                 account_b):
        """If we cannot tell who owns the target we must not silently hide
        everything — unknown is not the same as denied."""
        _make_role(db_session, account_a, "Local", ["dynamodb:GetItem"])
        _make_role(db_session, account_b, "Foreign", ["dynamodb:GetItem"])

        _ctx, ridx = _index(db_session)
        page = ridx.inbound_page(
            "arn:aws:dynamodb:us-east-1:999999999999:table/untracked")
        assert page.filtered_cross_account == 0
        assert len(page.neighbors) == 2


class TestAbuseOnResource:
    def test_lambda_with_exec_role_reports_its_own_abusers(self, db_session,
                                                           account_a):
        """The forward graph points lambda_code_overwrite at the execution role,
        which left "who can overwrite this function" unanswerable."""
        exec_role = _make_role(db_session, account_a, "FnRole", [])
        fn = _make_resource(db_session, account_a, "lambda", "function", "fn",
                            role=exec_role)
        abuser = _make_role(db_session, account_a, "Abuser",
                            ["lambda:UpdateFunctionCode"])

        _ctx, ridx = _index(db_session, account_a)

        # Still reported against the execution role (credential flow, unchanged)
        assert abuser.arn in {n.arn for n in ridx.inbound_page(exec_role.arn).neighbors}
        # …and now also against the function itself
        by_arn = {n.arn: n for n in ridx.inbound_page(fn.arn).neighbors}
        assert abuser.arn in by_arn
        assert any(e.edge_type == "lambda_code_overwrite"
                   for e in by_arn[abuser.arn].edges)

    def test_reverse_neighbors_is_unchanged(self, db_session, account_a):
        """The new index must not leak into reverse_neighbors — the parity test
        depends on it staying a faithful inverse of the forward graph."""
        exec_role = _make_role(db_session, account_a, "FnRole", [])
        fn = _make_resource(db_session, account_a, "lambda", "function", "fn",
                            role=exec_role)
        _make_role(db_session, account_a, "Abuser", ["lambda:UpdateFunctionCode"])

        _ctx, ridx = _index(db_session, account_a)
        assert list(ridx.reverse_neighbors(fn.arn)) == []


class TestCrossAccountActionScoping:
    """Admission is per-action: being let in for one action is not being let in
    for all of them."""

    def test_invoke_grant_does_not_confer_update(self, db_session, account_a,
                                                 account_b):
        arn = "arn:aws:lambda:us-east-1:111111111111:function:api"
        upsert_resource(db_session, account_a, arn=arn, service="lambda",
                        resource_type="function", name="api", region="us-east-1",
                        metadata={"resource_policy": {
                            "Version": "2012-10-17", "Statement": [
                                {"Effect": "Allow",
                                 "Principal": {"AWS": f"arn:aws:iam::{account_b.account_id}:root"},
                                 "Action": "lambda:InvokeFunction",
                                 "Resource": arn}]}})
        db_session.commit()
        caller = _make_role(db_session, account_b, "Caller",
                            ["lambda:InvokeFunction", "lambda:UpdateFunctionCode"])

        _ctx, ridx = _index(db_session)
        by_arn = {n.arn: n for n in ridx.inbound_page(arn).neighbors}

        assert caller.arn in by_arn, "the admitted action should still get it in"
        acts = " ".join(e.action for e in by_arn[caller.arn].edges)
        assert "lambda:InvokeFunction" in acts
        assert "lambda:UpdateFunctionCode" not in acts, (
            "UpdateFunctionCode is not admitted by the resource policy")

    def test_wildcard_action_grant_admits_everything(self, db_session, account_a,
                                                     account_b):
        bucket = _bucket(db_session, account_a, "wide-a", policy={
            "Version": "2012-10-17", "Statement": [
                {"Effect": "Allow",
                 "Principal": {"AWS": f"arn:aws:iam::{account_b.account_id}:root"},
                 "Action": "s3:*", "Resource": "arn:aws:s3:::wide-a/*"}]})
        caller = _make_role(db_session, account_b, "Caller",
                            ["s3:GetObject", "s3:PutBucketPolicy"])

        _ctx, ridx = _index(db_session)
        by_arn = {n.arn: n for n in ridx.inbound_page(bucket.arn).neighbors}
        acts = " ".join(e.action for e in by_arn[caller.arn].edges)
        assert "s3:GetObject" in acts and "s3:PutBucketPolicy" in acts

    def test_same_account_is_never_narrowed(self, db_session, account_a):
        bucket = _bucket(db_session, account_a, "local-a")
        reader = _make_role(db_session, account_a, "Reader",
                            ["s3:GetObject", "s3:PutObject"])

        _ctx, ridx = _index(db_session, account_a)
        by_arn = {n.arn: n for n in ridx.inbound_page(bucket.arn).neighbors}
        acts = " ".join(e.action for e in by_arn[reader.arn].edges)
        assert "s3:GetObject" in acts and "s3:PutObject" in acts

    def test_abuse_edge_needs_a_matching_admitted_action(self, db_session,
                                                         account_a, account_b):
        """A bucket policy granting only GetObject must not license
        s3:PutBucketPolicy takeover from another account."""
        bucket = _bucket(db_session, account_a, "read-only-a", policy={
            "Version": "2012-10-17", "Statement": [
                {"Effect": "Allow",
                 "Principal": {"AWS": f"arn:aws:iam::{account_b.account_id}:root"},
                 "Action": "s3:GetObject", "Resource": "arn:aws:s3:::read-only-a/*"}]})
        _make_role(db_session, account_b, "Taker", ["s3:PutBucketPolicy"])

        _ctx, ridx = _index(db_session)
        edge_types = {e.edge_type for n in ridx.inbound_page(bucket.arn).neighbors
                      for e in n.edges}
        assert "s3_bucket_policy_abuse" not in edge_types


# ─────────────────────────────────────────────────────────────────────────────
# Resource-type awareness: an ARN's service field says "ec2" for instances,
# VPCs, subnets and security groups alike, which is far too coarse.
# ─────────────────────────────────────────────────────────────────────────────

class TestResourceTypeActions:
    def test_subnet_is_not_scored_against_instance_actions(self, db_session, account_a):
        """The reported bug: every VPC-family resource was matched against
        ec2:TerminateInstances and friends, which cannot apply to a subnet."""
        subnet = _make_resource(db_session, account_a, "ec2", "subnet", "subnet-1")
        _make_role(db_session, account_a, "Ops",
                   ["ec2:TerminateInstances", "ec2:StartInstances"])

        _ctx, ridx = _index(db_session, account_a)
        page = ridx.inbound_page(subnet.arn)
        assert page.identity_applies is False
        assert not any(e.family == "identity_policy"
                       for n in page.neighbors for e in n.edges)

    def test_instance_still_matches_instance_actions(self, db_session, account_a):
        inst = _make_resource(db_session, account_a, "ec2", "instance", "i-1")
        ops = _make_role(db_session, account_a, "Ops", ["ec2:TerminateInstances"])

        _ctx, ridx = _index(db_session, account_a)
        page = ridx.inbound_page(inst.arn)
        assert page.identity_applies is True
        assert ops.arn in {n.arn for n in page.neighbors}

    def test_ecs_matches_real_actions_not_only_wildcards(self, db_session, account_a):
        """With no `ecs` entry the fallback was the literal string 'ecs:*', so a
        principal holding ecs:RunTask never showed up."""
        td = _make_resource(db_session, account_a, "ecs", "task-definition", "app:1")
        runner = _make_role(db_session, account_a, "Runner", ["ecs:RunTask"])
        wild = _make_role(db_session, account_a, "Wild", ["ecs:*"])

        _ctx, ridx = _index(db_session, account_a)
        arns = {n.arn for n in ridx.inbound_page(td.arn).neighbors}
        assert runner.arn in arns
        assert wild.arn in arns


class TestRunsAs:
    def test_instance_surfaces_its_role_and_the_roles_accessors(self, db_session,
                                                                account_a):
        """An instance is a strictly weaker view of its own profile role — it
        cannot show ssm_lateral on its own."""
        role = _make_role(db_session, account_a, "InstRole", [])
        inst = _make_resource(db_session, account_a, "ec2", "instance", "i-1",
                              role=role,
                              metadata={"MetadataOptions": {"HttpTokens": "optional"}})
        lander = _make_role(db_session, account_a, "Lander", ["ssm:SendCommand"])

        _ctx, ridx = _index(db_session, account_a)
        page = ridx.inbound_page(inst.arn)
        by_arn = {n.arn: n for n in page.neighbors}

        assert page.runs_as == role.arn
        assert role.arn in by_arn
        assert any(e.family == "runs_as" for e in by_arn[role.arn].edges)
        # The role's own accessors are folded in and attributed.
        assert lander.arn in by_arn
        folded = [e for e in by_arn[lander.arn].edges if e.detail]
        assert folded and folded[0].detail == "via InstRole"

    def test_family_can_be_filtered_out(self, db_session, account_a):
        role = _make_role(db_session, account_a, "InstRole", [])
        inst = _make_resource(db_session, account_a, "ec2", "instance", "i-1", role=role)
        _ctx, ridx = _index(db_session, account_a)
        page = ridx.inbound_page(inst.arn, families=("identity_policy",))
        assert page.runs_as is None
        assert role.arn not in {n.arn for n in page.neighbors}


class TestNetworkFamily:
    def _vpc_estate(self, db, account):
        vpc = _make_resource(db, account, "ec2", "vpc", "vpc-1",
                             metadata={"vpc_id": "vpc-1"})
        subnet = _make_resource(db, account, "ec2", "subnet", "subnet-1",
                                metadata={"vpc_id": "vpc-1", "subnet_id": "subnet-1"})
        sg = _make_resource(db, account, "ec2", "security-group", "sg-1",
                            metadata={"vpc_id": "vpc-1", "group_id": "sg-1"})
        inst = _make_resource(db, account, "ec2", "instance", "i-1",
                              metadata={"vpc_id": "vpc-1", "subnet_id": "subnet-1",
                                        "security_groups": ["sg-1"]})
        return vpc, subnet, sg, inst

    def test_vpc_lists_its_members(self, db_session, account_a):
        vpc, subnet, sg, inst = self._vpc_estate(db_session, account_a)
        _ctx, ridx = _index(db_session, account_a)
        page = ridx.inbound_page(vpc.arn)
        arns = {n.arn for n in page.neighbors}
        assert {subnet.arn, sg.arn, inst.arn} <= arns
        assert all(e.family == "network" for n in page.neighbors for e in n.edges)

    def test_subnet_and_sg_list_their_members(self, db_session, account_a):
        _vpc, subnet, sg, inst = self._vpc_estate(db_session, account_a)
        _ctx, ridx = _index(db_session, account_a)
        assert inst.arn in {n.arn for n in ridx.inbound_page(subnet.arn).neighbors}
        assert inst.arn in {n.arn for n in ridx.inbound_page(sg.arn).neighbors}

    def test_network_is_not_cross_account_gated(self, db_session, account_a):
        """Membership is same-account by construction; the gate must not eat it."""
        vpc, _s, _g, inst = self._vpc_estate(db_session, account_a)
        _ctx, ridx = _index(db_session)   # multi-account context
        page = ridx.inbound_page(vpc.arn)
        assert inst.arn in {n.arn for n in page.neighbors}

    def test_network_can_be_filtered_out(self, db_session, account_a):
        vpc, _s, _g, _i = self._vpc_estate(db_session, account_a)
        _ctx, ridx = _index(db_session, account_a)
        page = ridx.inbound_page(vpc.arn, families=("identity_policy", "abuse"))
        assert page.neighbors == []

    def test_network_members_are_capped(self, db_session, account_a):
        from worstassume.core.reverse_index import NETWORK_LIMIT
        _make_resource(db_session, account_a, "ec2", "vpc", "vpc-1",
                       metadata={"vpc_id": "vpc-1"})
        for i in range(NETWORK_LIMIT + 12):
            _make_resource(db_session, account_a, "ec2", "security-group", f"sg-{i}",
                           metadata={"vpc_id": "vpc-1", "group_id": f"sg-{i}"})
        _ctx, ridx = _index(db_session, account_a)
        page = ridx.inbound_page(f"arn:aws:ec2:us-east-1:{account_a.account_id}:vpc/vpc-1")
        assert len(page.neighbors) == NETWORK_LIMIT
        assert page.total_found == NETWORK_LIMIT + 12
        assert page.truncated is True
