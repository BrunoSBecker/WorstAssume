"""
tests/test_threat_model.py — Test suite for core.threat_model (Phase 5).

Covers:
  - statement-level identity matching (_statement_grants): Resource scoping,
    NotAction, Deny-wins, actions filter.
  - direct_accessors(): identity-policy accessors on a target.
  - resource_policy_accessors(): S3 bucket policy / Lambda resource policy /
    role trust policy resolution + public/cross-account flags.
  - reverse_reachability(): multi-hop assume-role chain, hops/severity/path.
  - analyze_threat_model(): target-type resolution + blast-radius aggregates.

Follows the fixture conventions from test_attack_path.py.
"""
from __future__ import annotations

from worstassume.db.store import (
    link_principal_policy,
    upsert_policy,
    upsert_principal,
    upsert_resource,
)
import json
from dataclasses import asdict

from worstassume.db.models import ThreatModelRun
from worstassume.core.attack_graph import (
    NeighborContext,
    build_attack_graph,
    build_access_graph,
)
from worstassume.core.threat_model import (
    _normalize_statement,
    _statement_grants,
    direct_accessors,
    resource_policy_accessors,
    reverse_reachability,
    analyze_threat_model,
)


# ─────────────────────────────────────────────────────────────────────────────
# Local helpers
# ─────────────────────────────────────────────────────────────────────────────

def _principal(db, account, name, ptype, doc=None, trust=None, actions=None):
    arn = f"arn:aws:iam::{account.account_id}:{ptype}/{name}"
    p = upsert_principal(db, account, arn=arn, name=name,
                         principal_type=ptype, trust_policy=trust)
    if doc is None and actions is not None:
        doc = {"Version": "2012-10-17",
               "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}
    if doc:
        pol = upsert_policy(db, account, arn=f"{arn}:inline/p", name=f"{name}-p",
                            policy_type="inline", document=doc)
        link_principal_policy(db, p, pol)
    db.commit()
    return p


def _norm(stmt):
    return _normalize_statement(stmt)


def _assume_trust(*principal_arns):
    return {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": list(principal_arns)},
        "Action": "sts:AssumeRole",
    }]}


# ─────────────────────────────────────────────────────────────────────────────
# _statement_grants — statement-level matcher
# ─────────────────────────────────────────────────────────────────────────────

class TestStatementGrants:

    def test_resource_scoping_narrows_match(self):
        stmts = [_norm({"Effect": "Allow", "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::bucketA/*"})]
        granted, _ = _statement_grants(stmts, "arn:aws:s3:::bucketA/data.txt",
                                       ["s3:GetObject"])
        assert "s3:GetObject" in granted

        granted2, _ = _statement_grants(stmts, "arn:aws:s3:::bucketB/data.txt",
                                        ["s3:GetObject"])
        assert not granted2

    def test_notaction_grants_everything_except_excluded(self):
        stmts = [_norm({"Effect": "Allow", "NotAction": "s3:DeleteObject",
                        "Resource": "*"})]
        granted, _ = _statement_grants(stmts, "arn:aws:s3:::b/x",
                                       ["s3:GetObject", "s3:DeleteObject"])
        assert "s3:GetObject" in granted
        assert "s3:DeleteObject" not in granted

    def test_deny_wins_over_allow(self):
        stmts = [
            _norm({"Effect": "Allow", "Action": "s3:*", "Resource": "*"}),
            _norm({"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"}),
        ]
        granted, _ = _statement_grants(stmts, "arn:aws:s3:::b/x",
                                       ["s3:GetObject", "s3:DeleteObject"])
        assert "s3:GetObject" in granted
        assert "s3:DeleteObject" not in granted

    def test_condition_flagged(self):
        stmts = [_norm({"Effect": "Allow", "Action": "s3:GetObject",
                        "Resource": "*", "Condition": {"StringEquals": {"aws:username": "x"}}})]
        granted, conditional = _statement_grants(stmts, "arn:aws:s3:::b/x",
                                                 ["s3:GetObject"])
        assert "s3:GetObject" in granted
        assert conditional is True


# ─────────────────────────────────────────────────────────────────────────────
# direct_accessors
# ─────────────────────────────────────────────────────────────────────────────

class TestDirectAccessors:

    def test_identity_accessor_on_resource(self, db_session, account_a):
        bucket_arn = f"arn:aws:s3:::data-{account_a.account_id}"
        upsert_resource(db_session, account_a, arn=bucket_arn, service="s3",
                        resource_type="bucket", name="data")
        _principal(db_session, account_a, "reader", "role",
                   actions=["s3:GetObject", "s3:ListBucket"])
        _principal(db_session, account_a, "nobody", "role",
                   actions=["ec2:DescribeInstances"])
        db_session.commit()

        ctx = NeighborContext(db_session)
        accessors = direct_accessors(ctx, bucket_arn, "resource")
        arns = {a.arn for a in accessors}
        assert f"arn:aws:iam::{account_a.account_id}:role/reader" in arns
        assert f"arn:aws:iam::{account_a.account_id}:role/nobody" not in arns

    def test_actions_filter_narrows(self, db_session, account_a):
        bucket_arn = f"arn:aws:s3:::data-{account_a.account_id}"
        upsert_resource(db_session, account_a, arn=bucket_arn, service="s3",
                        resource_type="bucket", name="data")
        _principal(db_session, account_a, "reader", "role",
                   actions=["s3:GetObject"])
        db_session.commit()

        ctx = NeighborContext(db_session)
        # reader only has GetObject → filtering on PutObject yields nothing
        accessors = direct_accessors(ctx, bucket_arn, "resource",
                                     actions=["s3:PutObject"])
        assert accessors == []
        accessors2 = direct_accessors(ctx, bucket_arn, "resource",
                                      actions=["s3:GetObject"])
        assert len(accessors2) == 1
        assert accessors2[0].actions == ["s3:GetObject"]

    def test_principal_target_iam_control(self, db_session, account_a):
        target = _principal(db_session, account_a, "target", "role")
        _principal(db_session, account_a, "admin", "user", actions=["iam:*"])
        db_session.commit()

        ctx = NeighborContext(db_session)
        accessors = direct_accessors(ctx, target.arn, "principal")
        arns = {a.arn for a in accessors}
        assert f"arn:aws:iam::{account_a.account_id}:user/admin" in arns


# ─────────────────────────────────────────────────────────────────────────────
# resource_policy_accessors
# ─────────────────────────────────────────────────────────────────────────────

class TestResourcePolicyAccessors:

    def test_s3_cross_account_and_public(self, db_session, account_a, account_b):
        policy = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow",
             "Principal": {"AWS": f"arn:aws:iam::{account_b.account_id}:root"},
             "Action": ["s3:GetObject"], "Resource": "*"},
            {"Effect": "Allow", "Principal": "*",
             "Action": ["s3:GetObject"], "Resource": "*"},
        ]}
        bucket = upsert_resource(
            db_session, account_a, arn="arn:aws:s3:::shared", service="s3",
            resource_type="bucket", name="shared", metadata={"policy": policy},
        )
        db_session.commit()

        known = {account_a.account_id, account_b.account_id}
        accessors, flags = resource_policy_accessors(
            bucket, "resource", known, account_a.account_id
        )
        arns = {a.arn for a in accessors}
        assert "*" in arns
        assert f"arn:aws:iam::{account_b.account_id}:root" in arns
        assert flags["public"] is True
        assert flags["cross_account"] is True
        # account B is a known account, so not "external", but still cross-account
        ext = next(a for a in accessors if a.arn.endswith(":root"))
        assert ext.external is False

    def test_lambda_resource_policy(self, db_session, account_a, account_b):
        policy = {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_b.account_id}:role/ext"},
            "Action": "lambda:InvokeFunction", "Resource": "*",
        }]}
        fn = upsert_resource(
            db_session, account_a,
            arn=f"arn:aws:lambda:us-east-1:{account_a.account_id}:function/f",
            service="lambda", resource_type="function", name="f",
            metadata={"resource_policy": policy},
        )
        db_session.commit()

        # account_b NOT in known set → external
        accessors, flags = resource_policy_accessors(
            fn, "resource", {account_a.account_id}, account_a.account_id
        )
        ext = next(a for a in accessors if "role/ext" in a.arn)
        assert ext.external is True
        assert flags["cross_account"] is True

    def test_role_trust_policy(self, db_session, account_a, account_b):
        trust = _assume_trust(f"arn:aws:iam::{account_b.account_id}:root")
        role = _principal(db_session, account_a, "trusting", "role", trust=trust)
        db_session.commit()

        accessors, flags = resource_policy_accessors(
            role, "principal", {account_a.account_id}, account_a.account_id
        )
        assert flags["has_policy"] is True
        arns = {a.arn for a in accessors}
        assert f"arn:aws:iam::{account_b.account_id}:root" in arns
        assert all(a.via == "trust_policy" for a in accessors)


# ─────────────────────────────────────────────────────────────────────────────
# reverse_reachability
# ─────────────────────────────────────────────────────────────────────────────

class TestReverseReachability:

    def _build_assume_chain(self, db, account):
        """user →assume→ roleA →assume→ roleB (target)."""
        user = _principal(db, account, "user1", "user", actions=["sts:AssumeRole"])
        roleA = _principal(db, account, "roleA", "role",
                           actions=["sts:AssumeRole"], trust=_assume_trust(user.arn))
        roleB = _principal(db, account, "roleB", "role",
                           trust=_assume_trust(roleA.arn))
        db.commit()
        return user, roleA, roleB

    def test_two_hop_chain(self, db_session, account_a):
        user, roleA, roleB = self._build_assume_chain(db_session, account_a)
        G = build_access_graph(db_session)

        accessors = reverse_reachability({roleB.arn}, max_hops=5, graph=G)
        by_arn = {a.arn: a for a in accessors}

        assert roleA.arn in by_arn
        assert user.arn in by_arn
        assert by_arn[roleA.arn].hops == 1
        assert by_arn[user.arn].hops == 2

        # user's forward path is user → roleA → roleB
        upath = by_arn[user.arn].path
        assert upath[0].actor == user.arn
        assert upath[0].target == roleA.arn
        assert upath[-1].target == roleB.arn
        assert by_arn[user.arn].entry_arn == roleB.arn

    def test_seed_itself_excluded(self, db_session, account_a):
        _, _, roleB = self._build_assume_chain(db_session, account_a)
        G = build_access_graph(db_session)
        accessors = reverse_reachability({roleB.arn}, graph=G)
        assert roleB.arn not in {a.arn for a in accessors}

    def test_max_hops_limits_depth(self, db_session, account_a):
        user, roleA, roleB = self._build_assume_chain(db_session, account_a)
        G = build_access_graph(db_session)
        accessors = reverse_reachability({roleB.arn}, max_hops=1, graph=G)
        arns = {a.arn for a in accessors}
        assert roleA.arn in arns   # 1 hop
        assert user.arn not in arns  # 2 hops — beyond limit


# ─────────────────────────────────────────────────────────────────────────────
# analyze_threat_model — orchestrator
# ─────────────────────────────────────────────────────────────────────────────

class TestAnalyzeThreatModel:

    def test_principal_target_aggregates(self, db_session, account_a):
        user = _principal(db_session, account_a, "user1", "user",
                          actions=["sts:AssumeRole"])
        roleA = _principal(db_session, account_a, "roleA", "role",
                           actions=["sts:AssumeRole"], trust=_assume_trust(user.arn))
        roleB = _principal(db_session, account_a, "roleB", "role",
                           trust=_assume_trust(roleA.arn))
        db_session.commit()

        result = analyze_threat_model(db_session, roleB.arn, max_hops=5)
        assert result.target["type"] == "principal"
        assert result.target["arn"] == roleB.arn

        trans_arns = {t.arn for t in result.transitive_accessors}
        assert user.arn in trans_arns
        assert roleA.arn in trans_arns
        assert result.blast_radius["transitive"] == len(result.transitive_accessors)
        assert result.blast_radius["total_unique"] >= 2
        assert set(result.blast_radius["by_severity"]) == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

    def test_resource_target_type(self, db_session, account_a):
        bucket_arn = "arn:aws:s3:::mybucket"
        upsert_resource(db_session, account_a, arn=bucket_arn, service="s3",
                        resource_type="bucket", name="mybucket")
        _principal(db_session, account_a, "reader", "role", actions=["s3:GetObject"])
        db_session.commit()

        result = analyze_threat_model(db_session, bucket_arn, max_hops=5)
        assert result.target["type"] == "resource"
        assert result.target["service"] == "s3"
        reader = f"arn:aws:iam::{account_a.account_id}:role/reader"
        assert reader in {a.arn for a in result.direct_accessors}

    def test_result_is_json_serializable_and_persists(self, db_session, account_a):
        bucket_arn = "arn:aws:s3:::store"
        upsert_resource(db_session, account_a, arn=bucket_arn, service="s3",
                        resource_type="bucket", name="store")
        _principal(db_session, account_a, "reader", "role", actions=["s3:GetObject"])
        db_session.commit()

        result = analyze_threat_model(db_session, bucket_arn, max_hops=5)
        # asdict → json round-trip must not choke on dataclasses / Counters
        payload = json.dumps(asdict(result))
        round = json.loads(payload)
        assert round["target"]["arn"] == bucket_arn

        br = result.blast_radius
        run = ThreatModelRun(
            target_arn=bucket_arn, target_type=result.target["type"],
            target_label=result.target["label"], account_id=account_a.account_id,
            max_hops=5, status="done",
            total_unique=br["total_unique"], direct_count=br["direct"],
            transitive_count=br["transitive"], external_count=br["external"],
            critical_count=br["by_severity"]["CRITICAL"], public=br["public"],
            result_json=payload,
        )
        db_session.add(run)
        db_session.commit()

        fetched = db_session.query(ThreatModelRun).filter_by(target_arn=bucket_arn).first()
        assert fetched is not None
        assert fetched.status == "done"
        assert fetched.result["target"]["arn"] == bucket_arn
        assert fetched.direct_count == br["direct"]

    def test_unknown_target(self, db_session, account_a):
        result = analyze_threat_model(db_session, "arn:aws:iam::999:role/ghost")
        assert result.target["type"] == "unknown"
        assert result.direct_accessors == []
        assert result.transitive_accessors == []


# ─────────────────────────────────────────────────────────────────────────────
# build_access_graph — access/pivot edges only (excludes escalation edges)
# ─────────────────────────────────────────────────────────────────────────────

_ESCALATION_EDGE_TYPES = {
    "iam_policy_inject", "group_membership",
    "trust_policy_update", "credential_theft",
}


class TestAccessGraphScoping:

    def test_excludes_iam_manipulation_edges(self, db_session, account_a):
        # admin can take over any principal via iam:* — an escalation edge family
        _principal(db_session, account_a, "admin", "user", actions=["iam:*"])
        _principal(db_session, account_a, "victim", "role")
        db_session.commit()

        admin_arn = f"arn:aws:iam::{account_a.account_id}:user/admin"

        full = build_attack_graph(db_session)
        access = build_access_graph(db_session)

        # Full graph: admin fans out to victim via iam_policy_inject
        full_types = {d.get("edge_type") for _, _, d in full.out_edges(admin_arn, data=True)}
        assert full_types & _ESCALATION_EDGE_TYPES

        # Access graph: none of admin's edges are escalation edges
        access_types = {d.get("edge_type") for _, _, d in access.out_edges(admin_arn, data=True)}
        assert not (access_types & _ESCALATION_EDGE_TYPES)

    def test_includes_assume_and_passrole(self, db_session, account_a):
        user, roleA, _ = TestReverseReachability()._build_assume_chain(db_session, account_a)
        access = build_access_graph(db_session)
        types = {d.get("edge_type") for _, _, d in access.out_edges(user.arn, data=True)}
        assert "assume_role" in types


class TestThreatModelAccessScoping:
    """The asset-centric transitive walk should surface pivot-reachable
    identities (compromise → asset) but NOT escalation-only admins."""

    def test_pivot_included_escalation_only_excluded(self, db_session, account_a):
        bucket_arn = "arn:aws:s3:::pii"
        upsert_resource(db_session, account_a, arn=bucket_arn, service="s3",
                        resource_type="bucket", name="pii")
        # a user that can assume the reader role → pivot-reachable (transitive)
        pivot = _principal(db_session, account_a, "pivot", "user",
                           actions=["sts:AssumeRole"])
        # reader role can read the bucket (identity policy → direct accessor)
        # and trusts the pivot user, so pivot can pivot into it.
        reader = _principal(db_session, account_a, "reader", "role",
                            actions=["s3:GetObject"], trust=_assume_trust(pivot.arn))
        # an admin that can only escalate (iam:*) — NO pivot path to reader
        _principal(db_session, account_a, "admin", "user", actions=["iam:*"])
        db_session.commit()

        result = analyze_threat_model(db_session, bucket_arn, max_hops=5)

        assert reader.arn in {a.arn for a in result.direct_accessors}
        trans = {t.arn for t in result.transitive_accessors}
        assert pivot.arn in trans
        admin_arn = f"arn:aws:iam::{account_a.account_id}:user/admin"
        assert admin_arn not in trans
