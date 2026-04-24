"""
tests/test_attack_graph.py — Full test suite for attack_graph.build_attack_graph().

15 test cases as specified in spec_phases_4_to_8.md §4.7.
All helpers follow the same pattern as test_privilege_escalation.py.
"""

from __future__ import annotations

import json
import pytest

from worstassume.db.store import (
    get_or_create_account,
    link_principal_policy,
    upsert_cross_account_link,
    upsert_policy,
    upsert_principal,
    upsert_resource,
)


# ─────────────────────────────────────────────────────────────────────────────
# Local helpers
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


def _make_group(db, account, name):
    arn = f"arn:aws:iam::{account.account_id}:group/{name}"
    grp = upsert_principal(db, account, arn=arn, name=name, principal_type="group")
    db.commit()
    return grp


def _make_ec2_resource(db, account, name, role=None, http_tokens="optional"):
    arn = f"arn:aws:ec2:us-east-1:{account.account_id}:instance/{name}"
    r = upsert_resource(db, account, arn=arn, service="ec2", resource_type="instance",
                        name=name, region="us-east-1", execution_role=role,
                        metadata={"MetadataOptions": {"HttpTokens": http_tokens}})
    db.commit()
    return r


def _make_lambda_resource(db, account, name, role=None):
    arn = f"arn:aws:lambda:us-east-1:{account.account_id}:function/{name}"
    r = upsert_resource(db, account, arn=arn, service="lambda", resource_type="function",
                        name=name, region="us-east-1", execution_role=role)
    db.commit()
    return r


def _graph(db, account=None):
    from worstassume.core.attack_graph import build_attack_graph
    return build_attack_graph(db, account=account)


# ── Trust policy fixtures (reused across all PassRole test classes) ────────────────

_LAMBDA_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow",
                   "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}

_EC2_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow",
                   "Principal": {"Service": "ec2.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}

_CFN_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow",
                   "Principal": {"Service": "cloudformation.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}

_NO_SERVICE_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow",
                   "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                   "Action": "sts:AssumeRole"}],
}


def _edge_types(G, src_arn, dst_arn):
    """Return set of edge_type values between src and dst."""
    return {d["edge_type"] for _, _, d in G.out_edges(src_arn, data=True)
            if _ == src_arn and list(G.edges)[0][1] == dst_arn
           } if G.has_node(src_arn) else set()


def _all_edge_types(G, src_arn=None, dst_arn=None):
    """Return all edge_type values for edges matching optional src/dst filters."""
    result = set()
    for u, v, data in G.edges(data=True):
        if src_arn and u != src_arn:
            continue
        if dst_arn and v != dst_arn:
            continue
        result.add(data["edge_type"])
    return result


def _edges_between(G, src_arn, dst_arn):
    """Return list of edge data dicts for all edges from src to dst."""
    return [d for u, v, d in G.edges(data=True) if u == src_arn and v == dst_arn]


def _edges_from(G, src_arn):
    return [(v, d) for u, v, d in G.edges(data=True) if u == src_arn]


# ─────────────────────────────────────────────────────────────────────────────
# 1. test_graph_has_principal_nodes
# ─────────────────────────────────────────────────────────────────────────────
class TestGraphHasPrincipalNodes:
    def test_roles_become_nodes(self, db_session, account_a):
        role = _make_role(db_session, account_a, "MyRole", [])
        G = _graph(db_session, account_a)
        assert role.arn in G.nodes
        assert G.nodes[role.arn]["node_type"] == "principal"
        assert G.nodes[role.arn]["principal_type"] == "role"

    def test_users_become_nodes(self, db_session, account_a):
        user = _make_user(db_session, account_a, "alice", [])
        G = _graph(db_session, account_a)
        assert user.arn in G.nodes
        assert G.nodes[user.arn]["node_type"] == "principal"
        assert G.nodes[user.arn]["principal_type"] == "user"

    def test_groups_become_nodes(self, db_session, account_a):
        grp = _make_group(db_session, account_a, "Devs")
        G = _graph(db_session, account_a)
        assert grp.arn in G.nodes
        assert G.nodes[grp.arn]["principal_type"] == "group"


# ─────────────────────────────────────────────────────────────────────────────
# 2. test_graph_has_resource_nodes
# ─────────────────────────────────────────────────────────────────────────────
class TestGraphHasResourceNodes:
    def test_ec2_instance_becomes_node(self, db_session, account_a):
        ec2 = _make_ec2_resource(db_session, account_a, "i-001")
        G = _graph(db_session, account_a)
        assert ec2.arn in G.nodes
        assert G.nodes[ec2.arn]["node_type"] == "resource"
        assert G.nodes[ec2.arn]["service"] == "ec2"

    def test_lambda_function_becomes_node(self, db_session, account_a):
        fn = _make_lambda_resource(db_session, account_a, "my-fn")
        G = _graph(db_session, account_a)
        assert fn.arn in G.nodes
        assert G.nodes[fn.arn]["service"] == "lambda"

    def test_execution_role_added_as_node(self, db_session, account_a):
        exec_role = _make_role(db_session, account_a, "LambdaExecRole", [])
        fn = _make_lambda_resource(db_session, account_a, "fn-with-role", role=exec_role)
        G = _graph(db_session, account_a)
        # Both resource and its execution role should be nodes
        assert fn.arn in G.nodes
        assert exec_role.arn in G.nodes


# ─────────────────────────────────────────────────────────────────────────────
# 3. test_iam_policy_inject_edge_created
# ─────────────────────────────────────────────────────────────────────────────
class TestIamPolicyInjectEdge:
    def test_create_policy_version_creates_edges_to_all_principals(self, db_session, account_a):
        attacker = _make_role(db_session, account_a, "attacker", ["iam:CreatePolicyVersion"])
        victim_r = _make_role(db_session, account_a, "victim-role", [])
        victim_u = _make_user(db_session, account_a, "victim-user", [])
        G = _graph(db_session, account_a)

        # attacker should have iam_policy_inject edges to both victims
        targets_with_inject = {v for u, v, d in G.edges(data=True)
                                if u == attacker.arn and d["edge_type"] == "iam_policy_inject"}
        assert victim_r.arn in targets_with_inject
        assert victim_u.arn in targets_with_inject

    def test_inject_severity_is_critical(self, db_session, account_a):
        attacker = _make_role(db_session, account_a, "attacker", ["iam:PutRolePolicy"])
        victim = _make_role(db_session, account_a, "victim", [])
        G = _graph(db_session, account_a)
        edges = _edges_between(G, attacker.arn, victim.arn)
        assert any(e["severity"] == "CRITICAL" and e["edge_type"] == "iam_policy_inject"
                   for e in edges)

    def test_no_inject_without_permission(self, db_session, account_a):
        attacker = _make_role(db_session, account_a, "safe", ["s3:GetObject"])
        victim = _make_role(db_session, account_a, "victim", [])
        G = _graph(db_session, account_a)
        assert "iam_policy_inject" not in _all_edge_types(G, src_arn=attacker.arn)


# ─────────────────────────────────────────────────────────────────────────────
# 4. test_credential_theft_edge_user_target
# ─────────────────────────────────────────────────────────────────────────────
class TestCredentialTheftEdge:
    def test_create_access_key_targets_users_only(self, db_session, account_a):
        attacker = _make_role(db_session, account_a, "attacker", ["iam:CreateAccessKey"])
        user = _make_user(db_session, account_a, "target-user", [])
        role = _make_role(db_session, account_a, "target-role", [])
        G = _graph(db_session, account_a)

        theft_targets = {v for u, v, d in G.edges(data=True)
                         if u == attacker.arn and d["edge_type"] == "credential_theft"}
        assert user.arn in theft_targets
        assert role.arn not in theft_targets  # roles are NOT valid targets for CreateAccessKey

    def test_create_access_key_severity_critical(self, db_session, account_a):
        attacker = _make_role(db_session, account_a, "attacker", ["iam:CreateAccessKey"])
        user = _make_user(db_session, account_a, "u", [])
        G = _graph(db_session, account_a)
        edges = _edges_between(G, attacker.arn, user.arn)
        assert any(e["path_id"] == "PATH-011" and e["severity"] == "CRITICAL" for e in edges)

    def test_create_login_profile_severity_high(self, db_session, account_a):
        attacker = _make_role(db_session, account_a, "attacker", ["iam:CreateLoginProfile"])
        user = _make_user(db_session, account_a, "u", [])
        G = _graph(db_session, account_a)
        edges = _edges_between(G, attacker.arn, user.arn)
        assert any(e["path_id"] == "PATH-012" and e["severity"] == "HIGH" for e in edges)


# ─────────────────────────────────────────────────────────────────────────────
# 5. test_trust_update_edge_role_target
# ─────────────────────────────────────────────────────────────────────────────
class TestTrustUpdateEdge:
    def test_update_assume_role_policy_targets_roles_only(self, db_session, account_a):
        attacker = _make_role(db_session, account_a, "attacker", ["iam:UpdateAssumeRolePolicy"])
        victim_role = _make_role(db_session, account_a, "victim-role", [])
        victim_user = _make_user(db_session, account_a, "victim-user", [])
        G = _graph(db_session, account_a)

        trust_targets = {v for u, v, d in G.edges(data=True)
                         if u == attacker.arn and d["edge_type"] == "trust_policy_update"}
        assert victim_role.arn in trust_targets
        assert victim_user.arn not in trust_targets  # users are NOT valid targets

    def test_trust_update_severity_critical(self, db_session, account_a):
        attacker = _make_role(db_session, account_a, "attacker", ["iam:UpdateAssumeRolePolicy"])
        victim = _make_role(db_session, account_a, "victim", [])
        G = _graph(db_session, account_a)
        edges = _edges_between(G, attacker.arn, victim.arn)
        assert any(e["severity"] == "CRITICAL" and e["path_id"] == "PATH-010" for e in edges)


# ─────────────────────────────────────────────────────────────────────────────
# 6. test_group_membership_edge
# ─────────────────────────────────────────────────────────────────────────────
class TestGroupMembershipEdge:
    def test_add_user_to_group_targets_groups_only(self, db_session, account_a):
        attacker = _make_role(db_session, account_a, "attacker", ["iam:AddUserToGroup"])
        grp = _make_group(db_session, account_a, "Admins")
        role = _make_role(db_session, account_a, "some-role", [])
        G = _graph(db_session, account_a)

        membership_targets = {v for u, v, d in G.edges(data=True)
                              if u == attacker.arn and d["edge_type"] == "group_membership"}
        assert grp.arn in membership_targets
        assert role.arn not in membership_targets  # roles are NOT valid targets

    def test_group_membership_severity_high(self, db_session, account_a):
        attacker = _make_role(db_session, account_a, "attacker", ["iam:AddUserToGroup"])
        grp = _make_group(db_session, account_a, "Admins")
        G = _graph(db_session, account_a)
        edges = _edges_between(G, attacker.arn, grp.arn)
        assert any(e["severity"] == "HIGH" and e["path_id"] == "PATH-009" for e in edges)


# ─────────────────────────────────────────────────────────────────────────────
# 7. test_passrole_lambda_edge
# ─────────────────────────────────────────────────────────────────────────────
class TestPassroleLambdaEdge:
    def test_passrole_create_function_targets_exec_role(self, db_session, account_a):
        exec_role = _make_role(db_session, account_a, "LambdaExecRole", [],
                               trust_policy=_LAMBDA_TRUST)
        fn = _make_lambda_resource(db_session, account_a, "my-fn", role=exec_role)
        attacker = _make_role(db_session, account_a, "attacker",
                              ["iam:PassRole", "lambda:CreateFunction"])
        G = _graph(db_session, account_a)

        # Edge must point to the EXECUTION ROLE, not the function resource
        edges_to_exec_role = _edges_between(G, attacker.arn, exec_role.arn)
        assert any(e["edge_type"] == "passrole_lambda_create" for e in edges_to_exec_role)
        # No edge should point directly to the Lambda function node
        edges_to_fn = _edges_between(G, attacker.arn, fn.arn)
        assert not any(e["edge_type"] == "passrole_lambda_create" for e in edges_to_fn)

    def test_passrole_lambda_severity_critical(self, db_session, account_a):
        exec_role = _make_role(db_session, account_a, "ExecRole", [],
                               trust_policy=_LAMBDA_TRUST)
        _make_lambda_resource(db_session, account_a, "fn", role=exec_role)
        attacker = _make_role(db_session, account_a, "attacker",
                              ["iam:PassRole", "lambda:CreateFunction"])
        G = _graph(db_session, account_a)
        edges = _edges_between(G, attacker.arn, exec_role.arn)
        assert any(e["severity"] == "CRITICAL" for e in edges)

    def test_no_passrole_no_lambda_edge(self, db_session, account_a):
        exec_role = _make_role(db_session, account_a, "ExecRole", [])
        _make_lambda_resource(db_session, account_a, "fn", role=exec_role)
        attacker = _make_role(db_session, account_a, "attacker", ["lambda:CreateFunction"])
        G = _graph(db_session, account_a)
        assert "passrole_lambda_create" not in _all_edge_types(G, src_arn=attacker.arn)


# ─────────────────────────────────────────────────────────────────────────────
# 8. test_passrole_cfn_edge
# ─────────────────────────────────────────────────────────────────────────────
class TestPassroleCfnEdge:
    def _make_cfn_resource(self, db, account, name, role=None):
        arn = f"arn:aws:cloudformation:us-east-1:{account.account_id}:stack/{name}"
        r = upsert_resource(db, account, arn=arn, service="cloudformation",
                            resource_type="stack", name=name, region="us-east-1",
                            execution_role=role)
        db.commit()
        return r

    def test_passrole_cfn_targets_exec_role(self, db_session, account_a):
        svc_role = _make_role(db_session, account_a, "CfnServiceRole", [],
                              trust_policy=_CFN_TRUST)
        self._make_cfn_resource(db_session, account_a, "my-stack", role=svc_role)
        attacker = _make_role(db_session, account_a, "attacker",
                              ["iam:PassRole", "cloudformation:CreateStack"])
        G = _graph(db_session, account_a)

        edges = _edges_between(G, attacker.arn, svc_role.arn)
        assert any(e["edge_type"] == "passrole_cfn" for e in edges)

    def test_passrole_cfn_severity_critical(self, db_session, account_a):
        svc_role = _make_role(db_session, account_a, "CfnServiceRole", [],
                              trust_policy=_CFN_TRUST)
        self._make_cfn_resource(db_session, account_a, "stack", role=svc_role)
        attacker = _make_role(db_session, account_a, "attacker",
                              ["iam:PassRole", "cloudformation:CreateStack"])
        G = _graph(db_session, account_a)
        edges = _edges_between(G, attacker.arn, svc_role.arn)
        assert any(e["severity"] == "CRITICAL" for e in edges)


# ─────────────────────────────────────────────────────────────────────────────
# 9. test_assume_role_trust_policy_check
# ─────────────────────────────────────────────────────────────────────────────
class TestAssumeRoleTrustPolicyCheck:
    def test_assume_role_added_when_trust_allows(self, db_session, account_a):
        trust = {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_a.account_id}:role/attacker"},
            "Action": "sts:AssumeRole",
        }]}
        target = _make_role(db_session, account_a, "target", [], trust_policy=trust)
        attacker = _make_role(db_session, account_a, "attacker", ["sts:AssumeRole"])
        G = _graph(db_session, account_a)

        edges = _edges_between(G, attacker.arn, target.arn)
        assert any(e["edge_type"] == "assume_role" for e in edges)

    def test_assume_role_not_added_when_trust_forbids(self, db_session, account_a):
        # Trust policy trusts a DIFFERENT principal, not the attacker
        trust = {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::999999999999:role/other"},
            "Action": "sts:AssumeRole",
        }]}
        target = _make_role(db_session, account_a, "target", [], trust_policy=trust)
        attacker = _make_role(db_session, account_a, "attacker", ["sts:AssumeRole"])
        G = _graph(db_session, account_a)

        edges = _edges_between(G, attacker.arn, target.arn)
        assert not any(e["edge_type"] == "assume_role" for e in edges)

    def test_assume_role_added_for_wildcard_trust(self, db_session, account_a):
        trust = {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sts:AssumeRole",
        }]}
        target = _make_role(db_session, account_a, "open-target", [], trust_policy=trust)
        attacker = _make_role(db_session, account_a, "attacker", ["sts:AssumeRole"])
        G = _graph(db_session, account_a)
        edges = _edges_between(G, attacker.arn, target.arn)
        assert any(e["edge_type"] == "assume_role" for e in edges)


# ─────────────────────────────────────────────────────────────────────────────
# 10. test_cross_account_assume_role
# ─────────────────────────────────────────────────────────────────────────────
class TestCrossAccountAssumeRole:
    def test_cross_account_trust_creates_critical_edge(self, db_session, account_a, account_b):
        attacker_arn = f"arn:aws:iam::{account_a.account_id}:role/attacker"
        trust = {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": attacker_arn},
            "Action": "sts:AssumeRole",
        }]}
        target = _make_role(db_session, account_b, "cross-target", [], trust_policy=trust)
        attacker = _make_role(db_session, account_a, "attacker", ["sts:AssumeRole"])
        G = _graph(db_session)  # no account filter — both accounts visible

        edges = _edges_between(G, attacker.arn, target.arn)
        assert any(e["edge_type"] == "cross_account_assume" and e["severity"] == "CRITICAL"
                   for e in edges)

    def test_cross_account_link_table_creates_edge(self, db_session, account_a, account_b):
        role_arn = f"arn:aws:iam::{account_b.account_id}:role/CrossRole"
        src_arn = f"arn:aws:iam::{account_a.account_id}:role/Caller"
        # Ensure both ARNs exist as nodes
        _make_role(db_session, account_b, "CrossRole", [])
        _make_role(db_session, account_a, "Caller", [])
        upsert_cross_account_link(db_session,
                                  source_account=account_a, target_account=account_b,
                                  role_arn=role_arn, trust_principal_arn=src_arn,
                                  is_wildcard=False)
        db_session.commit()
        G = _graph(db_session)
        edges = _edges_between(G, src_arn, role_arn)
        assert any(e["edge_type"] == "cross_account_assume" for e in edges)

    def test_wildcard_cross_account_link_is_critical(self, db_session, account_a, account_b):
        role_arn = f"arn:aws:iam::{account_b.account_id}:role/WildRole"
        src_arn = f"arn:aws:iam::{account_a.account_id}:role/Caller"
        _make_role(db_session, account_b, "WildRole", [])
        _make_role(db_session, account_a, "Caller", [])
        upsert_cross_account_link(db_session,
                                  source_account=account_a, target_account=account_b,
                                  role_arn=role_arn, trust_principal_arn=src_arn,
                                  is_wildcard=True)
        db_session.commit()
        G = _graph(db_session)
        edges = _edges_between(G, src_arn, role_arn)
        assert any(e["severity"] == "CRITICAL" for e in edges)


# ─────────────────────────────────────────────────────────────────────────────
# 11. test_imds_edge_only_for_imdsv1
# ─────────────────────────────────────────────────────────────────────────────
class TestImdsEdge:
    def test_imdsv1_instance_gets_imds_edge(self, db_session, account_a):
        exec_role = _make_role(db_session, account_a, "InstanceRole", [])
        _make_ec2_resource(db_session, account_a, "i-imdsv1", role=exec_role,
                           http_tokens="optional")
        attacker = _make_role(db_session, account_a, "attacker", [])
        G = _graph(db_session, account_a)
        # Any principal should have an imds_steal edge to the instance exec role
        imds_targets = {v for u, v, d in G.edges(data=True) if d["edge_type"] == "imds_steal"}
        assert exec_role.arn in imds_targets

    def test_imdsv2_instance_gets_no_imds_edge(self, db_session, account_a):
        exec_role = _make_role(db_session, account_a, "InstanceRole", [])
        _make_ec2_resource(db_session, account_a, "i-imdsv2", role=exec_role,
                           http_tokens="required")
        _make_role(db_session, account_a, "attacker", [])
        G = _graph(db_session, account_a)
        imds_targets = {v for u, v, d in G.edges(data=True) if d["edge_type"] == "imds_steal"}
        assert exec_role.arn not in imds_targets


# ─────────────────────────────────────────────────────────────────────────────
# 12. test_lambda_code_overwrite_edge
# ─────────────────────────────────────────────────────────────────────────────
class TestLambdaCodeOverwriteEdge:
    def test_update_function_code_targets_lambda_exec_role(self, db_session, account_a):
        exec_role = _make_role(db_session, account_a, "LambdaRole", [])
        fn = _make_lambda_resource(db_session, account_a, "fn", role=exec_role)
        attacker = _make_role(db_session, account_a, "attacker", ["lambda:UpdateFunctionCode"])
        G = _graph(db_session, account_a)

        # Edge points to exec role, not to the function
        edges = _edges_between(G, attacker.arn, exec_role.arn)
        assert any(e["edge_type"] == "lambda_code_overwrite" for e in edges)
        # No overwrite edge to the function node itself
        edges_to_fn = _edges_between(G, attacker.arn, fn.arn)
        assert not any(e["edge_type"] == "lambda_code_overwrite" for e in edges_to_fn)

    def test_lambda_code_overwrite_severity_high(self, db_session, account_a):
        exec_role = _make_role(db_session, account_a, "LambdaRole", [])
        _make_lambda_resource(db_session, account_a, "fn", role=exec_role)
        attacker = _make_role(db_session, account_a, "attacker", ["lambda:UpdateFunctionCode"])
        G = _graph(db_session, account_a)
        edges = _edges_between(G, attacker.arn, exec_role.arn)
        assert any(e["severity"] == "HIGH" for e in edges)

    def test_no_overwrite_without_permission(self, db_session, account_a):
        exec_role = _make_role(db_session, account_a, "LambdaRole", [])
        _make_lambda_resource(db_session, account_a, "fn", role=exec_role)
        attacker = _make_role(db_session, account_a, "attacker", ["s3:GetObject"])
        G = _graph(db_session, account_a)
        assert "lambda_code_overwrite" not in _all_edge_types(G, src_arn=attacker.arn)


# ─────────────────────────────────────────────────────────────────────────────
# 13. test_ssm_lateral_movement_edge
# ─────────────────────────────────────────────────────────────────────────────
class TestSsmLateralMovementEdge:
    def test_ssm_send_command_targets_ec2_exec_role(self, db_session, account_a):
        exec_role = _make_role(db_session, account_a, "EC2Role", [])
        _make_ec2_resource(db_session, account_a, "i-ssm", role=exec_role)
        attacker = _make_role(db_session, account_a, "attacker", ["ssm:SendCommand"])
        G = _graph(db_session, account_a)

        edges = _edges_between(G, attacker.arn, exec_role.arn)
        assert any(e["edge_type"] == "ssm_lateral" for e in edges)

    def test_ssm_lateral_severity_high(self, db_session, account_a):
        exec_role = _make_role(db_session, account_a, "EC2Role", [])
        _make_ec2_resource(db_session, account_a, "i-ssm", role=exec_role)
        attacker = _make_role(db_session, account_a, "attacker", ["ssm:SendCommand"])
        G = _graph(db_session, account_a)
        edges = _edges_between(G, attacker.arn, exec_role.arn)
        assert any(e["severity"] == "HIGH" for e in edges)

    def test_no_ssm_edge_without_permission(self, db_session, account_a):
        exec_role = _make_role(db_session, account_a, "EC2Role", [])
        _make_ec2_resource(db_session, account_a, "i-ssm", role=exec_role)
        attacker = _make_role(db_session, account_a, "attacker", ["s3:GetObject"])
        G = _graph(db_session, account_a)
        assert "ssm_lateral" not in _all_edge_types(G, src_arn=attacker.arn)


# ─────────────────────────────────────────────────────────────────────────────
# 14. test_empty_graph_no_principals
# ─────────────────────────────────────────────────────────────────────────────
class TestEmptyGraph:
    def test_empty_db_produces_empty_graph(self, db_session, account_a):
        G = _graph(db_session, account_a)
        assert G.number_of_nodes() == 0
        assert G.number_of_edges() == 0

    def test_empty_graph_with_no_account_filter(self, db_session):
        G = _graph(db_session)
        assert G.number_of_nodes() == 0


# ─────────────────────────────────────────────────────────────────────────────
# 15. test_filter_by_account
# ─────────────────────────────────────────────────────────────────────────────
class TestFilterByAccount:
    def test_account_filter_restricts_nodes(self, db_session, account_a, account_b):
        role_a = _make_role(db_session, account_a, "role-a", [])
        role_b = _make_role(db_session, account_b, "role-b", [])
        G = _graph(db_session, account_a)

        assert role_a.arn in G.nodes
        assert role_b.arn not in G.nodes

    def test_no_filter_includes_all_accounts(self, db_session, account_a, account_b):
        role_a = _make_role(db_session, account_a, "role-a", [])
        role_b = _make_role(db_session, account_b, "role-b", [])
        G = _graph(db_session)  # no account filter

        assert role_a.arn in G.nodes
        assert role_b.arn in G.nodes

    def test_account_filter_restricts_edges(self, db_session, account_a, account_b):
        # Attacker in account_a, victim in account_b — filtered graph should have no edges
        attacker = _make_role(db_session, account_a, "attacker", ["iam:CreatePolicyVersion"])
        victim = _make_role(db_session, account_b, "victim", [])
        G_a = _graph(db_session, account_a)

        # victim is not in account_a graph at all
        assert victim.arn not in G_a.nodes
        # No edges crossing accounts when filter is active
        account_b_arns = {n for n in G_a.nodes
                          if G_a.nodes[n].get("account_id") == account_b.account_id}
        assert len(account_b_arns) == 0


# ── PassRole trust policy guard helpers ─────────────────────────────────────

def _edges_of_type(G, src_arn, edge_type):
    """Return all edges from src_arn with the given edge_type attribute."""
    return [
        (u, v, d) for u, v, d in G.edges(src_arn, data=True)
        if d.get("edge_type") == edge_type
    ]


class TestPassRoleTrustGuard:
    """
    Verify that _add_passrole_edges() only creates a PassRole edge when the
    target role's trust policy actually trusts the required compute service.
    """

    def test_edge_created_when_role_trusts_lambda(self, db_session, account_a):
        """Role trusts lambda.amazonaws.com → passrole_lambda_create edge exists."""
        attacker = _make_role(db_session, account_a, "pr2-atk1",
                              ["iam:PassRole", "lambda:CreateFunction"])
        exec_role = _make_role(db_session, account_a, "pr2-lambda-exec",
                               [], trust_policy=_LAMBDA_TRUST)
        _make_lambda_resource(db_session, account_a, "pr2-fn-1", role=exec_role)
        G = _graph(db_session, account_a)
        edges = _edges_of_type(G, attacker.arn, "passrole_lambda_create")
        assert any(v == exec_role.arn for _, v, _ in edges)

    def test_no_edge_when_role_does_not_trust_lambda(self, db_session, account_a):
        """Role trusts EC2, not Lambda → no passrole_lambda_create edge."""
        attacker = _make_role(db_session, account_a, "pr2-atk2",
                              ["iam:PassRole", "lambda:CreateFunction"])
        exec_role = _make_role(db_session, account_a, "pr2-ec2-exec",
                               [], trust_policy=_EC2_TRUST)
        _make_lambda_resource(db_session, account_a, "pr2-fn-2", role=exec_role)
        G = _graph(db_session, account_a)
        edges = _edges_of_type(G, attacker.arn, "passrole_lambda_create")
        assert not any(v == exec_role.arn for _, v, _ in edges)

    def test_no_edge_when_role_has_no_service_trust(self, db_session, account_a):
        """Role only trusts an AWS principal → no passrole edge."""
        attacker = _make_role(db_session, account_a, "pr2-atk3",
                              ["iam:PassRole", "lambda:CreateFunction"])
        exec_role = _make_role(db_session, account_a, "pr2-aws-trust",
                               [], trust_policy=_NO_SERVICE_TRUST)
        _make_lambda_resource(db_session, account_a, "pr2-fn-3", role=exec_role)
        G = _graph(db_session, account_a)
        edges = _edges_of_type(G, attacker.arn, "passrole_lambda_create")
        assert not any(v == exec_role.arn for _, v, _ in edges)

    def test_edge_created_when_role_has_wildcard_trust(self, db_session, account_a):
        """Principal: '*' trust → passrole edge allowed for any service."""
        wildcard_trust = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": "*",
                           "Action": "sts:AssumeRole"}],
        }
        attacker = _make_role(db_session, account_a, "pr2-atk4",
                              ["iam:PassRole", "lambda:CreateFunction"])
        exec_role = _make_role(db_session, account_a, "pr2-wildcard",
                               [], trust_policy=wildcard_trust)
        _make_lambda_resource(db_session, account_a, "pr2-fn-4", role=exec_role)
        G = _graph(db_session, account_a)
        edges = _edges_of_type(G, attacker.arn, "passrole_lambda_create")
        assert any(v == exec_role.arn for _, v, _ in edges)

    def test_service_specificity(self, db_session, account_a):
        """EC2-trust role: passrole_ec2 edge yes, passrole_lambda_create edge no."""
        attacker = _make_role(db_session, account_a, "pr2-atk5",
                              ["iam:PassRole", "lambda:CreateFunction",
                               "ec2:RunInstances"])
        ec2_exec = _make_role(db_session, account_a, "pr2-ec2-role",
                              [], trust_policy=_EC2_TRUST)
        _make_ec2_resource(db_session, account_a, "pr2-inst-1", role=ec2_exec)
        _make_lambda_resource(db_session, account_a, "pr2-fn-5", role=ec2_exec)
        G = _graph(db_session, account_a)

        ec2_edges = _edges_of_type(G, attacker.arn, "passrole_ec2")
        assert any(v == ec2_exec.arn for _, v, _ in ec2_edges), \
            "Expected PassRole→EC2 edge for EC2-trusting role"

        lambda_edges = _edges_of_type(G, attacker.arn, "passrole_lambda_create")
        assert not any(v == ec2_exec.arn for _, v, _ in lambda_edges), \
            "Must NOT create PassRole→Lambda edge for a role that only trusts EC2"


# ─────────────────────────────────────────────────────────────────────────────
# PR 3 — Resource-scoped PassRole check
# ─────────────────────────────────────────────────────────────────────────────

def _make_role_with_passrole(db, account, name, resource_pattern, extra_actions=None):
    """Create a role with iam:PassRole scoped to resource_pattern."""
    arn = f"arn:aws:iam::{account.account_id}:role/{name}"
    role = upsert_principal(db, account, arn=arn, name=name, principal_type="role")
    stmt = {"Effect": "Allow", "Action": ["iam:PassRole"] + (extra_actions or []),
            "Resource": resource_pattern}
    pol = upsert_policy(db, account, arn=f"{arn}:inline/p", name=f"{name}-p",
                        policy_type="inline",
                        document={"Version": "2012-10-17", "Statement": [stmt]})
    link_principal_policy(db, role, pol)
    db.commit()
    return role


class TestResourceScopedPassRole:
    """
    Verify that _add_passrole_edges() respects the Resource field of iam:PassRole
    statements — edges must only be created for roles whose ARN matches the scope.
    """

    def test_wildcard_resource_allows_all_targets(self, db_session, account_a):
        """Resource: * → edge created for any target role that trusts the service."""
        attacker = _make_role_with_passrole(
            db_session, account_a, "pr3-atk1", "*",
            extra_actions=["lambda:CreateFunction"])
        exec_role = _make_role(db_session, account_a, "pr3-lambda-exec",
                               [], trust_policy=_LAMBDA_TRUST)
        _make_lambda_resource(db_session, account_a, "pr3-fn-1", role=exec_role)

        G = _graph(db_session, account_a)
        edges = _edges_of_type(G, attacker.arn, "passrole_lambda_create")
        assert any(v == exec_role.arn for _, v, _ in edges)

    def test_exact_arn_matches_only_that_role(self, db_session, account_a):
        """Resource: exact ARN → edge only to that role, not others."""
        exec_role = _make_role(db_session, account_a, "pr3-exec-targeted",
                               [], trust_policy=_LAMBDA_TRUST)
        other_role = _make_role(db_session, account_a, "pr3-exec-other",
                                [], trust_policy=_LAMBDA_TRUST)

        # PassRole scoped to exec_role only
        attacker = _make_role_with_passrole(
            db_session, account_a, "pr3-atk2", exec_role.arn,
            extra_actions=["lambda:CreateFunction"])
        _make_lambda_resource(db_session, account_a, "pr3-fn-t", role=exec_role)
        _make_lambda_resource(db_session, account_a, "pr3-fn-o", role=other_role)

        G = _graph(db_session, account_a)
        edges = _edges_of_type(G, attacker.arn, "passrole_lambda_create")

        assert any(v == exec_role.arn for _, v, _ in edges), \
            "Edge expected to the scoped target role"
        assert not any(v == other_role.arn for _, v, _ in edges), \
            "Edge must NOT exist to a role outside the resource scope"

    def test_arn_glob_matches_prefix_only(self, db_session, account_a):
        """Resource: arn:aws:iam::*:role/app-* → matches app- prefix only."""
        acct_id = account_a.account_id
        app_role = _make_role(db_session, account_a, "app-worker",
                              [], trust_policy=_LAMBDA_TRUST)
        svc_role = _make_role(db_session, account_a, "svc-worker",
                              [], trust_policy=_LAMBDA_TRUST)

        attacker = _make_role_with_passrole(
            db_session, account_a, "pr3-atk3",
            f"arn:aws:iam::{acct_id}:role/app-*",
            extra_actions=["lambda:CreateFunction"])
        _make_lambda_resource(db_session, account_a, "pr3-fn-app", role=app_role)
        _make_lambda_resource(db_session, account_a, "pr3-fn-svc", role=svc_role)

        G = _graph(db_session, account_a)
        edges = _edges_of_type(G, attacker.arn, "passrole_lambda_create")

        assert any(v == app_role.arn for _, v, _ in edges), \
            "Edge expected for role matching app-* prefix"
        assert not any(v == svc_role.arn for _, v, _ in edges), \
            "Edge must NOT exist for role not matching app-* prefix"

    def test_notaction_passrole_resource_scope(self, db_session, account_a):
        """NotAction-based PassRole grant (iam:* not excluded) uses Resource scope."""
        acct_id = account_a.account_id
        exec_role = _make_role(db_session, account_a, "pr3-na-exec",
                               [], trust_policy=_LAMBDA_TRUST)

        # Stmt 1: NotAction excludes iam:* → iam:PassRole NOT allowed here
        # Stmt 2: Action: iam:PassRole scoped to exec_role ARN only
        arn = f"arn:aws:iam::{acct_id}:role/pr3-atk4"
        attacker = upsert_principal(db_session, account_a, arn=arn,
                                    name="pr3-atk4", principal_type="role")
        doc = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "NotAction": ["iam:*"], "Resource": "*"},
            {"Effect": "Allow",
             "Action": ["iam:PassRole", "lambda:CreateFunction"],
             "Resource": exec_role.arn},
        ]}
        pol = upsert_policy(db_session, account_a, arn=f"{arn}:inline/p",
                            name="pr3-atk4-p", policy_type="inline", document=doc)
        link_principal_policy(db_session, attacker, pol)

        other_role = _make_role(db_session, account_a, "pr3-na-other",
                                [], trust_policy=_LAMBDA_TRUST)
        _make_lambda_resource(db_session, account_a, "pr3-na-fn1", role=exec_role)
        _make_lambda_resource(db_session, account_a, "pr3-na-fn2", role=other_role)
        db_session.commit()

        G = _graph(db_session, account_a)
        edges = _edges_of_type(G, attacker.arn, "passrole_lambda_create")

        assert any(v == exec_role.arn for _, v, _ in edges), \
            "Edge expected to the explicitly scoped role"
        assert not any(v == other_role.arn for _, v, _ in edges), \
            "Edge must NOT exist to a role outside the explicit PassRole scope"
