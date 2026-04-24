"""
tests/test_attack_path.py — Test suite for attack_path.find_paths() and persist().

PR 5-A tests: PathResult structure + find_paths() behaviour.
PR 5-B tests: persist() DB upsert.

Follows the same fixture conventions as test_attack_graph.py.
"""
from __future__ import annotations

import pytest

from worstassume.db.store import (
    link_principal_policy,
    upsert_policy,
    upsert_principal,
    upsert_resource,
)
from worstassume.core.attack_graph import build_attack_graph
from worstassume.core.attack_path import PathResult, find_paths, persist
from worstassume.db.models import AttackPath, AttackPathStep


# ─────────────────────────────────────────────────────────────────────────────
# Local helpers (same pattern as test_attack_graph.py)
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


def _make_lambda_resource(db, account, name, role=None):
    arn = f"arn:aws:lambda:us-east-1:{account.account_id}:function/{name}"
    r = upsert_resource(db, account, arn=arn, service="lambda", resource_type="function",
                        name=name, region="us-east-1", execution_role=role)
    db.commit()
    return r


def _graph(db, account=None):
    return build_attack_graph(db, account=account)


_LAMBDA_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow",
                   "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}


# ─────────────────────────────────────────────────────────────────────────────
# PR 5-A — PathResult + find_paths() tests
# ─────────────────────────────────────────────────────────────────────────────

class TestPathResultDataclass:
    """PathResult is a proper dataclass with the expected fields."""

    def test_pathresult_fields_exist(self):
        pr = PathResult(
            from_arn="arn:aws:iam::1:role/A",
            to_arn="arn:aws:iam::1:role/B",
            severity="HIGH",
            hops=1,
            steps=[{"actor": "a", "action": "x", "target": "b",
                    "edge_type": "assume_role", "explanation": "", "severity": "HIGH"}],
            objective="principal:arn:aws:iam::1:role/B",
        )
        assert pr.from_arn == "arn:aws:iam::1:role/A"
        assert pr.to_arn == "arn:aws:iam::1:role/B"
        assert pr.severity == "HIGH"
        assert pr.hops == 1
        assert len(pr.steps) == 1
        assert pr.objective == "principal:arn:aws:iam::1:role/B"

    def test_pathresult_step_has_required_keys(self):
        pr = PathResult(
            from_arn="f", to_arn="t", severity="MEDIUM", hops=1,
            steps=[{"actor": "f", "action": "a", "target": "t",
                    "edge_type": "et", "explanation": "expl", "severity": "MEDIUM"}],
            objective=None,
        )
        step = pr.steps[0]
        for key in ("actor", "action", "target", "edge_type", "explanation"):
            assert key in step, f"Missing key {key!r} in step"


class TestFindPathsFromArnNotInGraph:
    """from_arn not in graph → empty list, no exception."""

    def test_unknown_from_arn_returns_empty(self, db_session, account_a):
        G = _graph(db_session, account_a)
        result = find_paths(G, from_arn="arn:aws:iam::999:role/ghost")
        assert result == []


class TestDirectAssumeRole:
    """
    test_direct_assume_role: attacker has sts:AssumeRole and is in target's trust policy.
    Expected: 1-hop PathResult is returned.
    """

    def test_direct_assume_role_returns_one_hop_path(self, db_session, account_a):
        attacker_arn = f"arn:aws:iam::{account_a.account_id}:role/attacker"
        trust = {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": attacker_arn},
            "Action": "sts:AssumeRole",
        }]}
        target = _make_role(db_session, account_a, "target", [], trust_policy=trust)
        attacker = _make_role(db_session, account_a, "attacker", ["sts:AssumeRole"])
        G = _graph(db_session, account_a)

        paths = find_paths(G, from_arn=attacker.arn,
                           objective=f"principal:{target.arn}")
        assert len(paths) >= 1
        p = paths[0]
        assert p.from_arn == attacker.arn
        assert p.to_arn == target.arn
        assert p.hops == 1
        assert p.steps[0]["edge_type"] == "assume_role"

    def test_direct_assume_role_severity_propagated(self, db_session, account_a):
        attacker_arn = f"arn:aws:iam::{account_a.account_id}:role/attacker2"
        trust = {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": attacker_arn},
            "Action": "sts:AssumeRole",
        }]}
        target = _make_role(db_session, account_a, "target2", [], trust_policy=trust)
        attacker = _make_role(db_session, account_a, "attacker2", ["sts:AssumeRole"])
        G = _graph(db_session, account_a)

        paths = find_paths(G, from_arn=attacker.arn,
                           objective=f"principal:{target.arn}")
        assert paths[0].severity in ("CRITICAL", "HIGH", "MEDIUM")


class TestPassroleLambdaChain:
    """
    test_passrole_lambda_chain: 2-hop path attacker → lambda exec role.
    Requires: attacker has iam:PassRole + lambda:CreateFunction; lambda resource exists.
    """

    def test_passrole_lambda_two_hop_path(self, db_session, account_a):
        exec_role = _make_role(db_session, account_a, "LambdaExecRole", [],
                               trust_policy=_LAMBDA_TRUST)
        _make_lambda_resource(db_session, account_a, "my-fn", role=exec_role)
        attacker = _make_role(db_session, account_a, "attacker",
                              ["iam:PassRole", "lambda:CreateFunction"])
        G = _graph(db_session, account_a)

        paths = find_paths(G, from_arn=attacker.arn,
                           objective=f"principal:{exec_role.arn}")
        assert len(paths) >= 1
        p = paths[0]
        assert p.from_arn == attacker.arn
        assert p.to_arn == exec_role.arn
        assert p.hops == 1   # direct edge: attacker → exec_role via passrole_lambda_create

    def test_passrole_lambda_edge_type_in_steps(self, db_session, account_a):
        exec_role = _make_role(db_session, account_a, "LambdaExecRole2", [],
                               trust_policy=_LAMBDA_TRUST)
        _make_lambda_resource(db_session, account_a, "fn2", role=exec_role)
        attacker = _make_role(db_session, account_a, "attacker2",
                              ["iam:PassRole", "lambda:CreateFunction"])
        G = _graph(db_session, account_a)

        paths = find_paths(G, from_arn=attacker.arn,
                           objective=f"principal:{exec_role.arn}")
        edge_types = {s["edge_type"] for p in paths for s in p.steps}
        assert "passrole_lambda_create" in edge_types


class TestLambdaCodeOverwriteChain:
    """
    test_lambda_code_overwrite_chain: UpdateFunctionCode only — no PassRole needed.
    Expected: lambda_code_overwrite edge present in path.
    """

    def test_lambda_code_overwrite_path_found(self, db_session, account_a):
        exec_role = _make_role(db_session, account_a, "LambdaRole", [])
        _make_lambda_resource(db_session, account_a, "fn", role=exec_role)
        attacker = _make_role(db_session, account_a, "attacker",
                              ["lambda:UpdateFunctionCode"])
        G = _graph(db_session, account_a)

        paths = find_paths(G, from_arn=attacker.arn,
                           objective=f"principal:{exec_role.arn}")
        assert len(paths) >= 1
        edge_types = {s["edge_type"] for p in paths for s in p.steps}
        assert "lambda_code_overwrite" in edge_types


class TestPolicyInjectionChain:
    """
    test_policy_injection_chain: CreatePolicyVersion → iam_policy_inject edge to all principals.
    """

    def test_policy_inject_reaches_victim(self, db_session, account_a):
        victim = _make_role(db_session, account_a, "victim", [])
        attacker = _make_role(db_session, account_a, "attacker",
                              ["iam:CreatePolicyVersion"])
        G = _graph(db_session, account_a)

        paths = find_paths(G, from_arn=attacker.arn,
                           objective=f"principal:{victim.arn}")
        assert len(paths) >= 1
        edge_types = {s["edge_type"] for p in paths for s in p.steps}
        assert "iam_policy_inject" in edge_types

    def test_policy_inject_severity_critical(self, db_session, account_a):
        _make_role(db_session, account_a, "victim2", [])
        attacker = _make_role(db_session, account_a, "attacker2",
                              ["iam:CreatePolicyVersion"])
        G = _graph(db_session, account_a)

        paths = find_paths(G, from_arn=attacker.arn, objective="permission:*:*")
        critical = [p for p in paths if p.severity == "CRITICAL"]
        assert critical, "At least one CRITICAL path expected for CreatePolicyVersion"


class TestNoTargetReturnsAllReachable:
    """
    test_no_target_returns_all_reachable: unconstrained mode (objective=None).
    Expected: multiple PathResults returned.
    """

    def test_unconstrained_returns_multiple_paths(self, db_session, account_a):
        _make_role(db_session, account_a, "victim1", [])
        _make_role(db_session, account_a, "victim2", [])
        attacker = _make_role(db_session, account_a, "attacker",
                              ["iam:PutRolePolicy"])
        G = _graph(db_session, account_a)

        paths = find_paths(G, from_arn=attacker.arn, objective=None)
        assert len(paths) >= 2, "Expected paths to multiple victims in unconstrained mode"

    def test_unconstrained_paths_have_none_objective(self, db_session, account_a):
        _make_role(db_session, account_a, "other", [])
        attacker = _make_role(db_session, account_a, "attacker2",
                              ["iam:PutRolePolicy"])
        G = _graph(db_session, account_a)

        paths = find_paths(G, from_arn=attacker.arn, objective=None)
        for p in paths:
            assert p.objective is None


class TestMaxHopsRespected:
    """
    test_max_hops_respected: paths beyond the cutoff are not returned.
    Graph: A→B (assume_role), B→C (iam_policy_inject). max_hops=1 → only A→B.
    """

    def test_max_hops_one_excludes_two_hop_paths(self, db_session, account_a):
        # B trusts A
        attacker_arn = f"arn:aws:iam::{account_a.account_id}:role/A"
        trust_b = {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": attacker_arn},
            "Action": "sts:AssumeRole",
        }]}
        node_b = _make_role(db_session, account_a, "B",
                            ["iam:PutRolePolicy"], trust_policy=trust_b)
        node_c = _make_role(db_session, account_a, "C", [])
        node_a = _make_role(db_session, account_a, "A", ["sts:AssumeRole"])
        G = _graph(db_session, account_a)

        # With max_hops=1: A→B is reachable, A→B→C is not
        paths_1 = find_paths(G, from_arn=node_a.arn, objective=f"principal:{node_c.arn}",
                             max_hops=1)
        paths_2 = find_paths(G, from_arn=node_a.arn, objective=f"principal:{node_c.arn}",
                             max_hops=2)

        assert all(p.hops <= 1 for p in paths_1), "max_hops=1 must not return 2-hop paths"
        # With max_hops=2 there should be a path (A→B carries iam_policy_inject to C)
        assert len(paths_2) >= 1, "2-hop path A→B→C expected with max_hops=2"

    def test_default_max_hops_allows_long_paths(self, db_session, account_a):
        # Minimal sanity: default max_hops=10 allows finding 1-hop paths
        victim = _make_role(db_session, account_a, "victim", [])
        attacker = _make_role(db_session, account_a, "attacker",
                              ["iam:PutRolePolicy"])
        G = _graph(db_session, account_a)

        paths = find_paths(G, from_arn=attacker.arn,
                           objective=f"principal:{victim.arn}")
        assert len(paths) >= 1


class TestResultSortOrder:
    """Results are sorted by severity DESC (CRITICAL first), then hops ASC."""

    def test_results_sorted_by_severity_then_hops(self, db_session, account_a):
        _make_role(db_session, account_a, "victim", [])
        attacker = _make_role(db_session, account_a, "attacker",
                              ["iam:CreatePolicyVersion", "iam:PutRolePolicy"])
        G = _graph(db_session, account_a)

        paths = find_paths(G, from_arn=attacker.arn, objective=None)
        # Assert sorted correctly
        _SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
        for i in range(len(paths) - 1):
            a, b = paths[i], paths[i + 1]
            sev_a = _SEV_ORDER.get(a.severity, 99)
            sev_b = _SEV_ORDER.get(b.severity, 99)
            if sev_a == sev_b:
                assert a.hops <= b.hops, "Same severity: shorter paths must come first"
            else:
                assert sev_a <= sev_b, "Higher severity must come before lower severity"


# ─────────────────────────────────────────────────────────────────────────────
# PR 5-B — persist() tests (placeholder — will be activated in PR 5-B)
# ─────────────────────────────────────────────────────────────────────────────

class TestPersistCreatesOrmRows:
    """
    test_persist_creates_orm_rows: running persist() writes AttackPath + steps.
    NOTE: This class exercises the full stack including PR 5-B's persist().
    """

    def test_persist_creates_attack_path_rows(self, db_session, account_a):
        victim = _make_role(db_session, account_a, "victim", [])
        attacker = _make_role(db_session, account_a, "attacker",
                              ["iam:PutRolePolicy"])
        G = _graph(db_session, account_a)
        paths = find_paths(G, from_arn=attacker.arn,
                           objective=f"principal:{victim.arn}")
        assert paths, "Need at least one path to test persistence"

        persist(db_session, paths, from_arn=attacker.arn,
                objective=f"principal:{victim.arn}", account=account_a)
        db_session.commit()

        count = db_session.query(AttackPath).count()
        assert count > 0, "persist() must create AttackPath rows"

    def test_persist_creates_step_rows(self, db_session, account_a):
        victim = _make_role(db_session, account_a, "victim2", [])
        attacker = _make_role(db_session, account_a, "attacker2",
                              ["iam:PutRolePolicy"])
        G = _graph(db_session, account_a)
        paths = find_paths(G, from_arn=attacker.arn,
                           objective=f"principal:{victim.arn}")
        assert paths

        persist(db_session, paths, from_arn=attacker.arn,
                objective=f"principal:{victim.arn}", account=account_a)
        db_session.commit()

        step_count = db_session.query(AttackPathStep).count()
        assert step_count > 0, "persist() must create AttackPathStep rows"

    def test_persist_step_fields_populated(self, db_session, account_a):
        victim = _make_role(db_session, account_a, "victim3", [])
        attacker = _make_role(db_session, account_a, "attacker3",
                              ["iam:PutRolePolicy"])
        G = _graph(db_session, account_a)
        paths = find_paths(G, from_arn=attacker.arn,
                           objective=f"principal:{victim.arn}")
        assert paths

        persist(db_session, paths, from_arn=attacker.arn,
                objective=f"principal:{victim.arn}", account=account_a)
        db_session.commit()

        step = db_session.query(AttackPathStep).first()
        assert step is not None
        assert step.actor_arn
        assert step.target_arn
        assert step.edge_type
        assert step.action
        assert step.explanation is not None


class TestPersistDeduplicates:
    """
    test_persist_deduplicates: calling persist() twice produces the same number of rows.
    """

    def test_second_persist_does_not_duplicate(self, db_session, account_a):
        victim = _make_role(db_session, account_a, "victim", [])
        attacker = _make_role(db_session, account_a, "attacker",
                              ["iam:PutRolePolicy"])
        G = _graph(db_session, account_a)
        objective = f"principal:{victim.arn}"
        paths = find_paths(G, from_arn=attacker.arn, objective=objective)
        assert paths

        persist(db_session, paths, from_arn=attacker.arn,
                objective=objective, account=account_a)
        db_session.commit()
        count_after_first = db_session.query(AttackPath).count()

        # Run again with the same paths
        persist(db_session, paths, from_arn=attacker.arn,
                objective=objective, account=account_a)
        db_session.commit()
        count_after_second = db_session.query(AttackPath).count()

        assert count_after_first == count_after_second, \
            "Second persist() must not create duplicate AttackPath rows"

    def test_second_persist_does_not_duplicate_steps(self, db_session, account_a):
        victim = _make_role(db_session, account_a, "victim2", [])
        attacker = _make_role(db_session, account_a, "attacker2",
                              ["iam:PutRolePolicy"])
        G = _graph(db_session, account_a)
        objective = f"principal:{victim.arn}"
        paths = find_paths(G, from_arn=attacker.arn, objective=objective)
        assert paths

        persist(db_session, paths, from_arn=attacker.arn,
                objective=objective, account=account_a)
        db_session.commit()
        steps_first = db_session.query(AttackPathStep).count()

        persist(db_session, paths, from_arn=attacker.arn,
                objective=objective, account=account_a)
        db_session.commit()
        steps_second = db_session.query(AttackPathStep).count()

        assert steps_first == steps_second, \
            "Second persist() must not duplicate AttackPathStep rows"


# ─────────────────────────────────────────────────────────────────────────────
# PR-B — TestFindPathsBFS: BFS engine (no pre-built graph)
# ─────────────────────────────────────────────────────────────────────────────

from worstassume.core.attack_graph import NeighborContext
from worstassume.core.attack_path import find_paths_bfs


def _ctx(db, account=None):
    return NeighborContext(db, account=account)


class TestFindPathsBFS:
    """
    Verifies that find_paths_bfs() produces the same paths as find_paths()
    and respects BFS semantics (max_hops, visited dedup, early termination).
    """

    def test_bfs_finds_passrole_lambda_path(self, db_session, account_a):
        """BFS must find 1-hop passrole_lambda_create path when exec role trusts lambda."""
        exec_role = _make_role(db_session, account_a, "BFSExecRole", [],
                               trust_policy=_LAMBDA_TRUST)
        _make_lambda_resource(db_session, account_a, "bfs-fn", role=exec_role)
        attacker = _make_role(db_session, account_a, "bfs-attacker",
                              ["iam:PassRole", "lambda:CreateFunction"])

        ctx = _ctx(db_session, account_a)
        paths = find_paths_bfs(ctx, from_arn=attacker.arn,
                               objective=f"principal:{exec_role.arn}")
        assert len(paths) >= 1
        p = paths[0]
        assert p.from_arn == attacker.arn
        assert p.to_arn == exec_role.arn
        assert p.hops == 1

    def test_bfs_edge_type_in_steps(self, db_session, account_a):
        """Steps must contain passrole_lambda_create edge_type."""
        exec_role = _make_role(db_session, account_a, "BFSExecRole2", [],
                               trust_policy=_LAMBDA_TRUST)
        _make_lambda_resource(db_session, account_a, "bfs-fn2", role=exec_role)
        attacker = _make_role(db_session, account_a, "bfs-attacker2",
                              ["iam:PassRole", "lambda:CreateFunction"])

        ctx = _ctx(db_session, account_a)
        paths = find_paths_bfs(ctx, from_arn=attacker.arn,
                               objective=f"principal:{exec_role.arn}")
        edge_types = {s["edge_type"] for p in paths for s in p.steps}
        assert "passrole_lambda_create" in edge_types

    def test_bfs_no_path_when_no_passrole(self, db_session, account_a):
        """BFS must return empty list when attacker lacks iam:PassRole."""
        exec_role = _make_role(db_session, account_a, "BFSExecRole3", [],
                               trust_policy=_LAMBDA_TRUST)
        _make_lambda_resource(db_session, account_a, "bfs-fn3", role=exec_role)
        attacker = _make_role(db_session, account_a, "bfs-attacker3",
                              ["lambda:CreateFunction"])  # no PassRole

        ctx = _ctx(db_session, account_a)
        paths = find_paths_bfs(ctx, from_arn=attacker.arn,
                               objective=f"principal:{exec_role.arn}")
        assert paths == []

    def test_bfs_max_hops_respected(self, db_session, account_a):
        """BFS with max_hops=0 must return no paths (no expansion allowed)."""
        exec_role = _make_role(db_session, account_a, "BFSExecRole4", [],
                               trust_policy=_LAMBDA_TRUST)
        _make_lambda_resource(db_session, account_a, "bfs-fn4", role=exec_role)
        attacker = _make_role(db_session, account_a, "bfs-attacker4",
                              ["iam:PassRole", "lambda:CreateFunction"])

        ctx = _ctx(db_session, account_a)
        paths = find_paths_bfs(ctx, from_arn=attacker.arn,
                               objective=f"principal:{exec_role.arn}",
                               max_hops=0)
        assert paths == []

    def test_bfs_unresolvable_objective(self, db_session, account_a):
        """BFS with objective ARN not in context must return empty list."""
        attacker = _make_role(db_session, account_a, "bfs-attacker5",
                              ["iam:PassRole", "lambda:CreateFunction"])

        ctx = _ctx(db_session, account_a)
        paths = find_paths_bfs(ctx, from_arn=attacker.arn,
                               objective="principal:arn:aws:iam::999:role/ghost")
        assert paths == []

    def test_bfs_pathresult_fields(self, db_session, account_a):
        """PathResult returned by BFS must have all required fields."""
        exec_role = _make_role(db_session, account_a, "BFSExecRole6", [],
                               trust_policy=_LAMBDA_TRUST)
        _make_lambda_resource(db_session, account_a, "bfs-fn6", role=exec_role)
        attacker = _make_role(db_session, account_a, "bfs-attacker6",
                              ["iam:PassRole", "lambda:CreateFunction"])

        ctx = _ctx(db_session, account_a)
        paths = find_paths_bfs(ctx, from_arn=attacker.arn,
                               objective=f"principal:{exec_role.arn}")
        assert paths
        p = paths[0]
        assert p.severity in ("CRITICAL", "HIGH", "MEDIUM")
        assert p.hops >= 1
        assert p.steps
        step = p.steps[0]
        for key in ("actor", "action", "target", "edge_type", "explanation", "severity"):
            assert key in step, f"step missing key: {key}"
