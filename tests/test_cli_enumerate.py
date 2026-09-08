"""CLI enumeration behavior for read-constrained credentials."""

from unittest.mock import patch

from click.testing import CliRunner
from moto import mock_aws

from worstassume.cli import main
from worstassume.core.capability import CapabilityMap
from worstassume.db.engine import get_session
from worstassume.db.models import Principal


@mock_aws
def test_empty_capability_map_still_persists_caller(tmp_path):
    db_path = tmp_path / "create-only.sqlite"
    runner = CliRunner()

    with patch(
        "worstassume.core.capability.probe_capabilities",
        return_value=CapabilityMap(),
    ):
        result = runner.invoke(main, ["--db", str(db_path), "enumerate"])

    assert result.exit_code == 0, result.output
    assert "No readable inventory permissions were found" in result.output
    db = get_session()
    try:
        callers = db.query(Principal).all()
        assert len(callers) == 1
        assert callers[0].principal_type in {"user", "role", "federated", "unknown"}
    finally:
        db.close()
