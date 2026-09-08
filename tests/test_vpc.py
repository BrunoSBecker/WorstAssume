"""Tests for per-operation VPC capability gating."""

from unittest.mock import MagicMock, patch

from worstassume.core.capability import CapabilityMap
from worstassume.modules import vpc
from worstassume.session import SessionManager


def test_only_enumerates_allowed_vpc_subresources(db_session):
    session = MagicMock(spec=SessionManager)
    session.region = "us-east-1"
    account = MagicMock()
    cap = CapabilityMap(ec2_subnets=True)

    with (
        patch.object(vpc, "_enumerate_subnets") as subnets,
        patch.object(vpc, "_enumerate_internet_gateways") as igws,
        patch.object(vpc, "_enumerate_nat_gateways") as nats,
        patch.object(vpc, "_enumerate_route_tables") as routes,
    ):
        vpc.enumerate(session, db_session, account, cap)

    subnets.assert_called_once()
    igws.assert_not_called()
    nats.assert_not_called()
    routes.assert_not_called()


def test_no_vpc_capability_does_not_create_client(db_session):
    session = MagicMock(spec=SessionManager)

    vpc.enumerate(session, db_session, MagicMock(), CapabilityMap())

    session.client.assert_not_called()
