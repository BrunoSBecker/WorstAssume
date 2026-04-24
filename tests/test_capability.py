"""
Tests for worstassume.core.capability — adaptive probe engine.

Uses moto to mock AWS services and botocore stubs to simulate
AccessDenied responses for individual probes.
"""

from __future__ import annotations

import unittest.mock as mock
from unittest.mock import MagicMock, patch

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from worstassume.core.capability import (
    CapabilityMap,
    probe_capabilities,
)
from worstassume.session import SessionManager


def _access_denied_error(operation: str = "ListRoles") -> ClientError:
    return ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
        operation,
    )


def _make_session(region="us-east-1") -> SessionManager:
    return SessionManager(region=region)


# ─── CapabilityMap helpers ────────────────────────────────────────────────────

class TestCapabilityMap:
    def test_has_any_iam_true(self):
        cap = CapabilityMap(iam_full_dump=True)
        assert cap.has_any_iam is True

    def test_has_any_iam_false(self):
        cap = CapabilityMap()
        assert cap.has_any_iam is False

    def test_has_any_ec2_true(self):
        cap = CapabilityMap(ec2_instances=True)
        assert cap.has_any_ec2 is True

    def test_to_dict_contains_all_keys(self):
        cap = CapabilityMap(iam_full_dump=True, s3_buckets=True)
        d = cap.to_dict()
        assert d["iam_full_dump"] is True
        assert d["s3_buckets"] is True
        # all keys present
        assert "ec2_instances" in d
        assert "lambda_functions" in d

    def test_default_all_false(self):
        cap = CapabilityMap()
        assert all(not v for v in cap.to_dict().values())




# ─── probe_capabilities ───────────────────────────────────────────────────────

@mock_aws
class TestProbeCapabilities:
    """
    moto auto-approves all calls, so by default every probe succeeds.
    We selectively patch individual client calls to return AccessDenied.
    """

    def test_all_allowed_by_default(self):
        """When moto allows all calls, all capabilities should be True."""
        session = _make_session()
        cap = probe_capabilities(session, caller_arn="arn:aws:iam::123456789012:user/test")
        # At minimum we should detect some capabilities
        assert isinstance(cap, CapabilityMap)
        assert cap.iam_full_dump is True
        assert cap.s3_buckets is True
        assert cap.lambda_functions is True

    def test_iam_denied_marks_false(self):
        """If iam:GetAccountAuthorizationDetails is denied, iam_full_dump should be False."""
        session = _make_session()
        original_client = session.client

        def patched_client(svc):
            c = original_client(svc)
            if svc == "iam":
                c_mock = MagicMock(wraps=c)
                c_mock.get_account_authorization_details.side_effect = _access_denied_error("GetAccountAuthorizationDetails")
                c_mock.list_roles.side_effect = _access_denied_error("ListRoles")
                c_mock.list_users.side_effect = _access_denied_error("ListUsers")
                c_mock.list_policies.side_effect = _access_denied_error("ListPolicies")
                c_mock.simulate_principal_policy.side_effect = _access_denied_error("SimulatePrincipalPolicy")
                return c_mock
            return c

        with mock.patch.object(session, "client", side_effect=patched_client):
            cap = probe_capabilities(session, caller_arn="arn:aws:iam::123456789012:user/test")

        assert cap.iam_full_dump is False
        assert cap.iam_list_roles is False
        assert cap.iam_list_users is False

    def test_partial_permissions(self):
        """EC2 allowed but S3 denied → ec2_instances True, s3_buckets False."""
        session = _make_session()
        original_client = session.client

        def patched_client(svc):
            c = original_client(svc)
            if svc == "s3":
                c_mock = MagicMock(wraps=c)
                c_mock.list_buckets.side_effect = _access_denied_error("ListBuckets")
                return c_mock
            return c

        with mock.patch.object(session, "client", side_effect=patched_client):
            cap = probe_capabilities(session, caller_arn="arn:aws:iam::123456789012:user/test")

        assert cap.ec2_instances is True
        assert cap.s3_buckets is False
