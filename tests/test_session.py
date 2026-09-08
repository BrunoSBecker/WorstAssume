"""Tests for AWS request instrumentation."""

from moto import mock_aws

from worstassume.session import SessionManager


@mock_aws
def test_counts_direct_and_paginated_aws_calls():
    session = SessionManager(region="us-east-1")

    session.client("sts").get_caller_identity()
    list(session.client("iam").get_paginator("list_users").paginate())

    assert session.call_count == 2
    counts = session.call_counts()
    assert counts["sts.GetCallerIdentity"] == 1
    assert counts["iam.ListUsers"] == 1
