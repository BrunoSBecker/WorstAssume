"""AWS session management — wraps boto3.Session with profile/role-chain support."""

from __future__ import annotations

from collections import Counter
from threading import Lock

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


class SessionManager:
    """Creates and caches boto3 sessions, supports role chaining."""

    def __init__(
        self,
        profile: str | None = None,
        region: str = "us-east-1",
        access_key: str | None = None,
        secret_key: str | None = None,
        session_token: str | None = None,
        assume_role_arn: str | None = None,
    ):
        self.profile = profile
        self.region = region
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token
        self.assume_role_arn = assume_role_arn
        self._session: boto3.Session | None = None
        self._call_counts: Counter[str] = Counter()
        self._call_count_lock = Lock()

    def _instrument_client(self, client):
        """Count every botocore request, including requests made by paginators."""
        service = client.meta.service_model.service_name

        def before_call(model=None, **_kwargs):
            operation = getattr(model, "name", "UnknownOperation")
            with self._call_count_lock:
                self._call_counts[f"{service}.{operation}"] += 1

        client.meta.events.register("before-call.*.*", before_call)
        return client

    @property
    def call_count(self) -> int:
        """Total AWS API requests attempted by this manager."""
        with self._call_count_lock:
            return sum(self._call_counts.values())

    def call_counts(self) -> dict[str, int]:
        """Per service.operation request counts for diagnostics and tests."""
        with self._call_count_lock:
            return dict(sorted(self._call_counts.items()))

    def _base_session(self) -> boto3.Session:
        kwargs: dict = {"region_name": self.region}
        if self.profile:
            kwargs["profile_name"] = self.profile
        if self.access_key:
            kwargs["aws_access_key_id"] = self.access_key
            kwargs["aws_secret_access_key"] = self.secret_key
            if self.session_token:
                kwargs["aws_session_token"] = self.session_token
        return boto3.Session(**kwargs)

    def get_session(self) -> boto3.Session:
        """Return a ready-to-use session, assuming a role if configured."""
        if self._session is not None:
            return self._session

        base = self._base_session()

        if self.assume_role_arn:
            sts = self._instrument_client(base.client("sts"))
            try:
                resp = sts.assume_role(
                    RoleArn=self.assume_role_arn,
                    RoleSessionName="WorstAssume",
                )
                creds = resp["Credentials"]
                self._session = boto3.Session(
                    aws_access_key_id=creds["AccessKeyId"],
                    aws_secret_access_key=creds["SecretAccessKey"],
                    aws_session_token=creds["SessionToken"],
                    region_name=self.region,
                )
            except ClientError as e:
                raise RuntimeError(
                    f"Failed to assume role {self.assume_role_arn}: {e}"
                ) from e
        else:
            self._session = base

        return self._session

    def client(self, service: str):
        return self._instrument_client(self.get_session().client(service))

    def resource(self, service: str):
        resource = self.get_session().resource(service)
        if hasattr(resource, "meta") and hasattr(resource.meta, "client"):
            self._instrument_client(resource.meta.client)
        return resource
