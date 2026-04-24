"""SQLAlchemy ORM models for WorstAssume's local database."""

from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


# ─── Many-to-many: Principal ↔ Policy ────────────────────────────────────────

from sqlalchemy import Column as _Col

principal_policy_table = Table(
    "principal_policy",
    Base.metadata,
    _Col("principal_id", Integer, ForeignKey("principals.id"), primary_key=True),
    _Col("policy_id", Integer, ForeignKey("policies.id"), primary_key=True),
)


# ─── Account ──────────────────────────────────────────────────────────────────

class Account(Base):
    __tablename__ = "accounts"

    id:                     Mapped[int]             = mapped_column(Integer, primary_key=True, autoincrement=True)
    account_id:             Mapped[str]             = mapped_column(String(12), unique=True, nullable=False, index=True)
    account_name:           Mapped[str | None]      = mapped_column(String(256))
    org_id:                 Mapped[str | None]      = mapped_column(String(64))
    profile:                Mapped[str | None]      = mapped_column(String(128))
    last_enumerated_at:     Mapped[datetime | None] = mapped_column(DateTime)

    principals: Mapped[list["Principal"]] = relationship(
        "Principal", back_populates="account", cascade="all, delete-orphan"
    )
    resources: Mapped[list["Resource"]] = relationship(
        "Resource", back_populates="account", cascade="all, delete-orphan"
    )
    policies: Mapped[list["Policy"]] = relationship(
        "Policy", back_populates="account", cascade="all, delete-orphan"
    )
    runs: Mapped[list["EnumerationRun"]] = relationship(
        "EnumerationRun", back_populates="account", cascade="all, delete-orphan"
    )
    outbound_links: Mapped[list["CrossAccountLink"]] = relationship(
        "CrossAccountLink",
        foreign_keys="CrossAccountLink.source_account_id",
        back_populates="source_account",
        cascade="all, delete-orphan",
    )
    inbound_links: Mapped[list["CrossAccountLink"]] = relationship(
        "CrossAccountLink",
        foreign_keys="CrossAccountLink.target_account_id",
        back_populates="target_account",
        cascade="all, delete-orphan",
    )
    findings: Mapped[list["SecurityFinding"]] = relationship(
        "SecurityFinding", back_populates="account", cascade="all, delete-orphan"
    )
    attack_paths: Mapped[list["AttackPath"]] = relationship(
        "AttackPath", back_populates="account", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Account {self.account_id} ({self.account_name})>"


# ─── Principal ────────────────────────────────────────────────────────────────

class Principal(Base):
    """IAM users, roles, and groups."""

    __tablename__ = "principals"
    __table_args__ = (
        UniqueConstraint("account_id", "arn", name="uq_principal_arn"),
        Index("ix_principal_account_type", "account_id", "principal_type"),
    )

    id:                 Mapped[int]         = mapped_column(Integer, primary_key=True, autoincrement=True)
    account_id:         Mapped[int]         = mapped_column(Integer, ForeignKey("accounts.id"), nullable=False)
    arn:                Mapped[str]         = mapped_column(String(2048), nullable=False, index=True)
    name:               Mapped[str]         = mapped_column(String(256), nullable=False)
    principal_type:     Mapped[str]         = mapped_column(String(16), nullable=False)  # user / role / group
    path:               Mapped[str | None]  = mapped_column(String(512))
    # Trust policy (roles only)
    trust_policy_json:  Mapped[str | None]  = mapped_column(Text)
    # Raw metadata (tags, create date, etc.)
    metadata_json:      Mapped[str | None]  = mapped_column(Text)

    account:            Mapped["Account"]       = relationship("Account", back_populates="principals")
    policies:           Mapped[list["Policy"]]  = relationship(
                                                    "Policy", secondary=principal_policy_table, back_populates="principals"
                                                )
    # Resources that use this principal as their execution role
    resources:          Mapped[list["Resource"]]    = relationship(
                                                        "Resource", back_populates="execution_role"
                                                    )
    # Group memberships (populated during enumeration, Phase 8)
    group_memberships_as_user:  Mapped[list["GroupMembership"]] = relationship(
        "GroupMembership", foreign_keys="GroupMembership.user_id",  back_populates="user"
    )
    group_memberships_as_group: Mapped[list["GroupMembership"]] = relationship(
        "GroupMembership", foreign_keys="GroupMembership.group_id", back_populates="group"
    )

    @property
    def trust_policy(self) -> dict | None:
        if self.trust_policy_json:
            return json.loads(self.trust_policy_json)
        return None

    @property
    def extra(self) -> dict | None:
        if self.metadata_json:
            return json.loads(self.metadata_json)
        return None

    def __repr__(self) -> str:
        return f"<Principal {self.principal_type}:{self.name}>"


# ─── Policy ───────────────────────────────────────────────────────────────────

class Policy(Base):
    """IAM managed and inline policies."""

    __tablename__ = "policies"
    __table_args__ = (UniqueConstraint("account_id", "arn", name="uq_policy_arn"),)

    id:                 Mapped[int]             = mapped_column(Integer, primary_key=True, autoincrement=True)
    account_id:         Mapped[int]             = mapped_column(Integer, ForeignKey("accounts.id"), nullable=False)
    arn:                Mapped[str]             = mapped_column(String(2048), nullable=False, index=True)
    name:               Mapped[str]             = mapped_column(String(256), nullable=False)
    policy_type:        Mapped[str]             = mapped_column(String(16), nullable=False)  # managed / inline / aws_managed
    document_json:      Mapped[str | None]      = mapped_column(Text)

    account: Mapped["Account"] = relationship("Account", back_populates="policies")
    principals: Mapped[list["Principal"]] = relationship(
        "Principal", secondary=principal_policy_table, back_populates="policies"
    )

    @property
    def document(self) -> dict | None:
        if self.document_json:
            return json.loads(self.document_json)
        return None

    def __repr__(self) -> str:
        return f"<Policy {self.policy_type}:{self.name}>"


# ─── Resource ─────────────────────────────────────────────────────────────────

class Resource(Base):
    """Any AWS resource (EC2 instance, Lambda function, S3 bucket, ECS cluster, etc.)."""

    __tablename__ = "resources"
    __table_args__ = (
        UniqueConstraint("account_id", "arn", name="uq_resource_arn"),
        Index("ix_resource_account_service", "account_id", "service"),
    )

    id:                     Mapped[int]             = mapped_column(Integer, primary_key=True, autoincrement=True)
    account_id:             Mapped[int]             = mapped_column(Integer, ForeignKey("accounts.id"), nullable=False)
    arn:                    Mapped[str]             = mapped_column(String(2048), nullable=False, index=True)
    service:                Mapped[str]             = mapped_column(String(32), nullable=False)   # ec2, s3, lambda, ecs, vpc
    resource_type:          Mapped[str]             = mapped_column(String(64), nullable=False)  # instance, bucket, function, cluster
    name:                   Mapped[str | None]      = mapped_column(String(512))
    region:                 Mapped[str | None]      = mapped_column(String(32))
    # FK to the IAM role attached (if any)
    execution_role_id:      Mapped[int | None]      = mapped_column(Integer, ForeignKey("principals.id"))
    metadata_json:          Mapped[str | None]      = mapped_column(Text)

    account: Mapped["Account"] = relationship("Account", back_populates="resources")
    execution_role: Mapped["Principal | None"] = relationship(
        "Principal", back_populates="resources"
    )

    @property
    def extra(self) -> dict | None:
        if self.metadata_json:
            return json.loads(self.metadata_json)
        return None

    def __repr__(self) -> str:
        return f"<Resource {self.service}/{self.resource_type}:{self.name or self.arn}>"


# ─── CrossAccountLink ─────────────────────────────────────────────────────────

class CrossAccountLink(Base):
    """A discovered trust relationship between two tracked accounts."""

    __tablename__ = "cross_account_links"
    __table_args__ = (
        Index("ix_cross_account_wildcard", "is_wildcard"),
        Index("ix_cross_account_role_arn", "role_arn"),
    )

    id:                     Mapped[int]         = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_account_id:      Mapped[int]         = mapped_column(
                                                    Integer, ForeignKey("accounts.id"), nullable=False
                                                )
    target_account_id:      Mapped[int]         = mapped_column(
                                                    Integer, ForeignKey("accounts.id"), nullable=False
                                                )
    role_arn:               Mapped[str]         = mapped_column(String(2048), nullable=False)
    trust_principal_arn:    Mapped[str]         = mapped_column(String(2048), nullable=False)
    link_type:              Mapped[str]         = mapped_column(String(64), default="sts:AssumeRole")
    is_wildcard:            Mapped[bool]        = mapped_column(Boolean, default=False)
    condition_json:         Mapped[str | None]  = mapped_column(Text)  # trust condition block if any
    notes:                  Mapped[str | None]  = mapped_column(Text)

    source_account: Mapped["Account"] = relationship(
        "Account", foreign_keys=[source_account_id], back_populates="outbound_links"
    )
    target_account: Mapped["Account"] = relationship(
        "Account", foreign_keys=[target_account_id], back_populates="inbound_links"
    )

    def __repr__(self) -> str:
        return (
            f"<CrossAccountLink {self.source_account_id} → {self.target_account_id} "
            f"via {self.role_arn}>"
        )


# ─── EnumerationRun ───────────────────────────────────────────────────────────

class EnumerationRun(Base):
    """Tracks each `worst enumerate` invocation per account."""

    __tablename__ = "enumeration_runs"

    id:                 Mapped[int]                 = mapped_column(Integer, primary_key=True, autoincrement=True)
    account_id:         Mapped[int]                 = mapped_column(Integer, ForeignKey("accounts.id"), nullable=False)
    started_at:         Mapped[datetime]            = mapped_column(DateTime, default=datetime.utcnow)
    finished_at:        Mapped[datetime | None]     = mapped_column(DateTime)
    capabilities_json:  Mapped[str | None]          = mapped_column(Text)  # CapabilityMap snapshot
    success:            Mapped[bool]                = mapped_column(Boolean, default=True)
    error_message:      Mapped[str | None]          = mapped_column(Text)

    account:            Mapped["Account"]           = relationship("Account", back_populates="runs")

    @property
    def capabilities(self) -> dict | None:
        if self.capabilities_json:
            return json.loads(self.capabilities_json)
        return None

    def __repr__(self) -> str:
        return f"<EnumerationRun account={self.account_id} started={self.started_at}>"


# ─── SecurityFinding ──────────────────────────────────────────────────────────

class SecurityFinding(Base):
    """A persisted security misconfiguration finding from the assessment engine."""

    __tablename__ = "security_findings"
    __table_args__ = (
        UniqueConstraint("account_id", "entity_arn", "path_id", name="uq_security_finding"),
        Index("ix_sf_account_severity", "account_id", "severity"),
    )

    id:                Mapped[int]       = mapped_column(Integer, primary_key=True, autoincrement=True)
    account_id:        Mapped[int]       = mapped_column(Integer, ForeignKey("accounts.id"), nullable=False)
    entity_arn:        Mapped[str]       = mapped_column(String(2048), nullable=False, index=True)
    entity_type:       Mapped[str]       = mapped_column(String(16), nullable=False)   # role / user / group
    entity_name:       Mapped[str]       = mapped_column(String(256), nullable=False)
    # Machine-readable rule identifier, e.g. "WildcardTrustNoCondition"
    category:          Mapped[str]       = mapped_column(String(32), nullable=False)
    path_id:           Mapped[str]       = mapped_column(String(128), nullable=False)
    severity:          Mapped[str]       = mapped_column(String(16), nullable=False)
    original_severity: Mapped[str]       = mapped_column(String(16), nullable=False)
    message:           Mapped[str]       = mapped_column(Text, nullable=False)
    # Trust principal that triggered the finding (nullable — permission findings have no principal)
    principal_detail:  Mapped[str | None] = mapped_column(Text)
    condition_json:    Mapped[str | None] = mapped_column(Text)
    perm_risk:         Mapped[str | None] = mapped_column(String(16))  # HIGH / MEDIUM / LOW
    downgrade_note:    Mapped[str | None] = mapped_column(Text)
    suppressed:        Mapped[bool]       = mapped_column(Boolean, default=False)
    created_at:        Mapped[datetime]   = mapped_column(DateTime, default=datetime.utcnow)

    account: Mapped["Account"] = relationship("Account", back_populates="findings")

    @property
    def condition(self) -> dict | None:
        if self.condition_json:
            return json.loads(self.condition_json)
        return None

    def __repr__(self) -> str:
        return f"<SecurityFinding [{self.severity}] {self.path_id} @ {self.entity_arn}>"


# ─── AttackPath + AttackPathStep ──────────────────────────────────────────────

class AttackPath(Base):
    """A discovered multi-step attack chain from a starting identity to an objective."""

    __tablename__ = "attack_paths"
    __table_args__ = (
        Index("ix_ap_from_principal", "from_principal_arn"),
        Index("ix_ap_account_severity", "account_id", "severity"),
    )

    id:                 Mapped[int]       = mapped_column(Integer, primary_key=True, autoincrement=True)
    account_id:         Mapped[int]       = mapped_column(Integer, ForeignKey("accounts.id"), nullable=False)
    from_principal_arn: Mapped[str]       = mapped_column(String(2048), nullable=False)
    # objective_type: permission / resource / principal / None (unconstrained traversal)
    objective_type:     Mapped[str | None] = mapped_column(String(32))
    objective_value:    Mapped[str | None] = mapped_column(Text)
    severity:           Mapped[str]       = mapped_column(String(16), nullable=False)
    total_hops:         Mapped[int]       = mapped_column(Integer, nullable=False)
    summary:            Mapped[str]       = mapped_column(Text, nullable=False)
    created_at:         Mapped[datetime]  = mapped_column(DateTime, default=datetime.utcnow)

    account: Mapped["Account"] = relationship("Account", back_populates="attack_paths")
    steps:   Mapped[list["AttackPathStep"]] = relationship(
        "AttackPathStep",
        back_populates="path",
        order_by="AttackPathStep.step_index",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return (
            f"<AttackPath [{self.severity}] {self.total_hops} hops "
            f"from {self.from_principal_arn}>"
        )


class AttackPathStep(Base):
    """A single hop within an AttackPath."""

    __tablename__ = "attack_path_steps"

    id:          Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    path_id:     Mapped[int] = mapped_column(Integer, ForeignKey("attack_paths.id"), nullable=False)
    step_index:  Mapped[int] = mapped_column(Integer, nullable=False)
    actor_arn:   Mapped[str] = mapped_column(String(2048), nullable=False)
    # Human-readable action string, e.g. "iam:PassRole + lambda:CreateFunction"
    action:      Mapped[str] = mapped_column(String(256), nullable=False)
    target_arn:  Mapped[str] = mapped_column(String(2048), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    # Edge type key, e.g. "passrole_lambda_create", "assume_role", "lambda_code_overwrite"
    edge_type:   Mapped[str] = mapped_column(String(64), nullable=False)

    path: Mapped["AttackPath"] = relationship("AttackPath", back_populates="steps")

    def __repr__(self) -> str:
        return f"<AttackPathStep [{self.step_index}] {self.edge_type}: {self.actor_arn} → {self.target_arn}>"


# ─── GroupMembership (Phase 8) ──────────────────────────────────────────────────────────────

class GroupMembership(Base):
    """
    Maps an IAM user to each IAM group they belong to.
    Populated by the IAM enumeration module from GetAccountAuthorizationDetails
    (fast path) or ListGroupsForUser (slow path).
    """

    __tablename__ = "group_memberships"
    __table_args__ = (
        UniqueConstraint("user_id", "group_id", name="uq_group_membership"),
    )

    id:         Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id:    Mapped[int] = mapped_column(Integer, ForeignKey("principals.id"), nullable=False)
    group_id:   Mapped[int] = mapped_column(Integer, ForeignKey("principals.id"), nullable=False)
    account_id: Mapped[int] = mapped_column(Integer, ForeignKey("accounts.id"),   nullable=False)

    user:    Mapped["Principal"] = relationship("Principal", foreign_keys=[user_id],  back_populates="group_memberships_as_user")
    group:   Mapped["Principal"] = relationship("Principal", foreign_keys=[group_id], back_populates="group_memberships_as_group")
    account: Mapped["Account"]   = relationship("Account")

    def __repr__(self) -> str:
        return f"<GroupMembership user={self.user_id} → group={self.group_id}>"
