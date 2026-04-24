"""
resource_graph.py

Public API for building and querying the AWS resource relationship graph.
All heavy lifting is delegated to GraphStore; this module is kept as the
single import point used by the CLI and server.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from worstassume.core.graph_store import (
    GraphStore,
    build_graph,
    graph_to_cytoscape,
)

__all__ = [
    "GraphStore",
    "build_graph",
    "graph_to_cytoscape",
    "_normalize_assumed_role_arn",
]


def _normalize_assumed_role_arn(arn: str, db: Session) -> str | None:
    """
    Convert an assumed-role ARN to a real IAM role ARN.
    arn:aws:sts::ACCOUNT:assumed-role/ROLE-NAME/SESSION → role ARN
    Returns None if not found in DB.
    """
    from worstassume.db.models import Account, Principal

    if ":assumed-role/" not in arn:
        return None
    try:
        parts = arn.split(":")
        account_id = parts[4]
        role_name  = parts[5].split("/")[1]
    except (IndexError, ValueError):
        return None

    acct = db.query(Account).filter_by(account_id=account_id).first()
    if not acct:
        return None
    p = (
        db.query(Principal)
        .filter_by(account_id=acct.id, name=role_name, principal_type="role")
        .first()
    )
    return p.arn if p else None
