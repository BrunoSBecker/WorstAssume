"""
Cross-account trust analyzer.

After multiple accounts have been enumerated, this module:
1. Reads all role trust policies from the DB
2. Identifies trust principals that belong to OTHER tracked accounts
3. Creates CrossAccountLink rows for each discovered relationship
4. Flags wildcards (*, aws:PrincipalOrgID) as high-risk
"""

from __future__ import annotations

import json
import logging
import re

from sqlalchemy.orm import Session

from worstassume.db import store
from worstassume.db.models import Account, CrossAccountLink, Principal

log = logging.getLogger(__name__)

# Regex to extract account ID from an ARN
# ARN format: arn:partition:service:region:account:resource
# IAM/STS ARNs have an empty region field → arn:aws:iam::123456789012:...
_ARN_ACCOUNT_RE = re.compile(r"arn:aws[^:]*:[^:]*:[^:]*:(\d{12}):")


def build_cross_account_links(db: Session) -> list[CrossAccountLink]:
    """
    Walk all role trust policies in the DB and infer cross-account links.
    Returns the list of CrossAccountLink objects created/updated.
    """
    # Index tracked accounts by account_id string
    accounts: dict[str, Account] = {
        a.account_id: a for a in db.query(Account).all()
    }

    if len(accounts) < 2:
        log.info("[cross-account] fewer than 2 accounts tracked — nothing to infer")
        return []

    links: list[CrossAccountLink] = []

    roles = (
        db.query(Principal)
        .filter(Principal.principal_type == "role")
        .filter(Principal.trust_policy_json.isnot(None))
        .all()
    )

    log.info("[cross-account] analyzing trust policies of %d roles", len(roles))

    for role in roles:
        trust = role.trust_policy
        if not trust:
            continue

        target_account = accounts.get(
            _extract_account_id_from_arn(role.arn)
        )
        if target_account is None:
            continue

        for stmt in trust.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue

            action = stmt.get("Action", "")
            actions = [action] if isinstance(action, str) else action
            if not any("sts:AssumeRole" in a or a == "*" for a in actions):
                continue

            principal_block = stmt.get("Principal", {})
            condition = stmt.get("Condition")
            is_wildcard = principal_block == "*"

            # Collect all principal ARNs from the trust statement
            principal_arns: list[str] = []
            if principal_block == "*":
                principal_arns = ["*"]
            elif isinstance(principal_block, dict):
                for k, v in principal_block.items():
                    if isinstance(v, list):
                        principal_arns.extend(v)
                    else:
                        principal_arns.append(v)
            elif isinstance(principal_block, str):
                principal_arns = [principal_block]

            for principal_arn in principal_arns:
                source_account_id = _extract_account_id_from_arn(principal_arn)
                if source_account_id is None:
                    # Could be a service principal (lambda.amazonaws.com) — skip
                    continue
                if source_account_id == target_account.account_id:
                    # Same-account trust — not a cross-account link
                    continue
                if source_account_id not in accounts:
                    # Refers to an account we haven't enumerated
                    log.debug(
                        "[cross-account] unknown source account %s in trust of %s",
                        source_account_id, role.arn,
                    )
                    continue

                source_account = accounts[source_account_id]
                link = store.upsert_cross_account_link(
                    db,
                    source_account=source_account,
                    target_account=target_account,
                    role_arn=role.arn,
                    trust_principal_arn=principal_arn,
                    link_type="sts:AssumeRole",
                    is_wildcard=is_wildcard,
                    condition=condition,
                )
                links.append(link)
                log.info(
                    "[cross-account] %s → %s via %s (wildcard=%s)",
                    source_account_id,
                    target_account.account_id,
                    role.arn,
                    is_wildcard,
                )

    db.commit()
    log.info("[cross-account] %d cross-account links created/updated", len(links))
    return links


def _extract_account_id_from_arn(arn: str) -> str | None:
    """Extract the 12-digit account ID from an ARN, or None if not found."""
    m = _ARN_ACCOUNT_RE.search(arn)
    return m.group(1) if m else None
