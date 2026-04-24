# WorstAssume — Project Documentation

> **Version:** 0.1.0 (alpha)
> **Purpose:** Stealth-first AWS IAM enumeration, multi-account graph analysis and privilege escalation visualisation tool.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Data Model](#data-model)
4. [CLI Commands](#cli-commands)
5. [Enumeration Modules](#enumeration-modules)
6. [Core Analysis Engine](#core-analysis-engine)
7. [Visualization (Graph UI)](#visualization-graph-ui)
8. [API Reference](#api-reference)
9. [Graph Schema](#graph-schema)
10. [Privilege Escalation Catalogue](#privilege-escalation-catalogue)
11. [Frontend Component Reference](#frontend-component-reference)
12. [Development Guide](#development-guide)

---

## Overview

WorstAssume is an offensive AWS security tool designed for red teamers and penetration testers. It:

1. **Enumerates** IAM principals, policies, and resources across one or multiple AWS accounts using the caller's existing permissions (capability-adaptive — only calls what it is allowed to call)
2. **Stores** all enumerated data locally in a SQLite database
3. **Analyses** the collected data for known privilege escalation paths
4. **Visualises** the full IAM relationship graph interactively in a browser, with identity-aware path finding

### Key design principles

| Principle | Implementation |
|-----------|---------------|
| **Stealth-first** | `--stealth` flag adds random jitter between API calls. Minimal API surface used. |
| **Offline graph** | All analysis happens locally against the SQLite DB — no cloud API calls during analysis |
| **Capability-adaptive** | Probes for allowed APIs upfront, skips what it cannot call |
| **Multi-account** | Correlates cross-account trust relationships across all enumerated accounts |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      CLI (cli.py)                        │
│  worst enumerate │ worst privesc │ worst viz │ worst graph│
└──────────┬──────────────┬──────────────┬────────────────┘
           │              │              │
    ┌──────▼──────┐ ┌─────▼──────┐ ┌───▼────────────────┐
    │  Enumeration │ │  Analysis  │ │   Visualization     │
    │  Modules     │ │  Engine    │ │   (FastAPI + React) │
    │  modules/    │ │  core/     │ │   viz/              │
    └──────┬───────┘ └─────┬──────┘ └────────────────────┘
           │               │
    ┌──────▼───────────────▼──────┐
    │        SQLite Database       │
    │        (db/models.py)        │
    └─────────────────────────────┘
```

### Module layout

```
worstassume/
├── cli.py                   Entry point; Click command group
├── session.py               AWS session management + role assumption
├── core/
│   ├── capability.py        Capability probe (what APIs can we call?)
│   ├── cross_account.py     Cross-account trust link analysis
│   ├── privilege_escalation.py  PrivEsc path detector
│   └── resource_graph.py    Graph builder (NetworkX DiGraph)
├── db/
│   ├── engine.py            SQLAlchemy engine + session
│   ├── models.py            ORM models
│   └── store.py             CRUD helpers
├── modules/
│   ├── identity.py          sts:GetCallerIdentity
│   ├── iam.py               Users, roles, groups, policies
│   ├── ec2.py               EC2 instances + instance profiles
│   ├── s3.py                S3 buckets
│   ├── lambda_.py           Lambda functions + execution roles
│   ├── ecs.py               ECS clusters, services, task definitions
│   └── vpc.py               VPCs, subnets, security groups
└── viz/
    ├── server.py             FastAPI backend (REST API)
    └── frontend/             React + Cytoscape.js SPA
        └── src/
            ├── App.jsx       Main application state
            ├── api.js        API client
            └── components/
                ├── Sidebar.jsx         Left navigation sidebar
                ├── IdentityPanel.jsx   "Who Am I" identity picker
                ├── GraphCanvas.jsx     Cytoscape.js graph renderer
                ├── GraphControls.jsx   Slider controls (node size, proximity)
                ├── DetailPane.jsx      Right panel — node details + permissions
                ├── IdentityBar.jsx     Top canvas bar — current identity
                ├── PathExplainer.jsx   Path hop-by-hop explanation drawer
                └── PathsPanel.jsx      "Paths" tab — all discovered escalation chains
```

---

## Data Model

All data is stored in a SQLite database (default: `~/.worst/worst.db`; override with `--db` or `WORST_DB`).

### Entity Relationship

```
Account ──has_many──> Principal (users, roles, groups)
Account ──has_many──> Policy    (managed + inline)
Account ──has_many──> Resource  (EC2, S3, Lambda, ECS, VPC)
Principal ──M2M──> Policy       (via principal_policy join table)
Resource ──belongs_to──> Principal (execution_role)
Account ──has_many──> CrossAccountLink (outbound trust links)
Account ──has_many──> EnumerationRun  (audit trail)
```

### Model Reference

#### `Account`
| Field | Type | Description |
|-------|------|-------------|
| `id` | int PK | Internal DB id |
| `account_id` | str(12) | AWS account ID |
| `account_name` | str | Human-readable name |
| `org_id` | str | AWS Organization ID |
| `profile` | str | AWS CLI profile used for enumeration |
| `last_enumerated_at` | datetime | Timestamp of last `worst enumerate` |

#### `Principal`
| Field | Type | Description |
|-------|------|-------------|
| `id` | int PK | |
| `account_id` | FK → Account | |
| `arn` | str | Full IAM ARN |
| `name` | str | Short name |
| `principal_type` | str | `user` / `role` / `group` |
| `trust_policy_json` | text | Role trust policy as JSON (roles only) |
| `metadata_json` | text | Tags, create date, etc. |

#### `Policy`
| Field | Type | Description |
|-------|------|-------------|
| `arn` | str | Full policy ARN |
| `name` | str | |
| `policy_type` | str | `managed` / `inline` / `aws_managed` |
| `document_json` | text | IAM policy document as JSON |

#### `Resource`
| Field | Type | Description |
|-------|------|-------------|
| `arn` | str | |
| `service` | str | `ec2` / `s3` / `lambda` / `ecs` / `vpc` |
| `resource_type` | str | `instance` / `bucket` / `function` / etc. |
| `execution_role_id` | FK → Principal | Optional IAM role used by resource |

#### `CrossAccountLink`
| Field | Type | Description |
|-------|------|-------------|
| `source_account_id` | FK → Account | Account that can trust into target |
| `target_account_id` | FK → Account | Account hosting the role |
| `role_arn` | str | Role ARN that can be assumed |
| `trust_principal_arn` | str | The trusted principal ARN in the trust policy |
| `is_wildcard` | bool | True if trust policy uses `"Principal": "*"` |
| `link_type` | str | Default: `sts:AssumeRole` |

---

## CLI Commands

### `worst enumerate`
```
worst enumerate [OPTIONS]
```
Runs adaptive IAM + resource enumeration against an AWS account and stores results in the local DB.

**Options:**
| Option | Description |
|--------|-------------|
| `--profile / -p` | AWS CLI profile to use |
| `--region / -r` | AWS region (default: `us-east-1`) |
| `--access-key` | `AWS_ACCESS_KEY_ID` (or env var) |
| `--secret-key` | `AWS_SECRET_ACCESS_KEY` (or env var) |
| `--session-token` | `AWS_SESSION_TOKEN` (or env var) |
| `--assume-role` | ARN of a role to assume before enumerating |
| `--account-name` | Human-readable label stored in DB |
| `--stealth` | Adds random 0.3–1.2s jitter between API calls |

**Flow:**
1. Resolves caller identity (`sts:GetCallerIdentity`)
2. Probes capabilities (tries each known-useful API call, notes what's allowed)
3. Runs all enumeration modules in order: IAM → EC2 → S3 → Lambda → ECS → VPC
4. Commits everything to DB, saves capability snapshot

---

### `worst accounts list`
Displays all tracked accounts: ID, name, org ID, principal count, resource count, last enumeration timestamp.

### `worst accounts delete <account_id>`
Deletes an account and all its data (principals, policies, resources, runs, links) from the DB.

---

### `worst graph build`
Analyses all enumerated trust policies across accounts and writes `CrossAccountLink` rows to the DB.

### `worst graph export`
Exports the full graph to a Cytoscape.js-compatible JSON file (default: `graph.json`).

---

### `worst privesc`
```
worst privesc [--account-id ACCOUNT_ID]
```
Analyses all (or one account's) principals against the known privilege escalation catalogue. Prints findings table sorted by severity.

---

### `worst viz`
```
worst viz [--host HOST] [--port PORT] [--no-open-browser]
```
Launches the FastAPI backend serving both the REST API and the built React SPA. Opens browser automatically.

> **Note:** Run `cd worstassume/viz/frontend && npm run build` first to build the React app.
> During development, use `npm run dev` to use Vite's dev server with hot-reload (the FastAPI backend still needs to run separately on port 3000).

---

## Enumeration Modules

### `modules/capability.py`
Probes the following capabilities by attempting each API call and noting the response:
- `iam:ListUsers`, `iam:ListRoles`, `iam:ListGroups`
- `iam:GetPolicy`, `iam:ListAttachedUserPolicies`, etc.
- `ec2:DescribeInstances`, `s3:ListBuckets`, `lambda:ListFunctions`, `ecs:ListClusters`, `ec2:DescribeVpcs`

Returns a `CapabilityMap` object used by each module to skip calls that would fail.

### `modules/iam.py`
Enumerates:
- Users (with attached + inline policies)
- Roles (with attached + inline policies, trust policy)
- Groups (membership + attached policies)
- Stores all policies with their documents

### `modules/ec2.py`
Enumerates running EC2 instances; extracts IAM instance profile roles (creates `execution_role` links).

### `modules/s3.py`
Lists S3 buckets; stores as `Resource` with `service=s3`.

### `modules/lambda_.py`
Lists Lambda functions; extracts execution roles (creates `execution_role` links).

### `modules/ecs.py`
Lists ECS clusters, services, task definitions; extracts task execution roles.

### `modules/vpc.py`
Lists VPCs, subnets, security groups. Stored as resources for graph context.

---

## Core Analysis Engine

### `core/capability.py`
**CapabilityMap** — a frozen set of boolean flags (`can_list_users`, `can_list_roles`, etc.). Passed to each enumeration module.

### `core/cross_account.py`
**build_cross_account_links(db)** — iterates over all role trust policies. For any `Principal.AWS` ARN that resolves to a different tracked account, creates or updates a `CrossAccountLink` record.

### `core/privilege_escalation.py`
**analyze(db, account=None)** — checks every principal against the [PrivEsc Catalogue](#privilege-escalation-catalogue). Returns deduplicated `PrivEscFinding` list sorted by severity.

### `core/resource_graph.py`
**build_graph(db)** — builds a `networkx.DiGraph` from all DB content, then calls `_add_trust_edges()`.

**_add_trust_edges(G, db)** — parses every role's trust policy to add directed `can_assume` edges:
- Supports plain IAM ARNs (`arn:aws:iam::...`)
- Supports assumed-role session ARNs (`arn:aws:sts::ACC:assumed-role/NAME/SESSION` → normalized to the base role)
- Supports account-root principals (`arn:aws:iam::ACC:root` → account node)
- Unresolvable external principals become `external:*` nodes (dashed grey in UI)

**graph_to_cytoscape(G)** — serialises the graph to `{nodes: [...], edges: [...]}` format compatible with Cytoscape.js.

---

## Visualization (Graph UI)

The visualization is a React SPA (Vite + Cytoscape.js) backed by a FastAPI REST server.

### Sidebar Tabs

| Tab | Purpose |
|-----|---------|
| **👤 Who Am I** | Set current identity by searching principals or pasting an assumed-role ARN |
| **Entities** | Browse/search all enumerated principals, policies, resources; click to add to canvas |
| **Accounts** | Load entire account subgraphs onto the canvas |
| **PrivEsc** | Browse raw privilege escalation findings by severity; click to add to canvas |
| **🔗 Paths** | All discovered escalation path chains, sorted by severity, with full hop explanations |

### Canvas Interaction

- **Click a node** → opens DetailPane on the right
- **Double-click** → expands node's neighbours
- **Pan / Scroll** → navigate
- **⚙ Controls** (bottom-right) → sliders for node size and spacing
- **Canvas clear / Layout / Fit / PNG export** → header buttons

### Detail Pane (Right Panel)

Shows node properties. For principals, policies, and resources:
- `👤 Set as me` — marks node as current identity (green ring)
- `🎯 Set as target` — marks any node as path destination (amber ring)
- `🔗 Find path` — finds shortest assume-role path from identity to target and shows hop chain

### Identity Bar (Top of Canvas)
Shown when an identity is active:
- Displays identity name, type, account
- Displays target (if set)
- **⚡ Auto PrivEsc** — finds all same-account privesc findings and streams paths to canvas incrementally; button becomes **⟳ Cancel** while running
- **🔗 Find path** — finds path from identity to currently selected canvas node or explicit target

### PathExplainer Drawer
Collapsible panel below DetailPane. Shows per-hop explanation for the most recently found path. Each hop:
- Source node chip → edge type icon → destination node chip
- Semantic explanation of the relationship
- Associated privesc finding (if any)

---

## API Reference

Base URL: `http://localhost:3000` (default)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/accounts` | List all tracked accounts |
| GET | `/api/entities` | All principals, policies, resources as Cytoscape nodes |
| GET | `/api/privesc` | All privilege escalation findings |
| GET | `/api/cross-account-links` | All cross-account trust links |
| GET | `/api/principals?q=` | Search principals by name/ARN; resolves assumed-role ARNs |
| GET | `/api/neighbors/{node_id}` | First-degree graph neighbours of a node |
| GET | `/api/accounts/{account_id}/subgraph?limit=N` | Load full account subgraph |
| GET | `/api/node/{node_id}` | Full detail for a single node (with policy enrichment) |
| GET | `/api/path?from_id=&to_id=` | Shortest path between two nodes (returns hops + explanations) |
| GET | `/api/privesc-from/{node_id}` | Same-account privesc findings reachable from a principal |

### `/api/path` Response

```json
{
  "found": true,
  "nodes": [ { "data": { "id": "principal:...", "label": "...", ... } } ],
  "edges": [ { "data": { "id": "...", "source": "...", "target": "...", "edge_type": "..." } } ],
  "path":  ["node_id_1", "node_id_2", "node_id_3"],
  "hops":  [
    {
      "from_id":    "principal:arn:...",
      "from_label": "IAMRole...",
      "from_type":  "role",
      "to_id":      "principal:arn:...",
      "to_label":   "dev-role",
      "to_type":    "role",
      "edge_type":  "can_assume",
      "explanation": "Can assume this role via trust policy",
      "is_reversed": false
    }
  ]
}
```

### `/api/privesc-from/{node_id}` Scope Rules
Returns findings limited to:
1. The identity principal itself
2. Principals **in the same AWS account** as the identity
3. Roles reachable via an explicit `CrossAccountLink` from the identity's account

---

## Graph Schema

### Node ID Conventions

| Prefix | Example | Type |
|--------|---------|------|
| `account:` | `account:123456789012` | Account |
| `principal:` | `principal:arn:aws:iam::123456789012:role/dev-role` | IAM principal |
| `policy:` | `policy:arn:aws:iam::123456789012:policy/MyPolicy` | IAM policy |
| `resource:` | `resource:arn:aws:lambda::123456789012:function:myFn` | AWS resource |
| `external:` | `external:arn:aws:sts::...` | Unresolved trust principal |

### Edge Types

| Edge Type | Direction | Meaning |
|-----------|-----------|---------|
| `has_principal` | account → principal | Principal belongs to this account |
| `has_policy` | principal → policy | Policy is attached to this principal |
| `has_resource` | account → resource | Resource is in this account |
| `execution_role` | resource → principal | Resource runs as this IAM role |
| `cross_account` | account → account | Explicit trust link between accounts |
| `can_assume` | principal → role | Trust policy allows source to call `sts:AssumeRole` on target |

### Cytoscape Visual Legend

| Node type | Shape | Color |
|-----------|-------|-------|
| Account | Diamond | Indigo `#6366f1` |
| Role | Circle | Blue `#3b82f6` |
| User | Rectangle | Green `#22c55e` |
| Group | Hexagon | Purple `#a855f7` |
| Policy | Triangle | Pink `#ec4899` |
| Resource | Square | Amber `#f59e0b` |
| External | Dashed circle | Grey `#64748b` |

| Edge type | Color | Style |
|-----------|-------|-------|
| `can_assume` | Green `#22c55e` | Dashed |
| `cross_account` | Red `#ef4444` | Dashed |
| `execution_role` | Amber `#f59e0b` | Solid |
| `has_policy` | Pink `#ec4899` | Solid |
| `has_principal` / `has_resource` | Slate | Solid |

### Path Highlight Classes (Cytoscape)

| Class | Applied to | Effect |
|-------|-----------|--------|
| `identity-node` | Identity principal | Green 4px border |
| `target-node` | Target node | Amber 4px border |
| `path-node` | Nodes in found path | Gold 3px border |
| `path-edge` | Edges in found path | Gold highlight |
| `path-dim` | Everything else | 15% opacity |

---

## Privilege Escalation Catalogue

Implemented in `core/privilege_escalation.py`. Currently detects:

| # | Path Name | Severity | Required Permissions |
|---|-----------|----------|---------------------|
| 1 | `CreatePolicyVersion` | CRITICAL | `iam:CreatePolicyVersion` |
| 2 | `PassRole+Lambda:CreateFunction` | CRITICAL | `iam:PassRole` + `lambda:CreateFunction` |
| 3 | `PassRole+Lambda:UpdateFunctionCode` | HIGH | `iam:PassRole` + `lambda:UpdateFunctionCode` |
| 4 | `PassRole+EC2:RunInstances` | HIGH | `iam:PassRole` + `ec2:RunInstances` |
| 5 | `AttachPolicy` | CRITICAL | `iam:AttachUserPolicy` OR `iam:AttachRolePolicy` |
| 6 | `WildcardTrustPrincipal` | CRITICAL | Role trust policy has `"Principal": "*"` |
| 7 | `CrossAccountWildcardTrust` | CRITICAL | `CrossAccountLink.is_wildcard=True` |

**Wildcard matching:** All checks also trigger if the principal has `iam:*` or `*` in their allowed actions.

---

## Frontend Component Reference

### `App.jsx`
Root component. Owns all application state:
- `identity` / `target` — current identity and destination nodes
- `paths` — array of discovered path+finding objects (fed to PathsPanel)
- `pathActive` / `pathResult` / `privescFinding` — current path highlight state
- `privescRunning` — whether autoPrivesc loop is running
- `abortRef` — ref flag to cancel autoPrivesc mid-loop

Key functions:
- `setIdentity(nodeData)` — sets identity, applies green ring
- `setTarget(nodeData)` — sets target, applies amber ring
- `findPath(from, to, findingContext?)` — calls `/api/path`, merges result to canvas, stores in `pathResult`
- `autoPrivesc()` — incremental: fetches findings → processes one-by-one → yields browser → collects into `paths`
- `cancelPrivesc()` — sets `abortRef.current = true`
- `addPathToGraph(entry)` — re-applies a stored path from PathsPanel back to the canvas

### `IdentityPanel.jsx`
- Debounced search → `GET /api/principals?q=`
- Handles assumed-role ARN input by detecting `:assumed-role/` in query
- Shows `detail` of current identity's policies via `GET /api/node/{id}`

### `PathsPanel.jsx`
- Receives `paths` array from App.jsx
- Sorts by severity (CRITICAL → HIGH → MEDIUM)
- Filter bar for severity subsetting
- Each `PathCard` shows hop chain + step-by-step + privesc conclusion

### `GraphCanvas.jsx`
- Initializes Cytoscape.js with all node/edge styles
- Minimap overlay (pure canvas, no library dep)
- Exposes `cyRef` to parent for imperative operations

### `DetailPane.jsx`
- Shows enriched node properties (fetches `/api/node/{id}` on selection)
- `PermissionsSection`: Policy → Service accordion (`iam:`, `ec2:`, etc.)
- `AttachedPrincipals`: who uses this policy
- Buttons: `👤 Set as me`, `🎯 Set as target`, `🔗 Find path`, `⊕ Expand`, `✕ Remove`

---

## Development Guide

### Prerequisites
- Python 3.11+
- Node.js 18+
- AWS credentials (any mechanism: profile, env vars, role)

### Setup

```bash
# Python deps
pip install -e ".[dev]"

# Frontend deps
cd worstassume/viz/frontend
npm install
```

### Running in development

```bash
# Terminal 1: backend (auto-reloads on Python file changes)
uvicorn worstassume.viz.server:app --reload --port 3000

# Terminal 2: frontend dev server with hot-reload
cd worstassume/viz/frontend
npm run dev   # Vite proxies /api/* to :3000
```

### Running in production

```bash
cd worstassume/viz/frontend && npm run build
worst viz  # Serves React SPA + API from port 3000
```

### Database location

Default: `~/.worst/worst.db`
Override: `--db /path/to/file.db` or `export WORST_DB=/path/to/file.db`

### Adding a new privilege escalation check
Edit `worstassume/core/privilege_escalation.py`, add a new `if`-block inside `analyze()`:
```python
if "new:Permission" in actions or _has_wildcard(actions, "new:"):
    findings.append(PrivEscFinding(
        severity=SEVERITY_HIGH,
        path="NewPath",
        principal_arn=p.arn,
        account_id=account_id,
        description="...",
        details={"permissions": ["new:Permission"]},
    ))
```

### Adding a new edge type to the graph
1. Add the edge in `core/resource_graph.py` inside `build_graph()` or `_add_trust_edges()`
2. Add an explanation string to `_EDGE_EXPLANATIONS` in `viz/server.py`
3. Add a Cytoscape style rule in `viz/frontend/src/components/GraphCanvas.jsx`
