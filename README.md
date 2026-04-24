# WorstAssume

> **Stealth-first AWS IAM enumeration, attack graph analysis, and interactive security dashboard.**

Given a set of AWS credentials, WorstAssume silently enumerates the IAM model, persists it to a local SQLite database, and runs a multi-layered analysis engine to surface privilege escalation paths, misconfigurations, and attack chains — all displayed in a rich interactive web dashboard.

---

## Features

| Capability | Details |
|---|---|
| **Adaptive enumeration** | Uses `iam:GetAccountAuthorizationDetails` when available; falls back to per-principal API calls |
| **Stealth mode** | Jittered API calls + call minimisation to reduce CloudTrail noise |
| **Attack graph** | NetworkX-based multi-hop graph with 37 edge families (IAM, PassRole, resource abuse, lateral movement) |
| **BFS path finding** | Configurable hop limit, multiple objective types (principal, permission, wildcard) |
| **Security assessment** | Per-principal severity scoring with group-inherited permissions |
| **Attack chains** | Pattern-matching engine for 7 privilege escalation chain families |
| **Cross-account** | Trust relationship detection between enumerated accounts |
| **Web dashboard** | Cytoscape.js graph explorer, findings browser, attack path viewer, report export |
| **Report export** | JSON / CSV / HTML self-contained dark-mode report |

---

## Quick Start

### Option A — Docker (recommended)

```bash
git clone https://github.com/BrunoSBecke/WorstAssume.git
cd WorstAssume

# Build and start
docker compose up --build

# Set AWS credentials (or mount ~/.aws inside the container — see docker-compose.yml)
docker compose run --rm worstassume worst enumerate --profile default
docker compose run --rm worstassume worst assess
docker compose run --rm worstassume worst viz
```

Open `http://localhost:3000` in your browser.

### Option B — Local (Python + Node)

```bash
git clone https://github.com/your-org/worstassume.git
cd worstassume

# Python env
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -e .

# Build the frontend (only needed once or after UI changes)
cd worstassume/viz/frontend
npm install
npm run build
cd ../../..

# Run
worst enumerate --profile my-profile --region us-east-1
worst viz
```

---

## CLI Reference

All commands accept `--db <path>` (default: `~/.worstassume/db.sqlite`) and `--debug`.

```bash
# ── Enumeration ──────────────────────────────────────────────────────
worst enumerate --profile <profile> [--region <region>] [--stealth]
worst enumerate --access-key AKIA... --secret-key ... [--session-token ...]

# ── Account management ───────────────────────────────────────────────
worst accounts list

# ── Attack path discovery ────────────────────────────────────────────
worst privesc --from <arn>
worst privesc --from <arn> --target "permission:*:*"
worst privesc --from <arn> --target "principal:arn:aws:iam::123:role/Admin"
worst privesc --from <arn> --output json

# ── Security assessment ───────────────────────────────────────────────
worst assess
worst assess --account-id 123456789012 --min-severity MEDIUM

# ── Web dashboard ────────────────────────────────────────────────────
worst viz [--port 3000] [--host 127.0.0.1]

# ── Graph export ─────────────────────────────────────────────────────
worst graph-export --output graph.json
```

---

## Web Dashboard

Start it with `worst viz` (serves on `http://127.0.0.1:3000` by default).

| Page | Description |
|---|---|
| **Dashboard** | Summary stats (entities, principals, resources, findings) and per-account health table |
| **Entities** | IAM principal browser with per-entity detail panel (trust policy, permissions, findings) |
| **Assessment** | Security findings list with severity/category filters and a run modal |
| **PrivEsc** | Stored attack paths with expandable step views and "View in graph" |

### Graph Viewer

Click any entity's **"⬡ View in Graph"** or open an attack path graph:
- **Node colors**: Role (cyan) · User (green) · Group (purple) · Policy (pink) · Resource (amber) · Account (slate)
- **Controls**: Zoom in/out, fit view, re-layout, clear graph (top-right toolbar)
- **Entity panel**: click any node → full entity detail panel slides in from left of graph
- **Attack paths**: amber dashed directed edges, labeled with IAM action (e.g. `AssumeRole`)

### Export Report

Click **↓ Export** in the topbar to open the report modal. Supported formats:

| Format | Contents |
|---|---|
| **HTML** | Self-contained dark-mode page with stat cards, severity groups, entity table |
| **JSON** | Structured dump: `{ meta, summary, findings[], attackPaths[], entities[] }` |
| **CSV** | Flat findings table: Severity, Category, Entity ARN, Message, Detected |

---

## Architecture

```
worstassume/
├── cli.py                    # Click CLI — orchestrates all workflows
├── session.py                # AWS session/client factory (profiles + explicit creds)
│
├── modules/                  # Enumeration (read-only AWS API calls)
│   ├── iam.py                # IAM users, roles, groups, policies, memberships
│   ├── ec2.py                # EC2 instances + instance profiles
│   ├── ecs.py                # ECS clusters, services, task definitions
│   ├── lambda_.py            # Lambda functions + execution roles
│   ├── s3.py                 # S3 buckets + bucket policies
│   ├── vpc.py                # VPCs, subnets, security groups
│   └── identity.py           # GetCallerIdentity + CapabilityMap probing
│
├── core/                     # Analysis engine (no AWS calls)
│   ├── iam_actions.py        # Policy parsing, action matching, group-aware collection
│   ├── attack_chains.py      # Rule-based escalation chain detection (7 families)
│   ├── attack_graph.py       # NetworkX MultiDiGraph builder (37 edge families)
│   ├── attack_path.py        # BFS/DFS traversal, PathResult DTO, DB persistence
│   ├── security_assessment.py  # Per-principal severity scoring
│   ├── cross_account.py      # Cross-account role trust analysis
│   ├── graph_store.py        # Graph serialisation for the viz layer
│   └── privilege_escalation.py  # Legacy rule engine (still used by server)
│
├── db/                       # Persistence
│   ├── models.py             # SQLAlchemy ORM models
│   ├── store.py              # Idempotent upsert helpers
│   └── engine.py             # SQLite engine factory
│
└── viz/                      # Web visualisation
    ├── server.py             # FastAPI backend + static file serving
    └── frontend/             # React + Vite + Cytoscape.js dashboard
        ├── src/
        │   ├── App.jsx
        │   ├── context/AppContext.jsx
        │   ├── pages/         # Dashboard, Entities, Assessment, PrivEsc
        │   └── components/    # GraphViewer, EntityDetailPanel, ReportModal, …
        └── dist/              # Built static assets (git-ignored)
```

---

## Required AWS Permissions

### Optimal (single-call full dump)
```
iam:GetAccountAuthorizationDetails
```

### Minimum (slow-path fallback)
```
iam:ListUsers               iam:ListRoles              iam:ListGroups
iam:ListUserPolicies        iam:ListRolePolicies       iam:ListGroupPolicies
iam:GetUserPolicy           iam:GetRolePolicy          iam:GetGroupPolicy
iam:ListAttachedUserPolicies  iam:ListAttachedRolePolicies  iam:ListAttachedGroupPolicies
iam:GetPolicy               iam:GetPolicyVersion       iam:ListGroupsForUser
```

### Resource enumeration (optional)
```
ec2:DescribeInstances       lambda:ListFunctions       ecs:ListClusters
ecs:ListTaskDefinitions     s3:ListAllMyBuckets        s3:GetBucketPolicy
ec2:DescribeVpcs            ec2:DescribeSecurityGroups
```

---

## Development

### Running tests
```bash
pip install -e ".[dev]"
pytest tests/ -v --tb=short
```

264 tests across 12 files covering enumeration, attack graph construction, path finding, group membership, cross-account detection, and DB idempotency.

### Rebuilding the frontend
```bash
cd worstassume/viz/frontend
npm install
npm run build         # outputs to dist/ (served by FastAPI)
npm run dev           # hot-reload dev server on :5173
```

### Database location
Default: `~/.worstassume/db.sqlite`  
Override: `worst --db /path/to/custom.sqlite <command>`

---

## Deployment Notes

- The SQLite database is **local-only** — no data leaves your machine.
- All AWS API calls are **read-only**. No resources are created or modified.
- In stealth mode (`--stealth`) calls are serialised with random jitter to reduce noise patterns in CloudTrail.
- The web dashboard binds to `127.0.0.1` by default. Use `--host 0.0.0.0` to expose on the network (e.g. inside Docker).
