// API client — all calls to the FastAPI backend

const BASE = ''  // Same-origin in prod; Vite proxy handles /api in dev

async function get(path) {
  const res = await fetch(BASE + path)
  if (!res.ok) throw new Error(`API ${path}: ${res.status}`)
  return res.json()
}

async function post(path, body = {}) {
  const res = await fetch(BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(`API POST ${path}: ${res.status}`)
  return res.json()
}

async function put(path, body = {}) {
  const res = await fetch(BASE + path, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(`API PUT ${path}: ${res.status}`)
  return res.json()
}

async function del(path) {
  const res = await fetch(BASE + path, { method: 'DELETE' })
  if (!res.ok) throw new Error(`API DELETE ${path}: ${res.status}`)
  return res.json()
}

export const api = {
  // Account / stats / entities
  accounts:    ()       => get('/api/accounts'),
  stats:       ()       => get('/api/stats'),
  // No params → legacy full grouped dump (report export, graph enrichment).
  // With params (page_size>0) → { items, total, page, page_size }.
  entities: (params = {}) => {
    const qs = new URLSearchParams(
      Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== '')
    ).toString()
    return get(`/api/entities${qs ? '?' + qs : ''}`)
  },
  entitiesMeta: () => get('/api/entities/meta'),
  crossLinks:  ()       => get('/api/cross-account-links'),
  principals:  (q = '') => get(`/api/principals?q=${encodeURIComponent(q)}`),

  // Graph (neighborhood lookups)
  node:        (id)  => get(`/api/graph/node/${encodeURIComponent(id)}`),
  exportGraph: ()    => get('/api/graph/export'),

  // Rich detail for ONE node — policy documents, trust policy, resource policy,
  // metadata. Distinct from node() above, which returns a neighbourhood
  // subgraph. Backs the entity sidebar's tabs.
  nodeDetail:  (id)  => get(`/api/node/${encodeURIComponent(id)}`),

  // Live analysis endpoints (slow — run in executor)
  findings: (params = {}) => {
    const qs = new URLSearchParams(params).toString()
    return get(`/api/findings${qs ? '?' + qs : ''}`)
  },
  chains: (params = {}) => {
    const qs = new URLSearchParams(params).toString()
    return get(`/api/chains${qs ? '?' + qs : ''}`)
  },

  // Persisted security findings — written by `worst assess` CLI
  // GET reads stored rows; POST /run triggers assess() + persists
  securityFindings: (params = {}) => {
    const qs = new URLSearchParams(params).toString()
    return get(`/api/security-findings${qs ? '?' + qs : ''}`)
  },
  runSecurityFindings: (body = {}) => post('/api/security-findings/run', body),
  // Findings for a single entity (indexed on entity_arn).
  entityFindings: (arn) =>
    get(`/api/security-findings/entity/${encodeURIComponent(arn)}`),

  // PrivEsc BFS attack paths
  attackPaths: (params = {}) => {
    const qs = new URLSearchParams(params).toString()
    return get(`/api/attack-paths${qs ? '?' + qs : ''}`)
  },
  runAttackPaths: (from_arn, objective, max_hops = 10) =>
    post('/api/attack-paths/run', { from_arn, objective, max_hops }),
  attackPathDetail: (id) => get(`/api/attack-paths/${id}`),
  // Paths where the ARN appears anywhere — start, step actor, or step target.
  // Capped: a busy identity can sit on thousands. Callers ask for limit+1 so
  // they can tell "exactly N" from "N or more".
  attackPathsInvolving: (arn, limit = 51) =>
    get(`/api/attack-paths?involves_arn=${encodeURIComponent(arn)}&limit=${limit}`),

  // Threat model — one inbound hop ("who can reach this ARN?").
  // Returns { node, neighbors[], total_found, returned, truncated }, or
  // { pages: [...] } when hops > 1.
  threatModelNeighbors: (arn, { limit = 50, offset = 0, families = '', hops = 1 } = {}) => {
    const qs = new URLSearchParams({ arn, limit, offset, hops })
    if (families) qs.set('families', families)
    return get(`/api/threat-model/neighbors?${qs.toString()}`)
  },

  // Saved threat-model graphs — the exploration an analyst built by hand.
  threatModelGraphs:      ()           => get('/api/threat-model/graphs'),
  threatModelGraphGet:    (id)         => get(`/api/threat-model/graphs/${id}`),
  threatModelGraphSave:   (body)       => post('/api/threat-model/graphs', body),
  threatModelGraphUpdate: (id, body)   => put(`/api/threat-model/graphs/${id}`, body),
  threatModelGraphDelete: (id)         => del(`/api/threat-model/graphs/${id}`),

}
