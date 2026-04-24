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

export const api = {
  // Account / stats / entities
  accounts:    ()       => get('/api/accounts'),
  stats:       ()       => get('/api/stats'),
  entities:    ()       => get('/api/entities'),
  crossLinks:  ()       => get('/api/cross-account-links'),
  principals:  (q = '') => get(`/api/principals?q=${encodeURIComponent(q)}`),

  // Graph (neighborhood lookups)
  node:        (id)  => get(`/api/graph/node/${encodeURIComponent(id)}`),
  exportGraph: ()    => get('/api/graph/export'),

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

  // PrivEsc BFS attack paths
  attackPaths: (params = {}) => {
    const qs = new URLSearchParams(params).toString()
    return get(`/api/attack-paths${qs ? '?' + qs : ''}`)
  },
  runAttackPaths: (from_arn, objective, max_hops = 10) =>
    post('/api/attack-paths/run', { from_arn, objective, max_hops }),
  attackPathDetail: (id) => get(`/api/attack-paths/${id}`),

}
