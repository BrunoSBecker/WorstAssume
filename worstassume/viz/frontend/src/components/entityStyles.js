/**
 * entityStyles — constants shared by the Entities and Threat Model pages.
 * The matching components live in EntityBits.jsx (react-refresh wants a file to
 * export one kind of thing).
 *
 * These started life inside EntitiesPage.jsx and were copied into
 * ThreatModelPage.jsx, where they promptly drifted (different padding, a
 * different default risk). Having one definition is the point: an entity row
 * should look the same wherever it is rendered.
 */

export const TYPE_ICON = {
  role: '⚙', user: '👤', group: '👥', policy: '📄', resource: '☁', account: '🔷',
}

/** Display label → the `type` query param understood by /api/entities. */
export const TYPE_MAP = {
  Roles: 'role', Users: 'user', Groups: 'group', Policies: 'policy',
  Resources: 'resource',
}

export const RISK_FILTERS = ['All Risk', 'Critical', 'High', 'Clean']

export const RISK_STYLE = {
  CRITICAL: { bg: 'rgba(192,48,48,.12)', color: 'var(--red-hi)', border: 'rgba(192,48,48,.3)' },
  HIGH: { bg: 'rgba(217,124,20,.12)', color: 'var(--amber-hi)', border: 'rgba(217,124,20,.3)' },
  MEDIUM: { bg: 'rgba(184,160,32,.10)', color: 'var(--yellow-hi)', border: 'rgba(184,160,32,.25)' },
  LOW: { bg: 'rgba(42,112,128,.10)', color: 'var(--cyan-hi)', border: 'rgba(42,112,128,.25)' },
  CLEAN: { bg: 'rgba(46,125,82,.10)', color: 'var(--green-hi)', border: 'rgba(46,125,82,.25)' },
}

/** Styling for the small inline `<select>`s in a filter bar. */
export const selectStyle = (active) => ({
  background: active ? 'rgba(217,124,20,.08)' : 'var(--bg3)',
  color: active ? 'var(--amber)' : 'var(--text-dim)',
  border: `1px solid ${active ? 'rgba(217,124,20,.3)' : 'var(--border2)'}`,
  borderRadius: 3, padding: '3px 8px', fontSize: 10,
  fontFamily: 'IBM Plex Mono, monospace', cursor: 'pointer', outline: 'none',
})

export const PILL_STYLE = {
  service:   { bg: 'rgba(42,112,128,.1)',   color: 'var(--cyan-hi)',   border: '1px solid rgba(42,112,128,.25)' },
  principal: { bg: 'rgba(217,124,20,.1)',   color: 'var(--amber)',     border: '1px solid rgba(217,124,20,.25)' },
  critical:  { bg: 'rgba(192,48,48,.12)',   color: 'var(--red-hi)',    border: '1px solid rgba(192,48,48,.3)' },
  high:      { bg: 'rgba(217,124,20,.12)',  color: 'var(--amber-hi)',  border: '1px solid rgba(217,124,20,.3)' },
  medium:    { bg: 'rgba(184,160,32,.1)',   color: 'var(--yellow-hi)', border: '1px solid rgba(184,160,32,.2)' },
  dim:       { bg: 'var(--bg3)',            color: 'var(--text-dim)',  border: '1px solid var(--border2)' },
}

/** Heuristic entity risk, used when the server has not computed one. */
export function computeRisk(entity, findings) {
  const actions = entity.actions || []
  const trusts = entity.trust_principals || []
  const arn = entity.arn || entity.node_id || ''
  const related = (findings || []).filter(
    f => !f.suppressed && (f.entity_arn === arn || f.principal_arn === arn))

  if (related.some(f => f.severity === 'CRITICAL')) return 'CRITICAL'
  if (related.some(f => f.severity === 'HIGH')) return 'HIGH'
  if (actions.some(a => a === '*' || a === 'iam:*')) return 'CRITICAL'
  if (actions.some(a => a.startsWith('iam:') || a.startsWith('sts:'))) return 'HIGH'
  if (actions.some(a => a.startsWith('lambda:') || a.startsWith('ec2:') || a.startsWith('s3:'))) return 'MEDIUM'
  if (trusts.some(p => p.includes('*'))) return 'HIGH'
  if (actions.length > 0) return 'LOW'
  return 'CLEAN'
}
