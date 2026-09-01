/**
 * EntityBits — the small entity-presentation components shared by the Entities
 * and Threat Model pages.
 *
 * These started life inside EntitiesPage.jsx and were copied into
 * ThreatModelPage.jsx, where they promptly drifted (different padding, a
 * different default risk). Having one definition is the point: an entity row
 * should look the same wherever it is rendered.
 */
import { PILL_STYLE, RISK_STYLE, TYPE_ICON } from './entityStyles'

export function RiskBadge({ risk, style = {} }) {
  const s = RISK_STYLE[risk] || RISK_STYLE.LOW
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center',
      padding: '1px 6px', borderRadius: '2px', fontSize: '9px',
      fontWeight: 600, letterSpacing: '0.06em', whiteSpace: 'nowrap',
      background: s.bg, color: s.color, border: `1px solid ${s.border}`,
      ...style,
    }}>{risk}</span>
  )
}

export function TypeIcon({ type, size = 26 }) {
  const S = {
    role: { bg: 'rgba(58,154,176,.1)', border: 'rgba(58,154,176,.4)', color: 'var(--cyan-hi)' },
    user: { bg: 'rgba(90,96,112,.12)', border: 'var(--border2)', color: 'var(--text-dim)' },
    group: { bg: 'rgba(154,127,200,.1)', border: 'rgba(154,127,200,.4)', color: '#9a7fc8' },
    policy: { bg: 'rgba(200,120,176,.1)', border: 'rgba(200,120,176,.4)', color: '#c878b0' },
    resource: { bg: 'rgba(46,125,82,.1)', border: 'rgba(46,125,82,.4)', color: 'var(--green-hi)' },
    account: { bg: 'rgba(90,96,112,.1)', border: 'var(--border2)', color: 'var(--text-faint)' },
  }
  const s = S[type] || S.role
  return (
    <div style={{
      width: size, height: size, borderRadius: '50%', flexShrink: 0,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: s.bg, border: `1.5px solid ${s.border}`, color: s.color, fontSize: size * 0.44,
    }}>{TYPE_ICON[type] || '?'}</div>
  )
}

/** Truncated ARN with the account id picked out, matching `.table-arn em`. */
export function EntityArn({ arn = '', maxWidth = 300 }) {
  const acct = arn.split(':')[4]
  const parts = acct ? arn.split(acct) : [arn]
  return (
    <div className="table-arn" style={{ maxWidth }}>
      {acct && parts.length > 1
        ? <>{parts[0]}<em>{acct}</em>{parts.slice(1).join(acct)}</>
        : arn}
    </div>
  )
}


export function MiniPill({ variant = 'dim', children }) {
  const s = PILL_STYLE[variant] || PILL_STYLE.dim
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', padding: '2px 7px',
      borderRadius: '2px', fontSize: '10px', fontWeight: 600,
      letterSpacing: '0.06em', flexShrink: 0, whiteSpace: 'nowrap',
      background: s.bg, color: s.color, border: s.border,
    }}>{children}</span>
  )
}
