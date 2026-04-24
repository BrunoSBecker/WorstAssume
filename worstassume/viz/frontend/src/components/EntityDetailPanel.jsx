/**
 * EntityDetailPanel — shared entity detail sidebar.
 * Used by both EntitiesPage (right column) and SigmaViewer (inline on node click).
 *
 * Props:
 *   entity     – entity object from /api/entities
 *   findings   – all security findings from context
 *   onClose    – () => void
 *   onViewGraph – (entity) => void   (optional)
 */

// ─── Sub-components ───────────────────────────────────────────────────────────

const TYPE_ICON = { role: '⚙', user: '👤', group: '👥', policy: '📄', resource: '☁', account: '🔷', principal: '⚙' }

const RISK_STYLE = {
  CRITICAL: { bg: 'rgba(192,48,48,.12)',  color: 'var(--red-hi)',    border: 'rgba(192,48,48,.3)' },
  HIGH:     { bg: 'rgba(217,124,20,.12)', color: 'var(--amber-hi)',  border: 'rgba(217,124,20,.3)' },
  MEDIUM:   { bg: 'rgba(184,160,32,.10)', color: 'var(--yellow-hi)', border: 'rgba(184,160,32,.25)' },
  LOW:      { bg: 'rgba(42,112,128,.10)', color: 'var(--cyan-hi)',   border: 'rgba(42,112,128,.25)' },
  CLEAN:    { bg: 'rgba(46,125,82,.10)',  color: 'var(--green-hi)',  border: 'rgba(46,125,82,.25)' },
}

function RiskBadge({ risk }) {
  const s = RISK_STYLE[risk] || RISK_STYLE.LOW
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', padding: '2px 8px',
      borderRadius: '2px', fontSize: '10px', fontWeight: 600,
      letterSpacing: '0.06em', whiteSpace: 'nowrap',
      background: s.bg, color: s.color, border: `1px solid ${s.border}`,
    }}>{risk}</span>
  )
}

function MiniPill({ variant = 'dim', children }) {
  const S = {
    service:   { bg: 'rgba(42,112,128,.1)',  color: 'var(--cyan-hi)',  border: '1px solid rgba(42,112,128,.25)' },
    principal: { bg: 'rgba(217,124,20,.1)', color: 'var(--amber)',    border: '1px solid rgba(217,124,20,.25)' },
    critical:  { bg: 'rgba(192,48,48,.12)', color: 'var(--red-hi)',   border: '1px solid rgba(192,48,48,.3)' },
    high:      { bg: 'rgba(217,124,20,.12)',color: 'var(--amber-hi)', border: '1px solid rgba(217,124,20,.3)' },
    medium:    { bg: 'rgba(184,160,32,.1)', color: 'var(--yellow-hi)',border: '1px solid rgba(184,160,32,.2)' },
    dim:       { bg: 'var(--bg3)',           color: 'var(--text-dim)', border: '1px solid var(--border2)' },
  }
  const s = S[variant] || S.dim
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', padding: '2px 7px',
      borderRadius: '2px', fontSize: '10px', fontWeight: 600,
      letterSpacing: '0.06em', flexShrink: 0, whiteSpace: 'nowrap',
      background: s.bg, color: s.color, border: s.border,
    }}>{children}</span>
  )
}

function TypeIcon({ type, size = 32 }) {
  const S = {
    role:     { bg: 'rgba(58,154,176,.1)',  border: 'rgba(58,154,176,.4)',  color: 'var(--cyan-hi)' },
    user:     { bg: 'rgba(61,171,110,.1)',  border: 'rgba(61,171,110,.4)',  color: 'var(--green-hi)' },
    group:    { bg: 'rgba(154,127,200,.1)', border: 'rgba(154,127,200,.4)', color: '#9a7fc8' },
    policy:   { bg: 'rgba(200,120,176,.1)', border: 'rgba(200,120,176,.4)', color: '#c878b0' },
    resource: { bg: 'rgba(217,124,20,.1)',  border: 'rgba(217,124,20,.4)',  color: 'var(--amber)' },
    account:  { bg: 'rgba(90,96,112,.1)',   border: 'var(--border2)',       color: 'var(--text-dim)' },
    principal:{ bg: 'rgba(58,154,176,.1)',  border: 'rgba(58,154,176,.4)',  color: 'var(--cyan-hi)' },
  }
  const s = S[type] || S.role
  return (
    <div style={{
      width: size, height: size, borderRadius: '50%', flexShrink: 0,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: s.bg, border: `1.5px solid ${s.border}`, color: s.color,
      fontSize: size * 0.44,
    }}>{TYPE_ICON[type] || '?'}</div>
  )
}

// ─── Risk computation ─────────────────────────────────────────────────────────

export function computeRisk(entity, findings) {
  const actions = entity.actions || []
  const trusts  = entity.trust_principals || []
  const arn     = entity.arn || entity.node_id || ''
  const related = (findings || []).filter(f => !f.suppressed && (f.entity_arn === arn || f.principal_arn === arn))

  if (related.some(f => f.severity === 'CRITICAL')) return 'CRITICAL'
  if (related.some(f => f.severity === 'HIGH'))     return 'HIGH'
  if (actions.some(a => a === '*' || a === 'iam:*')) return 'CRITICAL'
  if (actions.some(a => a.startsWith('iam:') || a.startsWith('sts:'))) return 'HIGH'
  if (actions.some(a => a.startsWith('lambda:') || a.startsWith('ec2:') || a.startsWith('s3:'))) return 'MEDIUM'
  if (trusts.some(p => p.includes('*'))) return 'HIGH'
  if (actions.length > 0) return 'LOW'
  return 'CLEAN'
}

// ─── Section block wrapper ────────────────────────────────────────────────────

function SbBlock({ label, children }) {
  return (
    <div className="sb-block">
      <div className="sb-label">{label}</div>
      {children}
    </div>
  )
}

// ─── All permissions list (scrollable) ───────────────────────────────────────

function PermissionsList({ actions, label = 'Permissions' }) {
  if (!actions || actions.length === 0) return null

  const wildcards = actions.filter(a => a === '*' || a.endsWith(':*'))
  const iamSts    = actions.filter(a => !wildcards.includes(a) && (a.startsWith('iam:') || a.startsWith('sts:')))
  const other     = actions.filter(a => !wildcards.includes(a) && !iamSts.includes(a))

  const ordered   = [...wildcards, ...iamSts, ...other]

  function chipStyle(a) {
    if (wildcards.includes(a) || iamSts.includes(a)) return 'critical'
    if (['lambda:', 'ec2:', 's3:', 'kms:', 'secretsmanager:'].some(p => a.startsWith(p))) return 'high'
    return 'normal'
  }

  return (
    <SbBlock label={`${label} (${actions.length})`}>
      <div style={{
        display: 'flex', flexWrap: 'wrap', gap: '4px', marginTop: '6px',
        maxHeight: '160px', overflowY: 'auto', paddingRight: '4px',
      }}>
        {ordered.map((a, i) => (
          <span key={i} className={`action-chip ${chipStyle(a)}`}>{a}</span>
        ))}
      </div>
    </SbBlock>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function EntityDetailPanel({ entity, findings, onClose, onViewGraph, style = {} }) {
  if (!entity) return null

  const t      = entity.principal_type || entity.node_type || entity.policy_type || 'resource'
  const arn    = entity.arn || entity.node_id || ''
  const acct   = entity.account_id || ''
  const label  = entity.label || arn.split('/').pop() || arn
  const arnName = arn.split('/').pop() || label

  const actions            = entity.actions || []
  const trusts             = entity.trust_principals || []
  const policies           = entity.policies || []           // principal's attached policies
  const attachedPrincipals = entity.attached_principals || [] // policy's attached principals
  const executionRole      = entity.execution_role || null
  const service            = entity.service || ''
  const resourceType       = entity.resource_type || ''
  const region             = entity.region || ''

  const isPrincipal = ['role', 'user', 'group', 'principal'].includes(t)
  const isPolicy    = t === 'policy'
  const isResource  = t === 'resource'
  const isLocal     = entity.policy_type !== 'aws_managed'

  const risk    = computeRisk(entity, findings)
  const related = (findings || []).filter(f => !f.suppressed && (f.entity_arn === arn || f.principal_arn === arn))

  // ARN display with account id highlighted
  function ArnDisplay() {
    if (!arn) return <span>—</span>
    if (!acct) return <span>{arn}</span>
    const parts = arn.split(acct)
    if (parts.length !== 2) return <span>{arn}</span>
    const suffix   = parts[1]
    const slashIdx = suffix.lastIndexOf('/')
    const prefix2  = slashIdx >= 0 ? suffix.slice(0, slashIdx + 1) : suffix
    const namePart = slashIdx >= 0 ? suffix.slice(slashIdx + 1) : ''
    return (
      <>
        {parts[0]}
        <em style={{ color: 'var(--amber)', fontStyle: 'normal' }}>{acct}</em>
        {prefix2}
        {namePart && <em style={{ color: 'var(--white)', fontStyle: 'normal' }}>{namePart}</em>}
      </>
    )
  }

  return (
    <div className="ent-sidebar" style={{ width: '420px', flexShrink: 0, overflowY: 'auto', ...style }}>

      {/* ── Header ── */}
      <div className="ent-sidebar-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: 1, minWidth: 0 }}>
          <TypeIcon type={t} size={34} />
          <div style={{ minWidth: 0 }}>
            <div style={{
              fontFamily: "'Syne', sans-serif", fontSize: '17px', fontWeight: 800,
              color: 'var(--white)', letterSpacing: '-0.02em',
              whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
            }}>{label}</div>
            <div style={{ fontSize: '10px', color: 'var(--text-faint)', letterSpacing: '0.08em', textTransform: 'uppercase', marginTop: '1px' }}>
              {isPolicy ? `IAM POLICY · ${entity.policy_type || ''}` : isResource ? `AWS ${(service + ' ' + resourceType).trim().toUpperCase()}` : `IAM ${t.toUpperCase()}`}
              {acct ? ` · ${acct}` : ''}
            </div>
          </div>
        </div>
        {onClose && <button className="slideover-close" onClick={onClose}>✕</button>}
      </div>

      {/* ── ARN ── */}
      <SbBlock label="ARN">
        <div className="sb-arn"><ArnDisplay /></div>
      </SbBlock>

      {/* ── Risk / Paths / Policies grid ── */}
      {/* For policy: show risk only if local/managed (not AWS managed); omit Paths */}
      {(isPrincipal || (isPolicy && isLocal) || isResource) && (
        <div style={{
          display: 'grid',
          gridTemplateColumns: isPrincipal ? '1fr 1fr 1fr' : '1fr 1fr',
          gap: '1px', background: 'var(--border)', borderRadius: '3px', overflow: 'hidden', padding: 0,
        }}>
          {[
            { label: 'Risk',     value: <RiskBadge risk={risk} /> },
            ...(isPrincipal ? [{ label: 'Paths', value: <span style={{ fontFamily:"'Syne',sans-serif", fontSize:'18px', fontWeight:800, color: related.length > 0 ? 'var(--red-hi)' : 'var(--text-dim)' }}>{related.length}</span> }] : []),
            ...(isPrincipal ? [{ label: 'Policies', value: <span style={{ fontFamily:"'Syne',sans-serif", fontSize:'18px', fontWeight:800, color:'var(--white)' }}>{policies.length}</span> }] : []),
            ...(!isPrincipal ? [{ label: 'Actions', value: <span style={{ fontFamily:"'Syne',sans-serif", fontSize:'18px', fontWeight:800, color:'var(--white)' }}>{actions.length}</span> }] : []),
          ].map(({ label, value }) => (
            <div key={label} style={{ background: 'var(--bg2)', padding: '10px 12px', textAlign: 'center' }}>
              <div style={{ fontSize: '10px', letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-faint)', marginBottom: '4px' }}>{label}</div>
              {value}
            </div>
          ))}
        </div>
      )}

      {/* ── PRINCIPAL SECTIONS ── */}
      {isPrincipal && (
        <>
          {/* Trust Policy Principals */}
          <SbBlock label="Trust Policy Principals">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', marginTop: '6px' }}>
              {trusts.length === 0
                ? <div style={{ fontSize: '12px', color: 'var(--text-faint)' }}>No trust relationships</div>
                : trusts.map((p, i) => {
                    const isWild    = p.includes('*')
                    const isService = p.endsWith('.amazonaws.com')
                    return (
                      <div key={i} className={`trust-row${isWild ? ' warn' : ''}`}>
                        <MiniPill variant={isService ? 'service' : isWild ? 'critical' : 'principal'}>
                          {isService ? 'SERVICE' : 'PRINCIPAL'}
                        </MiniPill>
                        <span style={{ fontSize: '12px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: isWild ? 'var(--amber)' : 'var(--text)' }}>
                          {p}
                        </span>
                        {isWild && <span className="trust-warn-icon">⚠</span>}
                      </div>
                    )
                  })
              }
            </div>
          </SbBlock>

          {/* Attached policies */}
          {policies.length > 0 && (
            <SbBlock label="Effective Policies">
              <div style={{ display: 'flex', flexDirection: 'column', gap: '3px', marginTop: '6px' }}>
                {policies.map((p, i) => {
                  const nm       = typeof p === 'string' ? p : (p.name || String(p))
                  const polType  = typeof p === 'object' ? (p.type || '') : ''
                  const isInline = polType === 'inline' || nm.toLowerCase().includes('inline')
                  const isAWS    = polType === 'aws_managed' || nm.startsWith('AWS') || nm.startsWith('Amazon')
                  return (
                    <div key={i} className="policy-row">
                      <div className={`policy-dot ${isInline ? 'inline' : 'managed'}`} />
                      <span style={{ fontSize: '12px', color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{nm}</span>
                      <span className={`policy-type${isInline ? ' inline-label' : ''}`}>
                        {isInline ? 'INLINE' : isAWS ? 'AWS' : 'CUSTOM'}
                      </span>
                    </div>
                  )
                })}
              </div>
            </SbBlock>
          )}

          {/* All permissions */}
          <PermissionsList actions={actions} label="All Permissions" />

          {/* Attack paths */}
          {related.length > 0 && (
            <SbBlock label="Known Attack Paths">
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', marginTop: '6px' }}>
                {related.slice(0, 5).map((f, i) => {
                  const sev = f.severity || 'HIGH'
                  return (
                    <div key={i} className="sb-path-row">
                      <MiniPill variant={sev === 'CRITICAL' ? 'critical' : sev === 'HIGH' ? 'high' : sev === 'MEDIUM' ? 'medium' : 'dim'}>{sev}</MiniPill>
                      <span style={{ fontSize: '11px', color: 'var(--text-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
                        {f.message || f.category}
                      </span>
                    </div>
                  )
                })}
              </div>
            </SbBlock>
          )}
        </>
      )}

      {/* ── POLICY SECTIONS ── */}
      {isPolicy && (
        <>
          <PermissionsList actions={actions} label="Granted Actions" />

          {/* Attached principals */}
          {attachedPrincipals.length > 0 && (
            <SbBlock label={`Attached To (${attachedPrincipals.length})`}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '3px', marginTop: '6px' }}>
                {attachedPrincipals.slice(0, 8).map((pr, i) => (
                  <div key={i} className="policy-row">
                    <div className="policy-dot managed" />
                    <span style={{ fontSize: '12px', color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{pr.name}</span>
                    <span className="policy-type">{pr.type?.toUpperCase()}</span>
                  </div>
                ))}
                {attachedPrincipals.length > 8 && (
                  <div style={{ fontSize: '11px', color: 'var(--text-faint)', paddingTop: '2px' }}>+{attachedPrincipals.length - 8} more</div>
                )}
              </div>
            </SbBlock>
          )}
        </>
      )}

      {/* ── RESOURCE SECTIONS ── */}
      {isResource && (
        <>
          {/* Service metadata */}
          <SbBlock label="Resource Metadata">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', marginTop: '6px' }}>
              {[
                ['Service',  service.toUpperCase()],
                ['Type',     resourceType],
                ['Region',   region || '—'],
              ].map(([k, v]) => (
                <div key={k} style={{ display: 'flex', gap: '8px', fontSize: '12px', fontFamily: 'IBM Plex Mono' }}>
                  <span style={{ color: 'var(--text-faint)', minWidth: '70px' }}>{k}</span>
                  <span style={{ color: 'var(--text)' }}>{v || '—'}</span>
                </div>
              ))}
              {executionRole && (
                <div style={{ display: 'flex', gap: '8px', fontSize: '12px', fontFamily: 'IBM Plex Mono' }}>
                  <span style={{ color: 'var(--text-faint)', minWidth: '70px' }}>Role</span>
                  <span style={{ color: 'var(--amber)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{executionRole.name}</span>
                </div>
              )}
            </div>
          </SbBlock>

          {/* Execution role permissions */}
          {executionRole && actions.length > 0 && (
            <PermissionsList actions={actions} label="Role Permissions" />
          )}
          {!executionRole && (
            <SbBlock label="Permissions">
              <div style={{ fontSize: '12px', color: 'var(--text-faint)', marginTop: '4px', lineHeight: 1.6 }}>
                No execution role attached. Permissions are granted to principals that reference this resource.
              </div>
            </SbBlock>
          )}
        </>
      )}

      {/* ── Footer actions ── */}
      {onViewGraph && (
        <div className="sb-actions">
          <button className="btn btn-ghost" style={{ flex: 1, fontSize: '11px', justifyContent: 'center' }} onClick={() => onViewGraph(entity)}>
            ⬡ View in Graph
          </button>
        </div>
      )}
    </div>
  )
}
