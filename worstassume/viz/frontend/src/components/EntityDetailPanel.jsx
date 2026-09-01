/**
 * EntityDetailPanel — the entity inspector, used by every graph interaction.
 *
 * One component, four tabs, three call sites (GraphViewer, ThreatGraph,
 * EntitiesPage). Callers own the width and supply their own footer actions;
 * everything else is identical wherever it appears.
 *
 * Most of what the tabs show was already in the database and simply never
 * surfaced: policy documents, raw trust policies, resource policies, and the
 * full finding list rather than the first five.
 *
 * Props:
 *   entity     – entity object; may be a full /api/entities row or the sparse
 *                shape dataToEntity() produces from a graph node
 *   findings   – app-wide findings, used as a fallback before the per-entity
 *                fetch resolves
 *   onClose    – () => void
 *   actions    – [{label, onClick, variant, title}] rendered into .sb-actions
 *   extraTabs  – [{id, label, count, render}] for caller-specific tabs
 *   style      – escape hatch; width defaults to 100% so the wrapper decides
 */
import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import { MiniPill, RiskBadge, TypeIcon } from './EntityBits'
import { computeRisk } from './entityStyles'

// ─── Small shared pieces ──────────────────────────────────────────────────────

function SbBlock({ label, children }) {
  return (
    <div className="sb-block">
      <div className="sb-label">{label}</div>
      {children}
    </div>
  )
}

function EmptyNote({ children }) {
  return (
    <div style={{ padding: '18px 16px', fontSize: '11px', color: 'var(--text-faint)',
                  lineHeight: 1.6 }}>{children}</div>
  )
}

/** Pretty-printed JSON with a copy button. */
function JsonBlock({ value, maxHeight = 320 }) {
  const [copied, setCopied] = useState(false)
  const text = useMemo(() => {
    if (value == null) return ''
    return typeof value === 'string' ? value : JSON.stringify(value, null, 2)
  }, [value])
  if (!text) return null

  function copy() {
    navigator.clipboard?.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    }).catch(() => {})
  }

  return (
    <div style={{ position: 'relative', marginTop: 6 }}>
      <button className="btn secondary sm" onClick={copy}
        style={{ position: 'absolute', top: 4, right: 4, zIndex: 2 }}>
        {copied ? 'copied' : 'copy'}
      </button>
      <pre style={{
        margin: 0, padding: '8px 10px', maxHeight, overflow: 'auto',
        background: 'var(--bg)', border: '1px solid var(--border)',
        borderRadius: 'var(--radius-sm)', fontSize: '10px', lineHeight: 1.55,
        fontFamily: 'IBM Plex Mono, monospace', color: 'var(--text)',
        whiteSpace: 'pre-wrap', wordBreak: 'break-word',
      }}>{text}</pre>
    </div>
  )
}

function actionChipClass(a) {
  if (a === '*' || a.endsWith(':*') || a.startsWith('iam:') || a.startsWith('sts:')) return 'critical'
  if (['lambda:', 'ec2:', 's3:', 'kms:', 'secretsmanager:'].some(p => a.startsWith(p))) return 'high'
  return 'normal'
}

/** Actions as chips, wildcards and IAM/STS first. No height cap — the tab owns
 *  the scroll now, which was the point of giving permissions their own page. */
function ActionChips({ actions }) {
  const ordered = useMemo(() => {
    const wild = actions.filter(a => a === '*' || a.endsWith(':*'))
    const iam = actions.filter(a => !wild.includes(a) && (a.startsWith('iam:') || a.startsWith('sts:')))
    const rest = actions.filter(a => !wild.includes(a) && !iam.includes(a))
    return [...wild, ...iam, ...rest]
  }, [actions])
  if (!ordered.length) return null
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginTop: '6px' }}>
      {ordered.map((a, i) => <span key={i} className={`action-chip ${actionChipClass(a)}`}>{a}</span>)}
    </div>
  )
}

function humanizeKey(k) {
  return k.replace(/([A-Z])/g, ' $1').replace(/[_-]/g, ' ').replace(/\s+/g, ' ').trim()
    .replace(/\b\w/g, c => c.toUpperCase())
}

function ArnDisplay({ arn }) {
  const parts = String(arn).split(':')
  return (
    <div className="sb-arn">
      {parts.map((p, i) => (
        <span key={i}>
          {i > 0 && ':'}
          <span style={{ color: i === 4 ? 'var(--amber)' : i === parts.length - 1 ? 'var(--white)' : undefined }}>{p}</span>
        </span>
      ))}
    </div>
  )
}

// ─── Tab: Overview ────────────────────────────────────────────────────────────

function OverviewTab({ e, risk, findingCount }) {
  const meta = e.metadata && typeof e.metadata === 'object' ? e.metadata : null
  const imds = meta?.MetadataOptions
  const imdsWeak = imds && imds.HttpTokens && imds.HttpTokens !== 'required'

  const skip = new Set(['MetadataOptions', 'security_groups', 'attaches_to_vpcs',
                        'policy', 'resource_policy'])
  const rows = []
  if (meta) {
    for (const [k, v] of Object.entries(meta)) {
      if (skip.has(k) || v === null || v === undefined || v === '') continue
      if (typeof v === 'object') continue
      rows.push([humanizeKey(k), typeof v === 'boolean' ? (v ? 'yes' : 'no') : String(v)])
    }
  }
  const sgs = Array.isArray(meta?.security_groups) ? meta.security_groups : null
  const vpcs = Array.isArray(meta?.attaches_to_vpcs) ? meta.attaches_to_vpcs : null

  const rowStyle = { display: 'flex', gap: '8px', fontSize: '11px', marginTop: 4,
                     fontFamily: 'IBM Plex Mono, monospace' }
  const keyStyle = { color: 'var(--text-faint)', minWidth: '104px', flexShrink: 0 }
  const valStyle = { color: 'var(--text)', wordBreak: 'break-all' }

  const facts = [
    ['Account', e.account_id],
    ['Type', e.principal_type || e.policy_type || e.resource_type],
    ['Service', e.service],
    ['Region', e.region],
    ['Execution role', e.execution_role?.name],
  ].filter(([, v]) => v)

  const stats = [
    ['Risk', <RiskBadge key="r" risk={risk} />],
    ['Findings', findingCount],
    e.policies?.length ? ['Policies', e.policies.length] : null,
    e.actions?.length ? ['Actions', e.actions.length] : null,
  ].filter(Boolean)

  return (
    <>
      <SbBlock label="ARN"><ArnDisplay arn={e.arn || e.node_id || ''} /></SbBlock>

      <div style={{ display: 'grid', gridTemplateColumns: `repeat(${stats.length}, 1fr)`,
                    gap: 1, background: 'var(--border)',
                    borderBottom: '1px solid var(--border)' }}>
        {stats.map(([label, value]) => (
          <div key={label} style={{ background: 'var(--bg1)', padding: '10px 12px' }}>
            <div className="sb-label">{label}</div>
            <div className="sb-value" style={{ marginTop: 3 }}>{value}</div>
          </div>
        ))}
      </div>

      {facts.length > 0 && (
        <SbBlock label="Details">
          {facts.map(([k, v]) => (
            <div key={k} style={rowStyle}><span style={keyStyle}>{k}</span>
              <span style={valStyle}>{v}</span></div>
          ))}
        </SbBlock>
      )}

      {(imds || rows.length > 0 || sgs || vpcs) && (
        <SbBlock label="Configuration">
          {imds && (
            <div style={{ ...rowStyle, alignItems: 'center' }}>
              <span style={keyStyle}>IMDS</span>
              <MiniPill variant={imdsWeak ? 'critical' : 'dim'}>
                {imdsWeak ? 'IMDSv1 allowed ⚠' : 'IMDSv2 required'}
              </MiniPill>
            </div>
          )}
          {rows.map(([k, v]) => (
            <div key={k} style={rowStyle}><span style={keyStyle}>{k}</span>
              <span style={valStyle}>{v}</span></div>
          ))}
          {sgs?.length > 0 && (
            <div style={rowStyle}><span style={keyStyle}>Security Groups</span>
              <span style={valStyle}>{sgs.join(', ')}</span></div>
          )}
          {vpcs?.length > 0 && (
            <div style={rowStyle}><span style={keyStyle}>Attached VPCs</span>
              <span style={valStyle}>{vpcs.join(', ')}</span></div>
          )}
        </SbBlock>
      )}
    </>
  )
}

// ─── Tab: Permissions ─────────────────────────────────────────────────────────

function PolicyRow({ policy }) {
  const [open, setOpen] = useState(false)
  const inline = policy.type === 'inline'
  const typeLabel = policy.type === 'aws_managed' ? 'AWS' : inline ? 'INLINE' : 'CUSTOM'
  const hasDoc = !!policy.document
  return (
    <div style={{ borderBottom: '1px solid var(--border)' }}>
      <div className="policy-row" style={{ cursor: hasDoc ? 'pointer' : 'default', borderBottom: 'none' }}
        onClick={() => hasDoc && setOpen(o => !o)}>
        <span className={`policy-dot ${inline ? 'inline' : 'managed'}`} />
        <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {policy.name}
        </span>
        <span className={`policy-type${inline ? ' inline-label' : ''}`}>{typeLabel}</span>
        {hasDoc && <span style={{ color: 'var(--text-faint)', fontSize: '9px' }}>{open ? '▾' : '▸'}</span>}
      </div>
      {open && (
        <div style={{ padding: '0 0 8px 14px' }}>
          {policy.actions?.length > 0 && <ActionChips actions={policy.actions} />}
          <JsonBlock value={policy.document} />
        </div>
      )}
    </div>
  )
}

function PermissionsTab({ e, isResource }) {
  const policies = e.policies || []
  const actions = e.all_actions || e.actions || []
  const meta = e.metadata && typeof e.metadata === 'object' ? e.metadata : null
  const resourcePolicy = meta?.policy || meta?.resource_policy || null
  const attached = e.attached_principals || []

  const nothing = !policies.length && !actions.length && !resourcePolicy && !attached.length
  if (nothing) {
    return <EmptyNote>
      No policies or permissions recorded for this entity.
      {isResource && ' Resources only carry permissions through an execution role.'}
    </EmptyNote>
  }

  return (
    <>
      {policies.length > 0 && (
        <SbBlock label={`Attached policies (${policies.length})`}>
          <div style={{ marginTop: 4 }}>
            {policies.map((p, i) => <PolicyRow key={p.arn || i} policy={p} />)}
          </div>
        </SbBlock>
      )}

      {resourcePolicy && (
        <SbBlock label="Resource policy">
          <JsonBlock value={resourcePolicy} />
        </SbBlock>
      )}

      {meta?.acl_grants > 0 && (
        <SbBlock label="ACL grants">
          <div className="sb-value">{meta.acl_grants} legacy ACL grant(s)</div>
        </SbBlock>
      )}

      {attached.length > 0 && (
        <SbBlock label={`Attached to (${attached.length})`}>
          <div style={{ marginTop: 4 }}>
            {attached.map((p, i) => (
              <div key={i} className="policy-row">
                <span className="policy-dot managed" />
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {typeof p === 'string' ? p : p.name}
                </span>
                {typeof p !== 'string' && p.type && <span className="policy-type">{p.type}</span>}
              </div>
            ))}
          </div>
        </SbBlock>
      )}

      {actions.length > 0 && (
        <SbBlock label={`Effective permissions (${actions.length})`}>
          <ActionChips actions={actions} />
        </SbBlock>
      )}
    </>
  )
}

// ─── Tab: Trust ───────────────────────────────────────────────────────────────

function TrustTab({ e }) {
  const trusts = e.trust_principals || []
  // /api/node ships the trust policy as a JSON string; graph nodes may already
  // hold a parsed object.
  const doc = useMemo(() => {
    const raw = e.trust_policy
    if (!raw) return null
    if (typeof raw !== 'string') return raw
    try { return JSON.parse(raw) } catch { return raw }
  }, [e.trust_policy])

  if (!trusts.length && !doc) {
    return <EmptyNote>No trust policy — only IAM roles have one.</EmptyNote>
  }

  return (
    <>
      {trusts.length > 0 && (
        <SbBlock label={`Trusted principals (${trusts.length})`}>
          <div style={{ marginTop: 6 }}>
            {trusts.map((p, i) => {
              const wildcard = String(p).includes('*')
              const isService = String(p).endsWith('.amazonaws.com')
              return (
                <div key={i} className={`trust-row${wildcard ? ' warn' : ''}`}>
                  <MiniPill variant={isService ? 'service' : 'principal'}>
                    {isService ? 'SERVICE' : 'PRINCIPAL'}
                  </MiniPill>
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis',
                                 whiteSpace: 'nowrap' }}>{p}</span>
                  {wildcard && <span className="trust-warn-icon">⚠</span>}
                </div>
              )
            })}
          </div>
        </SbBlock>
      )}
      {doc && (
        <SbBlock label="Trust policy document">
          <JsonBlock value={doc} maxHeight={420} />
        </SbBlock>
      )}
    </>
  )
}

// ─── Tab: Risk ────────────────────────────────────────────────────────────────

const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

/** Paths shown inline before deferring to the PrivEsc page. */
const PATH_PAGE = 50

function PathRow({ path }) {
  const [open, setOpen] = useState(false)
  const [steps, setSteps] = useState(null)
  async function toggle() {
    setOpen(o => !o)
    if (steps === null) {
      try { setSteps((await api.attackPathDetail(path.id))?.steps || []) }
      catch { setSteps([]) }
    }
  }
  return (
    <div style={{ borderBottom: '1px solid var(--border)', padding: '6px 0' }}>
      <div onClick={toggle} style={{ display: 'flex', alignItems: 'center', gap: 6,
                                     cursor: 'pointer', fontSize: '11px' }}>
        <MiniPill variant={path.severity === 'CRITICAL' ? 'critical' : 'high'}>
          {path.severity}
        </MiniPill>
        <span style={{ color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis',
                       whiteSpace: 'nowrap', flex: 1 }}>{path.summary || path.objective_value}</span>
        <span style={{ color: 'var(--text-faint)', fontSize: '9px' }}>
          {path.total_hops} hops {open ? '▾' : '▸'}
        </span>
      </div>
      {open && (
        <div style={{ marginTop: 4, paddingLeft: 8 }}>
          {steps === null && <span style={{ fontSize: '10px', color: 'var(--text-faint)' }}>loading…</span>}
          {steps?.map((s, i) => (
            <div key={i} style={{ fontSize: '10px', color: 'var(--text-dim)', lineHeight: 1.6 }}>
              <span style={{ color: 'var(--text-faint)' }}>{i + 1}.</span>{' '}
              <span style={{ fontFamily: 'IBM Plex Mono, monospace' }}>{s.action}</span>{' → '}
              <span style={{ color: 'var(--text)' }}>{String(s.target_arn).split('/').pop()}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function RiskTab({ arn, risk, fallbackFindings, hasAnyAssessment, onRunAssessment, running }) {
  const { data: findings, isLoading } = useQuery({
    queryKey: ['entity-findings', arn],
    queryFn: () => api.entityFindings(arn),
    enabled: !!arn,
  })
  const { data: paths } = useQuery({
    queryKey: ['entity-paths', arn],
    queryFn: () => api.attackPathsInvolving(arn),
    enabled: !!arn,
  })

  const list = (findings ?? fallbackFindings ?? []).filter(f => !f.suppressed)
  const grouped = SEV_ORDER
    .map(sev => [sev, list.filter(f => f.severity === sev)])
    .filter(([, rows]) => rows.length > 0)

  return (
    <>
      <SbBlock label="Risk">
        <div style={{ marginTop: 4 }}><RiskBadge risk={risk} /></div>
      </SbBlock>

      {isLoading && <EmptyNote>Loading findings…</EmptyNote>}

      {!isLoading && list.length === 0 && (
        hasAnyAssessment
          ? <EmptyNote>No findings recorded for this entity.</EmptyNote>
          : <div className="sb-block">
              <div className="sb-label">Risk analysis</div>
              <div style={{ fontSize: '11px', color: 'var(--text-faint)', margin: '6px 0 8px',
                            lineHeight: 1.6 }}>
                No assessment has been run yet. This scans every account, not just
                this entity.
              </div>
              <button className="btn primary sm" disabled={running} onClick={onRunAssessment}>
                {running ? 'Running…' : '▶ Run assessment'}
              </button>
            </div>
      )}

      {grouped.map(([sev, rows]) => (
        <SbBlock key={sev} label={`${sev} (${rows.length})`}>
          <div style={{ marginTop: 4 }}>
            {rows.map((f, i) => (
              <div key={f.id ?? i} className="sb-path-row">
                <MiniPill variant={sev.toLowerCase()}>{f.category}</MiniPill>
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontSize: '11px', color: 'var(--text)', lineHeight: 1.5 }}>
                    {f.message}
                  </div>
                  {f.principal_detail && (
                    <div style={{ fontSize: '10px', color: 'var(--text-faint)', marginTop: 2 }}>
                      {f.principal_detail}
                    </div>
                  )}
                  {f.downgrade_note && (
                    <div style={{ fontSize: '10px', color: 'var(--text-faint)', marginTop: 2 }}>
                      {f.downgrade_note}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </SbBlock>
      ))}

      {/* Omitted entirely when no PrivEsc scan has produced paths for this ARN. */}
      {paths?.length > 0 && (
        <SbBlock label={`Privilege escalation paths (${
          paths.length > PATH_PAGE ? `${PATH_PAGE}+` : paths.length})`}>
          <div style={{ marginTop: 4 }}>
            {paths.slice(0, PATH_PAGE).map(p => <PathRow key={p.id} path={p} />)}
          </div>
          {paths.length > PATH_PAGE && (
            <div style={{ fontSize: '10px', color: 'var(--text-faint)', marginTop: 6 }}>
              Showing the first {PATH_PAGE}. Open the PrivEsc page for the full list.
            </div>
          )}
        </SbBlock>
      )}
    </>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function EntityDetailPanel({
  entity, findings, onClose, actions = [], extraTabs = [], style = {},
}) {
  const [tab, setTab] = useState('overview')
  const [running, setRunning] = useState(false)

  const arn = entity?.arn || entity?.node_id || ''
  const nodeId = entity?.node_id
    || (entity?.node_type && arn ? `${entity.node_type}:${arn}` : null)

  // Rich detail — policy documents, trust policy, resource policy — fetched per
  // entity. The panel renders immediately from whatever the caller had and
  // fills in when this resolves.
  const { data: detail } = useQuery({
    queryKey: ['node-detail', nodeId],
    queryFn: () => api.nodeDetail(nodeId),
    enabled: !!nodeId,
    retry: false,
    staleTime: 60_000,
  })

  const e = useMemo(() => ({ ...(entity || {}), ...(detail || {}) }), [entity, detail])

  const related = useMemo(() => (findings || []).filter(
    f => !f.suppressed && (f.entity_arn === arn || f.principal_arn === arn)), [findings, arn])

  if (!entity) return null

  const t = e.principal_type || e.node_type || e.policy_type || 'resource'
  const isPrincipal = ['role', 'user', 'group', 'principal'].includes(t)
  const isResource = t === 'resource'
  const risk = e.risk || computeRisk(e, findings)
  const label = e.label || String(arn).split('/').pop() || arn

  const subtitle = e.policy_type
    ? `IAM POLICY · ${String(e.policy_type).replace('_', ' ').toUpperCase()}`
    : isResource
      ? `AWS ${String(e.service || '').toUpperCase()} ${String(e.resource_type || '').toUpperCase()}`.trim()
      : `IAM ${String(t).toUpperCase()}`

  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'permissions', label: 'Permissions',
      count: (e.all_actions || e.actions || []).length || undefined },
    isPrincipal ? { id: 'trust', label: 'Trust',
                    count: (e.trust_principals || []).length || undefined } : null,
    { id: 'risk', label: 'Risk', count: related.length || undefined },
    ...extraTabs,
  ].filter(Boolean)

  const active = tabs.some(x => x.id === tab) ? tab : 'overview'

  async function runAssessment() {
    setRunning(true)
    try { await api.runSecurityFindings({}) } catch { /* surfaced by the query */ }
    finally { setRunning(false) }
  }

  // flex:1 1 0 + minWidth:0 is load-bearing: a flex item defaults to
  // min-width:auto, which lets a long ARN or an open policy document push the
  // panel wider than the pane it lives in.
  return (
    <div className="ent-sidebar"
      style={{ flex: '1 1 0', minWidth: 0, maxWidth: '100%', ...style }}>
      <div className="ent-sidebar-header">
        <TypeIcon type={t} size={34} />
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{ fontFamily: 'Syne, sans-serif', fontSize: '15px', fontWeight: 800,
                        color: 'var(--white)', overflow: 'hidden', textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap' }}>{label}</div>
          <div style={{ fontSize: '9px', letterSpacing: '.08em', color: 'var(--text-dim)',
                        marginTop: 2 }}>
            {subtitle}{e.account_id ? ` · ${e.account_id}` : ''}
          </div>
        </div>
        {onClose && <button className="slideover-close" onClick={onClose}>✕</button>}
      </div>

      <div className="tab-bar">
        {tabs.map(x => (
          <button key={x.id} className={`tab-btn${active === x.id ? ' active' : ''}`}
            onClick={() => setTab(x.id)}>
            {x.label}{x.count ? <span className="tab-count">{x.count}</span> : null}
          </button>
        ))}
      </div>

      <div style={{ flex: 1, overflowY: 'auto', minHeight: 0 }}>
        {active === 'overview' && (
          <OverviewTab e={e} risk={risk} findingCount={related.length} />
        )}
        {active === 'permissions' && <PermissionsTab e={e} isResource={isResource} />}
        {active === 'trust' && <TrustTab e={e} />}
        {active === 'risk' && (
          <RiskTab arn={arn} risk={risk} fallbackFindings={related}
            hasAnyAssessment={(findings || []).length > 0}
            onRunAssessment={runAssessment} running={running} />
        )}
        {extraTabs.map(x => (active === x.id ? <div key={x.id}>{x.render()}</div> : null))}
      </div>

      {actions.length > 0 && (
        <div className="sb-actions">
          {actions.map((a, i) => (
            <button key={i} className={`btn ${a.variant || 'secondary'} sm`} title={a.title}
              style={a.grow ? { flex: 1, justifyContent: 'center' } : undefined}
              onClick={a.onClick}>{a.label}</button>
          ))}
        </div>
      )}
    </div>
  )
}
