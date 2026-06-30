import { useState, useMemo } from 'react'
import { useApp } from '../context/AppContext'
import GraphViewer from '../components/GraphViewer'
import EntityDetailPanel, { computeRisk } from '../components/EntityDetailPanel'
import Paginator, { usePagination } from '../components/Paginator'

// ─── Helpers ──────────────────────────────────────────────
const TYPE_ICON = { role: '⚙', user: '👤', group: '👥', policy: '📄', resource: '☁', account: '🔷' }
const TYPE_TABS = ['All', 'Roles', 'Users', 'Groups', 'Policies', 'Resources']
const TYPE_MAP = { Roles: 'role', Users: 'user', Groups: 'group', Policies: 'policy', Resources: 'resource' }
const RISK_FILTERS = ['All Risk', 'Critical', 'High', 'Clean']
const RISK_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, CLEAN: 4 }
const SERVICE_FILTERS = ['All', 'ec2', 's3', 'lambda', 'ecs', 'vpc']
const SERVICE_LABEL = { ec2: 'EC2', s3: 'S3', lambda: 'Lambda', ecs: 'ECS', vpc: 'VPC' }
const _selectStyle = (active) => ({
  background: active ? 'rgba(217,124,20,.08)' : 'var(--bg3)',
  color: active ? 'var(--amber)' : 'var(--text-dim)',
  border: `1px solid ${active ? 'rgba(217,124,20,.3)' : 'var(--border2)'}`,
  borderRadius: 3, padding: '3px 8px', fontSize: 10,
  fontFamily: 'IBM Plex Mono, monospace', cursor: 'pointer', outline: 'none',
})

/**
 * Detect AWS-managed principals (service-linked roles, SSO reserved) and
 * AWS-managed policies.  Used by the Managed filter toggle.
 */
function isAwsManaged(entity) {
  const arn = entity.arn || ''
  const label = entity.label || ''
  const type = entity.principal_type || entity.node_type
  // AWS service-linked roles and SSO reserved roles
  if (type === 'role') {
    if (arn.includes('/aws-service-role/')) return true
    if (label.startsWith('AWSServiceRole')) return true
    if (arn.includes('/AWSReservedSSO_')) return true
    if (arn.includes('/aws-reserved/sso.amazonaws.com/')) return true
  }
  // AWS-managed policies (arn:aws:iam::aws:policy/...)
  if (type === 'policy' || entity.node_type === 'policy') {
    if (entity.policy_type === 'aws_managed') return true
    if (arn.includes(':aws:policy/')) return true
  }
  return false
}

/**
 * IAM-style prefix matching for the permission filter.
 * Typing "iam:Assume" matches iam:AssumeRole, iam:AssumeRoleWithSAML, etc.
 * Trailing wildcards (iam:*) are stripped and matched as prefixes.
 */
function matchesPermission(actions, query) {
  if (!query || !actions || actions.length === 0) return false
  const q = query.toLowerCase().replace(/\*$/, '')
  return actions.some(a => typeof a === 'string' && a.toLowerCase().startsWith(q))
}


// ─── Permission Multi-Select Dropdown ─────────────────────────
function PermissionMultiSelect({ selected, onChange, options, query, onQueryChange }) {
  const [open, setOpen] = useState(false)

  const filtered = useMemo(() => {
    if (!query.trim()) return options.slice(0, 50)
    const q = query.toLowerCase()
    return options.filter(a => a.toLowerCase().includes(q)).slice(0, 50)
  }, [query, options])

  function toggle(action) {
    if (selected.includes(action)) onChange(selected.filter(a => a !== action))
    else onChange([...selected, action])
  }

  return (
    <div style={{ position: 'relative', width: 220 }}>
      <div style={{
        display: 'flex', flexWrap: 'wrap', gap: 3, alignItems: 'center',
        background: 'var(--bg3)',
        border: `1px solid ${selected.length > 0 || query.trim() ? 'rgba(217,124,20,.3)' : 'var(--border2)'}`,
        borderRadius: 3, padding: '2px 6px', minHeight: 26,
      }}>
        {selected.map(p => (
          <span key={p} style={{
            display: 'inline-flex', alignItems: 'center', gap: 3,
            background: 'rgba(217,124,20,.12)', border: '1px solid rgba(217,124,20,.25)',
            borderRadius: 2, padding: '1px 6px', fontSize: 9, color: 'var(--amber)',
            fontFamily: 'IBM Plex Mono, monospace',
          }}>
            {p}
            <span onClick={() => toggle(p)}
              style={{ cursor: 'pointer', opacity: 0.7, lineHeight: 1 }}>×</span>
          </span>
        ))}
        <input
          style={{
            flex: 1, minWidth: 60, background: 'transparent', border: 'none',
            outline: 'none', color: 'var(--text)', fontSize: 10,
            fontFamily: 'IBM Plex Mono, monospace', padding: '2px 0',
          }}
          placeholder={selected.length === 0 ? 'Filter permissions…' : ''}
          value={query}
          onChange={e => { onQueryChange(e.target.value); setOpen(true) }}
          onKeyDown={e => {
            if (e.key === 'Enter' && query.trim() && !selected.includes(query.trim())) {
              onChange([...selected, query.trim()])
              onQueryChange('')
              setOpen(false)
            }
          }}
          onFocus={() => setOpen(true)}
          onBlur={() => setTimeout(() => setOpen(false), 180)}
        />
      </div>
      {open && filtered.length > 0 && (
        <div style={{
          position: 'absolute', zIndex: 200, top: '100%', left: 0,
          width: 320,
          background: 'var(--bg2)', border: '1px solid var(--border2)',
          borderRadius: 4, boxShadow: '0 8px 24px rgba(0,0,0,.5)',
          maxHeight: 200, overflowY: 'auto', marginTop: 2,
        }}>
          {filtered.map(a => {
            const isSel = selected.includes(a)
            return (
              <div key={a} onMouseDown={() => toggle(a)} style={{
                padding: '4px 10px', cursor: 'pointer', fontSize: 10,
                fontFamily: 'IBM Plex Mono, monospace',
                display: 'flex', alignItems: 'center', gap: 6,
                background: isSel ? 'rgba(217,124,20,.06)' : 'transparent',
                color: isSel ? 'var(--amber)' : 'var(--text-dim)',
                borderBottom: '1px solid var(--border)',
              }}>
                <span style={{ width: 14, textAlign: 'center', fontSize: 11 }}>{isSel ? '✓' : ''}</span>
                {a}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}


// entityRisk is now computeRisk imported from EntityDetailPanel
const entityRisk = computeRisk

const RISK_STYLE = {
  CRITICAL: { bg: 'rgba(192,48,48,.12)', color: 'var(--red-hi)', border: 'rgba(192,48,48,.3)' },
  HIGH: { bg: 'rgba(217,124,20,.12)', color: 'var(--amber-hi)', border: 'rgba(217,124,20,.3)' },
  MEDIUM: { bg: 'rgba(184,160,32,.10)', color: 'var(--yellow-hi)', border: 'rgba(184,160,32,.25)' },
  LOW: { bg: 'rgba(42,112,128,.10)', color: 'var(--cyan-hi)', border: 'rgba(42,112,128,.25)' },
  CLEAN: { bg: 'rgba(46,125,82,.10)', color: 'var(--green-hi)', border: 'rgba(46,125,82,.25)' },
}

function RiskBadge({ risk, style = {} }) {
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

function TypeIcon({ type, size = 26 }) {
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

function MiniPill({ variant = 'dim', children }) {
  const S = {
    service: { bg: 'rgba(42,112,128,.1)', color: 'var(--cyan-hi)', border: '1px solid rgba(42,112,128,.25)' },
    principal: { bg: 'rgba(217,124,20,.1)', color: 'var(--amber)', border: '1px solid rgba(217,124,20,.25)' },
    critical: { bg: 'rgba(192,48,48,.12)', color: 'var(--red-hi)', border: '1px solid rgba(192,48,48,.3)' },
    high: { bg: 'rgba(217,124,20,.12)', color: 'var(--amber-hi)', border: '1px solid rgba(217,124,20,.3)' },
    dim: { bg: 'var(--bg3)', color: 'var(--text-dim)', border: '1px solid var(--border2)' },
  }
  const s = S[variant] || S.dim
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', padding: '1px 7px',
      borderRadius: '2px', fontSize: '10px', fontWeight: 600,
      letterSpacing: '0.06em', flexShrink: 0, whiteSpace: 'nowrap',
      background: s.bg, color: s.color, border: s.border,
    }}>{children}</span>
  )
}


// ─── Main Page ────────────────────────────────────────────
export default function EntitiesPage() {
  const { entities, findings, accounts } = useApp()

  const [tab, setTab] = useState('All')
  const [riskFilter, setRiskFilter] = useState('All Risk')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState(null)
  const [serviceFilter, setServiceFilter] = useState('All')
  const [selectedPerms, setSelectedPerms] = useState([])
  const [permQuery, setPermQuery] = useState('')
  const [accountFilter, setAccountFilter] = useState('')
  const [showManaged, setShowManaged] = useState(true)
  const [showCustom, setShowCustom]   = useState(true)
  const [graphIds, setGraphIds] = useState([])
  const [showGraph, setShowGraph] = useState(false)

  const PAGE_SIZE = 50

  const all = entities || []

  const filtered = useMemo(() => {
    let arr = all
    // Type tab
    if (tab !== 'All') arr = arr.filter(e => (e.principal_type || e.node_type) === TYPE_MAP[tab])
    // Risk
    if (riskFilter !== 'All Risk') {
      const rf = riskFilter.toUpperCase()
      arr = arr.filter(e => entityRisk(e, findings) === rf)
    }
    // Text search
    if (search.trim()) {
      const q = search.toLowerCase()
      arr = arr.filter(e =>
        (e.label || '').toLowerCase().includes(q) ||
        (e.arn || '').toLowerCase().includes(q) ||
        (e.account_id || '').includes(q)
      )
    }
    // Service filter (resources only)
    if (serviceFilter !== 'All') {
      arr = arr.filter(e => e.service === serviceFilter)
    }
    // Permission filter — entities must match ALL selected permissions
    if (selectedPerms.length > 0) {
      arr = arr.filter(e => {
        if (!e.actions || e.actions.length === 0) return false
        return selectedPerms.every(perm => matchesPermission(e.actions, perm))
      })
    }
    // Account filter
    if (accountFilter) {
      arr = arr.filter(e => e.account_id === accountFilter)
    }
    // AWS Managed / Custom flags
    if (showManaged && !showCustom) {
      arr = arr.filter(e => isAwsManaged(e))
    } else if (!showManaged && showCustom) {
      arr = arr.filter(e => !isAwsManaged(e))
    } else if (!showManaged && !showCustom) {
      arr = []
    }
    return [...arr].sort((a, b) =>
      (RISK_RANK[entityRisk(a, findings)] ?? 5) - (RISK_RANK[entityRisk(b, findings)] ?? 5)
    )
  }, [all, tab, riskFilter, search, serviceFilter, selectedPerms, accountFilter, showManaged, showCustom, findings])

  const { page, totalPages, pageItems, goTo } = usePagination(filtered, PAGE_SIZE)

  const counts = useMemo(() => {
    const c = { All: all.length }
    for (const t of Object.keys(TYPE_MAP))
      c[t] = all.filter(e => (e.principal_type || e.node_type) === TYPE_MAP[t]).length
    return c
  }, [all])

  // Unique account IDs for the account dropdown, with labels from /api/accounts
  const uniqueAccounts = useMemo(() => {
    const ids = new Set()
    for (const e of all) { if (e.account_id) ids.add(e.account_id) }
    return [...ids].map(id => {
      const acct = (accounts || []).find(a => a.account_id === id)
      return { id, name: acct?.account_name || id }
    })
  }, [all, accounts])

  // All unique actions across every entity — populates the permission multi-select
  const allUniqueActions = useMemo(() => {
    const set = new Set()
    for (const e of all) {
      if (e.actions) e.actions.forEach(a => typeof a === 'string' && set.add(a))
    }
    return [...set].sort()
  }, [all])

  const activeFilterCount = (serviceFilter !== 'All' ? 1 : 0)
    + (selectedPerms.length > 0 ? 1 : 0) + (accountFilter ? 1 : 0)
    + (!showManaged ? 1 : 0) + (!showCustom ? 1 : 0)

  function clearAdvancedFilters() {
    setServiceFilter('All'); setSelectedPerms([]); setPermQuery(''); setAccountFilter('')
    setShowManaged(true); setShowCustom(true)
  }

  function handleViewGraph(entity) {
    const nid = entity.node_id || entity.arn
    if (!nid) return
    setGraphIds(prev => prev.includes(nid) ? prev : [...prev, nid])
    setShowGraph(true)
  }

  return (
    <div className="page-content" style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

      {/* Page header */}
      <div className="page-header">
        <div>
          <div className="page-title">Entities</div>
          <div className="page-subtitle">IAM principals browser</div>
        </div>
        <div style={{ display: 'flex', gap: '8px', marginLeft: 'auto' }}>
          {graphIds.length > 0 && (
            <button className="btn primary sm" onClick={() => setShowGraph(true)}>⬡ Graph ({graphIds.length})</button>
          )}
        </div>
      </div>

      {/* Table body */}
      <div style={{
        flex: 1, display: 'grid',
        gridTemplateColumns: '1fr',
        overflow: 'hidden',
        height: 0, minHeight: 0,
      }}>

        {/* LEFT: Table column */}
        <div style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden', borderRight: selected ? '1px solid var(--border)' : 'none' }}>

          {/* Tab bar */}
          <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', flexShrink: 0, background: 'var(--bg2)' }}>
            {TYPE_TABS.map(t => (
              <button key={t} onClick={() => {
                setTab(t)
                if (t !== 'All' && t !== 'Resources') setServiceFilter('All')
              }} style={{
                padding: '8px 16px', fontSize: '11px', cursor: 'pointer', border: 'none',
                background: 'transparent', fontFamily: 'IBM Plex Mono, monospace',
                borderBottom: `2px solid ${tab === t ? 'var(--amber)' : 'transparent'}`,
                color: tab === t ? 'var(--amber)' : 'var(--text-dim)',
                display: 'flex', alignItems: 'center', gap: '6px',
                transition: 'all 0.12s',
              }}>
                {t}
                <span style={{
                  background: tab === t ? 'var(--amber-glow)' : 'var(--bg3)',
                  border: `1px solid ${tab === t ? 'rgba(217,124,20,.3)' : 'var(--border2)'}`,
                  borderRadius: '2px', padding: '0 5px', fontSize: '9px',
                  color: tab === t ? 'var(--amber)' : 'var(--text-faint)',
                }}>{counts[t] || 0}</span>
              </button>
            ))}
          </div>

          {/* Filter bar */}
          <div style={{ flexShrink: 0, borderBottom: '1px solid var(--border)' }}>
            {/* Row 1: Search | Account | Resources | Managed flags | Permissions */}
            <div className="filter-bar" style={{ paddingBottom: '4px', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>

              <input className="filter-search" style={{ width: '170px' }}
                placeholder="Search name or ARN…" value={search}
                onChange={e => setSearch(e.target.value)} />
              <div style={{ width: 1, height: 20, background: 'var(--border2)', flexShrink: 0 }} />
              <select value={accountFilter} onChange={e => setAccountFilter(e.target.value)}
                style={_selectStyle(!!accountFilter)}>
                <option value="">All Accounts</option>
                {uniqueAccounts.map(a => (
                  <option key={a.id} value={a.id}>{a.name}</option>
                ))}
              </select>
              <div style={{ width: 1, height: 20, background: 'var(--border2)', flexShrink: 0 }} />
              <select value={serviceFilter}
                disabled={tab !== 'All' && tab !== 'Resources'}
                onChange={e => setServiceFilter(e.target.value)}
                style={{
                  ..._selectStyle(serviceFilter !== 'All'),
                  ...(tab !== 'All' && tab !== 'Resources' ? { opacity: 0.35, cursor: 'not-allowed' } : {}),
                }}>
                <option value="All">All Resources</option>
                {['ec2', 's3', 'lambda', 'ecs', 'vpc'].map(s => (
                  <option key={s} value={s}>{SERVICE_LABEL[s]}</option>
                ))}
              </select>
              <div style={{ width: 1, height: 20, background: 'var(--border2)', flexShrink: 0 }} />
              <label style={{
                display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer',
                fontSize: 10, color: showManaged ? 'var(--amber)' : 'var(--text-faint)',
                fontFamily: 'IBM Plex Mono, monospace', userSelect: 'none',
              }}>
                <input type="checkbox" checked={showManaged}
                  onChange={e => setShowManaged(e.target.checked)}
                  style={{ accentColor: 'var(--amber)', cursor: 'pointer' }} />
                AWS Managed
              </label>
              <label style={{
                display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer',
                fontSize: 10, color: showCustom ? 'var(--amber)' : 'var(--text-faint)',
                fontFamily: 'IBM Plex Mono, monospace', userSelect: 'none',
              }}>
                <input type="checkbox" checked={showCustom}
                  onChange={e => setShowCustom(e.target.checked)}
                  style={{ accentColor: 'var(--amber)', cursor: 'pointer' }} />
                Custom
              </label>
              <div style={{ width: 1, height: 20, background: 'var(--border2)', flexShrink: 0 }} />
              <PermissionMultiSelect
                selected={selectedPerms}
                onChange={setSelectedPerms}
                options={allUniqueActions}
                query={permQuery}
                onQueryChange={setPermQuery}
              />
              {activeFilterCount > 0 && (
                <button onClick={clearAdvancedFilters} title="Clear all filters"
                  style={{
                    background: 'rgba(192,48,48,.1)', color: 'var(--red-hi)',
                    border: '1px solid rgba(192,48,48,.25)', borderRadius: 3,
                    padding: '2px 8px', fontSize: 9, cursor: 'pointer',
                    fontFamily: 'IBM Plex Mono, monospace', flexShrink: 0,
                  }}>Clear ({activeFilterCount})</button>
              )}
            </div>
            {/* Row 2: Risk severity */}
            <div className="filter-bar" style={{ borderTop: 'none', paddingTop: 0 }}>
              {RISK_FILTERS.map(f => (
                <button key={f} className={`filter-chip${riskFilter === f ? ' active' : ''}`}
                  onClick={() => setRiskFilter(f)}>{f}</button>
              ))}
            </div>
          </div>

          {/* Table */}
          <div style={{ flex: 1, overflowY: 'auto' }}>
            {filtered.length === 0 ? (
              <div className="empty-state"><div className="empty-state-icon">🔍</div><div className="empty-state-title">No entities match</div></div>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead style={{ position: 'sticky', top: 0, background: 'var(--bg1)', zIndex: 5 }}>
                  <tr>
                    {['', 'PRINCIPAL', 'ACCOUNT', 'RISK', ...(selected ? [] : ['PATHS']), ''].map((h, i) => (
                      <th key={i} style={{
                        padding: i === 0 ? '8px 0 8px 16px' : '8px 12px',
                        textAlign: 'left', fontSize: '9px', letterSpacing: '0.08em',
                        color: 'var(--text-faint)', fontWeight: 500,
                        borderBottom: '1px solid var(--border)', width: i === 0 ? 36 : i === 5 ? 48 : 'auto',
                      }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {pageItems.map((e, i) => {
                    const t = e.principal_type || e.node_type || 'resource'
                    const arn = e.arn || e.node_id || ''
                    const nm = e.label || arn.split('/').pop() || arn
                    const acct = e.account_id || '—'
                    const risk = entityRisk(e, findings)
                    const isSel = selected && (selected.arn === arn || selected.node_id === arn)
                    const paths = (findings || []).filter(f => !f.suppressed && (f.entity_arn === arn || f.principal_arn === arn)).length

                    return (
                      <tr key={e.node_id || i} onClick={() => setSelected(isSel ? null : e)}
                        style={{
                          cursor: 'pointer',
                          background: isSel ? 'rgba(217,124,20,.04)' : 'transparent',
                          borderLeft: isSel ? '2px solid var(--amber)' : '2px solid transparent',
                          transition: 'background 0.1s',
                        }}
                        onMouseEnter={ev => { if (!isSel) ev.currentTarget.style.background = 'var(--bg2)' }}
                        onMouseLeave={ev => { if (!isSel) ev.currentTarget.style.background = 'transparent' }}
                      >
                        <td style={{ padding: '0 0 0 14px' }}>
                          <TypeIcon type={t} size={26} />
                        </td>
                        <td style={{ padding: '10px 12px' }}>
                          <div style={{ fontSize: '12px', color: 'var(--white)', fontWeight: 500 }}>{nm}</div>
                          <div style={{ fontSize: '9px', color: 'var(--text-faint)', fontFamily: 'IBM Plex Mono', marginTop: '2px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: selected ? '160px' : '300px' }}>
                            <em style={{ color: 'var(--text-dim)', fontStyle: 'normal' }}>{e.account_id}</em>
                            {arn.split(e.account_id || '')[1] || ''}
                          </div>
                        </td>
                        <td style={{ padding: '10px 12px', fontSize: '11px', color: 'var(--text-dim)', whiteSpace: 'nowrap' }}>{acct}</td>
                        <td style={{ padding: '10px 12px' }}><RiskBadge risk={risk} /></td>
                        {!selected && (
                          <td style={{ padding: '10px 12px' }}>
                            {paths > 0
                              ? <span style={{ fontSize: '9px', padding: '2px 7px', borderRadius: '2px', background: 'rgba(192,48,48,.1)', color: 'var(--red-hi)', border: '1px solid rgba(192,48,48,.25)' }}>{paths} paths</span>
                              : <span style={{ fontSize: '9px', color: 'var(--text-faint)' }}>—</span>}
                          </td>
                        )}
                        <td style={{ padding: '10px 8px' }} onClick={ev => ev.stopPropagation()}>
                          <button onClick={() => handleViewGraph(e)} title="View in Graph" style={{
                            background: 'transparent', border: '1px solid var(--border2)', borderRadius: '3px',
                            cursor: 'pointer', color: 'var(--text-dim)', padding: '2px 6px', fontSize: '11px', fontFamily: 'inherit',
                          }}
                            onMouseEnter={ev => { ev.currentTarget.style.background = 'var(--bg3)'; ev.currentTarget.style.color = 'var(--text)' }}
                            onMouseLeave={ev => { ev.currentTarget.style.background = 'transparent'; ev.currentTarget.style.color = 'var(--text-dim)' }}
                          >⬡</button>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
          </div>
          <Paginator page={page} totalPages={totalPages} total={filtered.length} pageSize={PAGE_SIZE} goTo={goTo} label="entities" />
        </div>
      </div>

      {/* Entity detail — fixed right panel, always full viewport height */}
      {selected && (
        <>
          <div
            style={{ position: 'fixed', inset: 0, zIndex: 499 }}
            onClick={() => setSelected(null)}
          />
          <div style={{
            position: 'fixed', top: 0, right: 0, bottom: 0,
            width: '420px',
            zIndex: 500,
            overflowY: 'auto',
            background: 'var(--bg1)',
            borderLeft: '1px solid var(--border2)',
            boxShadow: '-4px 0 24px rgba(0,0,0,0.5)',
          }}>
            <EntityDetailPanel
              entity={selected}
              findings={findings}
              onClose={() => setSelected(null)}
              onViewGraph={handleViewGraph}
            />
          </div>
        </>
      )}

      {/* Graph slide-over */}
      {showGraph && (
        <GraphViewer nodeIds={graphIds} onNodeIdsChange={setGraphIds} onClose={() => setShowGraph(false)} />
      )}
    </div>
  )
}
