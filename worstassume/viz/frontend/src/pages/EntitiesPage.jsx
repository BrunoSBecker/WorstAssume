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
  const { entities, findings } = useApp()

  const [tab, setTab] = useState('All')
  const [riskFilter, setRiskFilter] = useState('All Risk')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState(null)
  const [graphIds, setGraphIds] = useState([])
  const [showGraph, setShowGraph] = useState(false)

  const PAGE_SIZE = 50

  const all = entities || []

  const filtered = useMemo(() => {
    let arr = all
    if (tab !== 'All') arr = arr.filter(e => (e.principal_type || e.node_type) === TYPE_MAP[tab])
    if (riskFilter !== 'All Risk') {
      const rf = riskFilter.toUpperCase()
      arr = arr.filter(e => entityRisk(e, findings) === rf)
    }
    if (search.trim()) {
      const q = search.toLowerCase()
      arr = arr.filter(e =>
        (e.label || '').toLowerCase().includes(q) ||
        (e.arn || '').toLowerCase().includes(q) ||
        (e.account_id || '').includes(q)
      )
    }
    return [...arr].sort((a, b) =>
      (RISK_RANK[entityRisk(a, findings)] ?? 5) - (RISK_RANK[entityRisk(b, findings)] ?? 5)
    )
  }, [all, tab, riskFilter, search, findings])

  const { page, totalPages, pageItems, goTo } = usePagination(filtered, PAGE_SIZE)

  const counts = useMemo(() => {
    const c = { All: all.length }
    for (const t of Object.keys(TYPE_MAP))
      c[t] = all.filter(e => (e.principal_type || e.node_type) === TYPE_MAP[t]).length
    return c
  }, [all])

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
              <button key={t} onClick={() => setTab(t)} style={{
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
          <div className="filter-bar" style={{ flexShrink: 0 }}>
            {RISK_FILTERS.map(f => (
              <button key={f} className={`filter-chip${riskFilter === f ? ' active' : ''}`} onClick={() => setRiskFilter(f)}>{f}</button>
            ))}
            <input className="filter-search" placeholder="Search name or ARN…" value={search} onChange={e => setSearch(e.target.value)} />
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
