import { useState, useMemo, useEffect, useRef } from 'react'
import { useApp } from '../context/AppContext'
import { api } from '../api'
import { AttackSteps } from '../components/SecurityCards'
import GraphViewer from '../components/GraphViewer'
import Paginator, { usePagination } from '../components/Paginator'

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }

const PRESET_OBJECTIVES = [
  { label: 'Admin / AdministratorAccess', value: 'permission:*:*' },
  { label: 'Any principal (full scan)',   value: 'principal:*' },
  { label: 'iam:PassRole capability',     value: 'permission:iam:PassRole' },
  { label: 'iam:AttachUserPolicy',        value: 'permission:iam:AttachUserPolicy' },
  { label: 'iam:CreateAccessKey',         value: 'permission:iam:CreateAccessKey' },
]

// ─── Principal search dropdown ─────────────────────────────────────────────────

function PrincipalSearch({ label, value, onChange }) {
  const [query,   setQuery]   = useState('')
  const [results, setResults] = useState([])
  const [open,    setOpen]    = useState(false)
  const [loading, setLoading] = useState(false)
  const debounce = useRef(null)

  useEffect(() => {
    if (!query.trim()) { setResults([]); return }
    clearTimeout(debounce.current)
    debounce.current = setTimeout(async () => {
      setLoading(true)
      try {
        const data = await api.principals(query)
        setResults((Array.isArray(data) ? data : (data?.principals || [])).slice(0, 20))
        setOpen(true)
      } catch { setResults([]) }
      finally { setLoading(false) }
    }, 300)
  }, [query])

  function select(p) {
    onChange(p.arn || p.node_id)
    setQuery(p.label || (p.arn || '').split('/').pop())
    setOpen(false)
  }

  return (
    <div style={{ flex:1, position:'relative' }}>
      <div style={{ fontSize:'9px', color:'var(--text-dim)', marginBottom:'4px', textTransform:'uppercase', letterSpacing:'.06em' }}>{label}</div>
      <div style={{ display:'flex', gap:'4px', alignItems:'center' }}>
        <input className="filter-search" style={{ flex:1 }}
          placeholder="ARN or name…" value={query}
          onChange={e => { setQuery(e.target.value); onChange('') }}
          onFocus={() => results.length > 0 && setOpen(true)}
          onBlur={() => setTimeout(() => setOpen(false), 150)} />
        {loading && <span className="spinner-ring" style={{ width:14, height:14, borderWidth:2 }} />}
        {value && <button className="btn secondary sm" onClick={() => { onChange(''); setQuery(''); setResults([]) }}>✕</button>}
      </div>
      {value && (
        <div style={{ fontSize:'9px', color:'var(--amber)', marginTop:'3px', fontFamily:'IBM Plex Mono', wordBreak:'break-all' }}>
          ✓ {value}
        </div>
      )}
      {open && results.length > 0 && (
        <div style={{ position:'absolute', zIndex:200, top:'100%', left:0, right:0, background:'var(--bg2)', border:'1px solid var(--border2)', borderRadius:'4px', boxShadow:'0 8px 24px rgba(0,0,0,.5)', maxHeight:220, overflowY:'auto', marginTop:2 }}>
          {results.map((p, i) => {
            const arn  = p.arn || p.node_id || ''
            const name = p.label || arn.split('/').pop()
            const t    = p.principal_type || p.node_type || 'role'
            return (
              <div key={i} onMouseDown={() => select(p)}
                style={{ padding:'6px 10px', cursor:'pointer', display:'flex', alignItems:'center', gap:'6px', borderBottom:'1px solid var(--border)' }}>
                <span className={`type-tag ${t}`} style={{ fontSize:'9px' }}>{t}</span>
                <div>
                  <div style={{ fontSize:'11px', color:'var(--text)' }}>{name}</div>
                  <div style={{ fontSize:'9px', color:'var(--text-dim)', fontFamily:'IBM Plex Mono' }}>{arn}</div>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ─── Analyze modal ─────────────────────────────────────────────────────────────

function AnalyzeModal({ onRun, onClose }) {
  const [fromArn,   setFromArn]   = useState('')
  const [objective, setObjective] = useState('')
  const [customObj, setCustomObj] = useState('')
  const [maxHops,   setMaxHops]   = useState(10)
  const [running,   setRunning]   = useState(false)
  const [err,       setErr]       = useState(null)

  const effectiveObj = objective === '__custom__' ? customObj : objective

  async function submit() {
    if (!fromArn.trim()) return
    setRunning(true); setErr(null)
    try {
      await onRun(fromArn, effectiveObj || null, maxHops)
      onClose()
    } catch(e) {
      setErr(e.message)
    } finally {
      setRunning(false)
    }
  }

  return (
    <>
      <div className="modal-backdrop" onClick={onClose} />
      <div className="modal" style={{ width: 480 }}>
        <div className="modal-header">
          <span className="modal-title">Run Privilege Escalation Analysis</span>
          <button className="slideover-close" onClick={onClose}>✕</button>
        </div>
        <div className="modal-body" style={{ display:'flex', flexDirection:'column', gap:'14px' }}>
          <PrincipalSearch label="From (attacker identity)" value={fromArn} onChange={setFromArn} />
          <div>
            <div style={{ fontSize:'9px', color:'var(--text-dim)', marginBottom:'4px', textTransform:'uppercase', letterSpacing:'.06em' }}>Target / Objective</div>
            <select className="form-select" value={objective} onChange={e => setObjective(e.target.value)}>
              <option value="">— Any (full scan) —</option>
              {PRESET_OBJECTIVES.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              <option value="__custom__">Custom objective…</option>
            </select>
            {objective === '__custom__' && (
              <input className="filter-search" style={{ width:'100%', marginTop:'6px', fontFamily:'IBM Plex Mono' }}
                placeholder="principal:arn:aws:…  or  permission:iam:*"
                value={customObj} onChange={e => setCustomObj(e.target.value)} />
            )}
          </div>
          <div style={{ display:'flex', alignItems:'center', gap:'12px' }}>
            <div style={{ fontSize:'9px', color:'var(--text-dim)', textTransform:'uppercase', letterSpacing:'.06em' }}>Max hops</div>
            <select className="form-select" style={{ width:80 }} value={maxHops} onChange={e => setMaxHops(Number(e.target.value))}>
              {[2,3,5,7,10].map(n => <option key={n} value={n}>{n}</option>)}
            </select>
          </div>
          {err && <div style={{ fontSize:'11px', color:'var(--red-hi)' }}>⚠ {err}</div>}
        </div>
        <div className="modal-footer">
          <button className="btn secondary sm" onClick={onClose}>Cancel</button>
          <button className="btn primary sm" disabled={running || !fromArn.trim()} onClick={submit}>
            {running ? <><span className="spinner-ring" style={{ width:12, height:12, borderWidth:2 }} /> Analyzing…</> : '▶ Run'}
          </button>
        </div>
      </div>
    </>
  )
}

// ─── Path row ──────────────────────────────────────────────────────────────────

function PathRow({ path, expanded, onExpand, onViewGraph }) {
  const sev        = (path.severity || 'MEDIUM').toLowerCase()
  const [steps,    setSteps]    = useState(path.steps || null)
  const [loadingS, setLoadingS] = useState(false)

  async function toggle() {
    onExpand()
    // Lazy-load steps on first expand
    if (!expanded && steps === null) {
      setLoadingS(true)
      try {
        const detail = await api.attackPathDetail(path.id)
        setSteps(detail.steps || [])
      } catch { setSteps([]) }
      finally { setLoadingS(false) }
    }
  }

  const fromName = (path.from_principal_arn || '').split('/').pop() || path.from_principal_arn
  const objLabel = path.objective_value ? `→ ${path.objective_value}`.slice(0, 40) : ''

  return (
    <div className={`finding-card`} style={{ marginBottom:0, borderBottom:'1px solid var(--border)' }}>
      <div className="finding-header" onClick={toggle}>
        <div className={`finding-sev-bar ${sev}`} />
        <div style={{ flex:1, overflow:'hidden' }}>
          <div className="finding-title">
            {path.summary || `${fromName} ${objLabel}`}
          </div>
          <div className="finding-meta">
            <span className="type-tag" style={{ marginRight:'6px' }}>{path.total_hops} hops</span>
            <span title={path.from_principal_arn}>{fromName}</span>
            {path.objective_type && (
              <span style={{ marginLeft:'8px', color:'var(--text-faint)' }}>{path.objective_type}</span>
            )}
            {steps !== null && (
              <span style={{ marginLeft:'8px', color:'var(--text-faint)' }}>{steps.length} step{steps.length !== 1 ? 's' : ''}</span>
            )}
          </div>
        </div>
        <span className={`sev-badge ${sev}`}>{path.severity}</span>
        <span style={{ color:'var(--text-faint)', fontSize:'10px', marginLeft:'8px' }}>{expanded ? '▲' : '▼'}</span>
      </div>
      {expanded && (
        <div style={{ padding:'10px 16px 14px 31px', borderTop:'1px solid var(--border)', background:'var(--bg2)' }}>
          {path.from_principal_arn && (
            <div style={{ marginBottom:'8px' }}>
              <div style={{ fontSize:'9px', letterSpacing:'0.08em', textTransform:'uppercase', color:'var(--text-faint)', marginBottom:'3px' }}>From</div>
              <div style={{ fontFamily:'IBM Plex Mono', fontSize:'11px', color:'var(--cyan-hi)', wordBreak:'break-all' }}>{path.from_principal_arn}</div>
            </div>
          )}
          {path.objective_value && (
            <div style={{ marginBottom:'8px' }}>
              <div style={{ fontSize:'9px', letterSpacing:'0.08em', textTransform:'uppercase', color:'var(--text-faint)', marginBottom:'3px' }}>Objective</div>
              <div style={{ fontFamily:'IBM Plex Mono', fontSize:'11px', color:'var(--amber)', wordBreak:'break-all' }}>{path.objective_value}</div>
            </div>
          )}
          {loadingS && (
            <div style={{ display:'flex', alignItems:'center', gap:8, color:'var(--text-dim)', fontSize:'11px', marginBottom:'8px' }}>
              <span className="spinner-ring" style={{ width:12, height:12, borderWidth:2 }} /> Loading steps…
            </div>
          )}
          {steps && steps.length > 0 && <AttackSteps steps={steps} />}
          {steps && steps.length > 0 && (() => {
            // Deduplicate ARNs and cap at 60 steps for graph
            const seenArns = new Set()
            const capped = []
            for (const s of steps) {
              if (!seenArns.has(s.actor_arn)) seenArns.add(s.actor_arn)
              if (!seenArns.has(s.target_arn)) seenArns.add(s.target_arn)
              capped.push(s)
              if (seenArns.size >= 60) break
            }
            const truncated = capped.length < steps.length
            return (
              <div style={{ marginTop:'8px' }}>
                {truncated && (
                  <div style={{ fontSize:'10px', color:'var(--amber)', marginBottom:'6px' }}>
                    ⚠ Large path ({steps.length} steps) — showing first {capped.length} in graph
                  </div>
                )}
                <button className="btn primary sm" onClick={() => onViewGraph(capped)}>
                  🕸 View in graph
                </button>
              </div>
            )
          })()}
          {path.created_at && (
            <div style={{ fontSize:'10px', color:'var(--text-faint)', marginTop:'8px' }}>
              Found: {new Date(path.created_at).toLocaleString()}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function PrivEscPage() {
  const [storedPaths, setStoredPaths] = useState(null)
  const [loadErr,     setLoadErr]     = useState(null)
  const [sevFilter,   setSevFilter]   = useState('All')
  const [search,      setSearch]      = useState('')
  const [expanded,    setExpanded]    = useState(null)
  const [showModal,   setShowModal]   = useState(false)
  const [running,     setRunning]     = useState(false)

  const PAGE_SIZE = 25

  // Graph view state
  const [graphSteps,  setGraphSteps]  = useState(null)   // null = closed

  // Load stored paths on mount
  useEffect(() => {
    api.attackPaths()
      .then(data => setStoredPaths(Array.isArray(data) ? data : []))
      .catch(e   => setLoadErr(e.message))
  }, [])

  async function runAnalysis(fromArn, objective, maxHops) {
    setRunning(true)
    try {
      const raw  = await api.runAttackPaths(fromArn, objective, maxHops)
      const list = Array.isArray(raw) ? raw : (raw?.paths || [])
      // Append new results to stored paths
      setStoredPaths(prev => {
        const existing = new Set((prev || []).map(p => p.id))
        const fresh    = list.filter(p => !existing.has(p.id))
        return [...fresh, ...(prev || [])]
      })
    } catch(e) {
      throw e
    } finally {
      setRunning(false)
    }
  }

  const all = storedPaths || []

  const shown = useMemo(() => {
    let arr = [...all]
    if (sevFilter !== 'All') arr = arr.filter(p => p.severity === sevFilter)
    if (search.trim()) {
      const q = search.toLowerCase()
      arr = arr.filter(p =>
        (p.from_principal_arn || '').toLowerCase().includes(q) ||
        (p.summary            || '').toLowerCase().includes(q) ||
        (p.objective_value    || '').toLowerCase().includes(q)
      )
    }
    return arr.sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9))
  }, [all, sevFilter, search])

  const { page, totalPages, pageItems, goTo } = usePagination(shown, PAGE_SIZE)

  const critCount = all.filter(p => p.severity === 'CRITICAL').length

  return (
    <div className="page-content" style={{ display:'flex', flexDirection:'column', overflow:'hidden' }}>
      {showModal && (
        <AnalyzeModal
          onRun={runAnalysis}
          onClose={() => setShowModal(false)}
        />
      )}
      {graphSteps && (
        <GraphViewer
          pathSteps={graphSteps}
          onClose={() => setGraphSteps(null)}
        />
      )}

      <div className="page-header">
        <div>
          <div className="page-title">PrivEsc</div>
          <div className="page-subtitle">
            {storedPaths === null
              ? 'Loading stored paths…'
              : `${all.length} stored path${all.length !== 1 ? 's' : ''}${critCount > 0 ? ` · ${critCount} CRITICAL` : ''}`
            }
          </div>
        </div>
        <div style={{ marginLeft:'auto' }}>
          <button className="btn primary" disabled={running} onClick={() => setShowModal(true)}>
            {running ? <><span className="spinner-ring" style={{ width:12, height:12, borderWidth:2 }} /> Analyzing…</> : '▶ Analyze'}
          </button>
        </div>
      </div>

      {loadErr && (
        <div style={{ padding:'8px 20px', background:'var(--red-glow)', borderBottom:'1px solid rgba(192,48,48,.2)', fontSize:'11px', color:'var(--red-hi)' }}>
          ⚠ {loadErr}
        </div>
      )}

      {/* Filter bar */}
      <div className="filter-bar">
        <div style={{ display:'flex', gap:'4px' }}>
          {['All','CRITICAL','HIGH','MEDIUM','LOW'].map(s => (
            <button key={s} className={`filter-chip ${sevFilter === s ? 'active' : ''}`}
              onClick={() => setSevFilter(s)}>{s}</button>
          ))}
        </div>
        <input className="filter-search" style={{ marginLeft:'auto', width:'200px' }}
          placeholder="Search ARN or summary…" value={search} onChange={e => setSearch(e.target.value)} />
      </div>

      {/* Results */}
      <div style={{ flex:1, overflowY:'auto' }}>
        {storedPaths === null && !loadErr ? (
          <div className="empty-state">
            <div className="spinner-ring" style={{ width:24, height:24, borderWidth:3, margin:'0 auto 12px' }} />
            <div className="empty-state-title">Loading stored paths…</div>
          </div>
        ) : shown.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">⚡</div>
            <div className="empty-state-title">
              {all.length === 0 ? 'No stored attack paths' : 'No paths match filters'}
            </div>
            <div className="empty-state-hint">
              {all.length === 0
                ? <>Run <code style={{ color:'var(--amber)' }}>worst attack-paths</code> in the CLI, or click ▶ Analyze above.</>
                : 'Adjust severity filter or search above.'
              }
            </div>
          </div>
        ) : (
          pageItems.map((p, i) => (
            <PathRow
              key={p.id ?? i}
              path={p}
              expanded={expanded === (p.id ?? i)}
              onExpand={() => setExpanded(expanded === (p.id ?? i) ? null : (p.id ?? i))}
              onViewGraph={steps => setGraphSteps(steps)}
            />
          ))
        )}
      </div>
      <Paginator page={page} totalPages={totalPages} total={shown.length} pageSize={PAGE_SIZE} goTo={goTo} label="paths" />
    </div>
  )
}
