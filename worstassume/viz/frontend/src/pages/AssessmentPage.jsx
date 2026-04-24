import { useState, useEffect, useMemo } from 'react'
import { useApp } from '../context/AppContext'
import { api } from '../api'
import Paginator, { usePagination } from '../components/Paginator'

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }

function sevClass(sev) { return (sev || '').toLowerCase() }

// ─── Run modal ────────────────────────────────────────────────────────────────

function RunModal({ accounts, onRun, onClose }) {
  const [accountId,  setAccountId]  = useState('')
  const [minSev,     setMinSev]     = useState('')
  const [running,    setRunning]    = useState(false)
  const [err,        setErr]        = useState(null)

  async function submit() {
    setRunning(true); setErr(null)
    try {
      const body = {}
      if (accountId) body.account_id = accountId
      if (minSev)    body.min_severity = minSev
      await onRun(body)
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
      <div className="modal" style={{ width: 360 }}>
        <div className="modal-header">
          <span className="modal-title">Run Security Assessment</span>
          <button className="slideover-close" onClick={onClose}>✕</button>
        </div>
        <div className="modal-body">
          <div className="form-group">
            <label className="form-label">Account</label>
            <select className="form-select" value={accountId} onChange={e => setAccountId(e.target.value)}>
              <option value="">All accounts</option>
              {accounts.map(a => (
                <option key={a.account_id} value={a.account_id}>
                  {a.account_name || a.account_id}
                </option>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">Min severity</label>
            <select className="form-select" value={minSev} onChange={e => setMinSev(e.target.value)}>
              <option value="">— Any severity —</option>
              {['CRITICAL','HIGH','MEDIUM','LOW'].map(s => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>
          {err && <div style={{ fontSize:'11px', color:'var(--red-hi)', marginTop:'6px' }}>⚠ {err}</div>}
        </div>
        <div className="modal-footer">
          <button className="btn secondary sm" onClick={onClose}>Cancel</button>
          <button className="btn primary sm" disabled={running} onClick={submit}>
            {running ? <><span className="spinner-ring" style={{ width:12, height:12, borderWidth:2 }} /> Running…</> : 'Run'}
          </button>
        </div>
      </div>
    </>
  )
}

// ─── Finding row ──────────────────────────────────────────────────────────────

function FindingRow({ finding, expanded, onToggle }) {
  const sev  = sevClass(finding.severity)
  const name = finding.entity_name || (finding.entity_arn || '').split('/').pop()
  const arn  = finding.entity_arn || ''

  return (
    <div className="finding-card">
      <div className="finding-header" onClick={onToggle}>
        <div className={`finding-sev-bar ${sev}`} />
        <div style={{ flex:1, overflow:'hidden' }}>
          <div className="finding-title">{finding.message || finding.category}</div>
          <div className="finding-meta">
            <span className="type-tag" style={{ marginRight:'6px' }}>{finding.entity_type || 'principal'}</span>
            <span title={arn}>{name}</span>
            {finding.category && (
              <span style={{ marginLeft:'8px', color:'var(--text-faint)' }}>{finding.category}</span>
            )}
          </div>
        </div>
        <span className={`sev-badge ${sev}`}>{finding.severity}</span>
        <span style={{ color:'var(--text-faint)', fontSize:'10px', marginLeft:'8px' }}>{expanded ? '▲' : '▼'}</span>
      </div>
      {expanded && (
        <div style={{ padding:'10px 16px 14px 31px', borderTop:'1px solid var(--border)', background:'var(--bg2)' }}>
          {arn && (
            <div style={{ marginBottom:'8px' }}>
              <div style={{ fontSize:'9px', letterSpacing:'0.08em', textTransform:'uppercase', color:'var(--text-faint)', marginBottom:'3px' }}>ARN</div>
              <div style={{ fontFamily:'IBM Plex Mono', fontSize:'11px', color:'var(--cyan-hi)', wordBreak:'break-all' }}>{arn}</div>
            </div>
          )}
          {finding.principal_detail && (
            <div style={{ marginBottom:'8px' }}>
              <div style={{ fontSize:'9px', letterSpacing:'0.08em', textTransform:'uppercase', color:'var(--text-faint)', marginBottom:'3px' }}>Principal</div>
              <div style={{ fontSize:'11px', color:'var(--text)' }}>{finding.principal_detail}</div>
            </div>
          )}
          {finding.condition && (
            <div style={{ marginBottom:'8px' }}>
              <div style={{ fontSize:'9px', letterSpacing:'0.08em', textTransform:'uppercase', color:'var(--text-faint)', marginBottom:'3px' }}>Condition</div>
              <div style={{ fontFamily:'IBM Plex Mono', fontSize:'11px', color:'var(--text)' }}>{finding.condition}</div>
            </div>
          )}
          {finding.perm_risk && (
            <div style={{ marginBottom:'8px' }}>
              <div style={{ fontSize:'9px', letterSpacing:'0.08em', textTransform:'uppercase', color:'var(--text-faint)', marginBottom:'3px' }}>Permission Risk</div>
              <div style={{ fontSize:'11px', color:'var(--amber-hi)' }}>{finding.perm_risk}</div>
            </div>
          )}
          {finding.created_at && (
            <div style={{ fontSize:'10px', color:'var(--text-faint)', marginTop:'6px' }}>
              Detected: {new Date(finding.created_at).toLocaleString()}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function AssessmentPage() {
  const { findings, setFindings, accounts } = useApp()

  const [running,    setRunning]    = useState(false)
  const [showModal,  setShowModal]  = useState(false)
  const [lastRun,    setLastRun]    = useState(null)
  const [loadErr,    setLoadErr]    = useState(null)
  const [catFilter,  setCatFilter]  = useState('All')
  const [sevFilter,  setSevFilter]  = useState('All')
  const [search,     setSearch]     = useState('')
  const [expanded,   setExpanded]   = useState(null)

  const PAGE_SIZE = 50

  // Load persisted findings on mount
  useEffect(() => {
    if (findings !== null) return
    api.securityFindings()
      .then(raw => setFindings(Array.isArray(raw) ? raw : []))
      .catch(e  => setLoadErr(e.message))
  }, [])

  async function runAssessment(body = {}) {
    setRunning(true); setLoadErr(null)
    try {
      const result = await api.runSecurityFindings(body)
      const list = result?.findings ?? (Array.isArray(result) ? result : [])
      setFindings(list)
      setLastRun(new Date().toLocaleTimeString())
    } catch(e) {
      setLoadErr(e.message)
      throw e
    } finally {
      setRunning(false)
    }
  }

  const allFindings  = findings || []
  const critCount    = allFindings.filter(f => f.severity === 'CRITICAL' && !f.suppressed).length

  // Dynamic categories from actual data
  const categories = useMemo(() => {
    const cats = [...new Set(allFindings.map(f => f.category).filter(Boolean))]
    return ['All', ...cats.sort()]
  }, [allFindings])

  const shown = useMemo(() => {
    let arr = allFindings.filter(f => !f.suppressed)
    if (catFilter !== 'All') arr = arr.filter(f => f.category === catFilter)
    if (sevFilter !== 'All') arr = arr.filter(f => f.severity === sevFilter)
    if (search.trim()) {
      const q = search.toLowerCase()
      arr = arr.filter(f =>
        (f.message     || '').toLowerCase().includes(q) ||
        (f.entity_arn  || '').toLowerCase().includes(q) ||
        (f.entity_name || '').toLowerCase().includes(q)
      )
    }
    return arr.sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9))
  }, [allFindings, catFilter, sevFilter, search])

  const { page, totalPages, pageItems, goTo } = usePagination(shown, PAGE_SIZE)

  return (
    <div className="page-content" style={{ display:'flex', flexDirection:'column', overflow:'hidden' }}>
      {showModal && (
        <RunModal
          accounts={accounts || []}
          onRun={runAssessment}
          onClose={() => setShowModal(false)}
        />
      )}

      <div className="page-header">
        <div>
          <div className="page-title">Assessment</div>
          <div className="page-subtitle">
            {findings === null
              ? 'Loading persisted findings…'
              : `${allFindings.filter(f => !f.suppressed).length} findings · ${critCount} critical`
            }
            {lastRun && <span style={{ marginLeft:'8px', color:'var(--text-faint)' }}>Last run: {lastRun}</span>}
          </div>
        </div>
        <div style={{ marginLeft:'auto', display:'flex', alignItems:'center', gap:'8px' }}>
          <button className="btn primary" disabled={running} onClick={() => setShowModal(true)}>
            {running
              ? <><span className="spinner-ring" style={{ width:12, height:12, borderWidth:2 }} /> Running…</>
              : '▶ Run Assessment'
            }
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
        <div style={{ display:'flex', gap:'4px', flexWrap:'wrap' }}>
          {categories.map(c => (
            <button key={c} className={`filter-chip ${catFilter === c ? 'active' : ''}`}
              onClick={() => setCatFilter(c)}>
              {c === 'All' ? 'All' : c.replace(/_/g, ' ')}
            </button>
          ))}
        </div>
        <div style={{ display:'flex', gap:'4px', marginLeft:'auto' }}>
          {['All','CRITICAL','HIGH','MEDIUM','LOW'].map(s => (
            <button key={s} className={`filter-chip ${sevFilter === s ? 'active' : ''}`}
              onClick={() => setSevFilter(s)}>{s}</button>
          ))}
        </div>
        <input className="filter-search" style={{ marginLeft:'12px', width:'180px' }}
          placeholder="Search…" value={search} onChange={e => setSearch(e.target.value)} />
      </div>

      {/* Results */}
      <div style={{ flex:1, overflowY:'auto' }}>
        {findings === null && !loadErr ? (
          <div className="empty-state">
            <div className="spinner-ring" style={{ width:24, height:24, borderWidth:3, margin:'0 auto 12px' }} />
            <div className="empty-state-title">Loading findings…</div>
          </div>
        ) : shown.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">🛡️</div>
            <div className="empty-state-title">
              {allFindings.length === 0 ? 'No findings stored' : 'No findings match filters'}
            </div>
            <div className="empty-state-hint">
              {allFindings.length === 0
                ? 'Run worst assess in the CLI, then click ▶ Run Assessment to refresh.'
                : 'Adjust the severity or category filters above.'
              }
            </div>
          </div>
        ) : (
          pageItems.map((f, i) => (
            <FindingRow
              key={f.id ?? i}
              finding={f}
              expanded={expanded === (f.id ?? i)}
              onToggle={() => setExpanded(expanded === (f.id ?? i) ? null : (f.id ?? i))}
            />
          ))
        )}
      </div>
      <Paginator page={page} totalPages={totalPages} total={shown.length} pageSize={PAGE_SIZE} goTo={goTo} label="findings" />
    </div>
  )
}
