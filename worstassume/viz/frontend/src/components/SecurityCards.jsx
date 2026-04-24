import { useState } from 'react'

// Shared step renderer used by both FindingCard and PrivEsc path results
export function AttackSteps({ steps, maxShow = 30 }) {
  const [showAll, setShowAll] = useState(false)
  if (!steps?.length) return null
  const visible = showAll ? steps : steps.slice(0, maxShow)
  const hidden  = steps.length - visible.length
  return (
    <div className="attack-steps">
      {visible.map((s, i) => {
        const tgt = s.target_arn || s.target || ''
        return (
          <div key={i} className="attack-step">
            <div className="attack-step-num">{(s.step_index ?? i) + 1}</div>
            <div className="attack-step-body">
              <div className="attack-step-action">
                <span className="action-pill">{s.action || s.edge_type}</span>
                {tgt && (
                  <>
                    <span style={{ fontSize:'.6rem', color:'var(--text-faint)' }}>→</span>
                    <span className="action-target" title={tgt}>
                      {tgt.split('/').pop() || tgt.split(':').pop() || tgt}
                    </span>
                  </>
                )}
              </div>
              {s.explanation && <div className="attack-step-explain">{s.explanation}</div>}
            </div>
          </div>
        )
      })}
      {hidden > 0 && (
        <button className="btn secondary sm" style={{ marginTop:'6px', fontSize:'10px' }}
          onClick={() => setShowAll(true)}>
          ⊕ Show {hidden} more step{hidden !== 1 ? 's' : ''}
        </button>
      )}
    </div>
  )
}

export function FindingCard({ finding, onViewGraph }) {
  const [open, setOpen] = useState(false)
  const sev = (finding.severity || 'MEDIUM').toLowerCase()

  return (
    <div className={`attack-card ${sev}`}>
      <button className="attack-card-header" onClick={() => setOpen(o => !o)}>
        <span className={`sev-badge ${sev}`}>{finding.severity}</span>
        <span className="attack-card-title">{finding.description || finding.path || 'Finding'}</span>
        <span className="attack-card-meta ellipsis">
          {(finding.principal_arn || '').split('/').pop()}
        </span>
        <span className="attack-card-chevron">{open ? '▲' : '▼'}</span>
      </button>
      {open && (
        <div className="attack-card-body">
          <div className="detail-prop">
            <label>Principal</label>
            <div className="val mono">{finding.principal_arn}</div>
          </div>
          {finding.details && Object.keys(finding.details).length > 0 && (
            <div style={{ marginTop: '.5rem' }}>
              {Object.entries(finding.details).map(([k, v]) => (
                <div key={k} className="detail-prop">
                  <label>{k}</label>
                  <div className="val mono">{Array.isArray(v) ? v.join(', ') : String(v)}</div>
                </div>
              ))}
            </div>
          )}
          {onViewGraph && (
            <div style={{ display: 'flex', gap: '.4rem', marginTop: '.65rem' }}>
              <button className="btn sm primary" onClick={() => onViewGraph(finding)}>
                🕸️ View in graph
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export function ChainCard({ chain, onViewGraph }) {
  const [open, setOpen] = useState(false)
  const sev = (chain.severity || 'HIGH').toLowerCase()

  return (
    <div className={`attack-card ${sev}`}>
      <button className="attack-card-header" onClick={() => setOpen(o => !o)}>
        <span className={`sev-badge ${sev}`}>{chain.severity || 'HIGH'}</span>
        <span style={{
          fontSize: '.6rem', color: 'var(--steel)',
          background: 'var(--steel-muted)', border: '1px solid rgba(97,130,171,.2)',
          borderRadius: 3, padding: '.05rem .3rem', flexShrink: 0,
        }}>⛓ Chain</span>
        <span className="attack-card-title">{chain.title || chain.description}</span>
        <span className="attack-card-meta">{chain.steps?.length || 0} steps</span>
        <span className="attack-card-chevron">{open ? '▲' : '▼'}</span>
      </button>
      {open && (
        <div className="attack-card-body">
          {chain.relevance && <div className="attack-relevance">🎯 {chain.relevance}</div>}
          {chain.description && chain.description !== chain.title && (
            <div style={{ fontSize: '.72rem', color: 'var(--text-2)', marginBottom: '.6rem', lineHeight: 1.4 }}>
              {chain.description}
            </div>
          )}
          <AttackSteps steps={chain.steps} />
          {chain.outcome && (
            <div className={`attack-outcome ${sev}`}>🏴 {chain.outcome}</div>
          )}
          {onViewGraph && (
            <div style={{ display: 'flex', gap: '.4rem', marginTop: '.65rem' }}>
              <button className="btn sm amber" onClick={() => onViewGraph(chain)}>
                🕸️ View in graph
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
