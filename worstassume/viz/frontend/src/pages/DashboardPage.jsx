import { useApp } from '../context/AppContext'

/* ─── Account Health Row ─────────────────────────────── */
function AccountHealthRow({ account, allFindings }) {
  const af   = allFindings.filter(f => f.account_id === account.account_id && !f.suppressed)
  const crit = af.filter(f => f.severity === 'CRITICAL').length
  const high = af.filter(f => f.severity === 'HIGH').length
  const med  = af.filter(f => f.severity === 'MEDIUM').length
  const low  = af.filter(f => f.severity === 'LOW').length
  const total = crit + high + med + low

  const pct = (n) => total ? Math.round((n / total) * 100) : 0

  const entities = (account.principals ?? 0) + (account.resources ?? 0)

  let statusBadge
  if (total === 0) {
    statusBadge = <span style={{ fontSize: '11px', color: 'var(--green-hi)', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
      <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--green-hi)', display: 'inline-block' }} />
      Clean
    </span>
  } else if (crit > 0) {
    statusBadge = <span style={{ fontSize: '11px', padding: '1px 7px', borderRadius: '2px', background: 'rgba(192,48,48,.12)', color: 'var(--red-hi)', border: '1px solid rgba(192,48,48,.25)', fontWeight: 600 }}>
      {crit} CRIT
    </span>
  } else if (high > 0) {
    statusBadge = <span style={{ fontSize: '11px', padding: '1px 7px', borderRadius: '2px', background: 'rgba(217,124,20,.12)', color: 'var(--amber-hi)', border: '1px solid rgba(217,124,20,.25)', fontWeight: 600 }}>
      {high} HIGH
    </span>
  } else {
    statusBadge = <span style={{ fontSize: '11px', padding: '1px 7px', borderRadius: '2px', background: 'rgba(184,160,32,.1)', color: 'var(--yellow-hi)', border: '1px solid rgba(184,160,32,.2)', fontWeight: 600 }}>
      {med} MED
    </span>
  }

  return (
    <tr>
      <td>
        <div style={{ fontWeight: 500, fontSize: '13px', color: 'var(--white)' }}>
          {account.account_name || account.account_id}
        </div>
        <div className="table-arn"><em>{account.account_id}</em></div>
      </td>
      <td style={{ color: 'var(--text)' }}>{entities || '—'}</td>
      <td>
        {total === 0 ? (
          <div className="health-bar-track" style={{ width: '120px', height: '4px' }}>
            <div style={{ width: '100%', borderRadius: '2px', background: 'var(--green)', opacity: 0.4 }} />
          </div>
        ) : (
          <div className="health-bar-track" style={{ width: '120px', height: '4px' }}>
            <div className="health-seg" style={{ width: `${pct(crit)}%`, background: 'var(--red)' }} />
            <div className="health-seg" style={{ width: `${pct(high)}%`, background: 'var(--amber)' }} />
            <div className="health-seg" style={{ width: `${pct(med)}%`,  background: 'var(--yellow)' }} />
            <div className="health-seg" style={{ flex: 1, background: 'var(--bg3)' }} />
          </div>
        )}
      </td>
      <td>{statusBadge}</td>
    </tr>
  )
}

/* ─── Terminal Info Block ────────────────────────────── */
function TerminalBlock({ accounts, allFindings }) {
  const acctCount   = accounts.length
  const critCount   = allFindings.filter(f => !f.suppressed && f.severity === 'CRITICAL').length
  const highCount   = allFindings.filter(f => !f.suppressed && f.severity === 'HIGH').length

  const lastEnum = accounts
    .map(a => a.last_enum_at || a.last_enumerated_at)
    .filter(Boolean)
    .sort()
    .pop()

  const line = (key, val, cls = '') => (
    <div style={{ display: 'flex', gap: '8px', fontFamily: 'IBM Plex Mono', fontSize: '11px', lineHeight: 1.8 }}>
      <span style={{ color: 'var(--text-dim)', minWidth: '100px' }}>{key}</span>
      <span style={{ color: cls === 'err' ? 'var(--red-hi)' : cls === 'ok' ? 'var(--green-hi)' : cls === 'acc' ? 'var(--amber)' : 'var(--text)' }}>{val}</span>
    </div>
  )

  return (
    <div style={{
      background: 'var(--bg1)', border: '1px solid var(--border)',
      borderRadius: '6px', padding: '16px', fontFamily: 'IBM Plex Mono',
    }}>
      {line('accounts', acctCount, 'acc')}
      {lastEnum && line('last_enum', new Date(lastEnum).toLocaleString())}
      {line('db_path', '~/.worstassume/db.sqlite')}
      {line('engine', 'BFS + rule-based chains')}
      <div style={{ display: 'flex', gap: '8px', fontFamily: 'IBM Plex Mono', fontSize: '11px', lineHeight: 1.8 }}>
        <span style={{ color: 'var(--text-dim)', minWidth: '100px' }}>findings</span>
        <span>
          {allFindings.length === 0
            ? <span style={{ color: 'var(--text-faint)' }}>no assessment run</span>
            : <>
                {critCount > 0 && <span style={{ color: 'var(--red-hi)', marginRight: '8px' }}>{critCount} CRITICAL</span>}
                {highCount > 0 && <span style={{ color: 'var(--amber-hi)' }}>· {highCount} HIGH</span>}
              </>
          }
        </span>
      </div>
      <div style={{ marginTop: '10px', display: 'flex', gap: '6px', alignItems: 'center', fontFamily: 'IBM Plex Mono', fontSize: '11px' }}>
        <span style={{ color: 'var(--green-hi)' }}>✓</span>
        <span style={{ color: 'var(--text-dim)' }}>analysis complete</span>
        <span style={{ display: 'inline-block', width: '7px', height: '13px', background: 'var(--amber)', opacity: 0.7, animation: 'blink 1s step-end infinite' }} />
      </div>
    </div>
  )
}

/* ─── Main Page ──────────────────────────────────────── */
export default function DashboardPage() {
  const { entities, accounts, findings, stats } = useApp()

  const allEntities = entities || []
  const allAccounts = accounts || []
  const allFindings = findings || []

  const criticalCount = allFindings.filter(f => f.severity === 'CRITICAL' && !f.suppressed).length
  const highCount     = allFindings.filter(f => f.severity === 'HIGH'     && !f.suppressed).length
  const analysisRan   = findings !== null

  const accountCount   = stats?.accounts   ?? allAccounts.length
  const principalCount = stats?.principals ?? allEntities.filter(e => ['role','user','group'].includes(e.principal_type || e.node_type)).length
  const resourceCount  = stats?.resources  ?? allEntities.filter(e => e.node_type === 'resource').length
  const policyCount    = stats?.policies   ?? allEntities.filter(e => e.node_type === 'policy').length

  // Derived subtitles for metric cards
  const roleCount = allEntities.filter(e => e.principal_type === 'role').length
  const userCount = allEntities.filter(e => e.principal_type === 'user').length

  return (
    <div className="page-content" style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

      {/* Page header — no Run Assessment button */}
      <div className="page-header">
        <div>
          <div className="page-title">Dashboard</div>
          <div className="page-subtitle">Threat surface summary</div>
        </div>
      </div>

      <div style={{ flex: 1, overflowY: 'auto', padding: '20px' }}>

        {/* ── Metrics grid ── */}
        <div className="metrics-grid" style={{ marginBottom: '20px' }}>
          {[
            { label: 'Accounts',         variant: 'info',     value: accountCount,   sub: `${accountCount} AWS account${accountCount !== 1 ? 's' : ''}` },
            { label: 'Principals',       variant: 'info',     value: principalCount, sub: roleCount || userCount ? `${roleCount} roles · ${userCount} users` : 'users, roles & groups' },
            { label: 'Resources',        variant: 'info',     value: resourceCount,  sub: 'Lambda · EC2 · S3' },
            { label: 'Policies',         variant: 'info',     value: policyCount,    sub: 'managed & inline' },
            {
              label: 'Critical Findings',
              variant: analysisRan ? (criticalCount > 0 ? 'critical' : 'ok') : 'info',
              value: analysisRan ? criticalCount : '?',
              sub: analysisRan ? 'privilege escalations' : 'run assessment',
            },
            {
              label: 'High Findings',
              variant: analysisRan ? (highCount > 0 ? 'warn' : 'ok') : 'info',
              value: analysisRan ? highCount : '?',
              sub: analysisRan ? 'severity findings' : 'run assessment',
            },
          ].map(({ label, variant, value, sub }) => (
            <div key={label} className={`metric-card ${variant}`}>
              <div className="metric-label">{label}</div>
              <div className={`metric-value${variant === 'critical' ? ' critical' : variant === 'warn' ? ' warn' : variant === 'ok' ? ' ok' : ''}`}>
                {value ?? '—'}
              </div>
              {sub && <div className="metric-sub">{sub}</div>}
            </div>
          ))}
        </div>

        {/* ── Two-column: terminal left, account health right ── */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.6fr', gap: '16px' }}>

          <TerminalBlock
            accounts={allAccounts}
            allFindings={allFindings}
          />

          {/* Account Health */}
          <div className="section">
            <div className="section-header">
              <span className="section-title" style={{ margin: 0 }}>Account Health</span>
              <span className="section-count">{allAccounts.length} accounts</span>
            </div>
            {allAccounts.length === 0 ? (
              <div className="empty-state" style={{ padding: '32px' }}>
                <div className="empty-state-icon">🔍</div>
                <div className="empty-state-title">No accounts loaded</div>
                <div className="empty-state-sub">Run <code>worst enum</code> to populate</div>
              </div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Account</th>
                    <th>Entities</th>
                    <th>Severity Distribution</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {allAccounts.map((a, i) => (
                    <AccountHealthRow key={i} account={a} allFindings={allFindings} />
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

      </div>
    </div>
  )
}
