/* Icon-only nav rail — 56px wide, amber active indicator */

// SVG icons
function IconDashboard() {
  return (
    <svg width="18" height="18" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4">
      <rect x="1" y="1" width="6" height="6" rx="1"/>
      <rect x="9" y="1" width="6" height="6" rx="1"/>
      <rect x="1" y="9" width="6" height="6" rx="1"/>
      <rect x="9" y="9" width="6" height="6" rx="1"/>
    </svg>
  )
}
function IconEntities() {
  return (
    <svg width="18" height="18" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4">
      <circle cx="8" cy="5.5" r="3"/>
      <path d="M2 14c0-3.3 2.7-6 6-6s6 2.7 6 6" strokeLinecap="round"/>
    </svg>
  )
}
function IconAssessment() {
  return (
    <svg width="18" height="18" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4">
      <path d="M3.5 1.5h9a1 1 0 011 1v11a1 1 0 01-1 1h-9a1 1 0 01-1-1v-11a1 1 0 011-1z"/>
      <path d="M5 5.5h6M5 8h6M5 10.5h4" strokeLinecap="round"/>
    </svg>
  )
}
function IconPrivEsc() {
  return (
    <svg width="18" height="18" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4">
      <path d="M2 14L8 2L14 14" strokeLinecap="round" strokeLinejoin="round"/>
      <path d="M4.5 10h7" strokeLinecap="round"/>
    </svg>
  )
}

const ITEMS = [
  { id: 'dashboard',  Icon: IconDashboard,  label: 'Dashboard'  },
  { id: 'entities',   Icon: IconEntities,   label: 'Entities'   },
  { id: 'assessment', Icon: IconAssessment, label: 'Assessment' },
  { id: 'privesc',    Icon: IconPrivEsc,    label: 'PrivEsc'    },
]

export default function NavRail({ page, setPage, critCount = 0, findingCount = 0 }) {
  return (
    <nav className="nav-rail">
      {ITEMS.map(({ id, Icon, label }) => (
        <button
          key={id}
          className={`nav-item ${page === id ? 'active' : ''}`}
          onClick={() => setPage(id)}
          title={label}
          aria-label={label}
        >
          <Icon />
          {id === 'assessment' && findingCount > 0 && (
            <span className="nav-badge">{Math.min(findingCount, 99)}</span>
          )}
        </button>
      ))}

      <div className="nav-divider" style={{ marginTop: 'auto' }} />
      {/* Status indicator */}
      {critCount > 0 && (
        <div
          style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--red)', boxShadow: '0 0 6px var(--red)', margin: '4px auto' }}
          title={`${critCount} critical findings`}
        />
      )}
    </nav>
  )
}
