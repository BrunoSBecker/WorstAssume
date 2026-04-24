import { AppProvider, useApp } from './context/AppContext'
import NavRail from './components/NavRail'
import DashboardPage  from './pages/DashboardPage'
import EntitiesPage   from './pages/EntitiesPage'
import AssessmentPage from './pages/AssessmentPage'
import PrivEscPage    from './pages/PrivEscPage'
import ReportModal    from './components/ReportModal'
import { useState } from 'react'

// Logo mark SVG
function LogoMark() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
      <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z"
        stroke="var(--amber)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
      <path d="M9 12l2 2 4-4" stroke="var(--amber)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  )
}

const PAGE_LABELS = {
  dashboard:  'Dashboard',
  entities:   'Entities',
  assessment: 'Assessment',
  privesc:    'PrivEsc',
}

function AppShell() {
  const { page, setPage, findings, dataLoading, toastMsg } = useApp()
  const [showReport, setShowReport] = useState(false)

  const allFindings  = findings || []
  const critCount    = allFindings.filter(f => f.severity === 'CRITICAL' && !f.suppressed).length
  const findingCount = allFindings.filter(f => !f.suppressed).length

  if (dataLoading) {
    return (
      <div className="full-loading">
        <div className="spinner-ring" style={{ width: 32, height: 32, borderWidth: 3 }} />
        <div className="full-loading-text">LOADING AWS ENVIRONMENT DATA…</div>
      </div>
    )
  }

  return (
    <div className="app">
      {toastMsg && <div className="toast">{toastMsg}</div>}

      {/* Topbar — spans full width (grid col 1/-1) */}
      <div className="app-topbar">
        <div className="topbar-logo">
          <LogoMark />
        </div>
        <div className="topbar-breadcrumb">
          WORST<span>ASSUME</span> // <span>{PAGE_LABELS[page] || page}</span>
        </div>
        <div className="topbar-spacer" />
        <button className="btn secondary sm"
          style={{ marginRight:16, fontSize:11 }}
          onClick={() => setShowReport(true)}>
          ↓ Export
        </button>
      </div>

      {showReport && <ReportModal onClose={() => setShowReport(false)} />}

      {/* Nav rail */}
      <NavRail page={page} setPage={setPage} critCount={critCount} findingCount={findingCount} />

      {/* Page content area — fills remaining grid cell */}
      <div style={{ display: 'flex', minWidth: 0, overflow: 'hidden', flexDirection: 'column' }}>
        {page === 'dashboard'  && <DashboardPage />}
        {page === 'entities'   && <EntitiesPage />}
        {page === 'assessment' && <AssessmentPage />}
        {page === 'privesc'    && <PrivEscPage />}
      </div>
    </div>
  )
}

export default function App() {
  return (
    <AppProvider>
      <AppShell />
    </AppProvider>
  )
}
