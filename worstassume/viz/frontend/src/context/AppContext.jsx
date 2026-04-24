import { createContext, useContext, useRef, useState, useEffect, useCallback } from 'react'
import { api } from '../api'

const AppContext = createContext(null)

export function AppProvider({ children }) {
  // The graph canvas imperative handle (replaces cyRef)
  const graphRef  = useRef(null)
  const abortRef  = useRef(false)

  // ── Server data ──────────────────────────────────────────────────────
  const [entities,    setEntities]    = useState(null)
  const [accounts,    setAccounts]    = useState([])
  const [findings,    setFindings]    = useState(null)  // null = not yet fetched
  const [chains,      setChains]      = useState(null)  // null = not yet fetched
  const [stats,       setStats]       = useState(null)
  const [dataLoading, setDataLoading] = useState(true)

  // ── Graph / identity state ───────────────────────────────────────────
  const [identity,        setIdentityState]  = useState(null)
  const [target,          setTargetState]    = useState(null)
  const [pathActive,      setPathActive]     = useState(false)
  const [pathResult,      setPathResult]     = useState(null)
  const [paths,           setPaths]          = useState([])
  const [privescRunning,  setPrivescRunning] = useState(false)
  const [pathFinding,     setPathFinding]    = useState(false)
  const [selected,        setSelected]       = useState(null)
  const [nodeCount,       setNodeCount]      = useState(0)
  const [toastMsg,        setToastMsg]       = useState(null)

  // ── Active page ──────────────────────────────────────────────────────
  const [page, setPage] = useState('dashboard')

  function showToast(msg, ms = 4000) {
    setToastMsg(msg)
    setTimeout(() => setToastMsg(null), ms)
  }

  function refreshCount() {
    setNodeCount(graphRef.current?.getNodeCount() ?? 0)
  }

  // ── Load initial data ────────────────────────────────────────────────
  useEffect(() => {
    const loadData = async () => {
      try {
        // Load everything in parallel — findings needed by Dashboard & Accounts on first render
        const [entsRaw, accts, findingsData] = await Promise.all([
          api.entities(),
          api.accounts(),
          api.securityFindings(),
        ])
        const flat = [
          ...(entsRaw?.principals || []),
          ...(entsRaw?.policies   || []),
          ...(entsRaw?.resources  || []),
          ...(entsRaw?.accounts   || []),
        ]
        setEntities(flat)
        setAccounts(Array.isArray(accts) ? accts : (accts?.accounts || []))
        setFindings(Array.isArray(findingsData) ? findingsData : (findingsData?.findings || []))
        // Stats is fast (DB counts only)
        api.stats().then(setStats).catch(() => {})
      } catch (e) {
        console.error('Data load failed:', e)
      } finally {
        setDataLoading(false)
      }
    }
    loadData()
  }, [])

  // ── Identity / target setters ────────────────────────────────────────
  const setIdentity = useCallback((nodeData) => {
    setIdentityState(nodeData)
    graphRef.current?.setIdentityNode(nodeData?.id ?? null)
    setPathActive(false)
    setPathResult(null)
    if (nodeData) showToast(`👤 Identity set: ${nodeData.label}`)
  }, [])

  const setTarget = useCallback((nodeData) => {
    setTargetState(nodeData)
    graphRef.current?.setTargetNode(nodeData?.id ?? null)
    if (nodeData) showToast(`🎯 Target: ${nodeData.label}`)
  }, [])

  const cancelPrivesc = useCallback(() => {
    abortRef.current = true
  }, [])

  return (
    <AppContext.Provider value={{
      graphRef, abortRef,
      entities, accounts, findings, chains, stats, dataLoading,
      identity, setIdentity,
      target, setTarget,
      pathActive, setPathActive,
      pathResult, setPathResult,
      paths, setPaths,
      privescRunning, setPrivescRunning,
      pathFinding, setPathFinding,
      selected, setSelected,
      nodeCount, setNodeCount, refreshCount,
      toastMsg, showToast,
      page, setPage,
      setFindings, setChains, setStats,
      cancelPrivesc,
    }}>
      {children}
    </AppContext.Provider>
  )
}

export function useApp() {
  const ctx = useContext(AppContext)
  if (!ctx) throw new Error('useApp must be used within AppProvider')
  return ctx
}
