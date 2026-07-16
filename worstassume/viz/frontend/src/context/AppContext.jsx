import { createContext, useContext, useRef, useState, useEffect, useCallback } from 'react'
import { api } from '../api'

const AppContext = createContext(null)

export function AppProvider({ children }) {
  // The graph canvas imperative handle (replaces cyRef)
  const graphRef  = useRef(null)
  const abortRef  = useRef(false)
  // De-dupes concurrent lazy full-entity loads (report export / graph enrichment)
  const entitiesPromiseRef = useRef(null)

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

  // ── Cross-page "focus in graph" (Assessment → Graph linkage) ─────────
  const [graphFocusIds,    setGraphFocusIds]    = useState([])
  const [graphFocusNodeId, setGraphFocusNodeId] = useState(null)
  const [graphFocusOpen,   setGraphFocusOpen]   = useState(false)

  function showToast(msg, ms = 4000) {
    setToastMsg(msg)
    setTimeout(() => setToastMsg(null), ms)
  }

  function refreshCount() {
    setNodeCount(graphRef.current?.getNodeCount() ?? 0)
  }

  // ── Load initial data ────────────────────────────────────────────────
  // NOTE: the full entity catalogue is NO LONGER loaded here — it is huge for
  // large orgs and blocked the whole app. The Entities page fetches paginated,
  // server-filtered data directly. Consumers that still need the full array
  // (report export, graph enrichment) call ensureEntities() lazily.
  useEffect(() => {
    const loadData = async () => {
      try {
        const [accts, findingsData] = await Promise.all([
          api.accounts(),
          api.securityFindings(),
        ])
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

  // ── Lazy full-entity loader (report export / graph enrichment) ────────
  const ensureEntities = useCallback(async () => {
    if (entities) return entities
    if (entitiesPromiseRef.current) return entitiesPromiseRef.current
    const p = (async () => {
      const raw = await api.entities()  // no params → legacy full grouped dump
      const flat = [
        ...(raw?.principals || []),
        ...(raw?.policies   || []),
        ...(raw?.resources  || []),
        ...(raw?.accounts   || []),
      ]
      setEntities(flat)
      return flat
    })()
    entitiesPromiseRef.current = p
    try {
      return await p
    } finally {
      entitiesPromiseRef.current = null
    }
  }, [entities])

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

  // ── Focus a node in the global graph viewer from any page ────────────
  const focusNode = useCallback((nodeId) => {
    if (!nodeId) return
    setGraphFocusIds(prev => prev.includes(nodeId) ? prev : [...prev, nodeId])
    setGraphFocusNodeId(nodeId)
    setGraphFocusOpen(true)
  }, [])

  const closeFocusGraph = useCallback(() => {
    setGraphFocusOpen(false)
    setGraphFocusIds([])
    setGraphFocusNodeId(null)
  }, [])

  return (
    <AppContext.Provider value={{
      graphRef, abortRef,
      entities, ensureEntities, accounts, findings, chains, stats, dataLoading,
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
      graphFocusIds, graphFocusNodeId, graphFocusOpen,
      setGraphFocusIds, focusNode, closeFocusGraph,
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
