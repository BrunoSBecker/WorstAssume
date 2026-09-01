import { createContext, useContext, useMemo, useRef, useState, useEffect, useCallback } from 'react'
import { api } from '../api'

const AppContext = createContext(null)

export function AppProvider({ children }) {
  // The graph canvas imperative handle (replaces cyRef)
  const graphRef  = useRef(null)
  const abortRef  = useRef(false)
  // De-dupes concurrent lazy full-entity loads (report export / graph enrichment)
  const entitiesPromiseRef = useRef(null)

  // ── The engagement canvas ────────────────────────────────────────────
  //
  // One working graph the analyst builds up across the whole engagement, fed
  // from the Threat Model page and the Entities page. Pages are conditionally
  // rendered (App.jsx), so every page component unmounts on navigation and
  // takes its cytoscape instance with it — the canvas has to live above them.
  //
  // The snapshot is a REF, deliberately. It is rewritten on every node drag,
  // and this provider's value is consumed by most of the app; putting it in
  // useState would re-render everything on every pointer move. State here is
  // limited to the low-frequency metadata the header renders.
  const canvasRef = useRef({ nodes: [], edges: [], expanded: [], removed: [] })
  const canvasPendingRef = useRef([])
  const [canvasMeta, setCanvasMeta] = useState({
    savedId: null, savedName: '', nodes: 0, edges: 0,
  })
  // Bumped when another page queues entities, so a mounted canvas picks them
  // up. Never derived from the snapshot itself — feeding a fresh snapshot
  // object back as a prop would wipe and rebuild the canvas on every drag.
  const [canvasVersion, setCanvasVersion] = useState(0)

  const canvasWrite = useCallback((snapshot) => {
    canvasRef.current = snapshot
    setCanvasMeta(m => (m.nodes === snapshot.nodes.length && m.edges === snapshot.edges.length
      ? m
      : { ...m, nodes: snapshot.nodes.length, edges: snapshot.edges.length }))
  }, [])

  /** Queue entities onto the canvas from anywhere in the app. */
  const addToCanvas = useCallback((entities) => {
    const list = (Array.isArray(entities) ? entities : [entities]).filter(e => e?.arn)
    if (!list.length) return 0
    const known = new Set([
      ...canvasRef.current.nodes.map(n => n.arn),
      ...canvasPendingRef.current.map(n => n.arn),
    ])
    const fresh = list.filter(e => !known.has(e.arn))
    if (!fresh.length) return 0
    canvasPendingRef.current = [...canvasPendingRef.current, ...fresh]
    setCanvasVersion(v => v + 1)
    return fresh.length
  }, [])

  const takeCanvasPending = useCallback(() => {
    const queued = canvasPendingRef.current
    canvasPendingRef.current = []
    return queued
  }, [])

  const resetCanvas = useCallback(() => {
    canvasRef.current = { nodes: [], edges: [], expanded: [], removed: [] }
    canvasPendingRef.current = []
    setCanvasMeta({ savedId: null, savedName: '', nodes: 0, edges: 0 })
    setCanvasVersion(v => v + 1)
  }, [])

  const canvas = useMemo(() => ({
    ref: canvasRef, meta: canvasMeta, setMeta: setCanvasMeta,
    version: canvasVersion, write: canvasWrite,
    add: addToCanvas, takePending: takeCanvasPending, reset: resetCanvas,
  }), [canvasMeta, canvasVersion, canvasWrite, addToCanvas, takeCanvasPending, resetCanvas])

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

  // ── Cross-page "run PrivEsc toward this identity" (Threat Model → PrivEsc) ──
  const [privEscObjective, setPrivEscObjective] = useState(null)

  // Both are memoized: they go into the provider value, and a fresh identity
  // every render would defeat its useMemo.
  const showToast = useCallback((msg, ms = 4000) => {
    setToastMsg(msg)
    setTimeout(() => setToastMsg(null), ms)
  }, [])

  const refreshCount = useCallback(() => {
    setNodeCount(graphRef.current?.getNodeCount() ?? 0)
  }, [])

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

  // ── Jump to PrivEsc with a pre-filled objective (a Threat Model node) ──
  // The node becomes the *target* to escalate toward; the user then picks
  // their own identity as the attacker on the PrivEsc page. The objective
  // grammar distinguishes principal:<arn> from resource:<arn>, so pick the
  // right one — the Threat Model graph holds both kinds of node.
  const startPrivEsc = useCallback((objectiveArn) => {
    if (!objectiveArn) return
    const bare = objectiveArn.replace(/^(principal|resource):/, '')
    const isPrincipal = /:iam::?[^:]*:(role|user|group)\//.test(bare)
      || bare.includes(':assumed-role/')
    setPrivEscObjective(`${isPrincipal ? 'principal' : 'resource'}:${bare}`)
    setPage('privesc')
  }, [])

  const clearPrivEscObjective = useCallback(() => setPrivEscObjective(null), [])

  const value = useMemo(() => ({
      canvas,
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
      privEscObjective, startPrivEsc, clearPrivEscObjective,
  }), [
    canvas, entities, ensureEntities, accounts, findings, chains, stats, dataLoading,
    identity, setIdentity, target, setTarget,
    pathActive, pathResult, paths, privescRunning, pathFinding,
    selected, nodeCount, refreshCount, toastMsg, showToast, page,
    cancelPrivesc, graphFocusIds, graphFocusNodeId, graphFocusOpen,
    focusNode, closeFocusGraph, privEscObjective, startPrivEsc, clearPrivEscObjective,
  ])

  return (
    <AppContext.Provider value={value}>
      {children}
    </AppContext.Provider>
  )
}

export function useApp() {
  const ctx = useContext(AppContext)
  if (!ctx) throw new Error('useApp must be used within AppProvider')
  return ctx
}
