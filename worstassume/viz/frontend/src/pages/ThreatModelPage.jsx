/**
 * ThreatModelPage — interactive inbound access mapping.
 *
 * Left:  a filterable asset catalogue (the same server-side filters the
 *        Entities page uses) plus the list of saved graphs. Resizable and
 *        collapsible.
 * Right: the ThreatGraph canvas.
 *
 * The workflow is iterative rather than a batch scan: seed an asset, expand it
 * to see everything that can reach it in one hop, expand one of *those*, prune
 * what is noise, and save the result. Any node can be handed to a PrivEsc scan.
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import ThreatGraph from '../components/ThreatGraph'
import Paginator from '../components/Paginator'
import ResizeHandle from '../components/ResizeHandle'
import { useResizableWidth } from '../components/useResizableWidth'
import { RiskBadge, TypeIcon, EntityArn } from '../components/EntityBits'
import { RISK_FILTERS, selectStyle } from '../components/entityStyles'
import { useApp } from '../context/AppContext'

const PAGE_SIZE = 25

// Policies are deliberately absent: "who can reach this policy" is not a
// question the engine can answer, so seeding one would only be a dead end.
const TYPE_TABS = [
  { label: 'Resources', value: 'resource' },
  { label: 'Principals', value: 'principal' },
]

const SERVICE_FILTERS = ['All', 'ec2', 's3', 'lambda', 'ecs', 'vpc']

// ─── Asset picker row ─────────────────────────────────────────────────────────

function AssetRow({ entity, active, onSeed, onAdd }) {
  const type = entity.node_type === 'resource'
    ? 'resource' : (entity.principal_type || 'role')
  return (
    <div
      onClick={() => onSeed(entity)}
      style={{
        display: 'flex', alignItems: 'center', gap: 10,
        padding: '8px 12px', borderBottom: '1px solid var(--border)', cursor: 'pointer',
        background: active ? 'rgba(217,124,20,.04)' : 'transparent',
        borderLeft: `2px solid ${active ? 'var(--amber)' : 'transparent'}`,
      }}
      onMouseEnter={e => { if (!active) e.currentTarget.style.background = 'var(--bg2)' }}
      onMouseLeave={e => { if (!active) e.currentTarget.style.background = 'transparent' }}
    >
      <TypeIcon type={type} size={24} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{
          fontSize: '12px', color: 'var(--white)', fontWeight: 500,
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>{entity.label}</div>
        <EntityArn arn={entity.arn} maxWidth="100%" />
      </div>
      <RiskBadge risk={entity.risk || 'CLEAN'} />
      <button
        className="btn secondary sm"
        title="Add as an additional root, keeping what is already on the canvas"
        onClick={ev => { ev.stopPropagation(); onAdd(entity) }}
      >+ Add</button>
    </div>
  )
}

// ─── Saved graphs ─────────────────────────────────────────────────────────────

function SavedGraphRow({ graph, active, onLoad, onDelete }) {
  return (
    <div
      onClick={() => onLoad(graph)}
      style={{
        padding: '8px 12px', borderBottom: '1px solid var(--border)', cursor: 'pointer',
        background: active ? 'rgba(217,124,20,.04)' : 'transparent',
        borderLeft: `2px solid ${active ? 'var(--amber)' : 'transparent'}`,
        display: 'flex', alignItems: 'center', gap: 8,
      }}
      onMouseEnter={e => { if (!active) e.currentTarget.style.background = 'var(--bg2)' }}
      onMouseLeave={e => { if (!active) e.currentTarget.style.background = 'transparent' }}
    >
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{
          fontSize: '12px', color: 'var(--white)',
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>{graph.name}</div>
        <div style={{ fontSize: '10px', color: 'var(--text-faint)', marginTop: 2 }}>
          {graph.node_count} nodes · {graph.edge_count} edges
          {graph.updated_at ? ` · ${graph.updated_at.slice(0, 16)}` : ''}
        </div>
      </div>
      <button className="btn danger sm" title="Delete this saved graph"
        onClick={ev => { ev.stopPropagation(); onDelete(graph) }}>✕</button>
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function ThreatModelPage() {
  const { startPrivEsc, showToast, canvas } = useApp()

  // Asset picker state — mirrors the Entities page's server-side filters.
  const [tab, setTab] = useState('resource')
  const [search, setSearch] = useState('')
  const [debounced, setDebounced] = useState('')
  const [riskFilter, setRiskFilter] = useState('All Risk')
  const [serviceFilter, setServiceFilter] = useState('All')
  const [accountFilter, setAccountFilter] = useState('')
  const [page, setPage] = useState(1)
  const [collapsed, setCollapsed] = useState(false)

  const pane = useResizableWidth({
    initial: 360, min: 280, max: () => window.innerWidth * 0.45, side: 'left',
  })

  // Canvas state — the graph itself lives in AppContext so it survives leaving
  // the page. Read the snapshot ONCE at mount: ThreatGraph's restore effect is
  // keyed on object identity, so handing it a fresh snapshot on every drag
  // would wipe and rebuild the canvas.
  const [roots, setRoots] = useState([])
  const [activeArn, setActiveArn] = useState(null)
  const [initialGraph, setInitialGraph] = useState(() => (
    canvas.ref.current.nodes.length ? canvas.ref.current : null))
  const [saving, setSaving] = useState(false)
  const canvasRef = canvas.ref
  const savedId = canvas.meta.savedId
  const savedName = canvas.meta.savedName
  const counts = { nodes: canvas.meta.nodes, edges: canvas.meta.edges }
  const setSavedId = useCallback(
    (id) => canvas.setMeta(m => ({ ...m, savedId: id })), [canvas])
  const setSavedName = useCallback(
    (name) => canvas.setMeta(m => ({ ...m, savedName: name })), [canvas])

  useEffect(() => {
    const t = setTimeout(() => setDebounced(search), 250)
    return () => clearTimeout(t)
  }, [search])

  const filterParams = useMemo(() => ({
    type: tab,
    q: debounced.trim(),
    risk: riskFilter === 'All Risk' ? '' : riskFilter.toUpperCase(),
    service: tab === 'resource' && serviceFilter !== 'All' ? serviceFilter : '',
    account_id: accountFilter,
  }), [tab, debounced, riskFilter, serviceFilter, accountFilter])

  useEffect(() => { setPage(1) }, [filterParams])

  const { data: meta } = useQuery({
    queryKey: ['entities-meta'],
    queryFn: () => api.entitiesMeta(),
    staleTime: 60_000,
  })

  const { data: pageData, isFetching } = useQuery({
    queryKey: ['tm-entities', filterParams.type, filterParams.q, filterParams.risk,
               filterParams.service, filterParams.account_id, page],
    queryFn: () => api.entities({ ...filterParams, page, page_size: PAGE_SIZE }),
  })

  const { data: savedGraphs = [], refetch: refetchSaved } = useQuery({
    queryKey: ['tm-graphs'],
    queryFn: () => api.threatModelGraphs(),
  })

  const items = pageData?.items || []
  const total = pageData?.total || 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const counts_ = meta?.counts || {}
  const tabCount = (v) => v === 'principal'
    ? (counts_.role || 0) + (counts_.user || 0) + (counts_.group || 0)
    : (counts_.resource || 0)

  // ── Canvas actions ─────────────────────────────────────────────────────────

  const onStateChange = useCallback((state) => canvas.write(state), [canvas])

  // Entities queued from another page (Entities, PrivEsc, Assessment) arrive
  // here as extra roots the next time the canvas is on screen.
  useEffect(() => {
    const queued = canvas.takePending()
    if (queued.length) setRoots(prev => [...prev, ...queued])
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [canvas.version])

  const toRoot = (e) => ({
    arn: e.arn, label: e.label, node_type: e.node_type,
    principal_type: e.principal_type, service: e.service,
    resource_type: e.resource_type, account_id: e.account_id, risk: e.risk,
  })

  const seed = useCallback((entity) => {
    // Replace the canvas with this asset as its sole root.
    setInitialGraph({ nodes: [], edges: [], expanded: [], removed: [] })
    canvas.reset()
    setActiveArn(entity.arn)
    setRoots([toRoot(entity)])
  }, [canvas])

  const addRoot = useCallback((entity) => {
    // Read the answer off current state rather than a flag set inside the
    // updater — React runs updaters during render, so the flag would still be
    // false by the time the toast fires.
    const already = roots.some(r => r.arn === entity.arn)
    if (!already) setRoots(prev => [...prev, toRoot(entity)])
    setActiveArn(entity.arn)
    // Always say something: silently doing nothing when the asset is already on
    // the canvas is indistinguishable from a broken button.
    showToast?.(already
      ? `${entity.label} is already on the graph`
      : `Added ${entity.label} to the graph`)
  }, [roots, showToast])

  const loadSaved = useCallback(async (row) => {
    try {
      const full = await api.threatModelGraphGet(row.id)
      setRoots([])
      setInitialGraph(full.graph)
      setSavedId(full.id)
      setSavedName(full.name)
      setActiveArn(full.root_arn || null)
    } catch (err) {
      showToast?.(`Could not load graph: ${err.message}`)
    }
  }, [showToast, setSavedId, setSavedName])

  const deleteSaved = useCallback(async (row) => {
    try {
      await api.threatModelGraphDelete(row.id)
      if (savedId === row.id) { setSavedId(null); setSavedName('') }
      refetchSaved()
    } catch (err) {
      showToast?.(`Could not delete graph: ${err.message}`)
    }
  }, [savedId, refetchSaved, showToast, setSavedId, setSavedName])

  const save = useCallback(async ({ asNew = false } = {}) => {
    const state = canvasRef.current
    if (!state.nodes.length) {
      showToast?.('Nothing to save — the graph is empty.')
      return
    }
    const suggested = savedName
      || (state.nodes.find(n => n.isRoot)?.label ?? 'Threat model')
    const name = window.prompt(
      asNew || !savedId ? 'Name this threat model graph' : 'Rename this graph',
      suggested)
    if (!name) return
    setSaving(true)
    try {
      const root = state.nodes.find(n => n.isRoot)
      const saved = (savedId && !asNew)
        ? await api.threatModelGraphUpdate(savedId, {
            name, root_arn: root?.arn || null,
            account_id: root?.account_id || null, graph: state })
        : await api.threatModelGraphSave({
            name, root_arn: root?.arn || null,
            account_id: root?.account_id || null, graph: state })
      setSavedId(saved.id)
      setSavedName(saved.name)
      refetchSaved()
      showToast?.(`Saved "${saved.name}"`)
    } catch (err) {
      showToast?.(`Save failed: ${err.message}`)
    } finally {
      setSaving(false)
    }
  }, [savedId, savedName, refetchSaved, showToast, canvasRef, setSavedId, setSavedName])

  const clear = useCallback(() => {
    setRoots([])
    setInitialGraph({ nodes: [], edges: [], expanded: [], removed: [] })
    canvas.reset()
    setActiveArn(null)
  }, [canvas])

  const activeFilters = (riskFilter !== 'All Risk' ? 1 : 0)
    + (serviceFilter !== 'All' ? 1 : 0) + (accountFilter ? 1 : 0)

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="page-content" style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

      <div className="page-header">
        <div>
          <div className="page-title">Threat Model</div>
          <div className="page-subtitle">
            {savedName || 'Inbound access mapping'}
          </div>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: '8px', alignItems: 'center' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-faint)' }}>
            {counts.nodes} nodes · {counts.edges} edges
          </span>
          <button className="btn primary" disabled={saving || !counts.nodes}
            onClick={() => save()}>{savedId ? 'Save' : 'Save graph'}</button>
          {savedId && (
            <button className="btn secondary" disabled={saving}
              onClick={() => save({ asNew: true })}>Save as…</button>
          )}
          <button className="btn secondary" onClick={clear}>Clear</button>
        </div>
      </div>

      <div style={{ flex: 1, display: 'flex', minHeight: 0 }}>

        {/* ── Left: asset picker + saved graphs ── */}
        {collapsed ? (
          <div style={{
            width: 34, flexShrink: 0, borderRight: '1px solid var(--border2)',
            background: 'var(--bg2)', display: 'flex', flexDirection: 'column',
            alignItems: 'center', paddingTop: 8,
          }}>
            <button className="btn secondary sm" title="Show the asset picker"
              onClick={() => setCollapsed(false)}>›</button>
          </div>
        ) : (
          <div ref={pane.panelRef} style={{
            // No borderRight: the ResizeHandle draws that divider itself.
            width: `${pane.width}px`, flexShrink: 0, position: 'relative',
            display: 'flex', flexDirection: 'column', minHeight: 0,
          }}>
            <ResizeHandle onPointerDown={pane.onResizeDown} active={pane.resizing} side="right" />

            <div className="tab-bar">
              {TYPE_TABS.map(t => (
                <button key={t.value}
                  className={`tab-btn${tab === t.value ? ' active' : ''}`}
                  onClick={() => setTab(t.value)}>
                  {t.label}<span className="tab-count">{tabCount(t.value)}</span>
                </button>
              ))}
              <button className="btn secondary sm" title="Hide the asset picker"
                style={{ marginLeft: 'auto', alignSelf: 'center', marginRight: 6 }}
                onClick={() => setCollapsed(true)}>‹</button>
            </div>

            <div className="filter-bar" style={{ gap: 6, flexWrap: 'wrap' }}>
              <input className="filter-search" style={{ width: '100%' }}
                placeholder="Search name or ARN…"
                value={search} onChange={e => setSearch(e.target.value)} />
              {RISK_FILTERS.map(f => (
                <button key={f} className={`filter-chip${riskFilter === f ? ' active' : ''}`}
                  onClick={() => setRiskFilter(f)}>{f}</button>
              ))}
              <select value={accountFilter} onChange={e => setAccountFilter(e.target.value)}
                style={selectStyle(!!accountFilter)}>
                <option value="">All Accounts</option>
                {(meta?.accounts || []).map(a => (
                  <option key={a.id} value={a.id}>{a.name || a.id}</option>
                ))}
              </select>
              {tab === 'resource' && (
                <select value={serviceFilter} onChange={e => setServiceFilter(e.target.value)}
                  style={selectStyle(serviceFilter !== 'All')}>
                  {SERVICE_FILTERS.map(sv => (
                    <option key={sv} value={sv}>{sv === 'All' ? 'All Services' : sv}</option>
                  ))}
                </select>
              )}
              {activeFilters > 0 && (
                <button className="btn danger sm" onClick={() => {
                  setRiskFilter('All Risk'); setServiceFilter('All'); setAccountFilter('')
                }}>Clear ({activeFilters})</button>
              )}
            </div>

            <div style={{ flex: 1, overflowY: 'auto', minHeight: 0 }}>
              {isFetching && items.length === 0 && (
                <div className="full-loading">
                  <div className="spinner-ring" />
                </div>
              )}
              {!isFetching && items.length === 0 && (
                <div className="empty-state">
                  <div className="empty-state-icon">🔍</div>
                  <div className="empty-state-title">No matching assets</div>
                  <div className="empty-state-hint">Try a different filter or search term.</div>
                </div>
              )}
              {items.map(e => (
                <AssetRow key={e.arn || e.label} entity={e}
                  active={activeArn === e.arn} onSeed={seed} onAdd={addRoot} />
              ))}
            </div>

            <Paginator page={page} totalPages={totalPages} total={total}
              pageSize={PAGE_SIZE} goTo={setPage} label="assets" />

            <div style={{
              borderTop: '1px solid var(--border2)', maxHeight: '32%',
              display: 'flex', flexDirection: 'column', minHeight: 0,
            }}>
              <div className="section-header" style={{ padding: '8px 12px', margin: 0 }}>
                <span className="section-title" style={{ margin: 0 }}>Saved graphs</span>
                <span className="section-count">{savedGraphs.length}</span>
              </div>
              <div style={{ flex: 1, overflowY: 'auto', minHeight: 0 }}>
                {savedGraphs.length === 0 && (
                  <div style={{ padding: '12px', fontSize: '11px', color: 'var(--text-faint)' }}>
                    Nothing saved yet — build a graph and hit Save.
                  </div>
                )}
                {savedGraphs.map(g => (
                  <SavedGraphRow key={g.id} graph={g} active={savedId === g.id}
                    onLoad={loadSaved} onDelete={deleteSaved} />
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ── Right: graph ── */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column',
                      minWidth: 0, minHeight: 0 }}>
          <ThreatGraph
            roots={roots}
            initialGraph={initialGraph}
            onStateChange={onStateChange}
            onPrivEsc={arn => startPrivEsc(arn)}
          />
        </div>
      </div>
    </div>
  )
}
