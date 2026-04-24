/**
 * GraphViewer — Cytoscape.js graph panel
 *
 * Modes:
 *  - Normal: loads node neighborhoods via /api/graph/node/{id}
 *  - Path: renders attack path steps as amber directed edges (no API needed)
 *
 * Props:
 *  nodeIds    – array of graph node IDs to load from API
 *  pathSteps  – array of _ap_step objects {actor_arn, target_arn, action, edge_type}
 *  onClose    – close callback
 */
import { useEffect, useRef, useState, useCallback } from 'react'
import cytoscape from 'cytoscape'
import { api } from '../api'
import EntityDetailPanel from './EntityDetailPanel'
import { useApp } from '../context/AppContext'

// ─── Type config ──────────────────────────────────────────────────────────────

const NODE_CFG = {
  role: { shape: 'round-rectangle', icon: '⚙', color: '#3a9ab0' },
  principal: { shape: 'round-rectangle', icon: '⚙', color: '#3a9ab0' },
  user: { shape: 'ellipse', icon: '👤', color: '#3dab6e' },
  group: { shape: 'ellipse', icon: '👥', color: '#9a7fc8' },
  policy: { shape: 'round-rectangle', icon: '📄', color: '#c878b0' },
  resource: { shape: 'round-rectangle', icon: '☁', color: '#d97c14' },
  account: { shape: 'ellipse', icon: '🔷', color: '#6070a0' },
  external: { shape: 'ellipse', icon: '⚡', color: '#4e5668' },
}
const DEFAULT_CFG = { shape: 'ellipse', icon: '●', color: '#4e5668' }

function resolveType(n) { return n?.principal_type || n?.node_type || 'role' }
function cfgFor(n) { return NODE_CFG[resolveType(n)] || DEFAULT_CFG }

function arnType(arn = '') {
  if (arn.includes(':role/') || arn.includes('assumed-role')) return 'role'
  if (arn.includes(':user/')) return 'user'
  if (arn.includes(':group/')) return 'group'
  if (arn.includes(':policy/')) return 'policy'
  return 'resource'
}

function shortLabel(id = '') {
  const a = id.replace(/^[^:]+:/, '')
  const p = a.split('/').pop() || a.split(':').pop() || id
  return p.length > 22 ? p.slice(0, 21) + '…' : p
}

function emojiSvgUrl(emoji) {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64"><text x="32" y="44" font-size="38" text-anchor="middle">${emoji}</text></svg>`
  return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`
}

function makeData(n) {
  const nid = n.id || n.node_id
  const cfg = cfgFor(n)
  return {
    id: nid,
    label: shortLabel(n.label || nid),
    iconUrl: emojiSvgUrl(cfg.icon),
    nodeType: resolveType(n),
    typeColor: cfg.color,
    typeShape: cfg.shape,
    fullLabel: n.label || shortLabel(nid),
    arn: n.arn,
    account_id: n.account_id,
    node_type: n.node_type,
    principal_type: n.principal_type,
    policy_type: n.policy_type,
    service: n.service,
    resource_type: n.resource_type,
    region: n.region,
    actions: n.actions || [],
    trust_principals: n.trust_principals || [],
    policies: n.policies || [],
    attached_principals: n.attached_principals || [],
    execution_role: n.execution_role || null,
  }
}

function dataToEntity(d) {
  return {
    label: d.fullLabel,
    arn: d.arn,
    node_type: d.node_type,
    principal_type: d.principal_type,
    policy_type: d.policy_type,
    account_id: d.account_id,
    actions: d.actions || [],
    trust_principals: d.trust_principals || [],
    policies: d.policies || [],
    attached_principals: d.attached_principals || [],
    execution_role: d.execution_role || null,
    service: d.service,
    resource_type: d.resource_type,
    region: d.region,
  }
}

// Build cytoscape elements directly from path steps (no API call)
function pathStepsToElements(steps) {
  const nodeMap = new Map()   // arn → element
  const edgeMap = new Map()   // "src→tgt" → { actions: Set, data }

  steps.forEach((s) => {
    for (const arn of [s.actor_arn, s.target_arn]) {
      if (arn && !nodeMap.has(arn)) {
        const t = arnType(arn)
        const cfg = cfgFor({ node_type: t })
        nodeMap.set(arn, {
          group: 'nodes',
          data: {
            id: arn,
            label: shortLabel(arn),
            iconUrl: emojiSvgUrl(cfg.icon),
            nodeType: t,
            typeColor: cfg.color,
            typeShape: cfg.shape,
            fullLabel: arn,
            arn,
          },
        })
      }
    }
    if (s.actor_arn && s.target_arn) {
      const key = `${s.actor_arn}→${s.target_arn}`
      if (!edgeMap.has(key)) {
        edgeMap.set(key, { actions: new Set(), src: s.actor_arn, tgt: s.target_arn })
      }
      const action = (s.action || s.edge_type || '').split(':').pop()  // strip "sts:" prefix
      if (action) edgeMap.get(key).actions.add(action)
    }
  })

  const edges = [...edgeMap.entries()].map(([key, { actions, src, tgt }]) => ({
    group: 'edges',
    data: {
      id: `path-${key}`,
      source: src,
      target: tgt,
      edgeType: 'path',
      label: [...actions].join(' / '),
    },
  }))

  return [...nodeMap.values(), ...edges]
}

// ─── Cytoscape stylesheet ─────────────────────────────────────────────────────

function buildStylesheet(nodeSize, edgeOpacity) {
  const styles = [
    {
      selector: 'node',
      style: {
        'width': nodeSize,
        'height': nodeSize,
        'background-image': 'data(iconUrl)',
        'background-width': '60%',
        'background-height': '60%',
        'background-clip': 'node',
        'background-position-x': '50%',
        'background-position-y': '50%',
        'background-color': '#0b0d12',
        'background-opacity': 1,
        'border-width': 1.5,
        'border-opacity': 0.70,
        'border-color': 'data(typeColor)',
        'shape': 'data(typeShape)',
        'label': 'data(label)',
        'text-valign': 'bottom',
        'text-halign': 'center',
        'text-margin-y': 5,
        'font-size': 9,
        'font-family': 'IBM Plex Mono, monospace',
        'color': 'rgba(196,202,212,0.85)',
        'text-wrap': 'none',
        'overlay-opacity': 0,
      },
    },
    {
      selector: 'node:selected',
      style: {
        'border-width': 2.5,
        'border-opacity': 1,
        'shadow-blur': 20,
        'shadow-opacity': 0.80,
        'shadow-color': 'data(typeColor)',
        'shadow-offset-x': 0,
        'shadow-offset-y': 0,
        'overlay-opacity': 0,
      },
    },
    {
      selector: 'edge',
      style: {
        'width': 1,
        'line-color': `rgba(55,60,78,${edgeOpacity})`,
        'target-arrow-color': `rgba(55,60,78,${edgeOpacity})`,
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'arrow-scale': 0.6,
        'opacity': edgeOpacity,
        'overlay-opacity': 0,
      },
    },
    { selector: 'edge:selected', style: { 'width': 2, 'opacity': 1 } },
    // Path edges — amber, dashed, labelled with IAM action
    {
      selector: 'edge[edgeType = "path"]',
      style: {
        'width': 2,
        'line-style': 'dashed',
        'line-dash-pattern': [8, 4],
        'line-color': '#d97c14',
        'target-arrow-color': '#d97c14',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'arrow-scale': 0.8,
        'opacity': 1,
        'label': 'data(label)',
        'font-size': 8,
        'font-family': 'IBM Plex Mono, monospace',
        'color': '#d97c14',
        'text-rotation': 'autorotate',
        'text-margin-y': -8,
        'overlay-opacity': 0,
      },
    },
  ]

  // Per-type glass gradient
  Object.entries(NODE_CFG).forEach(([type, cfg]) => {
    styles.push({
      selector: `node[nodeType = "${type}"]`,
      style: {
        'background-fill': 'linear-gradient',
        'background-gradient-stop-colors': `${cfg.color} #080a0e`,
        'background-gradient-stop-positions': '0 100',
        'background-gradient-direction': 'to-bottom-right',
        'background-opacity': 0.50,
      },
    })
  })

  return styles
}

// ─── Layout configs ───────────────────────────────────────────────────────────

const CIRCLE_LAYOUT = {
  name: 'circle',
  fit: true,
  padding: 80,
  animate: false,
  avoidOverlap: true,
  radius: undefined,
  startAngle: (3 / 2) * Math.PI,
  counterclockwise: false,
  nodeDimensionsIncludeLabels: true,
}

const COSE_LAYOUT = {
  name: 'cose',
  animate: false,
  fit: true,
  padding: 80,
  nodeRepulsion: () => 4500,
  idealEdgeLength: () => 150,
  edgeElasticity: () => 0.45,
  gravity: 0.8,
  numIter: 1000,
  initialTemp: 200,
  coolingFactor: 0.99,
  minTemp: 1.0,
  randomize: true,
  nodeOverlap: 40,
}

// Directed hierarchical layout for attack path visualization
const PATH_LAYOUT = {
  name: 'breadthfirst',
  directed: true,
  fit: true,
  padding: 80,
  animate: false,
  avoidOverlap: true,
  spacingFactor: 2.5,
}

function pickLayout(n, isPath) {
  if (isPath) return PATH_LAYOUT
  return n <= 30 ? CIRCLE_LAYOUT : COSE_LAYOUT
}

// ─── Controls panel ───────────────────────────────────────────────────────────

function ControlsPanel({ cyRef, open, onToggle, nodeSize, setNodeSize, edgeOpacity, setEdgeOpacity, onRelayout, onClear }) {
  const base = { width: 28, height: 28, background: 'var(--bg2)', border: '1px solid var(--border2)', borderRadius: '3px', cursor: 'pointer', color: 'var(--text-dim)', fontSize: '13px', fontFamily: 'IBM Plex Mono,monospace', display: 'flex', alignItems: 'center', justifyContent: 'center', transition: 'all 0.12s' }
  const enter = e => { e.currentTarget.style.background = 'var(--bg3)'; e.currentTarget.style.color = 'var(--text)' }
  const leave = e => { e.currentTarget.style.background = 'var(--bg2)'; e.currentTarget.style.color = 'var(--text-dim)' }

  function zoom(factor) {
    const cy = cyRef.current; if (!cy) return
    cy.zoom({ level: cy.zoom() * factor, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } })
  }

  return (
    <div style={{ position: 'absolute', top: 12, right: 12, zIndex: 10, display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        {[
          { l: '+', title: 'Zoom in', fn: () => zoom(1.3) },
          { l: '−', title: 'Zoom out', fn: () => zoom(0.77) },
          { l: '⊙', title: 'Fit view', fn: () => cyRef.current?.fit(undefined, 60) },
          { l: '⟳', title: 'Re-layout', fn: onRelayout },
          { l: '🗑', title: 'Clear graph', fn: onClear },
        ].map(({ l, title, fn }) => (
          <button key={l} title={title} onClick={fn} style={base} onMouseEnter={enter} onMouseLeave={leave}>{l}</button>
        ))}
        <div style={{ height: 1, background: 'var(--border)', margin: '2px 0' }} />
        <button title="Controls" onClick={onToggle}
          style={{ ...base, background: open ? 'var(--amber-glow)' : 'var(--bg2)', border: `1px solid ${open ? 'rgba(217,124,20,.3)' : 'var(--border2)'}`, color: open ? 'var(--amber)' : 'var(--text-dim)', fontSize: '11px' }}>⛭</button>
      </div>
      {open && (
        <div style={{ background: 'var(--bg1)', border: '1px solid var(--border2)', borderRadius: '4px', padding: '10px 12px', width: '160px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {[
            { label: 'Node size', value: nodeSize, min: 14, max: 60, step: 2, fmt: v => `${v}px`, set: setNodeSize },
            { label: 'Edge alpha', value: edgeOpacity, min: 0.05, max: 1, step: 0.05, fmt: v => `${Math.round(v * 100)}%`, set: setEdgeOpacity },
          ].map(({ label, value, min, max, step, fmt, set }) => (
            <div key={label}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-dim)', marginBottom: '3px' }}>
                <span>{label}</span>
                <span style={{ color: 'var(--amber)', fontFamily: 'IBM Plex Mono' }}>{fmt(value)}</span>
              </div>
              <input type="range" min={min} max={max} step={step} value={value}
                onChange={e => set(Number(e.target.value))}
                style={{ width: '100%', accentColor: 'var(--amber)' }} />
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Main component ────────────────────────────────────────────────────────────

export default function GraphViewer({ nodeIds = [], pathSteps = [], onClose, onNodeIdsChange }) {
  const { findings, entities } = useApp()
  const entitiesRef = useRef(null)
  useEffect(() => { entitiesRef.current = entities }, [entities])
  const containerRef = useRef(null)
  const cyRef = useRef(null)
  const panelRef = useRef(null)

  const isPathMode = pathSteps?.length > 0

  const [width, setWidth] = useState(Math.min(window.innerWidth * 0.65, 1100))
  const [resizing, setResizing] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [selected, setSelected] = useState(null)
  const [selectedId, setSelectedId] = useState(null)
  const [controlsOpen, setControlsOpen] = useState(false)
  const [nodeCount, setNodeCount] = useState(0)
  const [edgeCount, setEdgeCount] = useState(0)
  const [nodeSize, setNodeSize] = useState(26)
  const [edgeOpacity, setEdgeOpacity] = useState(isPathMode ? 1 : 0.6)

  // ── Resize ─────────────────────────────────────────────────────────────────

  const startX = useRef(0), startW = useRef(0)
  const onResizeDown = useCallback((e) => {
    startX.current = e.clientX; startW.current = panelRef.current?.offsetWidth ?? width
    setResizing(true); e.preventDefault()
  }, [width])
  useEffect(() => {
    if (!resizing) return
    const move = e => setWidth(Math.max(360, Math.min(window.innerWidth * 0.93, startW.current + (startX.current - e.clientX))))
    const up = () => setResizing(false)
    window.addEventListener('mousemove', move); window.addEventListener('mouseup', up)
    return () => { window.removeEventListener('mousemove', move); window.removeEventListener('mouseup', up) }
  }, [resizing])

  // ── Init Cytoscape ─────────────────────────────────────────────────────────

  useEffect(() => {
    if (!containerRef.current) return
    const cy = cytoscape({
      container: containerRef.current,
      style: buildStylesheet(nodeSize, edgeOpacity),
      layout: { name: 'preset' },
      minZoom: 0.05,
      maxZoom: 4,
    })
    cy.on('tap', 'node', evt => {
      const d = evt.target.data()
      // Prefer full entity from AppContext (by ARN) so path-mode nodes show real data
      const rich = entitiesRef.current?.find(e => e.arn === d.arn)
      setSelected(rich || dataToEntity(d))
      setSelectedId(d.id)
    })
    cy.on('tap', evt => {
      if (evt.target === cy) { setSelected(null); setSelectedId(null) }
    })
    cyRef.current = cy
    return () => cy.destroy()
  }, [])

  // ── Load API nodes ─────────────────────────────────────────────────────────

  async function loadNodes(idList) {
    const cy = cyRef.current
    if (!cy || !idList?.length) return
    setLoading(true); setError(null)
    try {
      const existingIds = new Set(cy.nodes().map(n => n.id()))
      const toAdd = []
      await Promise.all(idList.map(async (qid) => {
        try {
          const data = await api.node(qid)
            ; (data.nodes || []).forEach(n => {
              const nid = n.id || n.node_id
              if (!nid || existingIds.has(nid)) return
              existingIds.add(nid)
              toAdd.push({ group: 'nodes', data: makeData(n) })
            })
            ; (data.edges || []).forEach(e => {
              if (!e.source || !e.target) return
              const eid = e.id || `${e.source}--${e.edge_type || 'edge'}--${e.target}`
              if (!existingIds.has(eid)) {
                existingIds.add(eid)
                toAdd.push({ group: 'edges', data: { id: eid, source: e.source, target: e.target } })
              }
            })
        } catch (err) { console.warn('Load failed:', qid, err.message) }
      }))
      if (toAdd.length) {
        cy.add(toAdd)
        cy.layout(pickLayout(cy.nodes().length, isPathMode)).run()
      }
      setNodeCount(cy.nodes().length)
      setEdgeCount(cy.edges().length)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadNodes(nodeIds) }, [nodeIds])

  // ── Load path steps (path mode) ────────────────────────────────────────────

  useEffect(() => {
    if (!pathSteps?.length) return
    const cy = cyRef.current; if (!cy) return
    const elements = pathStepsToElements(pathSteps)
    const existing = new Set([...cy.nodes().map(n => n.id()), ...cy.edges().map(e => e.id())])
    const toAdd = elements.filter(el => !existing.has(el.data.id))
    if (toAdd.length) cy.add(toAdd)
    cy.layout(PATH_LAYOUT).run()
    setNodeCount(cy.nodes().length)
    setEdgeCount(cy.edges().length)
  }, [pathSteps])

  async function expandNode(nodeId) {
    await loadNodes([nodeId])
    setSelected(null); setSelectedId(null)
  }

  // ── Sync slider changes ────────────────────────────────────────────────────

  useEffect(() => {
    const cy = cyRef.current; if (!cy) return
    cy.nodes().style({ 'width': nodeSize, 'height': nodeSize })
  }, [nodeSize])

  useEffect(() => {
    const cy = cyRef.current; if (!cy) return
    const c = `rgba(55,60,78,${edgeOpacity})`
    cy.edges('[edgeType != "path"]').style({ 'line-color': c, 'target-arrow-color': c, 'opacity': edgeOpacity })
  }, [edgeOpacity])

  function relayout() {
    const cy = cyRef.current; if (!cy) return
    cy.layout(pickLayout(cy.nodes().length, isPathMode)).run()
  }

  const title = isPathMode ? 'Attack Path' : 'Graph Viewer'

  return (
    <>
      <div className="detail-overlay" onClick={onClose} />

      {/* Entity detail — sits to the LEFT of the graph panel, never inside/overlapping the canvas */}
      {selected && (
        <div style={{
          position: 'fixed', top: 0, bottom: 0,
          right: `${Math.min(width, window.innerWidth * 0.93)}px`,
          maxWidth: 'calc(100vw - 56px)',  // never overflow behind nav rail
          zIndex: 1001,
          overflowY: 'auto',
          background: 'var(--bg1)',
          borderLeft: '1px solid var(--border2)',
          boxShadow: '-4px 0 24px rgba(0,0,0,0.5)',
        }}>
          <EntityDetailPanel
            entity={selected}
            findings={findings}
            onClose={() => { setSelected(null); setSelectedId(null); cyRef.current?.nodes().unselect() }}
            onViewGraph={null}
          />
          {!isPathMode && (
            <div style={{ padding: '8px 12px', borderTop: '1px solid var(--border)' }}>
              <button className="btn primary sm" style={{ width: '100%', justifyContent: 'center' }}
                onClick={() => expandNode(selectedId)}>
                ⊕ Expand neighbors
              </button>
            </div>
          )}
        </div>
      )}

      <div ref={panelRef} className="graph-slideover"
        style={{ width: `${width}px`, display: 'flex', flexDirection: 'column', maxWidth: '93vw' }}>

        {/* Resize handle */}
        <div onMouseDown={onResizeDown}
          style={{ position: 'absolute', left: 0, top: 0, bottom: 0, width: '6px', cursor: 'ew-resize', zIndex: 10, background: resizing ? 'var(--amber)' : 'transparent', transition: 'background 0.15s' }}
          onMouseEnter={e => { e.currentTarget.style.background = 'rgba(217,124,20,0.3)' }}
          onMouseLeave={e => { if (!resizing) e.currentTarget.style.background = 'transparent' }}
        />

        {/* Header */}
        <div className="slideover-header">
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="var(--amber)" strokeWidth="1.4">
            <circle cx="4" cy="4" r="2" /><circle cx="12" cy="4" r="2" /><circle cx="8" cy="12" r="2" />
            <path d="M6 4h4M5 5.5l-1 5M11 5.5l1 5" strokeLinecap="round" />
          </svg>
          <span className="slideover-title">{title}</span>
          {isPathMode && (
            <span style={{ fontSize: '10px', background: 'rgba(217,124,20,0.12)', color: 'var(--amber)', border: '1px solid rgba(217,124,20,0.25)', borderRadius: '3px', padding: '1px 6px', marginLeft: '6px' }}>
              attack path
            </span>
          )}
          <span style={{ fontSize: '10px', color: 'var(--text-faint)', marginLeft: '4px' }}>
            {nodeCount} nodes · {edgeCount} edges
          </span>
          <button className="slideover-close" onClick={onClose}>✕</button>
        </div>

        {/* Body — canvas fills all; entity panel overlays left side */}
        <div style={{ flex: 1, position: 'relative', overflow: 'hidden' }}>
          {/* Canvas fills 100% */}
          <div className="graph-canvas-area" style={{ position: 'absolute', inset: 0 }}>
            {loading && (
              <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 12, background: 'rgba(9,9,11,0.85)', zIndex: 20 }}>
                <div className="spinner-ring" style={{ width: 28, height: 28, borderWidth: 3 }} />
                <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>Loading graph…</div>
              </div>
            )}
            {error && !loading && (
              <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 8, padding: '24px', textAlign: 'center', zIndex: 10 }}>
                <div style={{ fontSize: '28px' }}>⚠</div>
                <div style={{ fontSize: '11px', color: 'var(--red-hi)' }}>{error}</div>
                <div style={{ fontSize: '10px', color: 'var(--text-faint)' }}>
                  Run <code style={{ color: 'var(--amber)' }}>worst enum</code> first.
                </div>
              </div>
            )}
            <div ref={containerRef} style={{ width: '100%', height: '100%' }} />
            <ControlsPanel cyRef={cyRef} open={controlsOpen} onToggle={() => setControlsOpen(o => !o)}
              nodeSize={nodeSize} setNodeSize={setNodeSize}
              edgeOpacity={edgeOpacity} setEdgeOpacity={setEdgeOpacity}
              onRelayout={relayout}
              onClear={() => {
                const cy = cyRef.current; if (!cy) return
                cy.elements().remove()
                setNodeCount(0); setEdgeCount(0)
                setSelected(null); setSelectedId(null)
                onNodeIdsChange?.([])
              }}
            />
            {/* Legend */}
            <div style={{ position: 'absolute', bottom: 12, left: 12, zIndex: 10, display: 'flex', flexDirection: 'column', gap: 4 }}>
              {isPathMode && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '10px', marginBottom: 4 }}>
                  <div style={{ width: 20, height: 2, background: '#d97c14', borderBottom: '2px dashed #d97c14' }} />
                  <span style={{ color: 'var(--amber)' }}>attack step</span>
                </div>
              )}
              {[['Role', '⚙', '#3a9ab0'], ['User', '👤', '#3dab6e'], ['Group', '👥', '#9a7fc8'], ['Policy', '📄', '#c878b0'], ['Resource', '☁', '#d97c14'], ['Account', '🔷', '#6070a0']].map(([lbl, icon, col]) => (
                <div key={lbl} style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '10px', color: 'var(--text-dim)' }}>
                  <span style={{ fontSize: '11px' }}>{icon}</span><span style={{ color: col }}>{lbl}</span>
                </div>
              ))}
            </div>
          </div>
        </div>{/* end body container */}

        <div className="slideover-footer">
          <span style={{ fontSize: '10px', color: 'var(--text-faint)', marginRight: 'auto' }}>
            {isPathMode ? 'Amber dashed = attack step · Click node to inspect' : 'Click to inspect · Drag nodes · Scroll to zoom · ⛭ Controls'}
          </span>
          <button className="btn secondary sm" onClick={onClose}>Close</button>
        </div>
      </div>
    </>
  )
}
