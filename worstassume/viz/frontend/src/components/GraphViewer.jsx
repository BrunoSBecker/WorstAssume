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
import { useEffect, useRef, useState } from 'react'
import cytoscape from 'cytoscape'
import { api } from '../api'
import EntityDetailPanel from './EntityDetailPanel'
import { useApp } from '../context/AppContext'
import {
  NODE_CFG, arnType, cfgFor, shortLabel, iconSvgUrl, makeData, dataToEntity,
  NETWORK_EDGE_LABELS, baseStylesheet, typeGradientStyles,
  PATH_LAYOUT, pickLayout,
} from './graphShared'
import ControlsPanel from './GraphControls'
import ResizeHandle from './ResizeHandle'
import NodeTypeIcon from './NodeTypeIcon'
import { useResizableWidth } from './useResizableWidth'

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
            iconUrl: iconSvgUrl(t),
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
  return [
    ...baseStylesheet(nodeSize, edgeOpacity),
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
        'overlay-opacity': 0,
      },
    },
    // Network-topology edges (in_vpc / in_subnet / uses_sg) — teal, labelled
    {
      selector: 'edge[edgeType = "in_vpc"], edge[edgeType = "in_subnet"], edge[edgeType = "uses_sg"]',
      style: {
        'width': 1.5,
        'line-color': '#2a9d8f',
        'target-arrow-color': '#2a9d8f',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'arrow-scale': 0.7,
        'opacity': 0.9,
        'overlay-opacity': 0,
      },
    },
    { selector: 'edge.hovered', style: { 'width': 3.5, 'opacity': 1, 'z-index': 99 } },
    ...typeGradientStyles(),
  ]
}

const NAV_W = 56        // the fixed nav rail, --nav-w
const MIN_GRAPH_W = 320 // never squeeze the canvas below this

// ─── Main component ────────────────────────────────────────────────────────────

export default function GraphViewer({ nodeIds = [], pathSteps = [], focusNodeId = null, onClose, onNodeIdsChange }) {
  const { findings, entities, ensureEntities } = useApp()
  const entitiesRef = useRef(null)
  useEffect(() => { entitiesRef.current = entities }, [entities])
  // Entities are loaded lazily app-wide; ensure they're available so node
  // clicks can be enriched with full entity data (esp. in path mode).
  useEffect(() => { ensureEntities?.().catch(() => {}) }, [ensureEntities])
  const containerRef = useRef(null)
  const cyRef = useRef(null)
  // Nodes the user explicitly removed — never re-added on subsequent loads
  const removedRef = useRef(new Set())

  const isPathMode = pathSteps?.length > 0

  const { width, resizing, onResizeDown, panelRef } = useResizableWidth({
    initial: Math.min(window.innerWidth * 0.65, 1100), min: 360, side: 'right',
  })
  // The detail panel needs its own width. Without one it is sized by its
  // content, which on the Risk tab (long finding messages) grows unbounded.
  const detail = useResizableWidth({
    initial: 420, min: 340, side: 'right',
    max: () => Math.max(340, window.innerWidth - NAV_W - MIN_GRAPH_W),
  })
  const [viewportW, setViewportW] = useState(window.innerWidth)
  useEffect(() => {
    const onResize = () => setViewportW(window.innerWidth)
    window.addEventListener('resize', onResize)
    return () => window.removeEventListener('resize', onResize)
  }, [])

  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [selected, setSelected] = useState(null)
  const [selectedId, setSelectedId] = useState(null)
  const [controlsOpen, setControlsOpen] = useState(false)
  const [nodeCount, setNodeCount] = useState(0)
  const [edgeCount, setEdgeCount] = useState(0)
  const [nodeSize, setNodeSize] = useState(26)
  const [edgeOpacity, setEdgeOpacity] = useState(isPathMode ? 1 : 0.6)
  const [ctxMenu, setCtxMenu] = useState(null)  // { x, y, id, label }
  const [edgeHover, setEdgeHover] = useState(null)

  // The graph and the detail panel sit side by side. When both cannot fit, the
  // graph yields — previously the panel simply ran off the left edge and under
  // the nav rail.
  const detailW = selected ? detail.width : 0
  const graphW = Math.max(
    MIN_GRAPH_W, Math.min(width, viewportW - NAV_W - detailW))

  // Cytoscape does not observe its container, so it has to be told when the
  // canvas changes size or it keeps rendering at the old dimensions.
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    const t = setTimeout(() => cy.resize(), 0)
    return () => clearTimeout(t)
  }, [graphW])

  // Re-fit only when the panel opens or closes, not while it is being dragged —
  // refitting on every pointer move would fight the analyst for the viewport.
  useEffect(() => {
    const cy = cyRef.current
    if (!cy || !cy.nodes().length) return
    const t = setTimeout(() => { cy.resize(); cy.fit(undefined, 60) }, 60)
    return () => clearTimeout(t)
  }, [!!selected])

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
      setCtxMenu(null)
    })
    cy.on('tap', evt => {
      if (evt.target === cy) { setSelected(null); setSelectedId(null) }
      setCtxMenu(null)
    })
    // Right-click a node → contextual removal menu
    cy.on('cxttap', 'node', evt => {
      const d = evt.target.data()
      const pos = evt.renderedPosition || { x: 0, y: 0 }
      setCtxMenu({ x: pos.x, y: pos.y, id: d.id, label: d.fullLabel || d.label })
    })
    // Edges are no longer drawn with a rotated label; hovering reveals it
    // horizontally instead, where it is actually legible.
    cy.on('mouseover', 'edge', evt => {
      const d = evt.target.data()
      if (!d.label && !d.edgeType) return
      evt.target.addClass('hovered')
      const pos = evt.renderedPosition || { x: 0, y: 0 }
      setEdgeHover({ x: pos.x, y: pos.y, label: d.label,
                     edgeType: d.edgeType, source: d.source, target: d.target })
    })
    cy.on('mouseout', 'edge', evt => {
      evt.target.removeClass('hovered')
      setEdgeHover(null)
    })
    cy.on('pan zoom', () => { setCtxMenu(null); setEdgeHover(null) })
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
              if (!nid || existingIds.has(nid) || removedRef.current.has(nid)) return
              existingIds.add(nid)
              toAdd.push({ group: 'nodes', data: makeData(n) })
            })
            ; (data.edges || []).forEach(e => {
              if (!e.source || !e.target) return
              if (removedRef.current.has(e.source) || removedRef.current.has(e.target)) return
              const eid = e.id || `${e.source}--${e.edge_type || 'edge'}--${e.target}`
              if (!existingIds.has(eid)) {
                existingIds.add(eid)
                const netLabel = NETWORK_EDGE_LABELS[e.edge_type]
                toAdd.push({ group: 'edges', data: {
                  id: eid, source: e.source, target: e.target,
                  edgeType: netLabel ? e.edge_type : (e.edge_type || 'edge'),
                  label: netLabel || '',
                } })
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

  // Remove a single node (and its edges). Optionally also drop neighbors that
  // become orphaned (no remaining edges). Removed ids are remembered so they
  // are not re-added on subsequent neighbor loads, and pruned from parent seeds.
  function removeNode(id, alsoOrphans = false) {
    const cy = cyRef.current
    if (!cy || !id) return
    const node = cy.getElementById(id)
    if (!node || node.empty()) return

    const removedIds = [id]
    if (alsoOrphans) {
      node.neighborhood('node').forEach(nb => {
        // degree === 1 means its only connection is the node being removed
        if (nb.degree(false) <= 1) removedIds.push(nb.id())
      })
    }
    let coll = cy.collection()
    removedIds.forEach(rid => {
      removedRef.current.add(rid)
      coll = coll.union(cy.getElementById(rid))
    })
    cy.remove(coll)

    setNodeCount(cy.nodes().length)
    setEdgeCount(cy.edges().length)
    setCtxMenu(null)
    if (removedIds.includes(selectedId)) { setSelected(null); setSelectedId(null) }
    onNodeIdsChange?.(nodeIds.filter(x => !removedIds.includes(x)))
  }

  // Focus mode — center + select a seeded node once it has loaded
  useEffect(() => {
    const cy = cyRef.current
    if (!cy || !focusNodeId) return
    const node = cy.getElementById(focusNodeId)
    if (!node || node.empty()) return
    cy.nodes().unselect()
    node.select()
    cy.center(node)
    const d = node.data()
    const rich = entitiesRef.current?.find(e => e.arn === d.arn)
    setSelected(rich || dataToEntity(d))
    setSelectedId(d.id)
  }, [focusNodeId, nodeCount])

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
        <div ref={detail.panelRef} style={{
          position: 'fixed', top: 0, bottom: 0,
          right: `${graphW}px`,
          width: `${detailW}px`,
          zIndex: 1001,
          display: 'flex',
          background: 'var(--bg1)',
          boxShadow: '-4px 0 24px rgba(0,0,0,0.5)',
        }}>
          <ResizeHandle onPointerDown={detail.onResizeDown}
            active={detail.resizing} side="left" />
          <EntityDetailPanel
            entity={selected}
            findings={findings}
            onClose={() => { setSelected(null); setSelectedId(null); cyRef.current?.nodes().unselect() }}
            actions={isPathMode ? [] : [
              { label: '⊕ Expand neighbors', variant: 'primary', grow: true,
                onClick: () => expandNode(selectedId) },
              { label: '✕ Remove', variant: 'danger',
                title: 'Remove this node from the graph',
                onClick: () => removeNode(selectedId) },
            ]}
          />
        </div>
      )}

      <div ref={panelRef} className="graph-slideover"
        style={{ width: `${graphW}px`, display: 'flex', flexDirection: 'column' }}>

        {/* Resize handle */}
        <ResizeHandle onPointerDown={onResizeDown} active={resizing} side="left" />

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
                setCtxMenu(null)
                onNodeIdsChange?.([])
              }}
            />
            {/* Edge hover card */}
            {edgeHover && (
              <div style={{
                position: 'absolute', left: edgeHover.x + 12, top: edgeHover.y + 12,
                zIndex: 30, pointerEvents: 'none', maxWidth: 320,
                background: 'var(--bg1)', border: '1px solid var(--border2)',
                borderRadius: '4px', boxShadow: '0 6px 20px rgba(0,0,0,0.55)',
                padding: '6px 10px',
              }}>
                <div style={{ fontSize: '9px', color: 'var(--text-faint)',
                              whiteSpace: 'nowrap', overflow: 'hidden',
                              textOverflow: 'ellipsis' }}>
                  {shortLabel(edgeHover.source)} → {shortLabel(edgeHover.target)}
                </div>
                {edgeHover.label && (
                  <div style={{ fontSize: '10px', color: 'var(--text)', marginTop: 3,
                                fontFamily: 'IBM Plex Mono, monospace',
                                wordBreak: 'break-word' }}>{edgeHover.label}</div>
                )}
                {edgeHover.edgeType && edgeHover.edgeType !== 'path' && (
                  <div style={{ fontSize: '9px', color: 'var(--text-faint)', marginTop: 2 }}>
                    {edgeHover.edgeType.replace(/_/g, ' ')}
                  </div>
                )}
              </div>
            )}

            {/* Node context menu (right-click) */}
            {ctxMenu && (
              <div style={{
                position: 'absolute', left: ctxMenu.x, top: ctxMenu.y, zIndex: 30,
                background: 'var(--bg1)', border: '1px solid var(--border2)', borderRadius: '4px',
                boxShadow: '0 6px 20px rgba(0,0,0,0.55)', minWidth: '180px', overflow: 'hidden',
              }}>
                <div style={{ padding: '6px 10px', fontSize: '10px', color: 'var(--text-faint)', borderBottom: '1px solid var(--border)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {ctxMenu.label}
                </div>
                {[
                  { label: '✕  Remove node', fn: () => removeNode(ctxMenu.id) },
                  { label: '✕  Remove node + orphaned', fn: () => removeNode(ctxMenu.id, true) },
                ].map(({ label, fn }) => (
                  <button key={label} onClick={fn}
                    style={{ display: 'block', width: '100%', textAlign: 'left', padding: '7px 10px', background: 'transparent', border: 'none', color: 'var(--text)', fontSize: '11px', cursor: 'pointer', fontFamily: 'inherit' }}
                    onMouseEnter={e => { e.currentTarget.style.background = 'var(--bg3)' }}
                    onMouseLeave={e => { e.currentTarget.style.background = 'transparent' }}>
                    {label}
                  </button>
                ))}
              </div>
            )}
            {/* Legend */}
            <div style={{ position: 'absolute', bottom: 12, left: 12, zIndex: 10, display: 'flex', flexDirection: 'column', gap: 4 }}>
              {isPathMode && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '10px', marginBottom: 4 }}>
                  <div style={{ width: 20, height: 2, background: '#d97c14', borderBottom: '2px dashed #d97c14' }} />
                  <span style={{ color: 'var(--amber)' }}>attack step</span>
                </div>
              )}
              {!isPathMode && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '10px', marginBottom: 4 }}>
                  <div style={{ width: 20, height: 2, background: '#2a9d8f' }} />
                  <span style={{ color: '#3fb8a8' }}>network link</span>
                </div>
              )}
              {/* Driven from NODE_CFG so the legend and the canvas glyphs stay in step. */}
              {[['Role', 'role'], ['User', 'user'], ['Group', 'group'],
                ['Policy', 'policy'], ['Resource', 'resource'], ['Account', 'account']]
                .map(([lbl, key]) => (
                <div key={lbl} style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '10px', color: 'var(--text-dim)' }}>
                  <NodeTypeIcon type={key} />
                  <span style={{ color: NODE_CFG[key].color }}>{lbl}</span>
                </div>
              ))}
            </div>
          </div>
        </div>{/* end body container */}

        <div className="slideover-footer">
          <span style={{ fontSize: '10px', color: 'var(--text-faint)', marginRight: 'auto' }}>
            {isPathMode ? 'Amber dashed = attack step · Click node to inspect' : 'Click to inspect · Right-click to remove · Drag nodes · Scroll to zoom · ⛭ Controls'}
          </span>
          <button className="btn secondary sm" onClick={onClose}>Close</button>
        </div>
      </div>
    </>
  )
}
