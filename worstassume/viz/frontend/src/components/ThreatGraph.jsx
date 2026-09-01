/**
 * ThreatGraph — inline, incrementally-expanded inbound access graph.
 *
 * The analyst seeds an asset, expands it to see everything that can
 * reach it in one hop, expands one of those, prunes the noise, and repeats.
 * Every expansion is a call to /api/threat-model/neighbors, so the canvas only
 * ever holds what was deliberately pulled onto it.
 *
 * Distinct from GraphViewer: that one is a slide-over over the *structural*
 * graph (IAM attachments, trust, network topology). This one is embedded in a
 * page and walks *access* edges backwards, coloured by family and severity.
 *
 * Props:
 *   roots        – array of {arn, label, node_type, ...} to seed the canvas
 *   initialGraph – a saved {nodes, edges, expanded, removed} blob to restore
 *   onStateChange – (state) => void, fired with the serialisable canvas state
 *   onPrivEsc    – (arn) => void, "send this node to a PrivEsc scan"
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import cytoscape from 'cytoscape'
import { api } from '../api'
import EntityDetailPanel from './EntityDetailPanel'
import ControlsPanel from './GraphControls'
import ResizeHandle from './ResizeHandle'
import NodeTypeIcon from './NodeTypeIcon'
import { useResizableWidth } from './useResizableWidth'
import { useApp } from '../context/AppContext'
import {
  cfgFor, shortLabel, iconSvgUrl, dataToEntity, NODE_CFG, CANVAS,
  baseStylesheet, typeGradientStyles, CIRCLE_LAYOUT, COSE_LAYOUT,
  SEV_COLOR, SEV_RANK, FAMILY_META,
} from './graphShared'

// Node types the legend spells out, read off NODE_CFG so the icons and colours
// cannot drift from what the canvas actually draws.
const LEGEND_TYPES = [
  ['Role', 'role'], ['User', 'user'], ['Group', 'group'],
  ['Resource', 'resource'], ['Account', 'account'],
]

// ─── Edge helpers ─────────────────────────────────────────────────────────────

function edgeId(source, target) { return `tm-${source}→${target}` }

/** Compact edge label: the worst edge's action, truncated. */
function edgeLabel(edges) {
  const first = [...edges].sort(
    (a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9))[0]
  const action = first?.action || first?.edge_type || ''
  return action.length > 26 ? action.slice(0, 25) + '…' : action
}

function worstSeverity(edges) {
  return [...edges].sort(
    (a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9))[0]?.severity || 'MEDIUM'
}

/** Backend node dict → cytoscape node data. */
function nodeData(n, { isRoot = false } = {}) {
  const cfg = cfgFor(n)
  // Every account has its own AWSControlTowerExecution / OrganizationAccount-
  // AccessRole, so a bare name is genuinely ambiguous on a cross-account graph.
  // Tag the account onto anything outside the target's own.
  const short = shortLabel(n.label || n.arn)
  const label = n.external && n.account_id ? `${short} @${n.account_id}` : short
  const nodeType = n.node_type === 'resource'
    ? 'resource' : (n.principal_type || n.node_type || 'role')
  return {
    id: n.arn,
    label,
    // Root nodes use the same type icon as everything else; they are marked out
    // by the border treatment in the stylesheet, not by a special glyph.
    iconUrl: iconSvgUrl(nodeType),
    nodeType,
    typeColor: cfg.color,
    typeShape: cfg.shape,
    fullLabel: n.label || n.arn,
    arn: n.arn,
    account_id: n.account_id,
    node_type: n.node_type,
    principal_type: n.principal_type,
    service: n.service,
    resource_type: n.resource_type,
    risk: n.risk || null,
    findings: n.findings || 0,
    external: !!n.external,
    isRoot: !!isRoot,
  }
}

function buildStylesheet(nodeSize, edgeOpacity) {
  const familyStyles = Object.entries(FAMILY_META).map(([family, meta]) => ({
    selector: `edge[family = "${family}"]`,
    style: { 'line-color': meta.color, 'target-arrow-color': meta.color },
  }))
  const sevStyles = Object.entries(SEV_COLOR).map(([sev, color]) => ({
    // Abuse edges carry real severity, so colour those by severity instead.
    selector: `edge[family = "abuse"][severity = "${sev}"]`,
    style: { 'line-color': color, 'target-arrow-color': color },
  }))
  return [
    ...baseStylesheet(nodeSize, edgeOpacity),
    {
      // No label here on purpose. Rotated labels on parallel bezier edges stack
      // on top of each other and sit across the lines they describe; the colour
      // carries family/severity and hovering an edge shows the detail.
      selector: 'edge',
      style: {
        'width': 1.6,
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'arrow-scale': 0.8,
        'opacity': edgeOpacity,
        'overlay-opacity': 0,
      },
    },
    // Hovered edge — thickened and opaque so the hover card has an obvious anchor.
    {
      selector: 'edge.hovered',
      style: { 'width': 3.5, 'opacity': 1, 'z-index': 99 },
    },
    ...familyStyles,
    ...sevStyles,
    { selector: 'edge:selected', style: { 'width': 3, 'opacity': 1 } },
    ...typeGradientStyles(),
    // The seeded asset — same icon and colour as any other node of its type,
    // picked out with a heavier ring and a glow in the app's accent.
    {
      selector: 'node[?isRoot]',
      style: {
        'border-width': 3,
        'border-color': CANVAS.amber,
        'border-opacity': 1,
        'shadow-blur': 26,
        'shadow-color': CANVAS.amber,
        'shadow-opacity': 0.55,
        'font-size': 11,
        'color': CANVAS.amber,
      },
    },
    // External identities get a red ring so they read at a glance.
    {
      selector: 'node[?external]',
      style: { 'border-color': CANVAS.red, 'border-width': 2.5, 'border-opacity': 0.95 },
    },
  ]
}

// ─── Neighbour picker ─────────────────────────────────────────────────────────

function SevBadge({ sev }) {
  return (
    <span style={{
      fontSize: '9px', padding: '1px 5px', borderRadius: '3px',
      color: SEV_COLOR[sev] || 'var(--text-dim)',
      border: `1px solid ${SEV_COLOR[sev] || 'var(--border2)'}55`,
      background: `${SEV_COLOR[sev] || '#333'}18`,
    }}>{sev}</span>
  )
}

/**
 * When an expansion returns more neighbours than fit on a canvas, the analyst
 * picks which ones matter instead of having hundreds dumped on them.
 */
function NeighborPicker({ target, page, families, onToggleFamily, onAdd, onLoadMore,
                          loading, onClose, width, resizing, onResizeDown, panelRef }) {
  const [query, setQuery] = useState('')
  const [chosen, setChosen] = useState(() => new Set())

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return page.neighbors
    return page.neighbors.filter(n =>
      (n.label || '').toLowerCase().includes(q) || (n.arn || '').toLowerCase().includes(q))
  }, [page.neighbors, query])

  function toggle(arn) {
    setChosen(prev => {
      const next = new Set(prev)
      if (next.has(arn)) next.delete(arn); else next.add(arn)
      return next
    })
  }

  return (
    <div ref={panelRef} style={{
      position: 'absolute', top: 0, right: 0, bottom: 0, width: `${width}px`, zIndex: 25,
      background: 'var(--bg1)', borderLeft: '1px solid var(--border2)',
      display: 'flex', flexDirection: 'column', boxShadow: '-4px 0 24px rgba(0,0,0,0.5)',
    }}>
      <ResizeHandle onPointerDown={onResizeDown} active={resizing} side="left" />
      <div style={{ padding: '10px 12px', borderBottom: '1px solid var(--border)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: '11px', color: 'var(--text)', flex: 1, overflow: 'hidden',
                         textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            Who can reach <strong>{shortLabel(target)}</strong>
          </span>
          <button className="btn secondary sm" onClick={onClose}>✕</button>
        </div>
        <div style={{ fontSize: '10px', color: 'var(--text-faint)', marginTop: 4 }}>
          Showing top {page.neighbors.length} of {page.total_found.toLocaleString()}
          {page.truncated && ' — ranked by exposure'}
        </div>
        <div style={{ display: 'flex', gap: 4, marginTop: 8, flexWrap: 'wrap' }}>
          {Object.entries(FAMILY_META)
            .filter(([f]) => f !== 'trust_policy')
            .map(([f, meta]) => (
              <button key={f} title={meta.hint} onClick={() => onToggleFamily(f)}
                style={{
                  fontSize: '9px', padding: '2px 7px', borderRadius: '3px', cursor: 'pointer',
                  fontFamily: 'inherit',
                  background: families.includes(f) ? `${meta.color}22` : 'transparent',
                  border: `1px solid ${families.includes(f) ? meta.color : 'var(--border2)'}`,
                  color: families.includes(f) ? meta.color : 'var(--text-faint)',
                }}>{meta.label}</button>
            ))}
        </div>
        <input value={query} onChange={e => setQuery(e.target.value)}
          placeholder="Filter by name or ARN…" className="filter-search"
          style={{ width: '100%', marginTop: 8 }} />
      </div>

      <div style={{ flex: 1, overflowY: 'auto' }}>
        {shown.length === 0 && (
          <div style={{ padding: '20px 14px', fontSize: '11px',
                        color: 'var(--text-faint)', lineHeight: 1.6 }}>
            {loading ? 'Loading…' : page.identity_applies === false
              ? 'IAM identity policies are not how access to a network container is '
                + 'granted — there is nothing to call on a VPC, subnet or security group. '
                + 'Turn on the Network family to see what sits inside it, then inspect '
                + 'those instances or their roles for real access.'
              : 'Nothing can reach this node via the selected families.'}
          </div>
        )}
        {shown.map(n => (
          <label key={n.arn} style={{
            display: 'flex', gap: 8, padding: '7px 12px', cursor: 'pointer',
            borderBottom: '1px solid var(--border)', alignItems: 'flex-start',
          }}>
            <input type="checkbox" checked={chosen.has(n.arn)}
              onChange={() => toggle(n.arn)} style={{ marginTop: 3, accentColor: 'var(--amber)' }} />
            <div style={{ minWidth: 0, flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontSize: '11px', color: 'var(--text)', overflow: 'hidden',
                               textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{n.label}</span>
                <SevBadge sev={n.worst_severity} />
                {n.external && (
                  <span style={{ fontSize: '9px', color: '#c03030' }}>EXTERNAL</span>
                )}
              </div>
              <div style={{ fontSize: '9px', color: 'var(--text-faint)', marginTop: 2,
                            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {n.arn}
              </div>
              <div style={{ display: 'flex', gap: 4, marginTop: 3, flexWrap: 'wrap' }}>
                {[...new Set(n.edges.map(e => e.family))].map(f => (
                  <span key={f} style={{
                    fontSize: '8px', padding: '0 4px', borderRadius: '2px',
                    color: FAMILY_META[f]?.color || 'var(--text-faint)',
                    border: `1px solid ${FAMILY_META[f]?.color || 'var(--border2)'}44`,
                  }}>{FAMILY_META[f]?.label || f}</span>
                ))}
              </div>
              {/* Why this principal is on the list, not just that it is. */}
              <div style={{ marginTop: 4, display: 'flex', flexDirection: 'column', gap: 2 }}>
                {n.edges.slice(0, 3).map((e, i) => (
                  <div key={i} style={{ fontSize: '9px', color: 'var(--text-dim)',
                                        lineHeight: 1.45 }}>
                    <span style={{ color: SEV_COLOR[e.severity] || 'var(--text-dim)' }}>•</span>{' '}
                    <span style={{ fontFamily: 'IBM Plex Mono, monospace' }}>{e.action}</span>
                    {e.detail && <span style={{ color: 'var(--text-faint)' }}> ({e.detail})</span>}
                  </div>
                ))}
                {n.edges.length > 3 && (
                  <div style={{ fontSize: '9px', color: 'var(--text-faint)' }}>
                    +{n.edges.length - 3} more
                  </div>
                )}
              </div>
            </div>
          </label>
        ))}
      </div>

      <div style={{ padding: '8px 12px', borderTop: '1px solid var(--border)',
                    display: 'flex', gap: 8 }}>
        <button className="btn primary sm" style={{ flex: 1, justifyContent: 'center' }}
          disabled={chosen.size === 0}
          onClick={() => onAdd(page.neighbors.filter(n => chosen.has(n.arn)))}>
          ⊕ Add {chosen.size || ''} to graph
        </button>
        <button className="btn secondary sm"
          onClick={() => onAdd(shown)}>Add all shown</button>
        {page.truncated && (
          <button className="btn secondary sm" disabled={loading} onClick={onLoadMore}>
            Load more
          </button>
        )}
      </div>
    </div>
  )
}

/** "What this can reach" — one block per target, with the reasons for each. */
function ReachTab({ groups }) {
  return (
    <div className="sb-block" style={{ borderBottom: 'none' }}>
      {groups.map(grp => (
        <div key={grp.target} style={{ marginTop: 8 }}>
          <div style={{ fontSize: '10px', color: 'var(--white)',
                        display: 'flex', alignItems: 'center', gap: 5 }}>
            <span style={{ color: 'var(--text-faint)' }}>→</span>
            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis',
                           whiteSpace: 'nowrap' }}>{shortLabel(grp.targetLabel)}</span>
          </div>
          <div className="sb-arn" style={{ fontSize: '9px' }}>{grp.target}</div>
          {grp.reasons.map((e, i) => (
            <div key={i} style={{ marginTop: 5, marginLeft: 10,
                                  fontSize: '10px', lineHeight: 1.5 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{ fontSize: '8px', padding: '0 4px', borderRadius: '2px',
                               color: FAMILY_META[e.family]?.color || 'var(--text-faint)',
                               border: `1px solid ${FAMILY_META[e.family]?.color || 'var(--border2)'}44` }}>
                  {FAMILY_META[e.family]?.label || e.family}
                </span>
                <SevBadge sev={e.severity} />
              </div>
              <div style={{ color: 'var(--text)', fontFamily: 'IBM Plex Mono, monospace',
                            marginTop: 2, wordBreak: 'break-word' }}>{e.action}</div>
              {e.explanation && (
                <div style={{ color: 'var(--text-faint)', marginTop: 2 }}>{e.explanation}</div>
              )}
            </div>
          ))}
        </div>
      ))}
    </div>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

const AUTO_ADD_THRESHOLD = 12   // below this, skip the picker and just expand

export default function ThreatGraph({ roots = [], initialGraph = null,
                                      onStateChange, onPrivEsc }) {
  const { findings, entities, ensureEntities } = useApp()
  const entitiesRef = useRef(null)
  useEffect(() => { entitiesRef.current = entities }, [entities])
  useEffect(() => { ensureEntities?.().catch(() => {}) }, [ensureEntities])

  const containerRef = useRef(null)
  const cyRef = useRef(null)
  const removedRef = useRef(new Set())     // never re-add what the analyst pruned
  const expandedRef = useRef(new Set())    // nodes already expanded
  const rootsRef = useRef(new Set())

  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [selected, setSelected] = useState(null)
  const [selectedId, setSelectedId] = useState(null)
  const [ctxMenu, setCtxMenu] = useState(null)
  const [edgeHover, setEdgeHover] = useState(null)
  const [controlsOpen, setControlsOpen] = useState(false)   // {x, y, edges, source, target}
  const [picker, setPicker] = useState(null)   // {target, page, limit}
  const [families, setFamilies] = useState(
    ['identity_policy', 'resource_policy', 'abuse', 'runs_as', 'network'])
  // One width for both right-hand panels: they are mutually exclusive and
  // share an edge, so resizing one and swapping should not make it jump.
  // Bounded by the canvas, not a fixed number — the graph pane can be narrower
  // than any constant we might pick, and the panel must never exceed it.
  const panel = useResizableWidth({
    initial: 380, min: 320, side: 'right',
    max: () => Math.max(320, (containerRef.current?.clientWidth ?? window.innerWidth) - 40),
  })
  const [nodeSize, setNodeSize] = useState(28)
  const [edgeOpacity, setEdgeOpacity] = useState(0.8)
  const [counts, setCounts] = useState({ nodes: 0, edges: 0 })

  // ── Canvas state → parent (for saving) ─────────────────────────────────────

  const emitState = useCallback(() => {
    const cy = cyRef.current
    if (!cy) return
    const state = {
      nodes: cy.nodes().map(n => {
        const d = n.data()
        const p = n.position()
        return {
          arn: d.arn, label: d.fullLabel, node_type: d.node_type,
          principal_type: d.principal_type, service: d.service,
          resource_type: d.resource_type, account_id: d.account_id,
          risk: d.risk, findings: d.findings, external: d.external,
          isRoot: d.isRoot, x: p.x, y: p.y,
        }
      }),
      edges: cy.edges().map(e => {
        const d = e.data()
        return { source: d.source, target: d.target, family: d.family,
                 edge_type: d.edge_type, action: d.action, severity: d.severity,
                 details: d.details || [] }
      }),
      expanded: [...expandedRef.current],
      removed: [...removedRef.current],
    }
    setCounts({ nodes: state.nodes.length, edges: state.edges.length })
    onStateChange?.(state)
  }, [onStateChange])

  // ── Element helpers ────────────────────────────────────────────────────────

  const addElements = useCallback((nodes, edges, { relayout = true } = {}) => {
    const cy = cyRef.current
    if (!cy) return false
    const toAdd = []
    nodes.forEach(n => {
      if (!n.arn || removedRef.current.has(n.arn)) return
      if (cy.getElementById(n.arn).nonempty()) return
      toAdd.push({ group: 'nodes', data: nodeData(n, { isRoot: rootsRef.current.has(n.arn) }) })
    })
    edges.forEach(e => {
      if (!e.source || !e.target || e.source === e.target) return
      if (removedRef.current.has(e.source) || removedRef.current.has(e.target)) return
      const id = edgeId(e.source, e.target)
      if (cy.getElementById(id).nonempty()) return
      toAdd.push({ group: 'edges', data: { id, ...e } })
    })
    if (!toAdd.length) return false
    // Only add edges whose endpoints will exist on the canvas.
    const pending = new Set([...cy.nodes().map(n => n.id()),
                             ...toAdd.filter(el => el.group === 'nodes').map(el => el.data.id)])
    cy.add(toAdd.filter(el => el.group === 'nodes'
                          || (pending.has(el.data.source) && pending.has(el.data.target))))
    if (relayout) {
      cy.layout(cy.nodes().length <= 30 ? CIRCLE_LAYOUT : COSE_LAYOUT).run()
    }
    emitState()
    return true
  }, [emitState])

  /** Turn one InboundPage into nodes + edges pointing at its target. */
  const pageToElements = useCallback((page, neighbors) => {
    const nodes = [page.node, ...neighbors]
    const edges = neighbors.map(n => ({
      source: n.arn,
      target: page.node.arn,
      family: n.edges[0]?.family || 'abuse',
      edge_type: n.edges[0]?.edge_type || '',
      action: n.edges[0]?.action || '',
      severity: n.worst_severity || worstSeverity(n.edges),
      label: edgeLabel(n.edges),
      details: n.edges,
    }))
    return { nodes, edges }
  }, [])

  // ── Expansion ──────────────────────────────────────────────────────────────

  const fetchNeighbors = useCallback(async (arn, limit) => {
    return api.threatModelNeighbors(arn, { limit, families: families.join(',') })
  }, [families])

  const expand = useCallback(async (arn) => {
    if (!arn) return
    setLoading(true); setError(null); setCtxMenu(null)
    try {
      const page = await fetchNeighbors(arn, 50)
      expandedRef.current.add(arn)
      if (page.total_found <= AUTO_ADD_THRESHOLD) {
        const { nodes, edges } = pageToElements(page, page.neighbors)
        addElements(nodes, edges)
        if (page.total_found === 0) setError(`Nothing can reach ${shortLabel(arn)} via the selected families.`)
      } else {
        setPicker({ target: arn, page, limit: 50 })
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [fetchNeighbors, pageToElements, addElements])

  const loadMore = useCallback(async () => {
    if (!picker) return
    setLoading(true)
    try {
      const limit = picker.limit + 50
      const page = await fetchNeighbors(picker.target, limit)
      setPicker({ target: picker.target, page, limit })
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [picker, fetchNeighbors])

  // Toggling a family has to re-ask the server — the picker renders a page
  // that was already fetched, so without this the chips changed colour and
  // nothing else happened.
  const pickerTarget = picker?.target
  const pickerLimit = picker?.limit
  useEffect(() => {
    if (!pickerTarget) return
    let cancelled = false
    setLoading(true)
    fetchNeighbors(pickerTarget, pickerLimit || 50)
      .then(page => { if (!cancelled) setPicker({ target: pickerTarget, page, limit: pickerLimit || 50 }) })
      .catch(err => { if (!cancelled) setError(err.message) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
    // Deliberately keyed on families only: re-running on every picker change
    // would loop, since this effect sets picker itself.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [families])

  const autoExpand = useCallback(async (arn, hops) => {
    setLoading(true); setError(null); setCtxMenu(null)
    try {
      const { pages } = await api.threatModelNeighbors(arn, {
        hops, limit: 25, families: families.join(','),
      })
      const nodes = []
      const edges = []
      ;(pages || []).forEach(page => {
        expandedRef.current.add(page.node.arn)
        const el = pageToElements(page, page.neighbors)
        nodes.push(...el.nodes); edges.push(...el.edges)
      })
      addElements(nodes, edges)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [families, pageToElements, addElements])

  // ── Removal (with memory, so pruning survives later expansions) ────────────

  const removeNode = useCallback((id, alsoOrphans = false) => {
    const cy = cyRef.current
    if (!cy || !id) return
    const node = cy.getElementById(id)
    if (node.empty()) return
    const ids = [id]
    if (alsoOrphans) {
      node.neighborhood('node').forEach(nb => {
        if (nb.degree(false) <= 1) ids.push(nb.id())
      })
    }
    let coll = cy.collection()
    ids.forEach(rid => {
      removedRef.current.add(rid)
      rootsRef.current.delete(rid)
      coll = coll.union(cy.getElementById(rid))
    })
    cy.remove(coll)
    setCtxMenu(null)
    if (ids.includes(selectedId)) { setSelected(null); setSelectedId(null) }
    emitState()
  }, [selectedId, emitState])

  const clearAll = useCallback(() => {
    const cy = cyRef.current
    if (!cy) return
    cy.elements().remove()
    removedRef.current = new Set()
    expandedRef.current = new Set()
    rootsRef.current = new Set()
    setSelected(null); setSelectedId(null); setCtxMenu(null); setPicker(null)
    emitState()
  }, [emitState])

  // ── Init cytoscape ─────────────────────────────────────────────────────────

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
      const rich = entitiesRef.current?.find(e => e.arn === d.arn)
      setSelected(rich || dataToEntity(d))
      setSelectedId(d.id)
      setCtxMenu(null)
    })
    cy.on('tap', evt => {
      if (evt.target === cy) { setSelected(null); setSelectedId(null) }
      setCtxMenu(null)
    })
    cy.on('cxttap', 'node', evt => {
      const d = evt.target.data()
      const pos = evt.renderedPosition || { x: 0, y: 0 }
      setCtxMenu({ x: pos.x, y: pos.y, id: d.id, label: d.fullLabel || d.label })
    })
    cy.on('dragfree', 'node', () => emitState())
    // Edges carry no drawn label; hovering one reveals why it exists.
    cy.on('mouseover', 'edge', evt => {
      const d = evt.target.data()
      evt.target.addClass('hovered')
      const pos = evt.renderedPosition || evt.target.midpoint() || { x: 0, y: 0 }
      setEdgeHover({
        x: pos.x, y: pos.y,
        source: d.source, target: d.target,
        edges: d.details?.length ? d.details : [d],
      })
    })
    cy.on('mouseout', 'edge', evt => {
      evt.target.removeClass('hovered')
      setEdgeHover(null)
    })
    cy.on('pan zoom', () => { setCtxMenu(null); setEdgeHover(null) })
    cyRef.current = cy
    return () => cy.destroy()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // ── Restore a saved graph ──────────────────────────────────────────────────

  useEffect(() => {
    const cy = cyRef.current
    if (!cy || !initialGraph) return
    cy.elements().remove()
    removedRef.current = new Set(initialGraph.removed || [])
    expandedRef.current = new Set(initialGraph.expanded || [])
    rootsRef.current = new Set((initialGraph.nodes || []).filter(n => n.isRoot).map(n => n.arn))
    const nodes = (initialGraph.nodes || []).map(n => ({
      group: 'nodes',
      data: nodeData(n, { isRoot: !!n.isRoot }),
      position: (typeof n.x === 'number' && typeof n.y === 'number')
        ? { x: n.x, y: n.y } : undefined,
    }))
    const present = new Set(nodes.map(n => n.data.id))
    const edges = (initialGraph.edges || [])
      .filter(e => present.has(e.source) && present.has(e.target))
      .map(e => ({
        group: 'edges',
        data: { id: edgeId(e.source, e.target), ...e, label: e.action ? edgeLabel([e]) : '' },
      }))
    cy.add([...nodes, ...edges])
    // Saved layouts are restored verbatim; only re-run if positions were absent.
    if (nodes.some(n => !n.position)) {
      cy.layout(cy.nodes().length <= 30 ? CIRCLE_LAYOUT : COSE_LAYOUT).run()
    } else {
      cy.fit(undefined, 60)
    }
    setSelected(null); setSelectedId(null); setPicker(null)
    emitState()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialGraph])

  // ── Seed roots ─────────────────────────────────────────────────────────────

  useEffect(() => {
    const cy = cyRef.current
    if (!cy || !roots.length) return
    const fresh = roots.filter(r => r.arn && !rootsRef.current.has(r.arn))
    if (!fresh.length) return
    fresh.forEach(r => {
      rootsRef.current.add(r.arn)
      removedRef.current.delete(r.arn)
    })
    const added = addElements(fresh, [])
    // Expansion stays an explicit act — seeding an asset that 2,000 principals
    // can reach should not immediately throw a picker at the analyst. Instead
    // select the new node so its "⊕ Expand inbound" button is already on screen.
    //
    // Only when something was actually added: returning to the page re-runs
    // this effect with roots that are already on the restored canvas, and
    // popping the panel open every time would be noise.
    if (!added) return
    const last = fresh[fresh.length - 1]
    setSelected(dataToEntity(nodeData(last, { isRoot: true })))
    setSelectedId(last.arn)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [roots])

  // ── Slider sync ────────────────────────────────────────────────────────────

  useEffect(() => {
    cyRef.current?.nodes().style({ width: nodeSize, height: nodeSize })
  }, [nodeSize])

  useEffect(() => {
    cyRef.current?.edges().style({ opacity: edgeOpacity })
  }, [edgeOpacity])

  // ── Render ─────────────────────────────────────────────────────────────────

  const isEmpty = counts.nodes === 0

  // What the selected node can reach, grouped by target.
  //
  // A node stays on the canvas across expansions, so it can hold edges to
  // several different assets — and AWS names roles identically across accounts
  // (every account has its own AWSControlTowerExecution). Listing the reasons
  // without saying which asset each one is for invites reading a neighbour as
  // "reaching" something it has no edge to at all.
  const selectedReach = (() => {
    const cy = cyRef.current
    if (!cy || !selectedId) return []
    // Filtered in JS rather than via a selector string: ARNs are full of
    // characters cytoscape's selector grammar would need escaping for.
    return cy.edges().map(e => e.data())
      .filter(d => d.source === selectedId)
      .map(d => ({
        target: d.target,
        targetLabel: cy.getElementById(d.target).data('fullLabel') || d.target,
        reasons: d.details?.length ? d.details : [d],
      }))
  })()

  return (
    <div className="graph-canvas-area" style={{ minHeight: 0 }}>
      <div ref={containerRef} style={{ width: '100%', height: '100%' }} />

      {isEmpty && !loading && (
        <div style={{
          position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
          alignItems: 'center', justifyContent: 'center', gap: 10, pointerEvents: 'none',
        }}>
          <div className="empty-state-icon">🔍</div>
          <div style={{ fontSize: '12px', color: 'var(--text-dim)' }}>
            Pick an asset on the left to start mapping
          </div>
          <div style={{ fontSize: '10px', color: 'var(--text-faint)', maxWidth: 380,
                        textAlign: 'center', lineHeight: 1.6 }}>
            Each expansion shows everything that can reach the selected node in one hop.
            Expand a neighbour to keep walking the exposure outwards.
          </div>
        </div>
      )}

      {loading && (
        <div style={{
          position: 'absolute', top: 12, left: 12, zIndex: 20, display: 'flex',
          alignItems: 'center', gap: 8, background: 'var(--bg1)', padding: '5px 10px',
          border: '1px solid var(--border2)', borderRadius: '4px',
        }}>
          <div className="spinner-ring" style={{ width: 13, height: 13, borderWidth: 2 }} />
          <span style={{ fontSize: '10px', color: 'var(--text-dim)' }}>Expanding…</span>
        </div>
      )}

      {error && (
        <div style={{
          position: 'absolute', bottom: 12, left: 12, zIndex: 20, maxWidth: '60%',
          background: 'var(--bg1)', border: '1px solid rgba(192,48,48,.35)',
          borderRadius: '4px', padding: '6px 10px', fontSize: '10px', color: 'var(--red-hi)',
          display: 'flex', alignItems: 'center', gap: 8,
        }}>
          <span style={{ flex: 1 }}>{error}</span>
          <button className="btn secondary sm" onClick={() => setError(null)}>✕</button>
        </div>
      )}

      <ControlsPanel cyRef={cyRef} open={controlsOpen}
        onToggle={() => setControlsOpen(o => !o)}
        nodeSize={nodeSize} setNodeSize={setNodeSize}
        edgeOpacity={edgeOpacity} setEdgeOpacity={setEdgeOpacity}
        onRelayout={() => {
          const cy = cyRef.current
          cy?.layout(cy.nodes().length <= 30 ? CIRCLE_LAYOUT : COSE_LAYOUT).run()
        }}
        onClear={clearAll} />

      {/* Legend — bottom-left, same layout as the GraphViewer legend */}
      <div style={{ position: 'absolute', bottom: 12, left: 12, zIndex: 10,
                    display: 'flex', flexDirection: 'column', gap: 4 }}>
        {Object.entries(FAMILY_META).filter(([f]) => f !== 'trust_policy').map(([f, meta]) => (
          <div key={f} title={meta.hint}
            style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '10px' }}>
            <div style={{ width: 20, height: 2, background: meta.color }} />
            <span style={{ color: meta.color }}>{meta.label}</span>
          </div>
        ))}
        <div style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '10px',
                      marginBottom: 4 }}>
          <div style={{ width: 8, height: 8, borderRadius: '50%',
                        border: '2px solid #c03030' }} />
          <span style={{ color: '#c03030' }}>external</span>
        </div>
        {LEGEND_TYPES.map(([lbl, key]) => (
          <div key={lbl} style={{ display: 'flex', alignItems: 'center', gap: '5px',
                                  fontSize: '10px', color: 'var(--text-dim)' }}>
            <NodeTypeIcon type={key} />
            <span style={{ color: NODE_CFG[key].color }}>{lbl}</span>
          </div>
        ))}
      </div>

      {/* Context menu */}
      {ctxMenu && (
        <div style={{
          position: 'absolute', left: ctxMenu.x, top: ctxMenu.y, zIndex: 30,
          background: 'var(--bg1)', border: '1px solid var(--border2)', borderRadius: '4px',
          boxShadow: '0 6px 20px rgba(0,0,0,0.55)', minWidth: '210px', overflow: 'hidden',
        }}>
          <div style={{ padding: '6px 10px', fontSize: '10px', color: 'var(--text-faint)',
                        borderBottom: '1px solid var(--border)', whiteSpace: 'nowrap',
                        overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {ctxMenu.label}
          </div>
          {[
            { label: '⊕  Expand inbound (1 hop)', fn: () => expand(ctxMenu.id) },
            { label: '⊕⊕ Auto-expand 2 hops', fn: () => autoExpand(ctxMenu.id, 2) },
            { label: '⚡ Send to PrivEsc', fn: () => { onPrivEsc?.(ctxMenu.id); setCtxMenu(null) } },
            { label: '✕  Remove node', fn: () => removeNode(ctxMenu.id) },
            { label: '✕  Remove node + orphaned', fn: () => removeNode(ctxMenu.id, true) },
          ].map(({ label, fn }) => (
            <button key={label} onClick={fn}
              style={{ display: 'block', width: '100%', textAlign: 'left', padding: '7px 10px',
                       background: 'transparent', border: 'none', color: 'var(--text)',
                       fontSize: '11px', cursor: 'pointer', fontFamily: 'inherit' }}
              onMouseEnter={e => { e.currentTarget.style.background = 'var(--bg3)' }}
              onMouseLeave={e => { e.currentTarget.style.background = 'transparent' }}>
              {label}
            </button>
          ))}
        </div>
      )}

      {/* Edge hover card — horizontal and readable, unlike a rotated canvas label */}
      {edgeHover && (
        <div style={{
          position: 'absolute', left: edgeHover.x + 12, top: edgeHover.y + 12, zIndex: 35,
          pointerEvents: 'none', maxWidth: 340,
          background: 'var(--bg1)', border: '1px solid var(--border2)', borderRadius: '4px',
          boxShadow: '0 6px 20px rgba(0,0,0,0.55)', padding: '7px 10px',
        }}>
          <div style={{ fontSize: '9px', color: 'var(--text-faint)', marginBottom: 4,
                        whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {shortLabel(edgeHover.source)} → {shortLabel(edgeHover.target)}
          </div>
          {edgeHover.edges.slice(0, 4).map((e, i) => (
            <div key={i} style={{ marginTop: i ? 5 : 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{ fontSize: '8px', padding: '0 4px', borderRadius: '2px',
                               color: FAMILY_META[e.family]?.color || 'var(--text-faint)',
                               border: `1px solid ${FAMILY_META[e.family]?.color || 'var(--border2)'}44` }}>
                  {FAMILY_META[e.family]?.label || e.family}
                </span>
                <SevBadge sev={e.severity} />
              </div>
              <div style={{ fontSize: '10px', color: 'var(--text)', marginTop: 2,
                            fontFamily: 'IBM Plex Mono, monospace', wordBreak: 'break-word' }}>
                {e.action}
              </div>
            </div>
          ))}
          {edgeHover.edges.length > 4 && (
            <div style={{ fontSize: '9px', color: 'var(--text-faint)', marginTop: 4 }}>
              +{edgeHover.edges.length - 4} more — select the node to see them all
            </div>
          )}
        </div>
      )}

      {/* Neighbour picker */}
      {picker && (
        <NeighborPicker
          target={picker.target}
          page={picker.page}
          families={families}
          loading={loading}
          width={panel.width}
          resizing={panel.resizing}
          onResizeDown={panel.onResizeDown}
          panelRef={panel.panelRef}
          onToggleFamily={f => setFamilies(prev =>
            prev.includes(f) ? (prev.length > 1 ? prev.filter(x => x !== f) : prev) : [...prev, f])}
          onAdd={chosen => {
            const { nodes, edges } = pageToElements(picker.page, chosen)
            addElements(nodes, edges)
            setPicker(null)
          }}
          onLoadMore={loadMore}
          onClose={() => setPicker(null)}
        />
      )}

      {/* Node detail */}
      {selected && !picker && (
        <div ref={panel.panelRef} style={{
          position: 'absolute', top: 0, right: 0, bottom: 0,
          width: `${panel.width}px`, zIndex: 20,
          display: 'flex', background: 'var(--bg1)',
          boxShadow: '-4px 0 24px rgba(0,0,0,0.5)',
        }}>
          <ResizeHandle onPointerDown={panel.onResizeDown} active={panel.resizing} side="left" />
          <EntityDetailPanel
            entity={selected}
            findings={findings}
            onClose={() => { setSelected(null); setSelectedId(null); cyRef.current?.nodes().unselect() }}
            actions={[
              { label: '⊕ Expand inbound', variant: 'primary', grow: true,
                onClick: () => expand(selectedId) },
              { label: '⚡ PrivEsc', onClick: () => onPrivEsc?.(selectedId) },
              { label: '✕ Remove', variant: 'danger',
                title: 'Remove this node from the graph',
                onClick: () => removeNode(selectedId) },
            ]}
            // Reachability is derived from what is on this canvas, so it stays
            // owned by the graph and is handed to the sidebar as its own tab.
            extraTabs={selectedReach.length > 0 ? [{
              id: 'reaches',
              label: 'Reaches',
              count: selectedReach.length,
              render: () => <ReachTab groups={selectedReach} />,
            }] : []}
          />
        </div>
      )}
    </div>
  )
}
