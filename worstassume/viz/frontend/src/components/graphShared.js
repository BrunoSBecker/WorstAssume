/**
 * graphShared — cytoscape primitives shared by GraphViewer and ThreatGraph.
 *
 * Node iconography, label shortening, layout presets and the base stylesheet
 * live here so the two canvases look and behave the same. Each canvas appends
 * its own edge selectors on top of the base stylesheet: GraphViewer styles
 * attack paths and network links, ThreatGraph styles inbound access families.
 *
 * Constants and helpers only — the shared ControlsPanel component lives in
 * GraphControls.jsx so react-refresh can treat each file as one kind of module.
 */

// ─── Canvas palette ───────────────────────────────────────────────────────────
// Cytoscape renders to a canvas and does NOT resolve CSS custom properties — a
// `var(--amber)` here silently parses as black. Every colour that reaches a
// stylesheet must be a literal. These mirror index.css.
export const CANVAS = {
  bg: '#0b0d12',
  text: '#c8cdd8',
  textDim: '#8891a4',
  textFaint: '#4e5668',
  border: '#252830',
  amber: '#d97c14',
  red: '#c03030',
}

// ─── Type config ──────────────────────────────────────────────────────────────

// ─── Node type config ─────────────────────────────────────────────────────────
// `icon` is the MUI icon name (the legend renders the component); `pathD` is
// that icon's 24x24 path data, which is what the cytoscape canvas needs — it
// takes only a URL for background-image, so a React component cannot be used
// there. Keeping both on one record is what stops the legend and the canvas
// drifting apart, as four hand-copied emoji maps previously did.
export const NODE_CFG = {
  role: { shape: 'round-rectangle', color: '#3a9ab0',
    icon: 'AdminPanelSettings', pathD: 'M17 11c.34 0 .67.04 1 .09V6.27L10.5 3 3 6.27v4.91c0 4.54 3.2 8.79 7.5 9.82.55-.13 1.08-.32 1.6-.55-.69-.98-1.1-2.17-1.1-3.45 0-3.31 2.69-6 6-6 M17 13c-2.21 0-4 1.79-4 4s1.79 4 4 4 4-1.79 4-4-1.79-4-4-4m0 1.38c.62 0 1.12.51 1.12 1.12s-.51 1.12-1.12 1.12-1.12-.51-1.12-1.12.5-1.12 1.12-1.12m0 5.37c-.93 0-1.74-.46-2.24-1.17.05-.72 1.51-1.08 2.24-1.08s2.19.36 2.24 1.08c-.5.71-1.31 1.17-2.24 1.17' },
  principal: { shape: 'round-rectangle', color: '#3a9ab0',
    icon: 'AdminPanelSettings', pathD: 'M17 11c.34 0 .67.04 1 .09V6.27L10.5 3 3 6.27v4.91c0 4.54 3.2 8.79 7.5 9.82.55-.13 1.08-.32 1.6-.55-.69-.98-1.1-2.17-1.1-3.45 0-3.31 2.69-6 6-6 M17 13c-2.21 0-4 1.79-4 4s1.79 4 4 4 4-1.79 4-4-1.79-4-4-4m0 1.38c.62 0 1.12.51 1.12 1.12s-.51 1.12-1.12 1.12-1.12-.51-1.12-1.12.5-1.12 1.12-1.12m0 5.37c-.93 0-1.74-.46-2.24-1.17.05-.72 1.51-1.08 2.24-1.08s2.19.36 2.24 1.08c-.5.71-1.31 1.17-2.24 1.17' },
  user: { shape: 'ellipse', color: '#3dab6e',
    icon: 'Person', pathD: 'M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4m0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4' },
  group: { shape: 'ellipse', color: '#9a7fc8',
    icon: 'Groups', pathD: 'M12 12.75c1.63 0 3.07.39 4.24.9 1.08.48 1.76 1.56 1.76 2.73V18H6v-1.61c0-1.18.68-2.26 1.76-2.73 1.17-.52 2.61-.91 4.24-.91M4 13c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2m1.13 1.1c-.37-.06-.74-.1-1.13-.1-.99 0-1.93.21-2.78.58C.48 14.9 0 15.62 0 16.43V18h4.5v-1.61c0-.83.23-1.61.63-2.29M20 13c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2m4 3.43c0-.81-.48-1.53-1.22-1.85-.85-.37-1.79-.58-2.78-.58-.39 0-.76.04-1.13.1.4.68.63 1.46.63 2.29V18H24zM12 6c1.66 0 3 1.34 3 3s-1.34 3-3 3-3-1.34-3-3 1.34-3 3-3' },
  policy: { shape: 'round-rectangle', color: '#c878b0',
    icon: 'Policy', pathD: 'm21 5-9-4-9 4v6c0 5.55 3.84 10.74 9 12 2.3-.56 4.33-1.9 5.88-3.71l-3.12-3.12c-1.94 1.29-4.58 1.07-6.29-.64-1.95-1.95-1.95-5.12 0-7.07s5.12-1.95 7.07 0c1.71 1.71 1.92 4.35.64 6.29l2.9 2.9C20.29 15.69 21 13.38 21 11z' },
  resource: { shape: 'round-rectangle', color: '#d97c14',
    icon: 'Cloud', pathD: 'M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96' },
  account: { shape: 'ellipse', color: '#6070a0',
    icon: 'AccountBalance', pathD: 'M4 10h3v7H4zm6.5 0h3v7h-3zM2 19h20v3H2zm15-9h3v7h-3zm-5-9L2 6v2h20V6z' },
  external: { shape: 'ellipse', color: '#4e5668',
    icon: 'Bolt', pathD: 'M11 21h-1l1-7H7.5c-.58 0-.57-.32-.38-.66s.05-.08.07-.12C8.48 10.94 10.42 7.54 13 3h1l-1 7h3.5c.49 0 .56.33.47.51l-.07.15C12.96 17.55 11 21 11 21' },
  service: { shape: 'ellipse', color: '#6070a0',
    icon: 'Memory', pathD: 'M15 9H9v6h6zm-2 4h-2v-2h2zm8-2V9h-2V7c0-1.1-.9-2-2-2h-2V3h-2v2h-2V3H9v2H7c-1.1 0-2 .9-2 2v2H3v2h2v2H3v2h2v2c0 1.1.9 2 2 2h2v2h2v-2h2v2h2v-2h2c1.1 0 2-.9 2-2v-2h2v-2h-2v-2zm-4 6H7V7h10z' },
  wildcard: { shape: 'ellipse', color: '#c03030',
    icon: 'Public', pathD: 'M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2m-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39' },
}
export const DEFAULT_CFG = { shape: 'ellipse', color: '#4e5668',
  icon: 'Circle', pathD: 'M12 2C6.47 2 2 6.47 2 12s4.47 10 10 10 10-4.47 10-10S17.53 2 12 2' }

export function resolveType(n) { return n?.principal_type || n?.node_type || 'role' }
export function cfgFor(n) { return NODE_CFG[resolveType(n)] || DEFAULT_CFG }

export function arnType(arn = '') {
  if (arn.includes(':role/') || arn.includes('assumed-role')) return 'role'
  if (arn.includes(':user/')) return 'user'
  if (arn.includes(':group/')) return 'group'
  if (arn.includes(':policy/')) return 'policy'
  return 'resource'
}

export function shortLabel(id = '') {
  const a = id.replace(/^[^:]+:/, '')
  const p = a.split('/').pop() || a.split(':').pop() || id
  return p.length > 22 ? p.slice(0, 21) + '…' : p
}

/**
 * Node glyph for the cytoscape canvas, as a data-URI SVG.
 *
 * Cytoscape only accepts a URL for `background-image`, so an MUI icon has to be
 * serialized to markup before it can get here. Building it from the stored path
 * data keeps this a pure function — the alternative, rendering the React
 * component with react-dom/server, would drag the SSR renderer into the client
 * bundle to draw a 24px glyph.
 */
export function iconSvgUrl(type, color) {
  const cfg = NODE_CFG[type] || DEFAULT_CFG
  const fill = color || cfg.color
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="64" height="64">`
    + `<path fill="${fill}" d="${cfg.pathD}"/></svg>`
  return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`
}

export function makeData(n) {
  const nid = n.id || n.node_id
  const cfg = cfgFor(n)
  return {
    id: nid,
    label: shortLabel(n.label || nid),
    iconUrl: iconSvgUrl(resolveType(n)),
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
    metadata: n.metadata || null,
  }
}

export function dataToEntity(d) {
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
    metadata: d.metadata || null,
  }
}

// Network-topology edge types (built from resource metadata in graph_store)
export const NETWORK_EDGE_LABELS = { in_vpc: 'in vpc', in_subnet: 'in subnet', uses_sg: 'uses sg' }

// ─── Stylesheet ───────────────────────────────────────────────────────────────

/** Node + generic edge styles. Callers append their own edge selectors, then
 *  typeGradientStyles() last so the per-type gradients win. */
export function baseStylesheet(nodeSize, edgeOpacity) {
  return [
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
  ]
}

/** Per-type glass gradient — must be appended last. */
export function typeGradientStyles() {
  return Object.entries(NODE_CFG).map(([type, cfg]) => ({
    selector: `node[nodeType = "${type}"]`,
    style: {
      'background-fill': 'linear-gradient',
      'background-gradient-stop-colors': `${cfg.color} #080a0e`,
      'background-gradient-stop-positions': '0 100',
      'background-gradient-direction': 'to-bottom-right',
      'background-opacity': 0.50,
    },
  }))
}

// ─── Layout configs ───────────────────────────────────────────────────────────

export const CIRCLE_LAYOUT = {
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

export const COSE_LAYOUT = {
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
export const PATH_LAYOUT = {
  name: 'breadthfirst',
  directed: true,
  fit: true,
  padding: 80,
  animate: false,
  avoidOverlap: true,
  spacingFactor: 2.5,
}

export function pickLayout(n, isPath) {
  if (isPath) return PATH_LAYOUT
  return n <= 30 ? CIRCLE_LAYOUT : COSE_LAYOUT
}

// ─── Threat-model access families ─────────────────────────────────────────────
// An inbound hop can be justified by three different kinds of grant; each gets
// its own colour so the reason a neighbour is on the canvas reads at a glance.

export const SEV_COLOR = {
  CRITICAL: '#c03030',
  HIGH: '#d97c14',
  MEDIUM: '#c9a227',
  LOW: '#5b6472',
}

export const SEV_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }

export const FAMILY_META = {
  identity_policy: { label: 'Identity policy', color: '#3a9ab0',
                     hint: 'A principal policy grants actions on this node' },
  resource_policy: { label: 'Resource policy', color: '#9a7fc8',
                     hint: "The node's own policy admits this principal" },
  trust_policy:    { label: 'Trust policy', color: '#9a7fc8',
                     hint: "The role's trust policy admits this principal" },
  abuse:           { label: 'Abuse path', color: '#d97c14',
                     hint: 'Assume-role, PassRole, takeover or lateral movement' },
  runs_as:         { label: 'Runs as', color: '#e0c060',
                     hint: 'The resource executes with this role — same credentials' },
  network:         { label: 'Network', color: '#2a9d8f',
                     hint: 'VPC / subnet / security-group membership' },
}
