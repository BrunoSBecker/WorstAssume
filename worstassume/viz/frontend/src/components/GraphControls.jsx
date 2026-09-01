/**
 * GraphControls — zoom / fit / re-layout / clear plus the node-size and
 * edge-alpha sliders. Shared by GraphViewer and the engagement canvas.
 */
import ZoomInIcon from '@mui/icons-material/ZoomIn'
import ZoomOutIcon from '@mui/icons-material/ZoomOut'
import CenterFocusStrongIcon from '@mui/icons-material/CenterFocusStrong'
import RefreshIcon from '@mui/icons-material/Refresh'
import DeleteOutlineIcon from '@mui/icons-material/DeleteOutline'
import TuneIcon from '@mui/icons-material/Tune'

export default function ControlsPanel({ cyRef, open, onToggle, nodeSize, setNodeSize, edgeOpacity, setEdgeOpacity, onRelayout, onClear }) {
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
          { icon: <ZoomInIcon sx={{ fontSize: 16 }} />, title: 'Zoom in', fn: () => zoom(1.3) },
          { icon: <ZoomOutIcon sx={{ fontSize: 16 }} />, title: 'Zoom out', fn: () => zoom(0.77) },
          { icon: <CenterFocusStrongIcon sx={{ fontSize: 16 }} />, title: 'Fit view', fn: () => cyRef.current?.fit(undefined, 60) },
          { icon: <RefreshIcon sx={{ fontSize: 16 }} />, title: 'Re-layout', fn: onRelayout },
          { icon: <DeleteOutlineIcon sx={{ fontSize: 16 }} />, title: 'Clear graph', fn: onClear },
        ].map(({ icon, title, fn }) => (
          <button key={title} title={title} onClick={fn} style={base}
            onMouseEnter={enter} onMouseLeave={leave}>{icon}</button>
        ))}
        <div style={{ height: 1, background: 'var(--border)', margin: '2px 0' }} />
        <button title="Controls" onClick={onToggle}
          style={{ ...base, background: open ? 'var(--amber-glow)' : 'var(--bg2)', border: `1px solid ${open ? 'rgba(217,124,20,.3)' : 'var(--border2)'}`, color: open ? 'var(--amber)' : 'var(--text-dim)' }}>
          <TuneIcon sx={{ fontSize: 15 }} />
        </button>
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
