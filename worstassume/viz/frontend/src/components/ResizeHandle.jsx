/**
 * ResizeHandle — the draggable strip on a panel edge. Pairs with
 * useResizableWidth; `side` is the edge of the panel it sits on.
 *
 * Renders a visible hairline so the affordance is findable: a fully
 * transparent strip is there but nobody discovers it.
 */
export default function ResizeHandle({ onPointerDown, active = false, side = 'left' }) {
  const line = active ? 'var(--amber)' : 'var(--border2)'
  return (
    <div
      onPointerDown={onPointerDown}
      title="Drag to resize"
      style={{
        // Kept inside the panel: an overhanging strip gets clipped by the
        // panel's own overflow and can trigger a horizontal scrollbar.
        position: 'absolute', top: 0, bottom: 0, [side]: 0,
        width: '9px', cursor: 'col-resize', zIndex: 40,
        display: 'flex',
        justifyContent: side === 'left' ? 'flex-start' : 'flex-end',
      }}
      onMouseEnter={e => { e.currentTarget.firstChild.style.background = 'var(--amber)' }}
      onMouseLeave={e => {
        if (!active) e.currentTarget.firstChild.style.background = 'var(--border2)'
      }}
    >
      <div style={{
        width: active ? '3px' : '1px', height: '100%',
        background: line, transition: 'background 0.12s, width 0.12s',
      }} />
    </div>
  )
}
