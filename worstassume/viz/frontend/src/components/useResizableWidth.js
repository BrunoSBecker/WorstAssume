/**
 * useResizableWidth — drag-to-resize for a side panel.
 *
 * Extracted from GraphViewer, which was the only place in the app with a
 * resizable panel; the Threat Model page needs the same behaviour in three
 * more places (the asset picker, the neighbour picker, the node detail panel).
 *
 * `side` is the edge the panel is anchored to, which decides the drag sign:
 * a right-anchored panel grows as the pointer moves left.
 *
 * The drag listeners are keyed on `resizing` alone. That matters: callers
 * naturally pass an inline `max: () => window.innerWidth * 0.45`, whose
 * identity changes on every render, so keying the effect on the options would
 * tear down and re-attach the window listeners on every pointermove — and a
 * pointerup landing in one of those gaps leaves the drag stuck on. The live
 * values are read through a ref instead.
 */
import { useCallback, useEffect, useRef, useState } from 'react'

export function useResizableWidth({
  initial,
  min = 320,
  max = () => window.innerWidth * 0.93,
  side = 'right',
} = {}) {
  const [width, setWidth] = useState(initial)
  const [resizing, setResizing] = useState(false)
  const panelRef = useRef(null)
  const startPos = useRef(0)
  const startWidth = useRef(0)

  const opts = useRef({ min, max, side })
  opts.current = { min, max, side }

  const onResizeDown = useCallback((e) => {
    startPos.current = e.clientX
    startWidth.current = panelRef.current?.offsetWidth ?? initial
    setResizing(true)
    // Keep receiving moves even if the pointer outruns the 8px strip.
    e.currentTarget.setPointerCapture?.(e.pointerId)
    e.preventDefault()
  }, [initial])

  useEffect(() => {
    if (!resizing) return
    const move = (e) => {
      const { min: lo, max: hi, side: anchor } = opts.current
      const limit = typeof hi === 'function' ? hi() : hi
      const delta = anchor === 'right'
        ? startPos.current - e.clientX     // right-anchored: drag left to grow
        : e.clientX - startPos.current
      setWidth(Math.max(lo, Math.min(limit, startWidth.current + delta)))
    }
    const up = () => setResizing(false)
    const prevSelect = document.body.style.userSelect
    const prevCursor = document.body.style.cursor
    document.body.style.userSelect = 'none'
    document.body.style.cursor = 'col-resize'
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', up)
    window.addEventListener('pointercancel', up)
    return () => {
      document.body.style.userSelect = prevSelect
      document.body.style.cursor = prevCursor
      window.removeEventListener('pointermove', move)
      window.removeEventListener('pointerup', up)
      window.removeEventListener('pointercancel', up)
    }
  }, [resizing])

  return { width, setWidth, resizing, onResizeDown, panelRef }
}
