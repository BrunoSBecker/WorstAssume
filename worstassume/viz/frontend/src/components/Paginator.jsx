import { useState, useMemo, useEffect } from 'react'

// ─── Hook ─────────────────────────────────────────────────────────────────────
// Returns the current page's slice of `items` plus pagination controls.
// Resets to page 1 whenever `items` identity changes (e.g. filter applied).
export function usePagination(items, pageSize = 50) {
  const [page, setPage] = useState(1)

  // Reset to first page whenever the filtered list changes
  useEffect(() => { setPage(1) }, [items])

  const totalPages = Math.max(1, Math.ceil(items.length / pageSize))

  const pageItems = useMemo(() => {
    const start = (page - 1) * pageSize
    return items.slice(start, start + pageSize)
  }, [items, page, pageSize])

  function goTo(n) { setPage(Math.max(1, Math.min(totalPages, n))) }

  return { page, totalPages, pageItems, goTo }
}

// ─── Paginator UI ─────────────────────────────────────────────────────────────
export default function Paginator({ page, totalPages, total, pageSize, goTo, label = 'items' }) {
  if (totalPages <= 1) return null

  const start = (page - 1) * pageSize + 1
  const end   = Math.min(page * pageSize, total)

  // Build a compact page list: always show first, last, current ±1, with ellipsis gaps
  function pageNumbers() {
    const pages = []
    const addPage = (n) => { if (!pages.includes(n) && n >= 1 && n <= totalPages) pages.push(n) }
    addPage(1)
    addPage(page - 1)
    addPage(page)
    addPage(page + 1)
    addPage(totalPages)
    pages.sort((a, b) => a - b)
    // Insert null for gaps
    const result = []
    for (let i = 0; i < pages.length; i++) {
      if (i > 0 && pages[i] - pages[i - 1] > 1) result.push(null)
      result.push(pages[i])
    }
    return result
  }

  return (
    <div className="paginator">
      <span className="paginator-info">
        {start}–{end} of {total} {label}
      </span>
      <div className="paginator-btns">
        <button
          className="paginator-btn"
          disabled={page <= 1}
          onClick={() => goTo(page - 1)}
          title="Previous page"
        >‹</button>
        {pageNumbers().map((n, i) =>
          n === null
            ? <span key={`gap-${i}`} className="paginator-gap">…</span>
            : <button
                key={n}
                className={`paginator-btn${n === page ? ' active' : ''}`}
                onClick={() => goTo(n)}
              >{n}</button>
        )}
        <button
          className="paginator-btn"
          disabled={page >= totalPages}
          onClick={() => goTo(page + 1)}
          title="Next page"
        >›</button>
      </div>
    </div>
  )
}
