import { useState, useEffect, useMemo } from 'react'
import Chip from '@mui/material/Chip'
import TextField from '@mui/material/TextField'
import MenuItem from '@mui/material/MenuItem'
import Select from '@mui/material/Select'
import InputAdornment from '@mui/material/InputAdornment'
import SearchIcon from '@mui/icons-material/Search'
import ClearIcon from '@mui/icons-material/Clear'
import IconButton from '@mui/material/IconButton'

const TYPE_ORDER  = ['account', 'role', 'user', 'group', 'policy', 'resource']
const TYPE_COLORS = {
  account: '#6366f1', role: '#3b82f6', user: '#22c55e',
  group:   '#a855f7', policy: '#ec4899', resource: '#f59e0b',
}

function typeOf(e) {
  if (e.node_type === 'account')  return 'account'
  if (e.node_type === 'policy')   return 'policy'
  if (e.node_type === 'resource') return 'resource'
  return e.principal_type || 'unknown'
}

export default function EntityPanel({ entities, accounts, onAdd }) {
  const [query,       setQuery]       = useState('')
  const [types,       setTypes]       = useState(new Set(TYPE_ORDER))
  const [acctFilter,  setAcctFilter]  = useState('ALL')
  const [permFilter,  setPermFilter]  = useState('')

  const all = useMemo(() => {
    if (!entities) return []
    return [
      ...entities.accounts,
      ...entities.principals,
      ...entities.policies,
      ...entities.resources,
    ]
  }, [entities])

  const accountIds = useMemo(() => {
    const ids = new Set(all.map(e => e.account_id).filter(Boolean))
    return ['ALL', ...Array.from(ids).sort()]
  }, [all])

  const filtered = useMemo(() => {
    const q    = query.toLowerCase()
    const perm = permFilter.trim().toLowerCase()

    // Build a glob-aware matcher for the permission filter.
    // 'iam:*' → match any action starting with 'iam:'
    // 'iam:PassRole' → exact substring match
    let permMatcher = null
    if (perm) {
      if (perm.includes('*')) {
        // Convert simple glob (only * supported) to regex
        const reStr = perm.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')
        try { permMatcher = new RegExp('^' + reStr + '$', 'i') } catch { permMatcher = null }
      }
    }

    return all.filter(e => {
      const t = typeOf(e)
      if (!types.has(t)) return false
      if (acctFilter !== 'ALL' && e.account_id !== acctFilter) return false
      if (q && !e.label?.toLowerCase().includes(q) && !(e.arn || '').toLowerCase().includes(q)) return false
      if (perm) {
        const actions = e.actions || []
        if (actions.length === 0) return false  // no permissions data → doesn't match
        const matches = permMatcher
          ? actions.some(a => permMatcher.test(a))
          : actions.some(a => a.toLowerCase().includes(perm))
        if (!matches) return false
      }
      return true
    })
  }, [all, query, types, acctFilter, permFilter])

  function toggleType(t) {
    setTypes(prev => {
      const next = new Set(prev)
      next.has(t) ? next.delete(t) : next.add(t)
      return next
    })
  }

  function clearAll() {
    setQuery(''); setTypes(new Set(TYPE_ORDER)); setAcctFilter('ALL'); setPermFilter('')
  }

  return (
    <div className="entity-panel">
      {/* Search */}
      <div className="ep-search-row">
        <TextField
          size="small" fullWidth
          placeholder="Search name or ARN…"
          value={query}
          onChange={e => setQuery(e.target.value)}
          slotProps={{
            input: {
              startAdornment: <InputAdornment position="start"><SearchIcon sx={{ fontSize: 16, color: '#64748b' }} /></InputAdornment>,
              endAdornment: query ? (
                <InputAdornment position="end">
                  <IconButton size="small" onClick={() => setQuery('')}><ClearIcon sx={{ fontSize: 14 }} /></IconButton>
                </InputAdornment>
              ) : null,
            }
          }}
          sx={muiInputSx}
        />
      </div>

      {/* Account filter */}
      <div className="ep-row">
        <span className="ep-label">Account</span>
        <Select
          size="small" value={acctFilter}
          onChange={e => setAcctFilter(e.target.value)}
          sx={{ ...muiSelectSx, flex: 1 }}
        >
          {accountIds.map(id => (
            <MenuItem key={id} value={id} sx={{ fontSize: '0.72rem', fontFamily: 'monospace' }}>
              {id === 'ALL' ? 'All accounts' : id}
            </MenuItem>
          ))}
        </Select>
      </div>

      {/* Permission filter */}
      <div className="ep-row">
        <span className="ep-label">Permission</span>
        <TextField
          size="small"
          placeholder="e.g. iam:PassRole"
          value={permFilter}
          onChange={e => setPermFilter(e.target.value)}
          sx={{ ...muiInputSx, flex: 1 }}
        />
      </div>

      {/* Type chips */}
      <div className="ep-chips-row">
        {TYPE_ORDER.map(t => (
          <Chip
            key={t} label={t} size="small"
            onClick={() => toggleType(t)}
            sx={{
              fontSize: '0.62rem', height: 20,
              borderColor: types.has(t) ? TYPE_COLORS[t] : '#334155',
              color:       types.has(t) ? TYPE_COLORS[t] : '#64748b',
              backgroundColor: types.has(t) ? `${TYPE_COLORS[t]}18` : 'transparent',
              border: '1px solid',
              '&:hover': { backgroundColor: `${TYPE_COLORS[t]}28` },
            }}
            variant="outlined"
          />
        ))}
        <Chip
          label="Clear all" size="small"
          onClick={clearAll}
          sx={{ fontSize: '0.62rem', height: 20, color: '#64748b', border: '1px solid #334155' }}
          variant="outlined"
          icon={<ClearIcon sx={{ fontSize: '12px !important' }} />}
        />
      </div>

      <div className="ep-count">{filtered.length} of {all.length}</div>

      {/* Entity list */}
      <div className="entity-list">
        {filtered.map((e, i) => {
          const t = typeOf(e)
          return (
            <button key={i} className="entity-row" onClick={() => onAdd(e)}
                    style={{ background: 'transparent', width: '100%', textAlign: 'left' }}>
              <span className="entity-dot" style={{ background: TYPE_COLORS[t] || '#64748b' }} />
              <div className="entity-info">
                <span className="entity-label">{e.label}</span>
                {e.arn && <span className="entity-arn">{e.arn}</span>}
              </div>
              <span className="entity-type" style={{ color: TYPE_COLORS[t] || '#64748b' }}>{t}</span>
            </button>
          )
        })}
        {filtered.length === 0 && (
          <div className="ep-empty">No entities match</div>
        )}
      </div>
    </div>
  )
}

const muiInputSx = {
  '& .MuiOutlinedInput-root': {
    fontSize: '0.75rem', color: '#e2e8f0', fontFamily: 'inherit',
    '& fieldset': { borderColor: '#334155' },
    '&:hover fieldset': { borderColor: '#6366f1' },
    '&.Mui-focused fieldset': { borderColor: '#6366f1' },
    '& input': { padding: '5px 8px' },
  },
  '& input::placeholder': { color: '#64748b', opacity: 1 },
}

const muiSelectSx = {
  fontSize: '0.72rem', color: '#e2e8f0', fontFamily: 'inherit',
  '& .MuiOutlinedInput-notchedOutline': { borderColor: '#334155' },
  '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: '#6366f1' },
  '&.Mui-focused .MuiOutlinedInput-notchedOutline': { borderColor: '#6366f1' },
  '& .MuiSelect-icon': { color: '#64748b' },
}
