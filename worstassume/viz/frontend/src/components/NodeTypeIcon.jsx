/**
 * NodeTypeIcon — the MUI glyph for a graph node type, for DOM contexts
 * (legends, lists). The cytoscape canvas cannot use a React component, so it
 * builds the same glyph from `NODE_CFG[type].pathD` via `iconSvgUrl`. Both read
 * the same record, so they cannot drift.
 */
import AdminPanelSettings from '@mui/icons-material/AdminPanelSettings'
import Person from '@mui/icons-material/Person'
import Groups from '@mui/icons-material/Groups'
import Policy from '@mui/icons-material/Policy'
import Cloud from '@mui/icons-material/Cloud'
import AccountBalance from '@mui/icons-material/AccountBalance'
import Bolt from '@mui/icons-material/Bolt'
import Memory from '@mui/icons-material/Memory'
import Public from '@mui/icons-material/Public'
import Circle from '@mui/icons-material/Circle'
import { NODE_CFG, DEFAULT_CFG } from './graphShared'

const BY_NAME = {
  AdminPanelSettings, Person, Groups, Policy, Cloud,
  AccountBalance, Bolt, Memory, Public, Circle,
}

export default function NodeTypeIcon({ type, size = 13, color }) {
  const cfg = NODE_CFG[type] || DEFAULT_CFG
  const Icon = BY_NAME[cfg.icon] || Circle
  return <Icon sx={{ fontSize: size, color: color || cfg.color }} />
}
