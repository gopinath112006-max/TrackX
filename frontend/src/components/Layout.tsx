import { useState } from 'react'
import { Link, NavLink, useNavigate } from 'react-router-dom'
import {
  Activity,
  FileStack,
  FolderOpen,
  LayoutDashboard,
  Network,
  Search,
  ScrollText,
  ShieldCheck,
  FileSearch,
  FileText,
  Radar,
  Flame,
  Link2,
} from 'lucide-react'
import { useInvestigation } from '../hooks/useInvestigation'

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/scenarios', label: 'Scenario Selector', icon: Radar },
  { to: '/explorer', label: 'Evidence', icon: FolderOpen },
  { to: '/upload', label: 'Evidence Upload', icon: FileStack },
  { to: '/investigation', label: 'Investigation', icon: Activity },
  { to: '/timeline', label: 'Timeline', icon: ScrollText },
  { to: '/relationships', label: 'Relationships', icon: Network },
  { to: '/correlations', label: 'Correlations', icon: Link2 },
  { to: '/findings', label: 'Findings', icon: FileSearch },
  { to: '/story', label: 'Attack Story', icon: FileText },
  { to: '/report', label: 'Report', icon: Flame },
]

export function Layout({ children }: { children: React.ReactNode }) {
  const { investigationId, investigationName } = useInvestigation()
  const [search, setSearch] = useState('')
  const navigate = useNavigate()

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    if (search.trim()) {
      navigate(`/explorer?search=${encodeURIComponent(search.trim())}`)
    }
  }

  return (
    <div className="flex h-full">
      <aside className="w-60 shrink-0 bg-bg-card border-r border-bg-border flex flex-col">
        <div className="px-4 py-4 border-b border-bg-border">
          <div className="flex items-center gap-2">
            <ShieldCheck className="text-primary" size={22} />
            <div>
              <div className="text-sm font-bold text-slate-100 leading-tight">TraceLine</div>
              <div className="text-[10px] text-slate-500">Digital Forensics Investigation</div>
            </div>
          </div>
        </div>
        <nav className="flex-1 py-3 overflow-y-auto">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex items-center gap-3 px-4 py-2.5 text-sm transition-colors ${
                  isActive
                    ? 'bg-primary/10 text-primary border-r-2 border-primary'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                }`
              }
            >
              <item.icon size={16} />
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="px-4 py-3 border-t border-bg-border text-[10px] text-slate-500">
          Demo system · Simulated evidence only
        </div>
      </aside>

      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-14 shrink-0 bg-bg-card border-b border-bg-border flex items-center gap-4 px-5">
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <span className="text-slate-500">Investigation:</span>
            <span className="font-medium text-slate-200">
              {investigationName || (investigationId ? `#${investigationId}` : 'None selected')}
            </span>
            {investigationId && (
              <span className="text-slate-500">#{investigationId}</span>
            )}
          </div>
          <form onSubmit={handleSearch} className="ml-auto flex items-center gap-2">
            <div className="relative">
              <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search user, IP, file…"
                className="input pl-8 w-64"
              />
            </div>
          </form>
          <div className="flex items-center gap-1.5 text-[10px] text-emerald-400">
            <span className="status-dot h-2 w-2 rounded-full bg-emerald-400 inline-block" />
            SYSTEM ONLINE
          </div>
        </header>
        <main className="flex-1 overflow-y-auto p-5">{children}</main>
      </div>
    </div>
  )
}