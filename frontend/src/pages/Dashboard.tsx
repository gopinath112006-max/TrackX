import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Activity,
  AlertTriangle,
  FileWarning,
  Network,
  Server,
  User,
  FileText,
  Target,
  TrendingUp,
  BarChart3,
  Radio,
} from 'lucide-react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  CartesianGrid,
} from 'recharts'
import { api } from '../services/api'
import { useInvestigation } from '../hooks/useInvestigation'
import { Card, CardHeader, EmptyState, SeverityBadge, Spinner, StatCard, ConfidenceBar } from '../components/ui'
import type { InvestigationOverview, NormalizedEvent, Scenario, TimelineEntry } from '../types'

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#dc2626',
  HIGH: '#f59e0b',
  MEDIUM: '#2563eb',
  LOW: '#64748b',
  INFO: '#10b981',
}

export default function Dashboard() {
  const { investigationId } = useInvestigation()
  const navigate = useNavigate()
  const [overview, setOverview] = useState<InvestigationOverview | null>(null)
  const [events, setEvents] = useState<NormalizedEvent[]>([])
  const [timeline, setTimeline] = useState<TimelineEntry[]>([])
  const [scenarios, setScenarios] = useState<Scenario[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const load = async () => {
      setLoading(true)
      setError(null)
      try {
        const [sc, ev] = await Promise.all([api.listScenarios(), investigationId ? api.listEvents(investigationId) : Promise.resolve([])])
        setScenarios(sc)
        setEvents(ev)
        if (investigationId) {
          try {
            const [ov, tl] = await Promise.all([
              api.getInvestigation(investigationId),
              api.getTimeline(investigationId),
            ])
            setOverview(ov)
            setTimeline(tl.entries)
          } catch {
            setOverview(null)
            setTimeline([])
          }
        } else {
          setOverview(null)
          setTimeline([])
        }
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Failed to load dashboard')
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [investigationId])

  if (loading) {
    return (
      <div className="pt-16">
        <Spinner size={32} />
        <p className="text-center text-slate-500 text-sm mt-3">Loading investigation data…</p>
      </div>
    )
  }

  if (!investigationId) {
    return (
      <div className="max-w-3xl mx-auto pt-16">
        <Card>
          <CardHeader title="Welcome to the TraceLine Investigation Console" icon={<Activity />} />
          <p className="text-sm text-slate-400 mb-4">
            This system helps investigators reconstruct cyber-attack stories from raw forensic evidence.
            Load one of the three built-in simulated scenarios to begin.
          </p>
          <div className="grid md:grid-cols-3 gap-3 mb-5">
            {scenarios.slice(0, 3).map((s) => (
              <div key={s.id} className="border border-bg-border rounded-lg p-3">
                <div className="text-sm font-medium text-slate-200 mb-1">{s.name}</div>
                <div className="text-xs text-slate-500">{s.event_count} evidence events</div>
              </div>
            ))}
          </div>
          <button className="btn-primary w-full" onClick={() => navigate('/scenarios')}>
            Open Scenario Selector
          </button>
        </Card>
      </div>
    )
  }

  const counts = overview?.counts
  const sourceCounts = new Map<string, number>()
  events.forEach((e) => sourceCounts.set(e.source || 'unknown', (sourceCounts.get(e.source || 'unknown') || 0) + 1))
  const sourceData = Array.from(sourceCounts.entries()).map(([name, value]) => ({ name, value }))

  const severityCounts = new Map<string, number>()
  timeline.forEach((t) => severityCounts.set(t.severity || 'INFO', (severityCounts.get(t.severity || 'INFO') || 0) + 1))
  const severityData = Array.from(severityCounts.entries()).map(([name, value]) => ({ name, value }))

  const ipCounts = new Map<string, number>()
  overview?.blast_radius?.ips.forEach((ip) => ipCounts.set(ip, (ipCounts.get(ip) || 0) + 1))
  events.forEach((e) => {
    if (e.source_ip) ipCounts.set(e.source_ip, (ipCounts.get(e.source_ip) || 0) + 1)
  })
  const topIps = Array.from(ipCounts.entries())
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 5)

  const hostCounts = new Map<string, number>()
  overview?.blast_radius?.hosts.forEach((h) => hostCounts.set(h, (hostCounts.get(h) || 0) + 1))
  const topHosts = Array.from(hostCounts.entries())
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 5)

  return (
    <div className="max-w-6xl mx-auto">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100">DIGITAL FORENSICS INVESTIGATION</h1>
          <p className="text-xs text-slate-500">
            Investigation #{investigationId} &nbsp;·&nbsp; overall confidence {overview?.confidence.score.toFixed(1)}%
          </p>
        </div>
        {overview && (
          <div className={`px-4 py-2 rounded-lg font-bold text-sm ${
            overview.risk_level === 'HIGH' ? 'bg-red-900/40 text-red-300' : overview.risk_level === 'MEDIUM' ? 'bg-amber-900/40 text-amber-300' : 'bg-emerald-900/40 text-emerald-300'
          }`}>
            RISK LEVEL: {overview.risk_level}
          </div>
        )}
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3 mb-6">
        <StatCard label="Total events" value={counts?.total_events ?? events.length} icon={<BarChart3 size={16} />} />
        <StatCard label="Suspicious" value={counts?.suspicious_events ?? 0} accent="#f59e0b" icon={<AlertTriangle size={16} />} />
        <StatCard label="Users involved" value={overview?.blast_radius.users.length ?? 0} accent="#3b82f6" icon={<User size={16} />} />
        <StatCard label="IPs involved" value={overview?.blast_radius.ips.length ?? 0} accent="#8b5cf6" icon={<Network size={16} />} />
        <StatCard label="Systems affected" value={overview?.blast_radius.hosts.length ?? 0} accent="#10b981" icon={<Server size={16} />} />
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3 mb-6">
        <StatCard label="Files affected" value={overview?.blast_radius.files.length ?? 0} accent="#f59e0b" icon={<FileText size={16} />} />
        <StatCard label="Findings" value={counts?.findings ?? 0} accent="#f43f5e" icon={<FileWarning size={16} />} />
        <StatCard label="Entry point conf." value={overview?.entry_point ? `${overview.entry_point.confidence.toFixed(0)}%` : '—'} accent="#38bdf8" icon={<Target size={16} />} />
        <StatCard label="Correlations" value={counts?.correlations ?? 0} icon={<Radio size={16} />} />
        <StatCard label="Graph edges" value={counts?.graph_edges ?? 0} icon={<TrendingUp size={16} />} />
      </div>

      <div className="grid lg:grid-cols-3 gap-4 mb-6">
        <Card className="lg:col-span-2">
          <CardHeader title="Timeline preview" subtitle="Chronological sequence of the most relevant events" />
          {timeline.length === 0 ? (
            <EmptyState title="No analysis yet" message="Run the analysis to generate a timeline" />
          ) : (
            <div className="space-y-1 max-h-64 overflow-y-auto pr-1">
              {timeline.slice(-8).map((t) => (
                <div key={t.event_id} className="flex items-center gap-3 text-sm border-b border-bg-border py-1.5 last:border-0">
                  <span className="font-mono text-xs text-slate-500 whitespace-nowrap">{t.timestamp?.slice(11, 19)}</span>
                  <span className="truncate text-slate-300 flex-1">{t.display_text}</span>
                  <SeverityBadge severity={t.severity} />
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card>
          <CardHeader title="Evidence sources" subtitle="Distribution across uploaded files" />
          {sourceData.length === 0 ? (
            <EmptyState title="No evidence" message="Upload evidence files to get started" />
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={sourceData} dataKey="value" nameKey="name" innerRadius={40} outerRadius={75} paddingAngle={2}>
                  {sourceData.map((entry, i) => (
                    <Cell key={i} fill={['#2563eb', '#f59e0b', '#10b981', '#8b5cf6', '#f43f5e'][i % 5]} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: '#111a2e', border: '1px solid #1e2a44', borderRadius: 8, fontSize: 12 }} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </Card>
      </div>

      <div className="grid lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader title="Suspicious activity by severity" subtitle="Severity distribution of timeline events" />
          {severityData.length === 0 ? (
            <EmptyState title="No events" message="Upload evidence to populate" />
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={severityData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2a44" />
                <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} allowDecimals={false} />
                <Tooltip contentStyle={{ background: '#111a2e', border: '1px solid #1e2a44', borderRadius: 8, fontSize: 12 }} />
                <Bar dataKey="value" name="Events">
                  {severityData.map((entry, i) => (
                    <Cell key={i} fill={SEVERITY_COLORS[entry.name] || '#2563eb'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </Card>

        <Card>
          <CardHeader title="Top suspicious IPs" subtitle="IP addresses with the most event activity" />
          {topIps.length === 0 ? (
            <EmptyState title="No IPs" message="No IP activity found" />
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={topIps} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2a44" />
                <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 11 }} allowDecimals={false} />
                <YAxis type="category" dataKey="name" width={110} tick={{ fill: '#94a3b8', fontSize: 11 }} />
                <Tooltip contentStyle={{ background: '#111a2e', border: '1px solid #1e2a44', borderRadius: 8, fontSize: 12 }} />
                <Bar dataKey="value" name="Events" fill="#f59e0b" />
              </BarChart>
            </ResponsiveContainer>
          )}
        </Card>
      </div>

      {overview && (
        <div className="mt-6 grid lg:grid-cols-2 gap-4">
          <Card>
            <CardHeader title="Initial entry point" icon={<Target />} />
            {overview.entry_point ? (
              <div>
                <p className="text-sm text-slate-200">
                  Likely initial entry point: <span className="text-amber-300 font-medium">{overview.entry_point.description}</span>
                </p>
                <p className="text-xs text-slate-500 mt-1">
                  Event {overview.entry_point.event_id} · user{' '}
                  {overview.entry_point.user || 'unknown'} · {overview.entry_point.timestamp?.slice(0, 19)}
                </p>
                <div className="mt-2">
                  <ConfidenceBar value={overview.entry_point.confidence} label="Entry point confidence" />
                </div>
                <ul className="mt-3 space-y-1">
                  {overview.entry_point.reasoning.map((r, i) => (
                    <li key={i} className="text-xs text-slate-400 flex gap-2">
                      <span className="text-primary">•</span>
                      {r}
                    </li>
                  ))}
                </ul>
              </div>
            ) : (
              <EmptyState title="Not identified" message="No conclusive entry point could be determined" />
            )}
          </Card>
          <Card>
            <CardHeader title="Overall confidence" icon={<TrendingUp />} />
            <ConfidenceBar value={overview.confidence.score} />
            <p className="text-xs text-slate-500 mt-1 mb-3">
              Level: <span className="font-medium">{overview.confidence.level}</span>
            </p>
            <ul className="space-y-1">
              {overview.confidence.factors.map((f, i) => (
                <li key={i} className="text-xs text-slate-400 flex gap-2">
                  <span className="text-emerald-400">+</span>
                  {f}
                </li>
              ))}
            </ul>
          </Card>
        </div>
      )}

      {!overview && (
        <div className="mt-4">
          <button className="btn-primary" onClick={() => navigate('/investigation')}>
            Run Investigation Analysis
          </button>
        </div>
      )}
    </div>
  )
}