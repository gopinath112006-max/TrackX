import { useEffect, useRef, useState } from 'react'
import {
  Target,
  Users,
  Network,
  Server,
  FileText,
  Play,
  Loader2,
  TrendingUp,
  ShieldAlert,
  Activity,
} from 'lucide-react'
import { api } from '../services/api'
import { useInvestigation } from '../hooks/useInvestigation'
import { Card, CardHeader, ConfidenceBar, EmptyState, SeverityBadge, Spinner } from '../components/ui'
import type { InvestigationOverview } from '../types'

export default function Investigation() {
  const { investigationId, setInvestigation } = useInvestigation()
  const [overview, setOverview] = useState<InvestigationOverview | null>(null)
  const [loading, setLoading] = useState(false)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [progress, setProgress] = useState<{ percent: number; label: string } | null>(null)
  const closeProgress = useRef<(() => void) | null>(null)

  const load = async () => {
    if (!investigationId) return
    setLoading(true)
    setError(null)
    try {
      const ov = await api.getInvestigation(investigationId)
      setOverview(ov)
    } catch {
      setOverview(null)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [investigationId])

  useEffect(() => {
    return () => {
      closeProgress.current?.()
      closeProgress.current = null
    }
  }, [])

  const runAnalysis = async () => {
    if (!investigationId) return
    setRunning(true)
    setError(null)
    setProgress({ percent: 0, label: 'Connecting to pipeline' })
    closeProgress.current = api.streamProgress(investigationId, (ev) => {
      if (ev.event === 'progress' || ev.event === 'open') {
        setProgress({ percent: ev.percent, label: ev.label })
      }
      if (ev.event === 'error') {
        setError(String(ev.payload?.detail ?? 'Pipeline progress failed'))
      }
    })
    try {
      const result = await api.analyze(investigationId)
      if (result.investigation_id) {
        setInvestigation(result.investigation_id, `Investigation #${result.investigation_id}`)
      }
      await load()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Analysis failed')
    } finally {
      setProgress(null)
      closeProgress.current?.()
      closeProgress.current = null
      setRunning(false)
    }
  }

  if (!investigationId) {
    return (
      <div className="max-w-3xl mx-auto pt-16">
        <Card>
          <EmptyState title="No investigation selected" message="Load a demo scenario to begin." />
        </Card>
      </div>
    )
  }

  return (
    <div className="max-w-6xl mx-auto">
      <div className="flex items-center justify-between mb-2">
        <h1 className="text-xl font-bold text-slate-100">Investigation Analysis</h1>
        <div className="flex items-center gap-3">
          {overview && (
            <SeverityBadge severity={overview.risk_level} />
          )}
          <button className="btn-primary flex items-center gap-2" onClick={runAnalysis} disabled={running || loading}>
            {running ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
            {running ? 'Analyzing…' : overview ? 'Re-run Analysis' : 'Run Analysis'}
          </button>
        </div>
      </div>
      <p className="text-xs text-slate-500 mb-5">
        Correlates evidence, detects suspicious activity, identifies the likely entry point and computes the blast radius.
      </p>

      {error && <div className="mb-4 px-4 py-3 rounded-lg bg-red-900/30 border border-red-800 text-red-300 text-sm">{error}</div>}
      {running && progress && (
        <Card className="mb-4">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2 text-sm text-slate-200">
              <Loader2 size={14} className="animate-spin text-primary" />
              <span className="text-[11px] uppercase tracking-wider text-slate-400">Pipeline monitor</span>
            </div>
            <span className="text-xs font-mono text-slate-400">{progress.percent}%</span>
          </div>
          <div className="h-2 w-full rounded-full bg-slate-800 overflow-hidden">
            <div className="h-full rounded-full bg-primary transition-all duration-300" style={{ width: `${progress.percent}%` }} />
          </div>
          <p className="text-xs text-slate-400 mt-2">{progress.label}</p>
        </Card>
      )}
      {loading && (
        <div className="pt-12">
          <Spinner size={30} />
        </div>
      )}

      {!loading && !overview && (
        <div className="pt-10">
          <Card>
            <EmptyState title="Analysis not yet run" message="Click 'Run Analysis' to analyze the evidence for this investigation." />
          </Card>
        </div>
      )}

      {!loading && overview && (
        <>
          <div className="grid lg:grid-cols-2 gap-4 mb-4">
            <Card>
              <CardHeader title="Likely initial entry point" icon={<Target />} />
              {overview.entry_point ? (
                <div>
                  <p className="text-sm text-slate-200">
                    <span className="text-amber-300 font-medium">{overview.entry_point.description}</span>
                  </p>
                  <p className="text-xs font-mono text-slate-500 mt-1">
                    Event {overview.entry_point.event_id} · user {overview.entry_point.user || 'unknown'} · from{' '}
                    {overview.entry_point.source_ip || 'unknown'} · {overview.entry_point.timestamp?.slice(0, 19)}
                  </p>
                  <div className="mt-3">
                    <ConfidenceBar value={overview.entry_point.confidence} label="Entry point confidence" />
                  </div>
                  <div className="mt-3">
                    <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-1">Supporting evidence</div>
                    <ul className="space-y-1">
                      {overview.entry_point.reasoning.map((r, i) => (
                        <li key={i} className="text-xs text-slate-400 flex gap-2">
                          <span className="text-primary">•</span>
                          {r}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              ) : (
                <EmptyState title="Not identified" message="No conclusive entry point was found in this evidence set." />
              )}
            </Card>

            <Card>
              <CardHeader title="Overall incident confidence" icon={<TrendingUp />} />
              <ConfidenceBar value={overview.confidence.score} />
              <p className="text-xs text-slate-500 mt-1 mb-3">Level: {overview.confidence.level}</p>
              <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-1">Why this confidence</div>
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

          <Card>
            <CardHeader title="Blast radius" subtitle="Scope of systems, users, files and IP addresses involved" icon={<ShieldAlert />} />
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
              <BlastBox icon={<Users size={18} />} label="Affected users" items={overview.blast_radius.users} color="#3b82f6" />
              <BlastBox icon={<Network size={18} />} label="Affected IPs" items={overview.blast_radius.ips} color="#8b5cf6" />
              <BlastBox icon={<Server size={18} />} label="Affected systems" items={overview.blast_radius.hosts} color="#10b981" />
              <BlastBox icon={<FileText size={18} />} label="Affected files" items={overview.blast_radius.files} color="#f59e0b" />
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <Activity size={14} className="text-primary" />
              Total affected entities: <span className="font-mono text-slate-200">{overview.blast_radius.total_affected}</span>
            </div>
          </Card>
        </>
      )}
    </div>
  )
}

function BlastBox({ icon, label, items, color }: { icon: React.ReactNode; label: string; items: string[]; color: string }) {
  return (
    <div className="border border-bg-border rounded-lg p-3">
      <div className="flex items-center gap-2 mb-2" style={{ color }}>
        {icon}
        <span className="text-xs text-slate-300">{label}</span>
        <span className="ml-auto text-xs font-mono text-slate-500">{items.length}</span>
      </div>
      <div className="flex flex-wrap gap-1">
        {items.length === 0 ? (
          <span className="text-[11px] text-slate-600">None</span>
        ) : (
          items.slice(0, 5).map((x) => (
            <span key={x} className="text-[11px] px-1.5 py-0.5 rounded bg-slate-800/60 text-slate-300 font-mono">{x}</span>
          ))
        )}
        {items.length > 5 && (
          <span className="text-[11px] text-slate-500">+{items.length - 5} more</span>
        )}
      </div>
    </div>
  )
}