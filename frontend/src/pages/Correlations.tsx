import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Link2, Search, X } from 'lucide-react'
import { api } from '../services/api'
import { useInvestigation } from '../hooks/useInvestigation'
import { Card, EmptyState, Spinner, StatCard } from '../components/ui'
import type { Correlation, NormalizedEvent } from '../types'

const FACTOR_LABELS: Record<string, string> = {
  same_user: 'Same user',
  same_source_ip: 'Same source IP',
  close_timestamp: 'Close timestamp',
  same_host: 'Same host',
  related_action_sequence: 'Action sequence',
  cross_source_corroboration: 'Cross-source corroboration',
}

function scoreColor(score: number) {
  return score >= 80 ? '#10b981' : score >= 50 ? '#f59e0b' : '#64748b'
}

function EventHalf({ event, onOpen }: { event: NormalizedEvent | undefined; onOpen: (eid: string) => void }) {
  if (!event) return null
  return (
    <div className="min-w-0">
      <div className="flex items-center gap-2 flex-wrap">
        <button
          className="font-mono text-primary text-xs hover:underline"
          onClick={() => onOpen(event.event_id)}
          title="Open in evidence explorer"
        >
          {event.event_id}
        </button>
        <span className="text-xs text-slate-300">{event.user || '—'}</span>
        <span className="text-[10px] text-slate-500 font-mono">{event.source_ip || ''}</span>
      </div>
      <div className="text-[11px] text-slate-500 mt-0.5 truncate">
        {event.timestamp?.slice(0, 19)} · {event.event_type}
        {event.source ? ` · ${event.source}` : ''}
      </div>
      <div className="text-[11px] text-slate-400 truncate">{event.action}</div>
    </div>
  )
}

export default function Correlations() {
  const { investigationId } = useInvestigation()
  const navigate = useNavigate()
  const [correlations, setCorrelations] = useState<Correlation[]>([])
  const [events, setEvents] = useState<NormalizedEvent[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const [minScore, setMinScore] = useState(0)
  const [factor, setFactor] = useState('')
  const [search, setSearch] = useState('')

  useEffect(() => {
    const load = async () => {
      if (!investigationId) return
      setLoading(true)
      setError(null)
      try {
        const [corr, ev] = await Promise.all([
          api.getCorrelations(investigationId),
          api.listEvents(investigationId),
        ])
        setCorrelations(corr)
        setEvents(ev)
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Failed to load correlations')
        setCorrelations([])
        setEvents([])
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [investigationId])

  const eventMap = useMemo(() => {
    const m = new Map<string, NormalizedEvent>()
    events.forEach((e) => m.set(e.event_id, e))
    return m
  }, [events])

  const factorOptions = useMemo(
    () => Array.from(new Set(correlations.flatMap((c) => c.factors))).sort(),
    [correlations],
  )

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return correlations
      .filter((c) => c.score >= minScore)
      .filter((c) => !factor || c.factors.includes(factor))
      .filter((c) => {
        if (!q) return true
        const a = eventMap.get(c.event_a_event_id)
        const b = eventMap.get(c.event_b_event_id)
        const hay = [
          c.event_a_event_id,
          c.event_b_event_id,
          a?.user,
          a?.source_ip,
          b?.user,
          b?.source_ip,
        ]
        return hay.some((v) => v && v.toLowerCase().includes(q))
      })
      .sort((a, b) => b.score - a.score)
  }, [correlations, minScore, factor, search, eventMap])

  const highCount = correlations.filter((c) => c.score >= 80).length
  const mediumCount = correlations.filter((c) => c.score >= 50 && c.score < 80).length
  const crossSourceCount = correlations.filter((c) => c.factors.includes('cross_source_corroboration')).length

  if (!investigationId) {
    return (
      <div className="max-w-3xl mx-auto pt-16">
        <Card>
          <EmptyState title="No investigation selected" message="Load a demo scenario to explore correlations." />
        </Card>
      </div>
    )
  }

  return (
    <div className="max-w-5xl mx-auto">
      <h1 className="text-xl font-bold text-slate-100 mb-1">Evidence Correlations</h1>
      <p className="text-xs text-slate-500 mb-5">
        Related event pairs identified across evidence sources, with an explainable correlation score and the
        factors that link them. Pairs corroborated by independent sources are flagged.
      </p>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
        <StatCard label="Correlated pairs" value={correlations.length} accent="#3b82f6" icon={<Link2 size={16} />} />
        <StatCard label="High ({'\u2265'}80)" value={highCount} accent="#10b981" />
        <StatCard label="Medium (50–79)" value={mediumCount} accent="#f59e0b" />
        <StatCard label="Cross-source" value={crossSourceCount} accent="#8b5cf6" />
      </div>

      <div className="flex flex-wrap gap-2 mb-5 items-center">
        <select value={minScore} onChange={(e) => setMinScore(Number(e.target.value))} className="input">
          <option value={0}>Any score</option>
          <option value={50}>Score {'\u2265'} 50</option>
          <option value={80}>Score {'\u2265'} 80</option>
        </select>
        <select value={factor} onChange={(e) => setFactor(e.target.value)} className="input">
          <option value="">All factors</option>
          {factorOptions.map((f) => (
            <option key={f} value={f}>{FACTOR_LABELS[f] || f}</option>
          ))}
        </select>
        <div className="relative">
          <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Event ID, user, IP…"
            className="input pl-8 w-56"
          />
        </div>
        {(minScore !== 0 || factor || search) && (
          <button
            className="btn-outline flex items-center gap-1.5"
            onClick={() => {
              setMinScore(0)
              setFactor('')
              setSearch('')
            }}
          >
            <X size={13} /> Clear filters
          </button>
        )}
      </div>

      {error && <div className="mb-4 px-4 py-3 rounded-lg bg-red-900/30 border border-red-800 text-red-300 text-sm">{error}</div>}

      {loading ? (
        <div className="pt-10"><Spinner size={28} /></div>
      ) : correlations.length === 0 ? (
        <Card>
          <EmptyState title="No correlations yet" message="Run the analysis to compute correlations between evidence events." />
        </Card>
      ) : filtered.length === 0 ? (
        <Card>
          <EmptyState title="No matching correlations" message="Adjust the filters to see more pairs." />
        </Card>
      ) : (
        <div className="space-y-3">
          {filtered.map((c) => {
            const a = eventMap.get(c.event_a_event_id)
            const b = eventMap.get(c.event_b_event_id)
            const color = scoreColor(c.score)
            const isCross = c.factors.includes('cross_source_corroboration')
            return (
              <div key={`${c.event_a_event_id}|${c.event_b_event_id}|${c.score}`} className="card">
                <div className="flex items-center gap-4">
                  <div className="flex-1 min-w-0">
                    <EventHalf event={a} onOpen={(eid) => navigate(`/explorer?search=${encodeURIComponent(eid)}`)} />
                  </div>
                  <div className="flex flex-col items-center gap-1 shrink-0">
                    <div
                      className="text-center font-mono font-bold text-xs px-2 py-1 rounded"
                      style={{ color, backgroundColor: `${color}1a`, border: `1px solid ${color}33` }}
                    >
                      {c.score.toFixed(0)}
                    </div>
                    <Link2 size={14} className="text-slate-500" />
                    <div className="text-[10px] text-slate-500">
                      {c.score >= 80 ? 'High' : c.score >= 50 ? 'Medium' : 'Low'}
                    </div>
                  </div>
                  <div className="flex-1 min-w-0">
                    <EventHalf event={b} onOpen={(eid) => navigate(`/explorer?search=${encodeURIComponent(eid)}`)} />
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-1.5 mt-3">
                  {c.factors.map((f) => (
                    <span
                      key={f}
                      className={`px-2 py-0.5 rounded text-[10px] font-medium ${
                        f === 'cross_source_corroboration'
                          ? 'bg-purple-900/40 text-purple-300'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {FACTOR_LABELS[f] || f}
                    </span>
                  ))}
                  {isCross && (
                    <span className="ml-auto text-[10px] text-purple-300/80">
                      Corroborated by independent evidence sources
                    </span>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}