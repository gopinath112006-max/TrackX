import { useEffect, useMemo, useState } from 'react'
import { api } from '../services/api'
import { useInvestigation } from '../hooks/useInvestigation'
import { Card, EmptyState, SeverityBadge, Spinner } from '../components/ui'
import { EventDetailModal } from '../components/EventDetailModal'
import type { TimelineEntry, NormalizedEvent } from '../types'

export default function Timeline() {
  const { investigationId } = useInvestigation()
  const [entries, setEntries] = useState<TimelineEntry[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<TimelineEntry | null>(null)

  const [userFilter, setUserFilter] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')

  useEffect(() => {
    const load = async () => {
      if (!investigationId) return
      setLoading(true)
      try {
        const tl = await api.getTimeline(investigationId)
        setEntries(tl.entries)
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Failed to load timeline')
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [investigationId])

  const users = useMemo(() => Array.from(new Set(entries.map((e) => e.details?.user).filter(Boolean))), [entries])
  const types = useMemo(() => Array.from(new Set(entries.map((e) => e.details?.event_type as string))), [entries])

  const filtered = useMemo(() => {
    return entries.filter((e) => {
      if (userFilter && e.details?.user !== userFilter) return false
      if (typeFilter && e.details?.event_type !== typeFilter) return false
      if (severityFilter && e.severity !== severityFilter) return false
      return true
    })
  }, [entries, userFilter, typeFilter, severityFilter])

  const severityDot: Record<string, string> = {
    CRITICAL: 'bg-red-500',
    HIGH: 'bg-amber-500',
    MEDIUM: 'bg-blue-500',
    LOW: 'bg-purple-500',
    INFO: 'bg-emerald-500',
  }

  if (!investigationId) {
    return (
      <div className="max-w-3xl mx-auto pt-16">
        <Card>
          <EmptyState title="No investigation selected" message="Load a demo scenario to generate a timeline." />
        </Card>
      </div>
    )
  }

  return (
    <div className="max-w-5xl mx-auto">
      <h1 className="text-xl font-bold text-slate-100 mb-1">Attack Timeline</h1>
      <p className="text-xs text-slate-500 mb-5">
        Chronological reconstruction of events across all evidence sources. Click an entry for full details.
      </p>

      <div className="flex flex-wrap gap-2 mb-5">
        <select value={userFilter} onChange={(e) => setUserFilter(e.target.value)} className="input">
          <option value="">All users</option>
          {users.map((u) => (
            <option key={u as string} value={u as string}>{u}</option>
          ))}
        </select>
        <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} className="input">
          <option value="">All event types</option>
          {types.map((t) => (
            <option key={t as string} value={t as string}>{t}</option>
          ))}
        </select>
        <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} className="input">
          <option value="">All severities</option>
          <option value="CRITICAL">CRITICAL</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="LOW">LOW</option>
          <option value="INFO">INFO</option>
        </select>
        <span className="text-xs text-slate-500 self-center">{filtered.length} of {entries.length} entries</span>
      </div>

      {error && <div className="mb-4 px-4 py-3 rounded-lg bg-red-900/30 border border-red-800 text-red-300 text-sm">{error}</div>}
      {loading ? (
        <div className="pt-10"><Spinner size={28} /></div>
      ) : filtered.length === 0 ? (
        <Card><EmptyState title="No timeline entries" message="No events match the current filters." /></Card>
      ) : (
        <div className="relative pl-6">
          <div className="absolute left-[5px] top-0 bottom-0 w-px bg-bg-border" />
          <div className="space-y-1">
            {filtered.map((entry) => (
              <button
                key={entry.event_id}
                onClick={() => setSelected(entry)}
                className="relative w-full text-left rounded-lg px-4 py-2.5 flex items-center gap-3 hover:bg-slate-800/30 transition-colors border border-transparent hover:border-bg-border"
              >
                <span className={`absolute -left-[23px] top-1/2 -translate-y-1/2 h-2.5 w-2.5 rounded-full ${severityDot[entry.severity] || 'bg-slate-500'}`} />
                <span className="font-mono text-xs text-slate-500 whitespace-nowrap w-24">{entry.timestamp?.slice(11, 19)}</span>
                <span className="flex-1 text-sm text-slate-200 truncate">{entry.display_text}</span>
                <SeverityBadge severity={entry.severity} />
              </button>
            ))}
          </div>
        </div>
      )}

      {selected && (
        <EventDetailModal event={selected.details as NormalizedEvent} onClose={() => setSelected(null)} />
      )}
    </div>
  )
}