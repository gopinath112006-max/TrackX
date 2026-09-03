import { useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Search, X, SlidersHorizontal } from 'lucide-react'
import { api } from '../services/api'
import { useInvestigation } from '../hooks/useInvestigation'
import { Card, EmptyState, SeverityBadge, Spinner } from '../components/ui'
import type { NormalizedEvent } from '../types'
import { EventDetailModal } from '../components/EventDetailModal'

export default function Explorer() {
  const { investigationId } = useInvestigation()
  const [searchParams] = useSearchParams()
  const [events, setEvents] = useState<NormalizedEvent[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const [search, setSearch] = useState(searchParams.get('search') || '')
  const [severity, setSeverity] = useState('')
  const [eventType, setEventType] = useState('')
  const [simUser, setSimUser] = useState('')
  const [sourceIp, setSourceIp] = useState('')
  const [status, setStatus] = useState('')
  const [sourceLog, setSourceLog] = useState('')
  const [startTime, setStartTime] = useState('')
  const [endTime, setEndTime] = useState('')
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [selected, setSelected] = useState<NormalizedEvent | null>(null)

  const hasFilters =
    search || severity || eventType || simUser || sourceIp || status || sourceLog || startTime || endTime
  const activeFilterCount = [sourceIp, status, sourceLog, startTime, endTime].filter(Boolean).length

  useEffect(() => {
    const load = async () => {
      if (!investigationId) return
      setLoading(true)
      setError(null)
      try {
        const rows = await api.listEvents(investigationId, {
          search: search || undefined,
          severity: severity || undefined,
          event_type: eventType || undefined,
          user: simUser || undefined,
          source_ip: sourceIp || undefined,
          status: status || undefined,
          source: sourceLog || undefined,
          start_time: startTime || undefined,
          end_time: endTime || undefined,
        })
        setEvents(rows)
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Failed to load events')
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [investigationId, search, severity, eventType, simUser, sourceIp, status, sourceLog, startTime, endTime])

  const distinctTypes = useMemo(
    () => Array.from(new Set(events.map((e) => e.event_type))).sort(),
    [events],
  )
  const distinctUsers = useMemo(
    () => Array.from(new Set(events.map((e) => e.user).filter(Boolean))) as string[],
    [events],
  )
  const distinctStatuses = useMemo(
    () => Array.from(new Set(events.map((e) => e.status).filter(Boolean))) as string[],
    [events],
  )
  const distinctSources = useMemo(
    () => Array.from(new Set(events.map((e) => e.source).filter(Boolean))) as string[],
    [events],
  )

  const clearFilters = () => {
    setSearch('')
    setSeverity('')
    setEventType('')
    setSimUser('')
    setSourceIp('')
    setStatus('')
    setSourceLog('')
    setStartTime('')
    setEndTime('')
  }

  if (!investigationId) {
    return (
      <div className="max-w-3xl mx-auto pt-16">
        <Card>
          <EmptyState title="No investigation selected" message="Load a demo scenario to explore its evidence." />
        </Card>
      </div>
    )
  }

  return (
    <div className="max-w-6xl mx-auto">
      <div className="flex items-center justify-between mb-2">
        <h1 className="text-xl font-bold text-slate-100">Evidence Explorer</h1>
        <span className="text-xs text-slate-500">{events.length} events</span>
      </div>
      <p className="text-xs text-slate-500 mb-5">
        Search and filter normalized evidence events. Each event preserves its raw source record.
      </p>

      <div className="flex flex-wrap gap-2 mb-4 items-center">
        <div className="relative">
          <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="IP, user, file, host…"
            className="input pl-8 w-56"
          />
        </div>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} className="input">
          <option value="">All severities</option>
          <option value="CRITICAL">CRITICAL</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="LOW">LOW</option>
          <option value="INFO">INFO</option>
        </select>
        <select value={eventType} onChange={(e) => setEventType(e.target.value)} className="input">
          <option value="">All event types</option>
          {distinctTypes.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
        <select value={simUser} onChange={(e) => setSimUser(e.target.value)} className="input">
          <option value="">All users</option>
          {distinctUsers.map((u) => (
            <option key={u} value={u}>{u}</option>
          ))}
        </select>
        {hasFilters && (
          <button className="btn-outline flex items-center gap-1.5" onClick={clearFilters}>
            <X size={13} /> Clear filters
          </button>
        )}
        <button
          className={`btn-outline flex items-center gap-1.5 ${showAdvanced ? 'bg-primary/10' : ''}`}
          onClick={() => setShowAdvanced((v) => !v)}
        >
          <SlidersHorizontal size={13} /> Advanced
          {activeFilterCount > 0 && (
            <span className="ml-0.5 rounded-full bg-primary/30 text-primary-foreground px-1.5 text-[10px]">
              {activeFilterCount}
            </span>
          )}
        </button>
      </div>

      {showAdvanced && (
        <div className="mb-4 p-3 rounded-lg border border-bg-border bg-bg-card/60 gap-2 grid grid-cols-1 md:grid-cols-3">
          <input
            value={sourceIp}
            onChange={(e) => setSourceIp(e.target.value)}
            placeholder="Source IP…"
            className="input"
          />
          <select value={status} onChange={(e) => setStatus(e.target.value)} className="input">
            <option value="">All statuses</option>
            {distinctStatuses.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <select value={sourceLog} onChange={(e) => setSourceLog(e.target.value)} className="input">
            <option value="">All sources</option>
            {distinctSources.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <label className="text-xs text-slate-500 flex flex-col gap-1">
            From
            <input type="datetime-local" value={startTime} onChange={(e) => setStartTime(e.target.value)} className="input" />
          </label>
          <label className="text-xs text-slate-500 flex flex-col gap-1">
            To
            <input type="datetime-local" value={endTime} onChange={(e) => setEndTime(e.target.value)} className="input" />
          </label>
        </div>
      )}

      {error && <div className="mb-4 px-4 py-3 rounded-lg bg-red-900/30 border border-red-800 text-red-300 text-sm">{error}</div>}

      {loading ? (
        <div className="pt-10">
          <Spinner size={28} />
        </div>
      ) : events.length === 0 ? (
        <Card>
          <EmptyState title="No events match" message="Adjust your filters or upload more evidence." />
        </Card>
      ) : (
        <Card className="p-0 overflow-hidden">
          <div className="overflow-x-auto max-h-[70vh] overflow-y-auto">
            <table className="w-full text-left text-xs">
              <thead className="sticky top-0 bg-bg-card">
                <tr className="text-slate-500 uppercase text-[10px] border-b border-bg-border">
                  <th className="py-2.5 px-3">Event</th>
                  <th className="py-2.5 px-3">Timestamp</th>
                  <th className="py-2.5 px-3">Type</th>
                  <th className="py-2.5 px-3">User</th>
                  <th className="py-2.5 px-3">Source IP</th>
                  <th className="py-2.5 px-3">Host</th>
                  <th className="py-2.5 px-3">File</th>
                  <th className="py-2.5 px-3">Action</th>
                  <th className="py-2.5 px-3">Severity</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <tr
                    key={e.event_id}
                    onClick={() => setSelected(e)}
                    className="border-b border-bg-border last:border-0 cursor-pointer hover:bg-slate-800/30"
                  >
                    <td className="py-2 px-3 font-mono text-primary">{e.event_id}</td>
                    <td className="py-2 px-3 font-mono text-slate-400 whitespace-nowrap">{e.timestamp?.slice(0, 19)}</td>
                    <td className="py-2 px-3 text-slate-300">{e.event_type}</td>
                    <td className="py-2 px-3 text-slate-200">{e.user || '—'}</td>
                    <td className="py-2 px-3 font-mono text-slate-400">{e.source_ip || '—'}</td>
                    <td className="py-2 px-3 text-slate-400">{e.destination_host || e.source_host || '—'}</td>
                    <td className="py-2 px-3 text-slate-400 max-w-[160px] truncate">{e.file_path || '—'}</td>
                    <td className="py-2 px-3 text-slate-300">{e.action}</td>
                    <td className="py-2 px-3"><SeverityBadge severity={e.severity} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {selected && <EventDetailModal event={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}