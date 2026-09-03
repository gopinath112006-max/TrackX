import { useEffect, useState } from 'react'
import { ChevronDown, ChevronUp } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { api } from '../services/api'
import { useInvestigation } from '../hooks/useInvestigation'
import { Card, ConfidenceBar, EmptyState, SeverityBadge, Spinner } from '../components/ui'
import type { Finding } from '../types'

const SEVERITY_BORDER: Record<string, string> = {
  CRITICAL: 'border-red-800/60',
  HIGH: 'border-amber-800/60',
  MEDIUM: 'border-blue-800/60',
  LOW: 'border-purple-800/60',
}

export default function Findings() {
  const { investigationId } = useInvestigation()
  const navigate = useNavigate()
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)

  useEffect(() => {
    const load = async () => {
      if (!investigationId) return
      setLoading(true)
      setError(null)
      try {
        const rows = await api.getFindings(investigationId)
        setFindings(rows)
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Failed to load findings')
        setFindings([])
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [investigationId])

  if (!investigationId) {
    return (
      <div className="max-w-3xl mx-auto pt-16">
        <Card>
          <EmptyState title="No investigation selected" message="Load a demo scenario to explore findings." />
        </Card>
      </div>
    )
  }

  return (
    <div className="max-w-4xl mx-auto">
      <h1 className="text-xl font-bold text-slate-100 mb-1">Findings & Supporting Evidence</h1>
      <p className="text-xs text-slate-500 mb-5">
        Detected suspicious activities, each with an explainable reason, confidence score, and links to the
        underlying evidence events.
      </p>

      {error && <div className="mb-4 px-4 py-3 rounded-lg bg-red-900/30 border border-red-800 text-red-300 text-sm">{error}</div>}
      {loading ? (
        <div className="pt-10"><Spinner size={28} /></div>
      ) : findings.length === 0 ? (
        <Card>
          <EmptyState title="No findings yet" message="Run the analysis to generate findings from the evidence." />
        </Card>
      ) : (
        <div className="space-y-4">
          {findings.map((f) => {
            const open = expanded === f.finding_id
            return (
              <div key={f.finding_id} className={`card border ${SEVERITY_BORDER[f.severity] || ''}`}>
                <button
                  className="w-full text-left flex items-center gap-3"
                  onClick={() => setExpanded(open ? null : f.finding_id)}
                >
                  <SeverityBadge severity={f.severity} />
                  <span className="flex-1 text-sm font-medium text-slate-100">{f.title}</span>
                  <span className="text-xs text-slate-500 font-mono">{f.finding_id}</span>
                  <span className="text-xs font-mono text-slate-400">{f.confidence.toFixed(0)}%</span>
                  {open ? <ChevronUp size={16} className="text-slate-500" /> : <ChevronDown size={16} className="text-slate-500" />}
                </button>

                {open && (
                  <div className="mt-4 pl-10">
                    <p className="text-sm text-slate-300 mb-4">{f.description}</p>

                    <div className="mb-4">
                      <ConfidenceBar value={f.confidence} label="Detection confidence" />
                    </div>

                    <div className="mb-4">
                      <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-1.5">Why was this detected?</div>
                      <p className="text-xs text-amber-300/90 bg-amber-900/10 border border-amber-800/30 rounded-lg px-3 py-2">{f.reason}</p>
                    </div>

                    <div className="mb-4">
                      <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-1.5">Supporting evidence</div>
                      <div className="flex flex-wrap gap-1.5">
                        {f.related_event_ids.map((eid) => (
                          <button
                            key={eid}
                            className="px-2 py-1 rounded bg-slate-800 font-mono text-[11px] text-primary hover:bg-slate-700"
                            onClick={() => navigate(`/explorer?search=${encodeURIComponent(eid)}`)}
                            title="Open in evidence explorer"
                          >
                            {eid}
                          </button>
                        ))}
                      </div>
                    </div>

                    <div className="text-xs text-slate-500">
                      Category: <span className="font-mono text-slate-400">{f.category}</span>
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}