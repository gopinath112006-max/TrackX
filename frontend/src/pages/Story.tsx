import { useEffect, useState } from 'react'
import { BookOpenText, AlertTriangle, ShieldCheck } from 'lucide-react'
import { api } from '../services/api'
import { useInvestigation } from '../hooks/useInvestigation'
import { Card, CardHeader, ConfidenceBar, EmptyState, Spinner } from '../components/ui'
import type { InvestigationOverview } from '../types'

export default function Story() {
  const { investigationId } = useInvestigation()
  const [overview, setOverview] = useState<InvestigationOverview | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const load = async () => {
      if (!investigationId) return
      setLoading(true)
      try {
        const ov = await api.getInvestigation(investigationId)
        setOverview(ov)
      } catch {
        setOverview(null)
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
          <EmptyState title="No investigation selected" message="Load a demo scenario to generate an attack story." />
        </Card>
      </div>
    )
  }

  return (
    <div className="max-w-4xl mx-auto">
      <h1 className="text-xl font-bold text-slate-100 mb-1">Attack Story</h1>
      <p className="text-xs text-slate-500 mb-5">
        A human-readable narrative generated strictly from the analyzed evidence. Uses cautious forensic language —
        nothing is stated as certain unless supported by evidence.
      </p>

      {error && <div className="mb-4 px-4 py-3 rounded-lg bg-red-900/30 border border-red-800 text-red-300 text-sm">{error}</div>}
      {loading ? (
        <div className="pt-10"><Spinner size={28} /></div>
      ) : !overview ? (
        <Card>
          <EmptyState title="Analysis not run" message="Run the analysis to generate the attack story." />
        </Card>
      ) : (
        <>
          <Card className="mb-4">
            <CardHeader title="Investigation narrative" icon={<BookOpenText size={16} />} />
            <p className="text-sm leading-relaxed text-slate-200 whitespace-pre-line">
              {overview.story.narrative}
            </p>
          </Card>

          <div className="grid lg:grid-cols-2 gap-4 mb-4">
            <Card>
              <CardHeader title="Overall confidence" icon={<ShieldCheck size={16} />} />
              <ConfidenceBar value={overview.confidence.score} label="Overall confidence" />
              <p className="text-xs text-slate-500 mt-1 mb-3">Level: {overview.confidence.level}</p>
              <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-1">Scoring factors</div>
              <ul className="space-y-1">
                {overview.confidence.factors.map((f, i) => (
                  <li key={i} className="text-xs text-slate-400 flex gap-2">
                    <span className="text-emerald-400">+</span>
                    {f}
                  </li>
                ))}
              </ul>
            </Card>

            <Card>
              <CardHeader title="Key findings referenced" icon={<AlertTriangle size={16} />} />
              {overview.story.key_findings.length === 0 ? (
                <p className="text-xs text-slate-500">No key findings to reference.</p>
              ) : (
                <ul className="space-y-1">
                  {overview.story.key_findings.map((k, i) => (
                    <li key={i} className="text-xs text-slate-300 flex gap-2">
                      <span className="text-amber-400">•</span>
                      {k}
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          </div>

          <Card>
            <CardHeader title="Investigation limitations" subtitle="Caveats that a forensic analyst should bear in mind" icon={<AlertTriangle size={16} />} />
            <ul className="space-y-1.5">
              {overview.story.limitations.map((l, i) => (
                <li key={i} className="text-xs text-slate-400 flex gap-2">
                  <span className="text-slate-600">-</span>
                  {l}
                </li>
              ))}
            </ul>
          </Card>
        </>
      )}
    </div>
  )
}