import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Loader2, PlayCircle, ShieldAlert, KeyRound, Database, Network } from 'lucide-react'
import { api } from '../services/api'
import { useInvestigation } from '../hooks/useInvestigation'
import { Card, CardHeader, EmptyState, Spinner } from '../components/ui'
import type { Scenario } from '../types'

const CATEGORY_META: Record<string, { icon: React.ReactNode; desc: string }> = {
  brute_force: { icon: <KeyRound size={20} />, desc: 'SQL / SSH brute-force + account compromise + sensitive file access' },
  data_theft: { icon: <Database size={20} />, desc: 'Privileged access → bulk sensitive-file collection → exfiltration' },
  lateral_movement: { icon: <Network size={20} />, desc: 'Server hop-by-hop access → credential reuse → database compromise' },
}

export default function Scenarios() {
  const navigate = useNavigate()
  const { setInvestigation } = useInvestigation()
  const [scenarios, setScenarios] = useState<Scenario[]>([])
  const [loadingScenarios, setLoadingScenarios] = useState(true)
  const [loadingId, setLoadingId] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api
      .listScenarios()
      .then((s) => {
        setScenarios(s)
        setLoadingScenarios(false)
      })
      .catch((e) => {
        setError(e.message)
        setLoadingScenarios(false)
      })
  }, [])

  const handleLoad = async (scenario: Scenario) => {
    setLoadingId(scenario.id)
    setError(null)
    try {
      const result = await api.loadScenario(scenario.id)
      setInvestigation(result.investigation_id, scenario.name)
      navigate('/investigation')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load scenario')
      setLoadingId(null)
    }
  }

  if (loadingScenarios) {
    return (
      <div className="pt-16">
        <Spinner size={32} />
        <p className="text-center text-slate-500 text-sm mt-3">Loading scenario catalogue…</p>
      </div>
    )
  }

  return (
    <div className="max-w-4xl mx-auto">
      <h1 className="text-xl font-bold text-slate-100 mb-1">Investigation Scenario Selector</h1>
      <p className="text-xs text-slate-500 mb-6">
        Select one of the built-in simulated attack scenarios. Each loads realistic (but clearly simulated) forensic
        evidence and runs the full analysis pipeline automatically.
      </p>

      {error && (
        <div className="mb-4 px-4 py-3 rounded-lg bg-red-900/30 border border-red-800 text-red-300 text-sm">{error}</div>
      )}

      {scenarios.length === 0 ? (
        <Card>
          <EmptyState title="No scenarios found" message="Check that the backend /data/scenarios directory exists." />
        </Card>
      ) : (
        <div className="grid md:grid-cols-3 gap-4">
          {scenarios.map((s) => {
            const meta = CATEGORY_META[s.category] || { icon: <ShieldAlert size={20} />, desc: 'Simulated forensic dataset' }
            return (
              <Card key={s.id} className="flex flex-col">
                <div className="flex items-start justify-between mb-3">
                  <div className="text-amber-300">{meta.icon}</div>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 uppercase">{s.category}</span>
                </div>
                <h2 className="text-sm font-semibold text-slate-100">{s.name}</h2>
                <p className="text-xs text-slate-400 mt-1 flex-1">{meta.desc}</p>
                <p className="text-xs text-slate-500 mt-3 mb-3">{s.event_count} evidence events in dataset</p>
                <div className="text-xs text-slate-500 mb-4">
                  Expected detections:
                  <div className="flex flex-wrap gap-1 mt-1">
                    {(s.expected_findings || []).map((f) => (
                      <span key={f} className="px-2 py-0.5 rounded bg-blue-900/40 text-blue-300">{f}</span>
                    ))}
                  </div>
                </div>
                <button
                  className="btn-primary w-full flex items-center justify-center gap-2"
                  disabled={loadingId !== null}
                  onClick={() => handleLoad(s)}
                >
                  {loadingId === s.id ? <Loader2 size={14} className="animate-spin" /> : <PlayCircle size={14} />}
                  {loadingId === s.id ? 'Loading…' : 'Load Demo Scenario'}
                </button>
              </Card>
            )
          })}
        </div>
      )}
    </div>
  )
}