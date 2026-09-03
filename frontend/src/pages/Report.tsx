import { useEffect, useState } from 'react'
import { Download, FileText, Printer, Loader2, ShieldCheck } from 'lucide-react'
import { api } from '../services/api'
import { useInvestigation } from '../hooks/useInvestigation'
import { Card, CardHeader, ConfidenceBar, EmptyState, SeverityBadge, Spinner } from '../components/ui'
import type { ReportData } from '../types'

export default function Report() {
  const { investigationId } = useInvestigation()
  const [report, setReport] = useState<ReportData | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const load = async () => {
      if (!investigationId) return
      setLoading(true)
      setError(null)
      try {
        const rep = await api.getReport(investigationId)
        setReport(rep)
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Failed to load report')
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [investigationId])

  const openHtml = () => {
    if (!investigationId) return
    window.open(api.reportHtmlUrl(investigationId), '_blank')
  }

  if (!investigationId) {
    return (
      <div className="max-w-3xl mx-auto pt-16">
        <Card>
          <EmptyState title="No investigation selected" message="Load a demo scenario to generate the report." />
        </Card>
      </div>
    )
  }

  return (
    <div className="max-w-4xl mx-auto">
      <div className="flex items-center justify-between mb-2">
        <h1 className="text-xl font-bold text-slate-100">Investigation Report</h1>
        <div className="flex gap-2">
          <button className="btn-outline flex items-center gap-2" onClick={() => window.print()}>
            <Printer size={14} /> Print
          </button>
          <button className="btn-primary flex items-center gap-2" onClick={openHtml} disabled={loading}>
            <Download size={14} /> Download / Open Report
          </button>
        </div>
      </div>
      <p className="text-xs text-slate-500 mb-5">
        A print-friendly HTML report with all investigation data, findings, timeline, and the attack story.
      </p>

      {error && <div className="mb-4 px-4 py-3 rounded-lg bg-red-900/30 border border-red-800 text-red-300 text-sm">{error}</div>}
      {loading ? (
        <div className="pt-10"><Spinner size={28} /></div>
      ) : !report ? (
        <Card>
          <EmptyState title="No report available" message="Run the analysis first, then reload this page." />
        </Card>
      ) : (
        <div className="space-y-4">
          <Card>
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-2">
                <FileText size={18} className="text-primary" />
                <div>
                  <h2 className="text-sm font-bold text-slate-100">INVESTIGATION REPORT — {report.investigation.name}</h2>
                  <p className="text-xs text-slate-500 mt-0.5">
                    ID #{report.investigation.id} · generated {report.investigation.created_at?.slice(0, 19) ?? ''} · {report.investigation.total_events} events
                  </p>
                </div>
              </div>
              <SeverityBadge severity={report.investigation.risk_level} />
            </div>
          </Card>

          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3">
            <ReportStat label="Total events" value={report.investigation.total_events} />
            <ReportStat label="Suspicious" value={report.investigation.suspicious_events} />
            <ReportStat label="Findings" value={report.investigation.total_findings} />
            <ReportStat label="Overall confidence" value={`${report.investigation.confidence.toFixed(1)}%`} />
          </div>

          <Card>
            <CardHeader title="Attack story" icon={<ShieldCheck size={16} />} />
            <p className="text-sm leading-relaxed text-slate-200 whitespace-pre-line">{report.attack_story.narrative}</p>
          </Card>

          <Card>
            <CardHeader title="Findings" />
            <div className="space-y-3">
              {report.findings.map((f) => (
                <div key={f.finding_id} className="border border-bg-border rounded-lg p-3">
                  <div className="flex items-center gap-2 mb-2">
                    <SeverityBadge severity={f.severity} />
                    <span className="text-sm font-medium text-slate-100">{f.title}</span>
                    <span className="ml-auto text-xs font-mono text-slate-500">{f.confidence.toFixed(0)}%</span>
                  </div>
                  <p className="text-xs text-slate-400 mb-2">{f.description}</p>
                  <div className="flex flex-wrap gap-1">
                    {f.related_event_ids.map((eid) => (
                      <span key={eid} className="px-1.5 py-0.5 rounded bg-slate-800 font-mono text-[10px] text-primary">{eid}</span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </Card>

          <Card>
            <CardHeader title="Blast radius" />
            <div className="grid sm:grid-cols-2 gap-3">
              <BlastList label="Affected users" items={report.blast_radius.users} />
              <BlastList label="Affected IPs" items={report.blast_radius.ips} />
              <BlastList label="Affected systems" items={report.blast_radius.hosts} />
              <BlastList label="Affected files" items={report.blast_radius.files} />
            </div>
          </Card>

          <Card>
            <CardHeader title="Confidence breakdown" />
            <ConfidenceBar value={report.attack_story.confidence.score} />
            <p className="text-xs text-slate-500 mt-1 mb-3">Level: {report.attack_story.confidence.level}</p>
            <ul className="space-y-1">
              {report.attack_story.confidence.factors.map((f, i) => (
                <li key={i} className="text-xs text-slate-400 flex gap-2">
                  <span className="text-emerald-400">+</span>
                  {f}
                </li>
              ))}
            </ul>
          </Card>

          <Card>
            <CardHeader title="Evidence integrity" subtitle="Uploaded forensic files with SHA-256 hashes" />
            {report.evidence_files.length === 0 ? (
              <p className="text-xs text-slate-500">No evidence files recorded.</p>
            ) : (
              <div className="space-y-2">
                {report.evidence_files.map((ef) => (
                  <div key={`${ef.filename}-${ef.sha256_hash}`} className="flex items-center gap-3 text-xs border border-bg-border rounded-lg px-3 py-2">
                    <FileText size={13} className="text-slate-500" />
                    <span className="text-slate-200">{ef.filename}</span>
                    <span className="ml-auto font-mono text-[10px] text-slate-500">{ef.sha256_hash.slice(0, 24)}…</span>
                    <SeverityBadge severity="INFO" />
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      )}
    </div>
  )
}

function ReportStat({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="card">
      <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-1">{label}</div>
      <div className="text-lg font-bold font-mono text-primary">{value}</div>
    </div>
  )
}

function BlastList({ label, items }: { label: string; items: string[] }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-1">{label} <span className="text-slate-600">({items.length})</span></div>
      <div className="flex flex-wrap gap-1">
        {items.length === 0 ? (
          <span className="text-xs text-slate-600">None</span>
        ) : (
          items.slice(0, 8).map((x) => (
            <span key={x} className="text-[11px] px-1.5 py-0.5 rounded bg-slate-800/60 text-slate-300 font-mono">{x}</span>
          ))
        )}
        {items.length > 8 && <span className="text-[11px] text-slate-500">+{items.length - 8}</span>}
      </div>
    </div>
  )
}