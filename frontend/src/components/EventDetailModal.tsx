import { X, FileText } from 'lucide-react'
import type { NormalizedEvent } from '../types'
import { SeverityBadge } from './ui'

function Field({ label, value }: { label: string; value?: string | null }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-slate-500">{label}</div>
      <div className="text-sm text-slate-200 font-mono">{value || '—'}</div>
    </div>
  )
}

export function EventDetailModal({ event, onClose }: { event: NormalizedEvent; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div className="bg-bg-card border border-bg-border rounded-xl w-full max-w-2xl max-h-[85vh] overflow-y-auto mx-4" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-bg-border">
          <div className="flex items-center gap-2">
            <span className="font-mono text-primary text-sm">{event.event_id}</span>
            <SeverityBadge severity={event.severity} />
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-200">
            <X size={18} />
          </button>
        </div>

        <div className="p-5">
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4 mb-5">
            <Field label="Timestamp" value={event.timestamp} />
            <Field label="Event type" value={event.event_type} />
            <Field label="Action" value={event.action} />
            <Field label="Status" value={event.status} />
            <Field label="User" value={event.user} />
            <Field label="Source IP" value={event.source_ip} />
            <Field label="Destination IP" value={event.destination_ip} />
            <Field label="Source host" value={event.source_host} />
            <Field label="Destination host" value={event.destination_host} />
            <Field label="File" value={event.file_path} />
            <Field label="Evidence source" value={event.source} />
          </div>

          {event.raw_data && Object.keys(event.raw_data).length > 0 && (
            <div>
              <div className="flex items-center gap-2 text-xs text-slate-400 mb-2">
                <FileText size={13} /> Original raw evidence record (unchanged)
              </div>
              <pre className="bg-bg rounded-md p-3 text-[11px] text-emerald-300 overflow-x-auto whitespace-pre-wrap font-mono max-h-48 overflow-y-auto">
                {JSON.stringify(event.raw_data, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}