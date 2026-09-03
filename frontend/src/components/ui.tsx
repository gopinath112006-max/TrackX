import React from 'react'

export function Card({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return <div className={`card ${className}`}>{children}</div>
}

export function CardHeader({ title, subtitle, icon }: { title: string; subtitle?: string; icon?: React.ReactNode }) {
  return (
    <div className="flex items-start gap-3 mb-4">
      {icon && <div className="text-primary mt-0.5">{icon}</div>}
      <div>
        <h2 className="text-sm font-semibold text-slate-100">{title}</h2>
        {subtitle && <p className="text-xs text-slate-400 mt-0.5">{subtitle}</p>}
      </div>
    </div>
  )
}

export function Badge({ children, color = 'slate', className = '' }: { children: React.ReactNode; color?: string; className?: string }) {
  const map: Record<string, string> = {
    slate: 'bg-slate-700 text-slate-200',
    blue: 'bg-blue-900 text-blue-200',
    green: 'bg-emerald-900 text-emerald-200',
    amber: 'bg-amber-900 text-amber-200',
    red: 'bg-red-900 text-red-200',
    purple: 'bg-purple-900 text-purple-200',
  }
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${map[color] || map.slate} ${className}`}>
      {children}
    </span>
  )
}

export function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, { label: string; color: string }> = {
    CRITICAL: { label: 'CRITICAL', color: 'red' },
    HIGH: { label: 'HIGH', color: 'amber' },
    MEDIUM: { label: 'MEDIUM', color: 'blue' },
    LOW: { label: 'LOW', color: 'purple' },
    INFO: { label: 'INFO', color: 'green' },
  }
  const s = (severity || 'INFO').toUpperCase()
  const cfg = map[s] || map.INFO
  return <Badge color={cfg.color}>{cfg.label}</Badge>
}

export function ConfidenceBar({ value, label = 'Confidence' }: { value: number; label?: string }) {
  const color = value >= 80 ? '#10b981' : value >= 50 ? '#f59e0b' : '#64748b'
  return (
    <div>
      <div className="flex justify-between text-xs mb-1">
        <span className="text-slate-400">{label}</span>
        <span className="font-mono font-semibold" style={{ color }}>{value.toFixed(1)}%</span>
      </div>
      <div className="h-2 rounded bg-slate-700 overflow-hidden">
        <div className="h-full rounded" style={{ width: `${Math.min(100, value)}%`, backgroundColor: color }} />
      </div>
    </div>
  )
}

export function StatCard({
  label,
  value,
  accent = '#3b82f6',
  icon,
}: {
  label: string
  value: React.ReactNode
  accent?: string
  icon?: React.ReactNode
}) {
  return (
    <div className="card">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-slate-400 uppercase tracking-wide">{label}</span>
        {icon && <span style={{ color: accent }}>{icon}</span>}
      </div>
      <div className="text-2xl font-bold font-mono" style={{ color: accent }}>
        {value}
      </div>
    </div>
  )
}

export function Spinner({ size = 20 }: { size?: number }) {
  return (
    <div
      className="animate-spin rounded-full border-2 border-slate-600 border-t-primary mx-auto"
      style={{ width: size, height: size }}
    />
  )
}

export function EmptyState({ title, message }: { title: string; message: string }) {
  return (
    <div className="py-10 text-center">
      <p className="text-slate-300 text-sm font-medium">{title}</p>
      <p className="text-slate-500 text-xs mt-1">{message}</p>
    </div>
  )
}