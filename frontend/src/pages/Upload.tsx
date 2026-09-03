import { useCallback, useRef, useState } from 'react'
import { useDropzone } from 'react-dropzone'
import { FileStack, UploadCloud, CheckCircle2, AlertCircle, ShieldCheck, FileText } from 'lucide-react'
import { api } from '../services/api'
import { useInvestigation } from '../hooks/useInvestigation'
import { Card, CardHeader, EmptyState } from '../components/ui'
import type { EvidenceFile } from '../types'

type CategoryKey = 'login' | 'file_access' | 'network' | 'system'

const CATEGORY_LABELS: Record<CategoryKey, string> = {
  login: 'Authentication / Login Logs',
  file_access: 'File Access Logs',
  network: 'Network Logs',
  system: 'System Logs',
}

export default function Upload() {
  const { investigationId } = useInvestigation()
  const [files, setFiles] = useState<EvidenceFile[]>([])
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [uploading, setUploading] = useState(false)
  const [selectedCategory, setSelectedCategory] = useState<CategoryKey>('login')

  const onDrop = useCallback(
    async (accepted: File[]) => {
      if (!investigationId) {
        setError('No investigation selected. Load a scenario first.')
        return
      }
      setError(null)
      setSuccess(null)
      for (const file of accepted) {
        setUploading(true)
        try {
          const result = await api.uploadEvidence(investigationId, file, selectedCategory)
          setFiles((prev) => [...prev, result])
          setSuccess(result.message)
        } catch (e) {
          setError(e instanceof Error ? e.message : `Failed to import ${file.name}`)
        } finally {
          setUploading(false)
        }
      }
    },
    [investigationId, selectedCategory],
  )

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'text/csv': ['.csv'],
      'application/json': ['.json'],
      'text/plain': ['.txt'],
    },
    maxSize: 10 * 1024 * 1024,
  })

  const refresh = async () => {
    if (!investigationId) return
    try {
      const ev = await api.listEvidence(investigationId)
      setFiles(ev)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to list evidence')
    }
  }

  return (
    <div className="max-w-4xl mx-auto">
      <div className="flex items-center justify-between mb-2">
        <h1 className="text-xl font-bold text-slate-100">Evidence Upload</h1>
        <button className="btn-outline" onClick={refresh}>
          Refresh list
        </button>
      </div>
      <p className="text-xs text-slate-500 mb-6">
        Upload simulated forensic evidence files (CSV, JSON, TXT). Files are hashed with SHA-256 for forensic
        integrity; the original records are never modified.
      </p>

      {!investigationId && (
        <div className="mb-4 px-4 py-3 rounded-lg bg-amber-900/30 border border-amber-800 text-amber-300 text-sm">
          No investigation selected. Go to the Scenario Selector and load a demo scenario first.
        </div>
      )}

      {error && (
        <div className="mb-4 px-4 py-3 rounded-lg bg-red-900/30 border border-red-800 text-red-300 text-sm flex items-center gap-2">
          <AlertCircle size={16} /> {error}
        </div>
      )}
      {success && (
        <div className="mb-4 px-4 py-3 rounded-lg bg-emerald-900/30 border border-emerald-800 text-emerald-300 text-sm flex items-center gap-2">
          <CheckCircle2 size={16} /> {success}
        </div>
      )}

      <div className="grid md:grid-cols-4 gap-3 mb-4">
        {(Object.keys(CATEGORY_LABELS) as CategoryKey[]).map((key) => (
          <button
            key={key}
            onClick={() => setSelectedCategory(key)}
            className={`border rounded-lg p-3 text-left transition-colors ${
              selectedCategory === key
                ? 'border-primary bg-primary/10'
                : 'border-bg-border hover:border-slate-500'
            }`}
          >
            <FileStack size={16} className={selectedCategory === key ? 'text-primary' : 'text-slate-500'} />
            <div className="text-xs font-medium text-slate-200 mt-1.5">{CATEGORY_LABELS[key]}</div>
          </button>
        ))}
      </div>

      <div
        {...getRootProps()}
        className={`border-2 border-dashed rounded-lg p-10 text-center cursor-pointer transition-colors mb-6 ${
          isDragActive ? 'border-primary bg-primary/5' : 'border-bg-border hover:border-slate-500'
        }`}
      >
        <input {...getInputProps()} />
        <UploadCloud size={28} className="mx-auto text-slate-500 mb-2" />
        <p className="text-sm text-slate-300">
          {isDragActive ? 'Drop the evidence files here…' : 'Drag & drop evidence files here, or click to browse'}
        </p>
        <p className="text-xs text-slate-500 mt-1">CSV, JSON, TXT · max 10 MB per file</p>
        {uploading && <p className="text-xs text-primary mt-2">Uploading…</p>}
      </div>

      <Card>
        <CardHeader
          title="Evidence integrity"
          subtitle="SHA-256 hashes document forensic integrity of uploaded evidence"
          icon={<ShieldCheck size={16} />}
        />
        {files.length === 0 ? (
          <EmptyState title="No evidence uploaded" message="Upload files or load a demo scenario to populate this list." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="text-slate-500 uppercase text-[10px] border-b border-bg-border">
                  <th className="py-2 px-2">Filename</th>
                  <th className="py-2 px-2">Category</th>
                  <th className="py-2 px-2">Events</th>
                  <th className="py-2 px-2">SHA-256</th>
                </tr>
              </thead>
              <tbody>
                {files.map((f) => (
                  <tr key={`${f.filename}-${f.sha256_hash}`} className="border-b border-bg-border last:border-0">
                    <td className="py-2 px-2 text-slate-200 flex items-center gap-1.5">
                      <FileText size={12} className="text-slate-500" /> {f.filename}
                    </td>
                    <td className="py-2 px-2 text-slate-400">{f.category}</td>
                    <td className="py-2 px-2 font-mono text-slate-300">{f.event_count}</td>
                    <td className="py-2 px-2 font-mono text-slate-500 text-[10px]">{f.sha256_hash.slice(0, 16)}…</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  )
}