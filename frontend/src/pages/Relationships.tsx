import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  Handle,
  Position,
  MarkerType,
  type NodeProps,
  type Edge as FlowEdge,
  type Node as FlowNode,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { User, Globe, Server, FileText, Zap, Activity, RefreshCw } from 'lucide-react'
import { api } from '../services/api'
import { useInvestigation } from '../hooks/useInvestigation'
import { Card, EmptyState, Spinner } from '../components/ui'
import type { GraphNode, GraphEdge } from '../types'

const TYPE_COLORS: Record<string, string> = {
  USER: '#3b82f6',
  IP: '#f59e0b',
  HOST: '#10b981',
  FILE: '#8b5cf6',
  EVENT: '#94a3b8',
  SERVER: '#ef4444',
}

const TYPE_ICONS: Record<string, React.ReactNode> = {
  USER: <User size={14} />,
  IP: <Globe size={14} />,
  HOST: <Server size={14} />,
  FILE: <FileText size={14} />,
  SERVER: <Server size={14} />,
  EVENT: <Zap size={14} />,
}

function GraphNodeComp({ data }: NodeProps) {
  const node = data.node as GraphNode
  return (
    <div>
      <Handle type="target" position={Position.Top} />
      <div
        className="flex items-center gap-2 rounded-md border px-3 py-1.5 text-xs font-medium"
        style={{ borderColor: node.color, backgroundColor: `${node.color}1a`, color: node.color }}
      >
        <span>{TYPE_ICONS[node.type] || <Activity size={14} />}</span>
        <span className="font-mono">{node.label}</span>
      </div>
      <Handle type="source" position={Position.Bottom} />
    </div>
  )
}

function computeLayout(nodes: GraphNode[], edges: GraphEdge[]): FlowNode[] {
  const columns: Record<string, GraphNode[]> = {}
  nodes.forEach((n) => {
    if (!columns[n.type]) columns[n.type] = []
    columns[n.type].push(n)
  })
  const order = ['IP', 'USER', 'HOST', 'SERVER', 'FILE', 'EVENT']
  const colOrder = order.filter((t) => columns[t])
  const others = Object.keys(columns).filter((t) => !order.includes(t))
  colOrder.push(...others)

  const result: FlowNode[] = []
  colOrder.forEach((type, ci) => {
    const colNodes = columns[type]
    const gapY = 90
    const startY = (colNodes.length - 1) * gapY / 2
    colNodes.forEach((n, ni) => {
      result.push({
        id: n.id,
        type: 'graphNode',
        position: { x: ci * 230 + 40, y: ni * gapY - startY },
        data: { node: n },
      })
    })
  })
  return result
}

export default function Relationships() {
  const { investigationId } = useInvestigation()
  const navigate = useNavigate()
  const [nodes, setNodes, onNodesChange] = useNodesState<FlowNode>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState<FlowEdge>([])
  const [graphData, setGraphData] = useState<{ nodes: GraphNode[]; edges: GraphEdge[] } | null>(null)
  const [loading, setLoading] = useState(false)
  const [loadingDetail, setLoadingDetail] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selectedInfo, setSelectedInfo] = useState<{
    label: string
    type: string
    detail: string
    reason?: string
    evidence?: string[]
  } | null>(null)
  const [highlighted, setHighlighted] = useState<Set<string>>(new Set())

  const nodeTypes = useMemo(() => ({ graphNode: GraphNodeComp }), [])

  const load = async () => {
    if (!investigationId) return
    setLoading(true)
    setError(null)
    try {
      const rel = await api.getRelationships(investigationId)
      setGraphData(rel)
      const layoutNodes = computeLayout(rel.nodes, rel.edges)
      setNodes(layoutNodes)
      setEdges(
        rel.edges.map((e) => ({
          id: e.id,
          source: e.source,
          target: e.target,
          label: e.label,
          animated: e.label?.includes('transfer') || e.label?.includes('logged in') || Boolean(e.inferred),
          markerEnd: { type: MarkerType.ArrowClosed, color: e.inferred ? '#8b5cf6' : '#64748b' },
          style: {
            stroke: e.inferred ? '#8b5cf6' : '#94a3b8',
            strokeWidth: e.inferred ? 1.5 : 1.5,
            strokeDasharray: e.inferred ? '5 5' : undefined,
          },
          labelStyle: { fill: e.inferred ? '#a78bfa' : '#94a3b8', fontSize: 9 },
          labelBgStyle: { fill: '#111a2e', fillOpacity: 0.8 },
        })),
      )
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load relationship graph')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [investigationId])

  const onNodeClick = (_: React.MouseEvent, node: FlowNode) => {
    const g = node.data.node as GraphNode
    setSelectedInfo({
      label: g.label,
      type: g.type,
      detail: `Connected via ${edges.filter((e) => e.source === g.id || e.target === g.id).length} relationship(s)`,
    })
  }

  const onEdgeClick = (_: React.MouseEvent, edge: FlowEdge) => {
    const srcNode = nodes.find((n) => n.id === edge.source)
    const tgtNode = nodes.find((n) => n.id === edge.target)
    const src = srcNode?.data.node as GraphNode | undefined
    const tgt = tgtNode?.data.node as GraphNode | undefined
    const related = graphData?.edges.find((e) => e.id === edge.id)
    setSelectedInfo({
      label: `${src?.label ?? '?'} ${related?.label ?? ''} ${tgt?.label ?? '?'}`,
      type: `RELATIONSHIP${related?.inferred ? ' · INFERRED (derived)' : ''}`,
      detail: `Source: ${src?.type ?? '?'} · Target: ${tgt?.type ?? '?'}${
        related?.reason ? ` · ${related.reason}` : ''
      }`,
      evidence: related?.evidence_event_ids,
    })
  }

  const highlightChain = (label: string) => {
    const ids = new Set<string>()
    edges.forEach((e) => {
      if (e.label === label) {
        ids.add(e.source)
        ids.add(e.target)
      }
    })
    setHighlighted(ids)
  }

  if (!investigationId) {
    return (
      <div className="max-w-3xl mx-auto pt-16">
        <Card>
          <EmptyState title="No investigation selected" message="Load a demo scenario to visualize relationships." />
        </Card>
      </div>
    )
  }

  return (
    <div className="max-w-6xl mx-auto">
      <div className="flex items-center justify-between mb-2">
        <h1 className="text-xl font-bold text-slate-100">Evidence Relationship Graph</h1>
        <button className="btn-outline flex items-center gap-2" onClick={load}>
          <RefreshCw size={14} /> Reload
        </button>
      </div>
      <p className="text-xs text-slate-500 mb-5">
        Interactive graph of entities (users, IPs, hosts, files) and the relationships detected in the evidence.
        Zoom, pan, and click nodes or edges for details.
      </p>

      {error && <div className="mb-4 px-4 py-3 rounded-lg bg-red-900/30 border border-red-800 text-red-300 text-sm">{error}</div>}

      <div className="grid lg:grid-cols-4 gap-4">
        <div className="lg:col-span-3 card p-0 overflow-hidden" style={{ height: 600 }}>
          {loading ? (
            <div className="pt-24"><Spinner size={28} /></div>
          ) : nodes.length === 0 ? (
            <div className="pt-24">
              <EmptyState title="No relationships found" message="Run analysis first to build the graph." />
            </div>
          ) : (
            <ReactFlow
              nodes={nodes.map((n) => ({
                ...n,
                style: highlighted.size > 0 && !highlighted.has(n.id) ? { opacity: 0.25 } : {},
              }))}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              nodeTypes={nodeTypes}
              onNodeClick={onNodeClick}
              onEdgeClick={onEdgeClick}
              fitView
              minZoom={0.2}
            >
              <Background color="#1e2a44" gap={24} />
              <Controls />
              <MiniMap
                nodeColor={(n) => (TYPE_COLORS[n.type ?? 'EVENT'] || '#64748b')}
                maskColor="rgba(11, 17, 32, 0.7)"
              />
            </ReactFlow>
          )}
        </div>

        <div className="space-y-4">
          <Card>
            <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-3">Node legend</h3>
            <div className="space-y-2">
              {Object.entries({ USER: 'User account', IP: 'IP address', HOST: 'Host / workstation', SERVER: 'Server', FILE: 'File / resource', EVENT: 'Event' }).map(([type, label]) => (
                <div key={type} className="flex items-center gap-2 text-xs">
                  <span className="h-3 w-3 rounded" style={{ backgroundColor: TYPE_COLORS[type] }} />
                  <span className="text-slate-300">{label}</span>
                </div>
              ))}
              <div className="flex items-center gap-2 text-xs">
                <svg width="12" height="12"><line x1="0" y1="6" x2="12" y2="6" stroke="#8b5cf6" strokeWidth="2" strokeDasharray="3 3" /></svg>
                <span className="text-purple-300">Inferred relation</span>
              </div>
            </div>
          </Card>

          <Card>
            <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-3">Highlight by relationship</h3>
            <div className="space-y-1.5">
              {Array.from(new Set(graphData?.edges.map((e) => e.label) ?? [])).map((label) => (
                <button
                  key={label}
                  className="w-full text-left text-xs px-2 py-1.5 rounded hover:bg-slate-800 text-slate-300 border border-transparent hover:border-bg-border"
                  onClick={() => highlightChain(label)}
                >
                  {label}
                </button>
              ))}
            </div>
          </Card>

          {selectedInfo && (
            <Card>
              <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">Selection</h3>
              <div className="text-sm text-slate-200 break-words">{selectedInfo.label}</div>
              <div className="text-xs text-slate-500 mt-1">{selectedInfo.type}</div>
              <div className="text-xs text-slate-500 mt-2">{selectedInfo.detail}</div>

              {selectedInfo.reason && (
                <div className="mt-3 text-xs text-purple-300/90 bg-purple-900/10 border border-purple-800/30 rounded-lg px-3 py-2">
                  {selectedInfo.reason}
                </div>
              )}

              {selectedInfo.evidence && selectedInfo.evidence.length > 0 && (
                <div className="mt-3">
                  <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-1.5">Supporting evidence</div>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedInfo.evidence.map((eid) => (
                      <button
                        key={eid}
                        className="px-2 py-1 rounded bg-slate-800 font-mono text-[10px] text-primary hover:bg-slate-700"
                        onClick={() => navigate(`/explorer?search=${encodeURIComponent(eid)}`)}
                        title="Open in evidence explorer"
                      >
                        {eid}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}