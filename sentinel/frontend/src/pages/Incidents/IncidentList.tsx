import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../../api/client'

interface Incident {
  id: string
  title: string
  incident_type: string
  severity: string
  status: string
  reporter_name: string
  created_at: string
  peca_required: boolean
  ioc_count: number
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low']

function SeverityBadge({ s }: { s: string }) {
  const cls: Record<string, string> = {
    critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low'
  }
  return <span className={cls[s] || 'badge-info'}>{s}</span>
}

function StatusBadge({ s }: { s: string }) {
  const colors: Record<string, string> = {
    new: 'bg-blue-900/50 text-blue-300 border-blue-700/50',
    investigating: 'bg-yellow-900/50 text-yellow-300 border-yellow-700/50',
    contained: 'bg-purple-900/50 text-purple-300 border-purple-700/50',
    recovering: 'bg-cyan-900/50 text-cyan-300 border-cyan-700/50',
    closed: 'bg-slate-700/50 text-slate-400 border-slate-600/50',
  }
  return (
    <span className={`border px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wide ${colors[s] || 'badge-info'}`}>
      {s.replace('_', ' ')}
    </span>
  )
}

export default function IncidentList() {
  const navigate = useNavigate()
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [loading, setLoading] = useState(true)
  const [filterStatus, setFilterStatus] = useState('')
  const [filterSeverity, setFilterSeverity] = useState('')

  useEffect(() => {
    loadIncidents()
  }, [filterStatus, filterSeverity])

  const loadIncidents = async () => {
    setLoading(true)
    try {
      const params: Record<string, string> = {}
      if (filterStatus) params.status = filterStatus
      if (filterSeverity) params.severity = filterSeverity
      const res = await api.get('/incidents', { params })
      setIncidents(res.data)
    } catch {}
    setLoading(false)
  }

  const counts = {
    total: incidents.length,
    open: incidents.filter(i => i.status !== 'closed').length,
    critical: incidents.filter(i => i.severity === 'critical' && i.status !== 'closed').length,
    closed: incidents.filter(i => i.status === 'closed').length,
  }

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="page-title mb-1">Incident Manager</h1>
          <p className="text-slate-400">Track, respond to, and learn from security incidents.</p>
        </div>
        <button className="btn-primary flex items-center gap-2" onClick={() => navigate('/incidents/new')}>
          <span>+</span> Report New Incident
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: 'Total', value: counts.total, color: 'text-slate-100' },
          { label: 'Open', value: counts.open, color: 'text-blue-400' },
          { label: 'Critical Open', value: counts.critical, color: 'text-red-400' },
          { label: 'Closed', value: counts.closed, color: 'text-green-400' },
        ].map(stat => (
          <div key={stat.label} className="card-sm text-center">
            <div className={`text-3xl font-bold ${stat.color}`}>{stat.value}</div>
            <div className="text-slate-400 text-sm mt-1">{stat.label}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex gap-3 mb-4">
        <select className="input w-auto" value={filterStatus} onChange={e => setFilterStatus(e.target.value)}>
          <option value="">All Statuses</option>
          <option value="new">New</option>
          <option value="investigating">Investigating</option>
          <option value="contained">Contained</option>
          <option value="recovering">Recovering</option>
          <option value="closed">Closed</option>
        </select>
        <select className="input w-auto" value={filterSeverity} onChange={e => setFilterSeverity(e.target.value)}>
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      {/* Table */}
      <div className="card p-0 overflow-hidden">
        <table className="w-full">
          <thead className="bg-slate-800/50 border-b border-slate-700">
            <tr>
              <th className="text-left py-3 px-4 table-header">Severity</th>
              <th className="text-left py-3 px-4 table-header">Title</th>
              <th className="text-left py-3 px-4 table-header">Type</th>
              <th className="text-left py-3 px-4 table-header">Status</th>
              <th className="text-left py-3 px-4 table-header">IOCs</th>
              <th className="text-left py-3 px-4 table-header">Reporter</th>
              <th className="text-left py-3 px-4 table-header">Date</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={7} className="py-12 text-center text-slate-500">Loading...</td></tr>
            ) : incidents.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-16 text-center">
                  <div className="text-slate-500 text-lg mb-2">No incidents yet</div>
                  <button className="btn-primary text-sm" onClick={() => navigate('/incidents/new')}>Report your first incident</button>
                </td>
              </tr>
            ) : (
              incidents.map(inc => (
                <tr
                  key={inc.id}
                  className="border-b border-slate-800 hover:bg-slate-800/30 cursor-pointer"
                  onClick={() => navigate(`/incidents/${inc.id}`)}
                >
                  <td className="py-3 px-4"><SeverityBadge s={inc.severity} /></td>
                  <td className="py-3 px-4">
                    <div className="text-slate-200 font-medium">{inc.title}</div>
                    {inc.peca_required && <div className="text-xs text-orange-400 mt-0.5">⚠ PECA Reporting Required</div>}
                  </td>
                  <td className="py-3 px-4 text-slate-400 text-sm capitalize">{inc.incident_type?.replace('_', ' ')}</td>
                  <td className="py-3 px-4"><StatusBadge s={inc.status} /></td>
                  <td className="py-3 px-4 text-slate-400 text-sm">{inc.ioc_count || 0}</td>
                  <td className="py-3 px-4 text-slate-400 text-sm">{inc.reporter_name}</td>
                  <td className="py-3 px-4 text-slate-500 text-sm">{new Date(inc.created_at).toLocaleDateString()}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
