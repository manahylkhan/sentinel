import { useEffect, useState } from 'react'
import toast from 'react-hot-toast'
import api from '../api/client'

interface IOC {
  id: string
  indicator: string
  indicator_type: string
  verdict: string
  severity: string
  source: string
  status: string
  incident_id: string | null
  notes: string
  created_at: string
}

const VERDICT_CLASS: Record<string, string> = {
  malicious: 'badge-malicious', suspicious: 'badge-suspicious', clean: 'badge-clean', unknown: 'badge-unknown'
}
const SEVERITY_CLASS: Record<string, string> = {
  critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low', info: 'badge-info'
}

export default function IOCTracker() {
  const [iocs, setIocs] = useState<IOC[]>([])
  const [stats, setStats] = useState({ total: 0, active: 0, blocked: 0, malicious: 0 })
  const [loading, setLoading] = useState(true)
  const [bulkChecking, setBulkChecking] = useState(false)
  const [showAdd, setShowAdd] = useState(false)
  const [filterVerdict, setFilterVerdict] = useState('')
  const [filterStatus, setFilterStatus] = useState('')
  const [newIoc, setNewIoc] = useState({ indicator: '', indicator_type: 'ip', severity: 'medium', notes: '' })

  useEffect(() => { load() }, [filterVerdict, filterStatus])

  const load = async () => {
    setLoading(true)
    try {
      const params: Record<string, string> = {}
      if (filterVerdict) params.verdict = filterVerdict
      if (filterStatus) params.status = filterStatus
      const [iocRes, statsRes] = await Promise.all([
        api.get('/iocs', { params }),
        api.get('/iocs/stats'),
      ])
      setIocs(iocRes.data)
      setStats(statsRes.data)
    } catch {}
    setLoading(false)
  }

  const addIoc = async () => {
    if (!newIoc.indicator) { toast.error('Enter an indicator value'); return }
    try {
      await api.post('/iocs', newIoc)
      toast.success('IOC added')
      setShowAdd(false)
      setNewIoc({ indicator: '', indicator_type: 'ip', severity: 'medium', notes: '' })
      load()
    } catch (e: any) {
      toast.error(e.response?.data?.detail || 'Failed to add IOC')
    }
  }

  const updateStatus = async (id: string, status: string) => {
    try {
      await api.patch(`/iocs/${id}`, { status })
      setIocs(prev => prev.map(i => i.id === id ? { ...i, status } : i))
    } catch { toast.error('Update failed') }
  }

  const deleteIoc = async (id: string) => {
    if (!confirm('Delete this IOC?')) return
    try {
      await api.delete(`/iocs/${id}`)
      setIocs(prev => prev.filter(i => i.id !== id))
      toast.success('IOC deleted')
    } catch { toast.error('Delete failed') }
  }

  const bulkCheck = async () => {
    setBulkChecking(true)
    try {
      const res = await api.post('/iocs/bulk-check')
      toast.success(`Re-checked ${res.data.updated} IOCs`)
      load()
    } catch { toast.error('Bulk check failed') }
    setBulkChecking(false)
  }

  const exportStix = async () => {
    try {
      const res = await api.get('/iocs/export/stix', { responseType: 'blob' })
      const url = URL.createObjectURL(res.data)
      const a = document.createElement('a')
      a.href = url; a.download = 'sentinel_iocs.stix.json'; a.click()
      URL.revokeObjectURL(url)
    } catch { toast.error('Export failed') }
  }

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="page-title mb-1">IOC Tracker</h1>
          <p className="text-slate-400">Centralized management of all Indicators of Compromise.</p>
        </div>
        <div className="flex gap-2">
          <button className="btn-secondary text-sm" onClick={bulkCheck} disabled={bulkChecking}>
            {bulkChecking ? '🔄 Checking...' : '🔄 Bulk Re-Check'}
          </button>
          <button className="btn-secondary text-sm" onClick={exportStix}>📦 Export STIX</button>
          <button className="btn-primary text-sm" onClick={() => setShowAdd(true)}>+ Add IOC</button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: 'Total IOCs', value: stats.total, color: 'text-slate-100' },
          { label: 'Active', value: stats.active, color: 'text-blue-400' },
          { label: 'Malicious', value: stats.malicious, color: 'text-red-400' },
          { label: 'Blocked', value: stats.blocked, color: 'text-purple-400' },
        ].map(s => (
          <div key={s.label} className="card-sm text-center">
            <div className={`text-3xl font-bold ${s.color}`}>{s.value}</div>
            <div className="text-slate-400 text-sm mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Add Modal */}
      {showAdd && (
        <div className="card mb-5 border-blue-700/50">
          <h3 className="section-title">Add IOC</h3>
          <div className="grid grid-cols-2 gap-3 mb-3">
            <div className="col-span-2">
              <label className="label">Indicator Value</label>
              <input className="input" placeholder="IP, domain, hash, URL, or email" value={newIoc.indicator} onChange={e => setNewIoc(p => ({ ...p, indicator: e.target.value }))} />
            </div>
            <div>
              <label className="label">Type</label>
              <select className="input" value={newIoc.indicator_type} onChange={e => setNewIoc(p => ({ ...p, indicator_type: e.target.value }))}>
                <option value="ip">IP Address</option>
                <option value="domain">Domain</option>
                <option value="url">URL</option>
                <option value="hash">File Hash</option>
                <option value="email">Email</option>
              </select>
            </div>
            <div>
              <label className="label">Severity</label>
              <select className="input" value={newIoc.severity} onChange={e => setNewIoc(p => ({ ...p, severity: e.target.value }))}>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </div>
            <div className="col-span-2">
              <label className="label">Notes</label>
              <input className="input" placeholder="Optional notes" value={newIoc.notes} onChange={e => setNewIoc(p => ({ ...p, notes: e.target.value }))} />
            </div>
          </div>
          <div className="flex gap-2">
            <button className="btn-primary" onClick={addIoc}>Add IOC</button>
            <button className="btn-secondary" onClick={() => setShowAdd(false)}>Cancel</button>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex gap-3 mb-4">
        <select className="input w-auto" value={filterVerdict} onChange={e => setFilterVerdict(e.target.value)}>
          <option value="">All Verdicts</option>
          <option value="malicious">Malicious</option>
          <option value="suspicious">Suspicious</option>
          <option value="clean">Clean</option>
          <option value="unknown">Unknown</option>
        </select>
        <select className="input w-auto" value={filterStatus} onChange={e => setFilterStatus(e.target.value)}>
          <option value="">All Statuses</option>
          <option value="active">Active</option>
          <option value="blocked">Blocked</option>
          <option value="investigating">Investigating</option>
          <option value="resolved">Resolved</option>
          <option value="false_positive">False Positive</option>
        </select>
      </div>

      {/* Table */}
      <div className="card p-0 overflow-hidden">
        <table className="w-full">
          <thead className="bg-slate-800/50 border-b border-slate-700">
            <tr>
              <th className="text-left py-3 px-4 table-header">Type</th>
              <th className="text-left py-3 px-4 table-header">Indicator</th>
              <th className="text-left py-3 px-4 table-header">Verdict</th>
              <th className="text-left py-3 px-4 table-header">Severity</th>
              <th className="text-left py-3 px-4 table-header">Status</th>
              <th className="text-left py-3 px-4 table-header">Source</th>
              <th className="text-left py-3 px-4 table-header">Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={7} className="py-12 text-center text-slate-500">Loading...</td></tr>
            ) : iocs.length === 0 ? (
              <tr><td colSpan={7} className="py-12 text-center text-slate-500">No IOCs found</td></tr>
            ) : iocs.map(ioc => (
              <tr key={ioc.id} className="border-b border-slate-800 hover:bg-slate-800/30">
                <td className="py-3 px-4 text-slate-400 text-xs uppercase font-mono">{ioc.indicator_type}</td>
                <td className="py-3 px-4 font-mono text-slate-300 text-sm max-w-xs truncate">{ioc.indicator}</td>
                <td className="py-3 px-4"><span className={VERDICT_CLASS[ioc.verdict] || 'badge-unknown'}>{ioc.verdict || 'unknown'}</span></td>
                <td className="py-3 px-4"><span className={SEVERITY_CLASS[ioc.severity] || 'badge-info'}>{ioc.severity}</span></td>
                <td className="py-3 px-4">
                  <select
                    className="bg-slate-800 border border-slate-700 rounded px-2 py-0.5 text-xs text-slate-300"
                    value={ioc.status}
                    onChange={e => updateStatus(ioc.id, e.target.value)}
                  >
                    <option value="active">Active</option>
                    <option value="blocked">Blocked</option>
                    <option value="investigating">Investigating</option>
                    <option value="resolved">Resolved</option>
                    <option value="false_positive">False Positive</option>
                  </select>
                </td>
                <td className="py-3 px-4 text-slate-500 text-xs">{ioc.source}</td>
                <td className="py-3 px-4">
                  <button className="text-red-400 hover:text-red-300 text-xs" onClick={() => deleteIoc(ioc.id)}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
