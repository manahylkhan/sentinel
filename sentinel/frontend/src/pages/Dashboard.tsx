import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { BarChart, Bar, XAxis, YAxis, Tooltip, PieChart, Pie, Cell, ResponsiveContainer } from 'recharts'
import api from '../api/client'

interface DashStats {
  open_incidents: { total: number; critical: number; high: number; medium: number; low: number }
  incidents_last_30_days: number
  incidents_by_month: { month: string; count: number }[]
  incidents_by_type: Record<string, number>
  active_iocs: { total: number; malicious: number; suspicious: number }
  ti_checks_today: number
  risk_score: number
  risk_level: string
  peca_required_open: number
  recent_incidents: any[]
  recent_ti_checks: any[]
}

const SEVERITY_COLORS = { critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#16a34a' }
const VERDICT_COLORS = { malicious: '#dc2626', suspicious: '#ea580c', clean: '#16a34a', unknown: '#64748b' }

function RiskMeter({ score, level }: { score: number; level: string }) {
  const color = score <= 25 ? '#16a34a' : score <= 50 ? '#d97706' : score <= 75 ? '#ea580c' : '#dc2626'
  const circ = 2 * Math.PI * 54
  const dash = circ * (1 - score / 100)
  return (
    <div className="flex flex-col items-center justify-center py-4">
      <svg viewBox="0 0 120 120" className="w-32 h-32">
        <circle cx="60" cy="60" r="54" fill="none" stroke="#1e293b" strokeWidth="10" />
        <circle cx="60" cy="60" r="54" fill="none" stroke={color} strokeWidth="10"
          strokeDasharray={circ} strokeDashoffset={dash}
          strokeLinecap="round" transform="rotate(-90 60 60)"
          style={{ transition: 'stroke-dashoffset 1s ease' }}
        />
        <text x="60" y="56" textAnchor="middle" fill={color} fontSize="24" fontWeight="bold">{score}</text>
        <text x="60" y="74" textAnchor="middle" fill="#94a3b8" fontSize="10">{level} Risk</text>
      </svg>
    </div>
  )
}

export default function Dashboard() {
  const navigate = useNavigate()
  const [stats, setStats] = useState<DashStats | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.get('/dashboard/stats').then(res => { setStats(res.data); setLoading(false) }).catch(() => setLoading(false))
  }, [])

  if (loading) return <div className="p-6 text-slate-400">Loading dashboard...</div>
  if (!stats) return <div className="p-6 text-red-400">Failed to load dashboard</div>

  const severityPieData = [
    { name: 'Critical', value: stats.open_incidents.critical, color: '#dc2626' },
    { name: 'High', value: stats.open_incidents.high, color: '#ea580c' },
    { name: 'Medium', value: stats.open_incidents.medium, color: '#d97706' },
    { name: 'Low', value: stats.open_incidents.low, color: '#16a34a' },
  ].filter(d => d.value > 0)

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="page-title mb-1">Security Dashboard</h1>
          <p className="text-slate-400">Real-time security posture overview.</p>
        </div>
        <div className="flex gap-2">
          <button className="btn-primary text-sm" onClick={() => navigate('/incidents/new')}>+ Report Incident</button>
          <button className="btn-secondary text-sm" onClick={() => navigate('/threat-intel')}>Check Indicator</button>
          <button className="btn-secondary text-sm" onClick={() => navigate('/logs')}>Upload Logs</button>
        </div>
      </div>

      {/* PECA Alert */}
      {stats.peca_required_open > 0 && (
        <div className="bg-orange-950/40 border border-orange-700/60 rounded-xl p-4 mb-6 flex gap-3 items-center">
          <span className="text-xl">⚠️</span>
          <div>
            <span className="font-bold text-orange-300">{stats.peca_required_open} open incident(s) require PECA 2016 reporting.</span>
            <span className="text-orange-400 text-sm ml-2">FIA Cybercrime: report.fia.gov.pk | 0800-02345</span>
          </div>
        </div>
      )}

      {/* Top row: Risk + Stats */}
      <div className="grid grid-cols-5 gap-4 mb-6">
        <div className="card col-span-1 flex flex-col items-center justify-center">
          <div className="text-xs text-slate-500 uppercase tracking-wide font-semibold mb-1">Risk Score</div>
          <RiskMeter score={stats.risk_score} level={stats.risk_level} />
        </div>

        <div className="col-span-4 grid grid-cols-4 gap-4">
          {[
            { label: 'Open Incidents', value: stats.open_incidents.total, sub: `${stats.open_incidents.critical} critical`, color: 'text-red-400', onClick: () => navigate('/incidents') },
            { label: 'Active IOCs', value: stats.active_iocs.total, sub: `${stats.active_iocs.malicious} malicious`, color: 'text-orange-400', onClick: () => navigate('/iocs') },
            { label: 'TI Checks Today', value: stats.ti_checks_today, sub: 'indicator lookups', color: 'text-blue-400', onClick: () => navigate('/threat-intel') },
            { label: 'PECA Actions', value: stats.peca_required_open, sub: 'require reporting', color: stats.peca_required_open > 0 ? 'text-orange-400' : 'text-green-400', onClick: () => navigate('/incidents') },
          ].map(s => (
            <div key={s.label} className="card cursor-pointer hover:border-slate-600 transition-colors" onClick={s.onClick}>
              <div className={`text-4xl font-bold ${s.color} mb-1`}>{s.value}</div>
              <div className="text-slate-300 font-medium text-sm">{s.label}</div>
              <div className="text-slate-500 text-xs mt-1">{s.sub}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-2 gap-4 mb-6">
        <div className="card">
          <h3 className="section-title">Incidents Per Month</h3>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={stats.incidents_by_month} margin={{ top: 5, right: 10, bottom: 5, left: 0 }}>
              <XAxis dataKey="month" tick={{ fill: '#94a3b8', fontSize: 11 }} />
              <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} allowDecimals={false} />
              <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', color: '#f1f5f9' }} />
              <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h3 className="section-title">Open Incidents by Severity</h3>
          {severityPieData.length > 0 ? (
            <div className="flex items-center gap-4">
              <ResponsiveContainer width="60%" height={200}>
                <PieChart>
                  <Pie data={severityPieData} cx="50%" cy="50%" outerRadius={80} dataKey="value">
                    {severityPieData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                  </Pie>
                  <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', color: '#f1f5f9' }} />
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-2">
                {severityPieData.map(d => (
                  <div key={d.name} className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full" style={{ background: d.color }}></div>
                    <span className="text-slate-300 text-sm">{d.name}: <span className="font-bold">{d.value}</span></span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="flex items-center justify-center h-48 text-slate-500">
              <div className="text-center">
                <div className="text-4xl mb-2">✅</div>
                <div>No open incidents</div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Recent activity */}
      <div className="grid grid-cols-2 gap-4">
        <div className="card">
          <h3 className="section-title">Recent Incidents</h3>
          {stats.recent_incidents.length ? (
            <div className="space-y-2">
              {stats.recent_incidents.map(inc => (
                <div
                  key={inc.id}
                  className="flex items-center justify-between py-2 border-b border-slate-800 last:border-0 cursor-pointer hover:bg-slate-800/30 -mx-2 px-2 rounded"
                  onClick={() => navigate(`/incidents/${inc.id}`)}
                >
                  <div className="flex items-center gap-2">
                    <span className={`text-xs font-bold uppercase ${
                      inc.severity === 'critical' ? 'text-red-400' :
                      inc.severity === 'high' ? 'text-orange-400' :
                      inc.severity === 'medium' ? 'text-yellow-400' : 'text-green-400'
                    }`}>[{inc.severity}]</span>
                    <span className="text-slate-300 text-sm">{inc.title}</span>
                  </div>
                  <span className="text-slate-500 text-xs">{new Date(inc.created_at).toLocaleDateString()}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-slate-500 text-sm">No incidents yet.</p>
          )}
        </div>

        <div className="card">
          <h3 className="section-title">Recent TI Checks</h3>
          {stats.recent_ti_checks.length ? (
            <div className="space-y-2">
              {stats.recent_ti_checks.map(ti => (
                <div key={ti.id} className="flex items-center justify-between py-2 border-b border-slate-800 last:border-0">
                  <div className="flex items-center gap-2">
                    <span className={`badge-${ti.verdict}`}>{ti.verdict}</span>
                    <span className="font-mono text-slate-300 text-sm">{ti.indicator}</span>
                  </div>
                  <span className="text-slate-500 text-xs">{new Date(ti.created_at).toLocaleDateString()}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-slate-500 text-sm">No TI checks yet.</p>
          )}
        </div>
      </div>
    </div>
  )
}
