import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import toast from 'react-hot-toast'
import api from '../../api/client'

interface Step {
  step_number: number
  action: string
  owner: string
  time_estimate: string
  critical: boolean
  details: string
}

interface Phase {
  phase_name: string
  time_target: string
  steps: Step[]
}

interface Playbook {
  phases: Phase[]
  notify_list?: any[]
  pakistan_specific?: string[]
  immediate_actions?: string[]
  tools_needed?: string[]
}

interface Incident {
  id: string
  title: string
  description: string
  incident_type: string
  severity: string
  status: string
  affected_systems: string
  reporter_name: string
  reporter_email: string
  ai_playbook: Playbook | null
  ai_classification: any
  mitre_techniques: any[]
  peca_required: boolean
  peca_reason: string
  created_at: string
  iocs?: any[]
}

interface TimelineEntry {
  id: string
  action: string
  detail: string
  created_by: string
  created_at: string
}

interface Evidence {
  id: string
  file_name: string
  file_size: number
  file_hash_sha256: string
  uploaded_by: string
  created_at: string
  description: string
}

const STATUS_OPTIONS = ['new', 'investigating', 'contained', 'recovering', 'closed']

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-green-400',
}

export default function IncidentDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [incident, setIncident] = useState<Incident | null>(null)
  const [timeline, setTimeline] = useState<TimelineEntry[]>([])
  const [evidence, setEvidence] = useState<Evidence[]>([])
  const [activePhase, setActivePhase] = useState(0)
  const [activeTab, setActiveTab] = useState<'playbook' | 'timeline' | 'iocs' | 'evidence'>('playbook')
  const [loading, setLoading] = useState(true)
  const [checkedSteps, setCheckedSteps] = useState<Record<string, boolean>>(() => {
    try { return JSON.parse(localStorage.getItem(`sentinel_steps_${id}`) || '{}') } catch { return {} }
  })
  const [timelineInput, setTimelineInput] = useState({ action: '', detail: '', created_by: '' })
  const [uploadFile, setUploadFile] = useState<File | null>(null)
  const [uploadDesc, setUploadDesc] = useState('')
  const [uploadBy, setUploadBy] = useState('')
  const [uploading, setUploading] = useState(false)

  useEffect(() => { loadAll() }, [id])

  const loadAll = async () => {
    if (!id) return
    setLoading(true)
    try {
      const [incRes, tlRes, evRes] = await Promise.all([
        api.get(`/incidents/${id}`),
        api.get(`/incidents/${id}/timeline`),
        api.get(`/incidents/${id}/evidence`),
      ])
      setIncident(incRes.data)
      setTimeline(tlRes.data)
      setEvidence(evRes.data)
    } catch {
      toast.error('Failed to load incident')
    }
    setLoading(false)
  }

  const updateStatus = async (status: string) => {
    try {
      await api.patch(`/incidents/${id}/status`, { status })
      setIncident(prev => prev ? { ...prev, status } : prev)
      toast.success(`Status updated to ${status}`)
    } catch { toast.error('Failed to update status') }
  }

  const toggleStep = (key: string) => {
    const updated = { ...checkedSteps, [key]: !checkedSteps[key] }
    setCheckedSteps(updated)
    localStorage.setItem(`sentinel_steps_${id}`, JSON.stringify(updated))
  }

  const addTimeline = async () => {
    if (!timelineInput.action || !timelineInput.created_by) return
    try {
      const res = await api.post(`/incidents/${id}/timeline`, timelineInput)
      setTimeline(prev => [...prev, res.data])
      setTimelineInput({ action: '', detail: '', created_by: '' })
      toast.success('Timeline entry added')
    } catch { toast.error('Failed to add entry') }
  }

  const uploadEvidence = async () => {
    if (!uploadFile || !uploadBy) { toast.error('Select a file and enter your name'); return }
    setUploading(true)
    try {
      const fd = new FormData()
      fd.append('file', uploadFile)
      fd.append('description', uploadDesc)
      fd.append('uploaded_by', uploadBy)
      const res = await api.post(`/incidents/${id}/evidence`, fd)
      setEvidence(prev => [...prev, res.data])
      setUploadFile(null)
      setUploadDesc('')
      toast.success('Evidence uploaded')
    } catch { toast.error('Upload failed') }
    setUploading(false)
  }

  const downloadReport = async () => {
    try {
      const res = await api.get(`/incidents/${id}/report/pdf`, { responseType: 'blob' })
      const url = URL.createObjectURL(res.data)
      const a = document.createElement('a'); a.href = url
      a.download = `SENTINEL_Report_${id?.slice(0, 8)}.pdf`; a.click()
      URL.revokeObjectURL(url)
    } catch { toast.error('Failed to generate report') }
  }

  if (loading) return <div className="p-6 text-slate-400">Loading...</div>
  if (!incident) return <div className="p-6 text-red-400">Incident not found</div>

  const playbook: Playbook = incident.ai_playbook || { phases: [] }
  const currentPhase = playbook.phases?.[activePhase]

  return (
    <div className="p-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="mb-6">
        <button className="text-slate-400 hover:text-slate-200 text-sm mb-3 flex items-center gap-1" onClick={() => navigate('/incidents')}>
          ← Back to Incidents
        </button>
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1">
            <div className="flex items-center gap-3 mb-2 flex-wrap">
              <span className={`font-bold text-lg uppercase ${SEVERITY_COLOR[incident.severity] || 'text-slate-100'}`}>
                [{incident.severity}]
              </span>
              <h1 className="text-xl font-bold text-slate-100">{incident.title}</h1>
            </div>
            <div className="text-slate-400 text-sm">
              {incident.incident_type?.replace(/_/g, ' ').toUpperCase()} • Reporter: {incident.reporter_name} • {new Date(incident.created_at).toLocaleString()}
            </div>
          </div>
          <div className="flex gap-2 items-center">
            <select
              className="input w-auto py-1.5"
              value={incident.status}
              onChange={e => updateStatus(e.target.value)}
            >
              {STATUS_OPTIONS.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
            </select>
            <button className="btn-secondary text-sm" onClick={downloadReport}>📄 FIA Report</button>
          </div>
        </div>
      </div>

      {/* PECA Alert */}
      {incident.peca_required && (
        <div className="bg-orange-950/40 border border-orange-700/60 rounded-xl p-4 mb-5 flex gap-3">
          <span className="text-2xl">⚠️</span>
          <div>
            <div className="font-bold text-orange-300 mb-1">PECA 2016 Reporting Required</div>
            <p className="text-orange-200 text-sm">{incident.peca_reason}</p>
            <p className="text-orange-400 text-sm mt-1 font-medium">Contact FIA Cybercrime Wing: report.fia.gov.pk | 0800-02345 | cybercrime@fia.gov.pk</p>
          </div>
        </div>
      )}

      {/* Classification + MITRE */}
      <div className="grid grid-cols-2 gap-4 mb-5">
        <div className="card-sm">
          <div className="text-xs text-slate-500 uppercase tracking-wide font-semibold mb-2">AI Classification</div>
          {incident.ai_classification && (
            <div className="space-y-1 text-sm">
              <div><span className="text-slate-500">Severity Reason:</span> <span className="text-slate-300">{incident.ai_classification.severity_reason}</span></div>
              {incident.ai_classification.affected_data_types?.length > 0 && (
                <div><span className="text-slate-500">Data at Risk:</span> <span className="text-slate-300">{incident.ai_classification.affected_data_types.join(', ')}</span></div>
              )}
              {incident.ai_classification.initial_containment && (
                <div className="mt-2">
                  <div className="text-slate-500 text-xs mb-1">Immediate Actions:</div>
                  <ol className="list-decimal list-inside space-y-0.5">
                    {incident.ai_classification.initial_containment.map((a: string, i: number) => (
                      <li key={i} className="text-red-300 text-xs font-medium">{a}</li>
                    ))}
                  </ol>
                </div>
              )}
            </div>
          )}
        </div>

        {incident.mitre_techniques?.length > 0 && (
          <div className="card-sm">
            <div className="text-xs text-slate-500 uppercase tracking-wide font-semibold mb-2">MITRE ATT&CK</div>
            <div className="flex flex-wrap gap-2">
              {incident.mitre_techniques.map((t: any) => (
                <a
                  key={t.technique_id}
                  href={`https://attack.mitre.org/techniques/${t.technique_id}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="bg-slate-800 border border-slate-700 hover:border-blue-600/50 text-slate-300 hover:text-blue-300 px-2.5 py-1 rounded text-xs font-mono transition-colors"
                  title={`${t.tactic} — ${t.confidence} confidence`}
                >
                  {t.technique_id} {t.technique_name}
                </a>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-4 border-b border-slate-800">
        {([['playbook', '📖 Playbook'], ['timeline', '📅 Timeline'], ['iocs', '🎯 IOCs'], ['evidence', '📁 Evidence']] as const).map(([key, label]) => (
          <button
            key={key}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === key ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
            onClick={() => setActiveTab(key)}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Playbook Tab */}
      {activeTab === 'playbook' && (
        <div>
          {playbook.phases?.length ? (
            <>
              {/* Phase tabs */}
              <div className="flex gap-2 mb-4 flex-wrap">
                {playbook.phases.map((phase, i) => (
                  <button
                    key={i}
                    onClick={() => setActivePhase(i)}
                    className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                      activePhase === i ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {phase.phase_name}
                    <span className="ml-1.5 text-xs opacity-70">({phase.steps?.length || 0})</span>
                  </button>
                ))}
              </div>

              {currentPhase && (
                <div className="card">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="font-bold text-slate-100 text-lg">{currentPhase.phase_name}</h3>
                    <span className="text-sm text-blue-400 bg-blue-900/30 px-3 py-1 rounded-full border border-blue-800/50">
                      🕐 Target: {currentPhase.time_target}
                    </span>
                  </div>
                  <div className="space-y-3">
                    {(currentPhase.steps || []).map((step, si) => {
                      const key = `${activePhase}-${si}`
                      const checked = checkedSteps[key]
                      return (
                        <div
                          key={si}
                          className={`flex gap-3 p-4 rounded-lg border transition-colors ${
                            checked ? 'bg-green-950/20 border-green-800/40' :
                            step.critical ? 'bg-red-950/10 border-red-900/30' : 'bg-slate-800/30 border-slate-700/50'
                          }`}
                        >
                          <input
                            type="checkbox"
                            checked={checked || false}
                            onChange={() => toggleStep(key)}
                            className="mt-0.5 h-4 w-4 accent-blue-500 cursor-pointer shrink-0"
                          />
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="text-slate-500 text-xs">Step {step.step_number}</span>
                              {step.critical && <span className="text-xs bg-red-900/40 text-red-400 border border-red-800/40 px-1.5 py-0.5 rounded">CRITICAL</span>}
                            </div>
                            <div className={`font-medium mb-1 ${checked ? 'line-through text-slate-500' : 'text-slate-100'}`}>
                              {step.action}
                            </div>
                            {step.details && <p className="text-slate-400 text-sm">{step.details}</p>}
                            <div className="flex gap-3 mt-1.5 text-xs text-slate-500">
                              <span>👤 {step.owner}</span>
                              <span>⏱ {step.time_estimate}</span>
                            </div>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>
              )}

              {/* Pakistan-specific */}
              {playbook.pakistan_specific?.length && (
                <div className="card mt-4 border-green-900/40 bg-green-950/10">
                  <div className="text-sm font-semibold text-green-400 mb-2">🇵🇰 Pakistan-Specific Steps</div>
                  <ul className="space-y-1">
                    {playbook.pakistan_specific.map((s, i) => (
                      <li key={i} className="text-slate-300 text-sm flex gap-2"><span className="text-green-500">•</span>{s}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Notify list */}
              {playbook.notify_list?.length && (
                <div className="card mt-4">
                  <div className="text-sm font-semibold text-slate-300 mb-3">📢 Who to Notify</div>
                  <div className="space-y-3">
                    {playbook.notify_list.map((n: any, i: number) => (
                      <div key={i} className="bg-slate-800/40 border border-slate-700/50 rounded-lg p-3">
                        <div className="font-medium text-slate-200 text-sm">{n.who} <span className="text-slate-500 font-normal">— {n.when}</span></div>
                        <div className="text-slate-400 text-xs mt-0.5">{n.why}</div>
                        {n.template_hint && <div className="text-slate-500 text-xs mt-1 italic">"{n.template_hint}"</div>}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="text-slate-500 py-8 text-center">No playbook available</div>
          )}
        </div>
      )}

      {/* Timeline Tab */}
      {activeTab === 'timeline' && (
        <div className="space-y-4">
          <div className="space-y-3">
            {timeline.map(entry => (
              <div key={entry.id} className="flex gap-3">
                <div className="w-2 h-2 bg-blue-500 rounded-full mt-2 shrink-0"></div>
                <div className="card-sm flex-1">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-medium text-slate-200 text-sm">{entry.action}</span>
                    <span className="text-xs text-slate-500">{new Date(entry.created_at).toLocaleString()}</span>
                  </div>
                  {entry.detail && <p className="text-slate-400 text-sm">{entry.detail}</p>}
                  <div className="text-xs text-slate-500 mt-1">by {entry.created_by}</div>
                </div>
              </div>
            ))}
          </div>

          <div className="card">
            <div className="text-sm font-semibold text-slate-300 mb-3">Add Timeline Entry</div>
            <div className="space-y-2">
              <input className="input" placeholder="Action taken (e.g. 'Isolated affected machine')" value={timelineInput.action} onChange={e => setTimelineInput(p => ({ ...p, action: e.target.value }))} />
              <input className="input" placeholder="Details (optional)" value={timelineInput.detail} onChange={e => setTimelineInput(p => ({ ...p, detail: e.target.value }))} />
              <div className="flex gap-2">
                <input className="input" placeholder="Your name" value={timelineInput.created_by} onChange={e => setTimelineInput(p => ({ ...p, created_by: e.target.value }))} />
                <button className="btn-primary" onClick={addTimeline}>Add Entry</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* IOCs Tab */}
      {activeTab === 'iocs' && (
        <div className="card">
          <h3 className="section-title">Extracted Indicators of Compromise</h3>
          {incident.iocs?.length ? (
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-700">
                  <th className="text-left py-2 px-3 table-header">Type</th>
                  <th className="text-left py-2 px-3 table-header">Indicator</th>
                  <th className="text-left py-2 px-3 table-header">Verdict</th>
                  <th className="text-left py-2 px-3 table-header">Status</th>
                </tr>
              </thead>
              <tbody>
                {incident.iocs.map((ioc: any) => (
                  <tr key={ioc.id} className="border-b border-slate-800">
                    <td className="py-2 px-3 text-slate-400 text-sm uppercase">{ioc.indicator_type}</td>
                    <td className="py-2 px-3 font-mono text-slate-300 text-sm">{ioc.indicator}</td>
                    <td className="py-2 px-3"><span className={`badge-${ioc.verdict || 'unknown'}`}>{ioc.verdict || 'unknown'}</span></td>
                    <td className="py-2 px-3 text-slate-400 text-sm">{ioc.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="text-slate-500 text-sm">No IOCs extracted yet.</p>
          )}
        </div>
      )}

      {/* Evidence Tab */}
      {activeTab === 'evidence' && (
        <div className="space-y-4">
          {/* Upload */}
          <div className="card">
            <h3 className="section-title">Upload Evidence</h3>
            <div className="space-y-3">
              <div>
                <label className="label">File</label>
                <input type="file" className="input py-1.5" onChange={e => setUploadFile(e.target.files?.[0] || null)} />
              </div>
              <div>
                <label className="label">Description</label>
                <input className="input" placeholder="What is this file?" value={uploadDesc} onChange={e => setUploadDesc(e.target.value)} />
              </div>
              <div className="flex gap-2">
                <input className="input" placeholder="Uploaded by (your name)" value={uploadBy} onChange={e => setUploadBy(e.target.value)} />
                <button className="btn-primary" onClick={uploadEvidence} disabled={uploading}>
                  {uploading ? 'Uploading...' : 'Upload'}
                </button>
              </div>
            </div>
          </div>

          {/* Evidence list */}
          {evidence.length > 0 && (
            <div className="card">
              <h3 className="section-title">Evidence Files</h3>
              <table className="w-full">
                <thead>
                  <tr className="border-b border-slate-700">
                    <th className="text-left py-2 px-3 table-header">File</th>
                    <th className="text-left py-2 px-3 table-header">Size</th>
                    <th className="text-left py-2 px-3 table-header">SHA-256</th>
                    <th className="text-left py-2 px-3 table-header">Uploaded By</th>
                    <th className="text-left py-2 px-3 table-header">Date</th>
                  </tr>
                </thead>
                <tbody>
                  {evidence.map(ev => (
                    <tr key={ev.id} className="border-b border-slate-800">
                      <td className="py-2 px-3 text-slate-300 text-sm">{ev.file_name}</td>
                      <td className="py-2 px-3 text-slate-500 text-sm">{Math.round((ev.file_size || 0) / 1024)} KB</td>
                      <td className="py-2 px-3 font-mono text-slate-500 text-xs">{ev.file_hash_sha256?.slice(0, 16)}...</td>
                      <td className="py-2 px-3 text-slate-400 text-sm">{ev.uploaded_by}</td>
                      <td className="py-2 px-3 text-slate-500 text-sm">{new Date(ev.created_at).toLocaleDateString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
