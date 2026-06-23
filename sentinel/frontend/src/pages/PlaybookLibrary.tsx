import { useEffect, useState } from 'react'
import toast from 'react-hot-toast'
import api from '../api/client'

interface Playbook {
  id: string
  name: string
  incident_type: string
  description: string
  is_builtin: boolean
  phase_count: number
  step_count: number
  content: any
}

const TYPE_ICON: Record<string, string> = {
  ransomware: '🔒', phishing: '🎣', account_takeover: '👤', data_breach: '💀',
  insider: '🕵️', ddos: '💥', social_eng: '🎭', lost_device: '📱',
  vendor_breach: '🤝', malware: '🦠', other: '⚠️',
}

export default function PlaybookLibrary() {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([])
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<Playbook | null>(null)
  const [activePhase, setActivePhase] = useState(0)
  const [showCreate, setShowCreate] = useState(false)
  const [newPb, setNewPb] = useState({ name: '', incident_type: 'other', description: '' })

  useEffect(() => { load() }, [])

  const load = async () => {
    setLoading(true)
    try {
      const res = await api.get('/playbooks')
      setPlaybooks(res.data)
    } catch {}
    setLoading(false)
  }

  const createPlaybook = async () => {
    if (!newPb.name) { toast.error('Enter a playbook name'); return }
    const skeleton = JSON.stringify({
      phases: [
        { phase_name: 'Immediate Containment', time_target: 'Within 1 hour', steps: [{ step_number: 1, action: 'Your first step', owner: 'IT Person', time_estimate: '15 minutes', critical: true, details: 'Describe what to do' }] }
      ],
      notify_list: [], pakistan_specific: [], tools_needed: []
    }, null, 2)
    try {
      await api.post('/playbooks', { ...newPb, content_json: skeleton })
      toast.success('Custom playbook created')
      setShowCreate(false)
      setNewPb({ name: '', incident_type: 'other', description: '' })
      load()
    } catch (e: any) { toast.error(e.response?.data?.detail || 'Failed to create') }
  }

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="page-title mb-1">Playbook Library</h1>
          <p className="text-slate-400">Pre-built and custom incident response playbooks with Pakistan-specific steps.</p>
        </div>
        <button className="btn-primary" onClick={() => setShowCreate(true)}>+ Create Custom Playbook</button>
      </div>

      {showCreate && (
        <div className="card mb-6 border-blue-700/50">
          <h3 className="section-title">New Custom Playbook</h3>
          <div className="space-y-3">
            <div>
              <label className="label">Playbook Name</label>
              <input className="input" placeholder="e.g. Our Ransomware Response" value={newPb.name} onChange={e => setNewPb(p => ({ ...p, name: e.target.value }))} />
            </div>
            <div>
              <label className="label">Incident Type</label>
              <select className="input" value={newPb.incident_type} onChange={e => setNewPb(p => ({ ...p, incident_type: e.target.value }))}>
                <option value="ransomware">Ransomware</option>
                <option value="phishing">Phishing</option>
                <option value="account_takeover">Account Takeover</option>
                <option value="data_breach">Data Breach</option>
                <option value="insider">Insider Threat</option>
                <option value="ddos">DDoS</option>
                <option value="social_eng">Social Engineering</option>
                <option value="lost_device">Lost Device</option>
                <option value="vendor_breach">Vendor Breach</option>
                <option value="malware">Malware</option>
                <option value="other">Other</option>
              </select>
            </div>
            <div>
              <label className="label">Description</label>
              <input className="input" placeholder="Brief description" value={newPb.description} onChange={e => setNewPb(p => ({ ...p, description: e.target.value }))} />
            </div>
            <div className="flex gap-2">
              <button className="btn-primary" onClick={createPlaybook}>Create Playbook</button>
              <button className="btn-secondary" onClick={() => setShowCreate(false)}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      <div className="flex gap-6">
        {/* Playbook grid */}
        <div className={`${selected ? 'w-80 shrink-0' : 'w-full'}`}>
          {loading ? (
            <div className="text-slate-500 py-8 text-center">Loading playbooks...</div>
          ) : (
            <div className={`grid gap-3 ${selected ? 'grid-cols-1' : 'grid-cols-3'}`}>
              {playbooks.map(pb => (
                <div
                  key={pb.id}
                  className={`card cursor-pointer hover:border-blue-600/50 transition-colors ${selected?.id === pb.id ? 'border-blue-600' : ''}`}
                  onClick={() => { setSelected(pb); setActivePhase(0) }}
                >
                  <div className="text-3xl mb-2">{TYPE_ICON[pb.incident_type] || '⚠️'}</div>
                  <div className="font-semibold text-slate-200 mb-1 text-sm leading-tight">{pb.name}</div>
                  {pb.is_builtin && (
                    <span className="text-xs bg-blue-900/40 text-blue-400 border border-blue-800/40 px-1.5 py-0.5 rounded">BUILT-IN</span>
                  )}
                  <div className="text-slate-500 text-xs mt-2">{pb.phase_count} phases • {pb.step_count} steps</div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Playbook detail */}
        {selected && (
          <div className="flex-1 min-w-0">
            <div className="card">
              <div className="flex items-start justify-between mb-4">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-2xl">{TYPE_ICON[selected.incident_type] || '⚠️'}</span>
                    <h2 className="text-xl font-bold text-slate-100">{selected.name}</h2>
                    {selected.is_builtin && <span className="text-xs bg-blue-900/40 text-blue-400 border border-blue-800/40 px-2 py-0.5 rounded">BUILT-IN</span>}
                  </div>
                  {selected.description && <p className="text-slate-400 text-sm">{selected.description}</p>}
                </div>
                <button className="text-slate-500 hover:text-slate-300" onClick={() => setSelected(null)}>✕</button>
              </div>

              {/* Phase selector */}
              <div className="flex gap-2 mb-4 flex-wrap">
                {selected.content?.phases?.map((phase: any, i: number) => (
                  <button
                    key={i}
                    onClick={() => setActivePhase(i)}
                    className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                      activePhase === i ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {phase.phase_name}
                  </button>
                ))}
              </div>

              {selected.content?.phases?.[activePhase] && (
                <div>
                  <div className="text-blue-400 text-sm mb-3">
                    Target: {selected.content.phases[activePhase].time_target}
                  </div>
                  <div className="space-y-3">
                    {selected.content.phases[activePhase].steps?.map((step: any, si: number) => (
                      <div key={si} className={`p-4 rounded-lg border ${step.critical ? 'bg-red-950/10 border-red-900/30' : 'bg-slate-800/30 border-slate-700/50'}`}>
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-slate-500 text-xs">Step {step.step_number}</span>
                          {step.critical && <span className="text-xs bg-red-900/40 text-red-400 border border-red-800/40 px-1.5 py-0.5 rounded">CRITICAL</span>}
                        </div>
                        <div className="font-medium text-slate-100 mb-1">{step.action}</div>
                        <p className="text-slate-400 text-sm">{step.details}</p>
                        <div className="flex gap-3 mt-2 text-xs text-slate-500">
                          <span>👤 {step.owner}</span>
                          <span>⏱ {step.time_estimate}</span>
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Pakistan specific */}
                  {selected.content?.pakistan_specific?.length > 0 && activePhase === 0 && (
                    <div className="mt-4 bg-green-950/20 border border-green-800/30 rounded-lg p-4">
                      <div className="text-green-400 text-sm font-semibold mb-2">🇵🇰 Pakistan-Specific</div>
                      {selected.content.pakistan_specific.map((s: string, i: number) => (
                        <div key={i} className="text-slate-300 text-sm">• {s}</div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
