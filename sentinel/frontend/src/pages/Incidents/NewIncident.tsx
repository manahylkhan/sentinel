import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import toast from 'react-hot-toast'
import api from '../../api/client'

export default function NewIncident() {
  const navigate = useNavigate()
  const [form, setForm] = useState({
    title: '',
    description: '',
    affected_systems: '',
    reporter_name: '',
    reporter_email: '',
  })
  const [loading, setLoading] = useState(false)

  const handle = (field: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
    setForm(prev => ({ ...prev, [field]: e.target.value }))

  const submit = async () => {
    if (!form.title || !form.description || !form.reporter_name || !form.reporter_email) {
      toast.error('Please fill in all required fields')
      return
    }
    setLoading(true)
    const toastId = toast.loading('Analyzing incident with AI...')
    try {
      const res = await api.post('/incidents', form)
      toast.success('Incident created with AI analysis', { id: toastId })
      navigate(`/incidents/${res.data.id}`)
    } catch (e: any) {
      toast.error(e.response?.data?.detail || 'Failed to create incident', { id: toastId })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="p-6 max-w-3xl mx-auto">
      <div className="mb-6">
        <button className="text-slate-400 hover:text-slate-200 text-sm mb-4 flex items-center gap-1" onClick={() => navigate('/incidents')}>
          ← Back to Incidents
        </button>
        <h1 className="page-title">Report New Security Incident</h1>
        <p className="text-slate-400">Describe what happened and AI will classify it, generate a response playbook, and extract indicators of compromise automatically.</p>
      </div>

      <div className="card space-y-5">
        <div>
          <label className="label">Incident Title <span className="text-red-400">*</span></label>
          <input className="input" placeholder="e.g. Ransomware infection on accounting workstation" value={form.title} onChange={handle('title')} />
        </div>

        <div>
          <label className="label">What Happened? <span className="text-red-400">*</span></label>
          <p className="text-xs text-slate-500 mb-2">Describe in detail. Include any suspicious IPs, emails, files, or behaviors you noticed. More detail = better AI playbook.</p>
          <textarea
            className="input min-h-40 resize-none"
            placeholder="e.g. An employee called me saying all their files have a .locked extension and there's a ransom note on the desktop. This was on the accounts-PC machine. I also found emails from support@micros0ft-helpdesk.com yesterday that looked suspicious."
            value={form.description}
            onChange={handle('description')}
            rows={7}
          />
        </div>

        <div>
          <label className="label">Affected Systems</label>
          <input className="input" placeholder="e.g. accounts-PC, server-01, shared drive \\server\finance" value={form.affected_systems} onChange={handle('affected_systems')} />
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="label">Your Name <span className="text-red-400">*</span></label>
            <input className="input" placeholder="Full name" value={form.reporter_name} onChange={handle('reporter_name')} />
          </div>
          <div>
            <label className="label">Your Email <span className="text-red-400">*</span></label>
            <input className="input" type="email" placeholder="email@company.com" value={form.reporter_email} onChange={handle('reporter_email')} />
          </div>
        </div>

        <div className="flex gap-3 pt-2">
          <button className="btn-primary flex-1" onClick={submit} disabled={loading}>
            {loading ? '🔄 AI is analyzing...' : 'Submit Incident Report'}
          </button>
          <button className="btn-secondary" onClick={() => navigate('/incidents')}>Cancel</button>
        </div>
      </div>
    </div>
  )
}
