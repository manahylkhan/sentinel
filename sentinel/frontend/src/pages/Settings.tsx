import { useEffect, useState } from 'react'
import toast from 'react-hot-toast'
import api from '../api/client'

const FIELDS = [
  { key: 'ANTHROPIC_API_KEY', label: 'Anthropic API Key', hint: 'Required for AI analysis. Get from console.anthropic.com', required: true },
  { key: 'ABUSEIPDB_API_KEY', label: 'AbuseIPDB API Key', hint: 'Free at abuseipdb.com — 1000 checks/day', required: false },
  { key: 'VIRUSTOTAL_API_KEY', label: 'VirusTotal API Key', hint: 'Free at virustotal.com — 500 queries/day', required: false },
  { key: 'OTX_API_KEY', label: 'AlienVault OTX API Key', hint: 'Free at otx.alienvault.com', required: false },
  { key: 'IPINFO_API_KEY', label: 'IPinfo API Key', hint: 'Free at ipinfo.io — 50k requests/month', required: false },
  { key: 'SHODAN_API_KEY', label: 'Shodan API Key (Optional)', hint: 'Free tier available at shodan.io', required: false },
]

const EMAIL_FIELDS = [
  { key: 'ALERT_EMAIL', label: 'Alert Email Address', hint: 'Where to send critical incident alerts and PECA reminders', type: 'email' },
  { key: 'SMTP_HOST', label: 'SMTP Host', hint: 'e.g. smtp.gmail.com', type: 'text' },
  { key: 'SMTP_PORT', label: 'SMTP Port', hint: 'Usually 587 (TLS) or 465 (SSL)', type: 'number' },
  { key: 'SMTP_USER', label: 'SMTP Username', hint: 'Your email address', type: 'email' },
  { key: 'SMTP_PASSWORD', label: 'SMTP Password / App Password', hint: 'For Gmail: use App Password from Google Account settings', type: 'password' },
]

const ORG_FIELDS = [
  { key: 'ORG_NAME', label: 'Organization Name', hint: 'Appears in reports', type: 'text' },
  { key: 'ORG_TYPE', label: 'Organization Type', hint: 'Used for context in AI responses', type: 'select', options: ['SME', 'Clinic', 'School', 'Fintech', 'Bank', 'Retailer', 'Other'] },
]

export default function Settings() {
  const [values, setValues] = useState<Record<string, string>>({})
  const [changed, setChanged] = useState<Record<string, string>>({})
  const [saving, setSaving] = useState(false)
  const [testingEmail, setTestingEmail] = useState(false)
  const [showPasswords, setShowPasswords] = useState(false)

  useEffect(() => {
    api.get('/settings').then(res => setValues(res.data)).catch(() => {})
  }, [])

  const set = (key: string, val: string) => {
    setValues(p => ({ ...p, [key]: val }))
    setChanged(p => ({ ...p, [key]: val }))
  }

  const save = async () => {
    if (Object.keys(changed).length === 0) { toast('No changes to save'); return }
    setSaving(true)
    try {
      await api.post('/settings', changed)
      setChanged({})
      toast.success('Settings saved')
    } catch { toast.error('Failed to save settings') }
    setSaving(false)
  }

  const testEmail = async () => {
    setTestingEmail(true)
    try {
      const res = await api.post('/settings/test-email')
      if (res.data.sent) toast.success('Test email sent! Check your inbox.')
      else toast.error(res.data.message)
    } catch { toast.error('Test email failed — check SMTP configuration') }
    setTestingEmail(false)
  }

  const hasChanges = Object.keys(changed).length > 0

  return (
    <div className="p-6 max-w-3xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="page-title mb-1">Settings</h1>
          <p className="text-slate-400">Configure API keys, alerts, and organization profile.</p>
        </div>
        <button className="btn-primary" onClick={save} disabled={saving || !hasChanges}>
          {saving ? 'Saving...' : hasChanges ? 'Save Changes *' : 'Save Changes'}
        </button>
      </div>

      {/* API Keys */}
      <div className="card mb-5">
        <h3 className="section-title">Threat Intelligence API Keys</h3>
        <p className="text-slate-500 text-sm mb-4">All free tiers. Get API keys from the respective websites.</p>
        <div className="space-y-4">
          {FIELDS.map(f => (
            <div key={f.key}>
              <label className="label">
                {f.label}
                {f.required && <span className="text-red-400 ml-1">*</span>}
              </label>
              <input
                className="input font-mono text-sm"
                type={showPasswords ? 'text' : 'password'}
                placeholder={f.required ? 'Required' : 'Optional'}
                value={values[f.key] || ''}
                onChange={e => set(f.key, e.target.value)}
              />
              <p className="text-slate-500 text-xs mt-1">{f.hint}</p>
            </div>
          ))}
          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={showPasswords} onChange={e => setShowPasswords(e.target.checked)} className="accent-blue-500" />
            <span className="text-slate-400 text-sm">Show API keys</span>
          </label>
        </div>
      </div>

      {/* Email */}
      <div className="card mb-5">
        <h3 className="section-title">Email Notifications</h3>
        <p className="text-slate-500 text-sm mb-4">Receive alerts for critical incidents and PECA reporting obligations.</p>
        <div className="space-y-4">
          {EMAIL_FIELDS.map(f => (
            <div key={f.key}>
              <label className="label">{f.label}</label>
              <input
                className="input"
                type={f.key === 'SMTP_PASSWORD' && !showPasswords ? 'password' : f.type}
                placeholder={f.hint}
                value={values[f.key] || ''}
                onChange={e => set(f.key, e.target.value)}
              />
              <p className="text-slate-500 text-xs mt-1">{f.hint}</p>
            </div>
          ))}
          <button
            className="btn-secondary text-sm"
            onClick={testEmail}
            disabled={testingEmail}
          >
            {testingEmail ? '📧 Sending...' : '📧 Send Test Email'}
          </button>
        </div>
      </div>

      {/* Organization */}
      <div className="card mb-5">
        <h3 className="section-title">Organization Profile</h3>
        <div className="space-y-4">
          {ORG_FIELDS.map(f => (
            <div key={f.key}>
              <label className="label">{f.label}</label>
              {f.type === 'select' ? (
                <select className="input" value={values[f.key] || ''} onChange={e => set(f.key, e.target.value)}>
                  {f.options?.map(o => <option key={o} value={o}>{o}</option>)}
                </select>
              ) : (
                <input className="input" type={f.type} placeholder={f.hint} value={values[f.key] || ''} onChange={e => set(f.key, e.target.value)} />
              )}
              {f.hint && <p className="text-slate-500 text-xs mt-1">{f.hint}</p>}
            </div>
          ))}
        </div>
      </div>

      {/* Pakistan Context */}
      <div className="card bg-green-950/10 border-green-900/40">
        <h3 className="section-title text-green-400">🇵🇰 Pakistan Cybersecurity Resources</h3>
        <div className="space-y-2 text-sm">
          <div><span className="text-slate-400">FIA Cybercrime Wing:</span> <span className="text-slate-300">report.fia.gov.pk | 0800-02345 | cybercrime@fia.gov.pk</span></div>
          <div><span className="text-slate-400">PTA Cybersecurity:</span> <span className="text-slate-300">cybersecurity@pta.gov.pk</span></div>
          <div><span className="text-slate-400">PECA 2016:</span> <span className="text-slate-300">Prevention of Electronic Crimes Act — governs cyber incident reporting</span></div>
          <div><span className="text-slate-400">SBP Fraud Reporting:</span> <span className="text-slate-300">Consumer Protection Dept — for financial sector incidents</span></div>
        </div>
      </div>

      <div className="mt-4 flex justify-end">
        <button className="btn-primary" onClick={save} disabled={saving || !hasChanges}>
          {saving ? 'Saving...' : 'Save All Settings'}
        </button>
      </div>
    </div>
  )
}
