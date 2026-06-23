import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import toast from 'react-hot-toast'
import api from '../api/client'

interface Finding {
  rule: string
  severity: string
  description: string
  count: number
  affected_ips: string[]
  recommendation: string
  sample_urls?: string[]
}

interface TIFlag {
  ip: string
  verdict: string
  summary: string
}

interface AIAnalysis {
  summary: string
  top_concerns: string[]
  normal_explanation: string
  recommended_actions: string[]
}

interface AnalysisResult {
  file_name: string
  log_type: string
  total_entries: number
  unique_ip_count: number
  error_count: number
  error_rate: string
  time_range: string | null
  rule_findings: Finding[]
  ti_flagged_ips: TIFlag[]
  ai_analysis: AIAnalysis
}

const SEVERITY_CLASS: Record<string, string> = {
  high: 'badge-high', medium: 'badge-medium', low: 'badge-low', critical: 'badge-critical'
}

export default function LogAnalyzer() {
  const navigate = useNavigate()
  const [file, setFile] = useState<File | null>(null)
  const [loading, setLoading] = useState(false)
  const [progress, setProgress] = useState('')
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [dragOver, setDragOver] = useState(false)

  const analyze = async (f: File) => {
    if (f.size > 50 * 1024 * 1024) { toast.error('File too large — max 50MB'); return }
    setLoading(true)
    setResult(null)

    const steps = ['Detecting log format...', 'Parsing entries...', 'Checking IPs against threat feeds...', 'Running detection rules...', 'AI analyzing...']
    let step = 0
    const interval = setInterval(() => {
      if (step < steps.length) setProgress(steps[step++])
    }, 1500)

    try {
      const fd = new FormData()
      fd.append('file', f)
      const res = await api.post('/logs/analyze', fd)
      clearInterval(interval)
      setProgress('')
      setResult(res.data)
      toast.success('Analysis complete')
    } catch (e: any) {
      clearInterval(interval)
      setProgress('')
      toast.error(e.response?.data?.detail || 'Analysis failed')
    }
    setLoading(false)
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    const f = e.dataTransfer.files[0]
    if (f) { setFile(f); analyze(f) }
  }

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]
    if (f) { setFile(f); analyze(f) }
  }

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <div className="mb-6">
        <h1 className="page-title">Log Analyzer</h1>
        <p className="text-slate-400">Upload system, web server, or auth logs — AI finds suspicious patterns in plain English.</p>
        <p className="text-slate-500 text-sm mt-1">Supported: .log, .txt, .csv — Windows Security, Linux auth, Apache/Nginx access logs, generic</p>
      </div>

      {/* Upload area */}
      <div
        className={`card border-2 border-dashed transition-colors cursor-pointer mb-6 ${
          dragOver ? 'border-blue-500 bg-blue-950/20' : 'border-slate-700 hover:border-slate-600'
        }`}
        onDragOver={e => { e.preventDefault(); setDragOver(true) }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => document.getElementById('logfile')?.click()}
      >
        <input id="logfile" type="file" className="hidden" accept=".log,.txt,.csv,.evtx" onChange={handleFileSelect} />
        <div className="text-center py-8">
          <div className="text-4xl mb-3">📋</div>
          <div className="text-slate-300 font-medium mb-1">Drop your log file here or click to browse</div>
          <div className="text-slate-500 text-sm">Max 50MB • .log .txt .csv .evtx</div>
          {file && !loading && <div className="text-blue-400 text-sm mt-2">Selected: {file.name}</div>}
        </div>

        {loading && (
          <div className="border-t border-slate-800 pt-4 px-4 pb-2">
            <div className="flex items-center gap-3">
              <div className="w-5 h-5 border-2 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
              <span className="text-slate-300 text-sm">{progress || 'Processing...'}</span>
            </div>
          </div>
        )}
      </div>

      {/* Results */}
      {result && (
        <div className="space-y-5">
          {/* Stats bar */}
          <div className="grid grid-cols-4 gap-4">
            {[
              { label: 'Total Entries', value: result.total_entries.toLocaleString() },
              { label: 'Unique IPs', value: result.unique_ip_count },
              { label: 'Error Rate', value: result.error_rate },
              { label: 'Log Type', value: result.log_type.replace('_', ' ') },
            ].map(s => (
              <div key={s.label} className="card-sm text-center">
                <div className="text-2xl font-bold text-slate-100">{s.value}</div>
                <div className="text-slate-400 text-sm mt-1">{s.label}</div>
              </div>
            ))}
          </div>

          {result.time_range && (
            <div className="text-slate-500 text-sm">Time range: {result.time_range}</div>
          )}

          {/* AI Summary */}
          <div className="card bg-blue-950/20 border-blue-800/40">
            <div className="text-blue-400 font-semibold text-sm mb-2">🤖 AI Analysis — Plain English Summary</div>
            <p className="text-slate-200">{result.ai_analysis.summary}</p>
          </div>

          {/* Top Concerns */}
          {result.ai_analysis.top_concerns?.length > 0 && (
            <div className="card bg-orange-950/20 border-orange-800/40">
              <div className="text-orange-400 font-semibold text-sm mb-2">⚠️ Top Concerns</div>
              <ul className="space-y-1">
                {result.ai_analysis.top_concerns.map((c, i) => (
                  <li key={i} className="text-orange-200 text-sm flex gap-2"><span>•</span>{c}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Recommended Actions */}
          {result.ai_analysis.recommended_actions?.length > 0 && (
            <div className="card bg-green-950/20 border-green-800/40">
              <div className="text-green-400 font-semibold text-sm mb-2">✅ Recommended Actions</div>
              <ol className="space-y-1 list-decimal list-inside">
                {result.ai_analysis.recommended_actions.map((a, i) => (
                  <li key={i} className="text-green-200 text-sm">{a}</li>
                ))}
              </ol>
            </div>
          )}

          {/* Rule Findings */}
          {result.rule_findings?.length > 0 && (
            <div className="card">
              <h3 className="section-title">Rule-Based Findings ({result.rule_findings.length})</h3>
              <div className="space-y-3">
                {result.rule_findings.map((f, i) => (
                  <div key={i} className="bg-slate-800/40 border border-slate-700/50 rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className={SEVERITY_CLASS[f.severity] || 'badge-info'}>{f.severity}</span>
                        <span className="font-medium text-slate-200">{f.rule}</span>
                      </div>
                      <span className="text-slate-500 text-sm">{f.count} occurrence(s)</span>
                    </div>
                    <p className="text-slate-400 text-sm mb-2">{f.description}</p>
                    {f.affected_ips?.length > 0 && (
                      <div className="text-xs text-slate-500 mb-2">IPs: {f.affected_ips.slice(0, 5).join(', ')}{f.affected_ips.length > 5 && ` +${f.affected_ips.length - 5} more`}</div>
                    )}
                    <p className="text-blue-300 text-sm">→ {f.recommendation}</p>
                    <button
                      className="mt-2 text-xs text-slate-400 hover:text-slate-200 underline"
                      onClick={() => navigate('/incidents/new')}
                    >
                      Create Incident from this Finding
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TI Flagged IPs */}
          {result.ti_flagged_ips?.length > 0 && (
            <div className="card">
              <h3 className="section-title">Threat Intel — Flagged IPs in Logs</h3>
              <div className="space-y-2">
                {result.ti_flagged_ips.map((t, i) => (
                  <div key={i} className="flex items-center gap-3 bg-red-950/20 border border-red-800/30 rounded-lg px-4 py-2">
                    <span className="font-mono text-red-300 text-sm">{t.ip}</span>
                    <span className="badge-malicious">{t.verdict}</span>
                    <span className="text-slate-400 text-sm">{t.summary?.slice(0, 80)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
