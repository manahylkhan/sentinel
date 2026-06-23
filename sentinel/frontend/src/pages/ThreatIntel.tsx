import { useState, useEffect } from 'react'
import toast from 'react-hot-toast'
import api from '../api/client'

type Verdict = 'malicious' | 'suspicious' | 'clean' | 'unknown'

interface FeedResult {
  source: string
  flagged: boolean
  error?: string
  score?: number
  country?: string
  reports?: number
  malicious?: number
  suspicious?: number
  pulse_count?: number
  found?: boolean
  malware?: string
  malware_name?: string
  org?: string
  is_tor?: boolean
}

interface TIResult {
  indicator: string
  indicator_type: string
  verdict: Verdict
  confidence: string
  ai_summary: string
  ai_action: string
  feed_results: FeedResult[]
  flagged_by: string[]
  total_feeds_checked: number
  cached?: boolean
  checked_at?: string
}

interface HistoryItem {
  id: string
  indicator: string
  indicator_type: string
  verdict: Verdict
  confidence: string
  ai_summary: string
  flagged_by: string[]
  created_at: string
}

const FEED_LABELS: Record<string, string> = {
  abuseipdb: 'AbuseIPDB',
  virustotal: 'VirusTotal',
  otx: 'AlienVault OTX',
  threatfox: 'ThreatFox',
  ipinfo: 'IPinfo',
  urlhaus: 'URLhaus',
  malwarebazaar: 'MalwareBazaar',
}

const FEED_ORDER = ['abuseipdb', 'virustotal', 'otx', 'threatfox', 'ipinfo', 'urlhaus', 'malwarebazaar']

function detectType(value: string): string {
  const v = value.trim()
  if (/^[a-fA-F0-9]{64}$/.test(v)) return 'hash (SHA256)'
  if (/^[a-fA-F0-9]{40}$/.test(v)) return 'hash (SHA1)'
  if (/^[a-fA-F0-9]{32}$/.test(v)) return 'hash (MD5)'
  if (v.startsWith('http://') || v.startsWith('https://')) return 'url'
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) return 'email'
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return 'ip'
  if (v.length > 0) return 'domain'
  return ''
}

function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const classes = {
    malicious: 'bg-red-600 text-white border-red-500',
    suspicious: 'bg-orange-600 text-white border-orange-500',
    clean: 'bg-green-600 text-white border-green-500',
    unknown: 'bg-slate-600 text-slate-200 border-slate-500',
  }
  return (
    <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-bold uppercase tracking-wider border ${classes[verdict]}`}>
      {verdict === 'malicious' && '⛔'}
      {verdict === 'suspicious' && '⚠️'}
      {verdict === 'clean' && '✅'}
      {verdict === 'unknown' && '❓'}
      {verdict}
    </span>
  )
}

function FeedRow({ feed }: { feed: FeedResult }) {
  const label = FEED_LABELS[feed.source] || feed.source
  let detail = ''
  if (feed.error) {
    detail = `Error: ${feed.error}`
  } else if (feed.source === 'abuseipdb') {
    detail = `Score: ${feed.score ?? 0}/100 • ${feed.reports ?? 0} reports • ${feed.country ?? ''}`
  } else if (feed.source === 'virustotal') {
    detail = `${feed.malicious ?? 0} malicious, ${feed.suspicious ?? 0} suspicious of ${feed.malicious != null ? 'engines checked' : ''}`
  } else if (feed.source === 'otx') {
    detail = `${feed.pulse_count ?? 0} threat pulse(s)`
  } else if (feed.source === 'threatfox') {
    detail = feed.found ? `Found: ${feed.malware || 'malware'}` : 'Not found'
  } else if (feed.source === 'ipinfo') {
    detail = `${feed.org ?? ''} • ${feed.country ?? ''}${feed.is_tor ? ' • TOR exit node' : ''}`
  } else if (feed.source === 'urlhaus') {
    detail = feed.found ? 'Listed as malware distributor' : 'Not listed'
  } else if (feed.source === 'malwarebazaar') {
    detail = feed.found ? `Malware: ${feed.malware_name || 'unknown'}` : 'Not found'
  }

  return (
    <tr className="border-b border-slate-800 hover:bg-slate-800/30">
      <td className="py-3 px-4 font-medium text-slate-300">{label}</td>
      <td className="py-3 px-4">
        {feed.error ? (
          <span className="text-slate-500 text-sm">Error</span>
        ) : feed.flagged ? (
          <span className="text-red-400 font-semibold">⛔ Flagged</span>
        ) : (
          <span className="text-green-400">✓ Clear</span>
        )}
      </td>
      <td className="py-3 px-4 text-slate-400 text-sm">{detail}</td>
    </tr>
  )
}

export default function ThreatIntel() {
  const [indicator, setIndicator] = useState('')
  const [detectedType, setDetectedType] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<TIResult | null>(null)
  const [history, setHistory] = useState<HistoryItem[]>([])
  const [loadingFeeds, setLoadingFeeds] = useState<string[]>([])

  useEffect(() => {
    fetchHistory()
  }, [])

  useEffect(() => {
    setDetectedType(detectType(indicator))
  }, [indicator])

  const fetchHistory = async () => {
    try {
      const res = await api.get('/ti/history')
      setHistory(res.data.slice(0, 10))
    } catch {}
  }

  const handleCheck = async () => {
    if (!indicator.trim()) return
    setLoading(true)
    setResult(null)
    setLoadingFeeds(['abuseipdb', 'virustotal', 'otx', 'threatfox', 'ipinfo'])

    // Animate feed loading
    const feedOrder = FEED_ORDER
    let idx = 0
    const interval = setInterval(() => {
      if (idx < feedOrder.length) {
        setLoadingFeeds(feedOrder.slice(0, idx + 1))
        idx++
      } else {
        clearInterval(interval)
      }
    }, 400)

    try {
      const res = await api.post('/ti/check', { indicator: indicator.trim() })
      clearInterval(interval)
      setResult(res.data)
      fetchHistory()
      if (res.data.verdict === 'malicious') toast.error('Malicious indicator detected!')
      else if (res.data.verdict === 'suspicious') toast('Suspicious indicator — review carefully', { icon: '⚠️' })
      else if (res.data.verdict === 'clean') toast.success('Indicator appears clean')
    } catch (e: any) {
      clearInterval(interval)
      toast.error(e.response?.data?.detail || 'Check failed — ensure backend is running')
    } finally {
      setLoading(false)
      setLoadingFeeds([])
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleCheck()
  }

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <div className="mb-6">
        <h1 className="page-title">Threat Intelligence Checker</h1>
        <p className="text-slate-400">Check any IP, domain, URL, file hash, or email against 7+ free threat feeds instantly.</p>
      </div>

      {/* Input */}
      <div className="card mb-6">
        <div className="flex gap-3">
          <div className="flex-1 relative">
            <input
              className="input text-base py-3 pr-32"
              placeholder="Paste IP, domain, URL, file hash (MD5/SHA1/SHA256), or email..."
              value={indicator}
              onChange={e => setIndicator(e.target.value)}
              onKeyDown={handleKeyDown}
            />
            {detectedType && (
              <span className="absolute right-3 top-1/2 -translate-y-1/2 text-xs bg-slate-700 text-blue-300 px-2 py-0.5 rounded-full border border-slate-600">
                {detectedType}
              </span>
            )}
          </div>
          <button
            className="btn-primary px-6 py-3 text-base"
            onClick={handleCheck}
            disabled={loading || !indicator.trim()}
          >
            {loading ? 'Checking...' : 'Check Threat Feeds'}
          </button>
        </div>

        {/* Loading state */}
        {loading && (
          <div className="mt-4 p-4 bg-slate-800/50 rounded-lg">
            <p className="text-slate-400 text-sm mb-2">Querying threat feeds in parallel...</p>
            <div className="flex flex-wrap gap-2">
              {FEED_ORDER.map(feed => (
                <span
                  key={feed}
                  className={`text-xs px-2 py-1 rounded transition-all duration-300 ${
                    loadingFeeds.includes(feed)
                      ? 'bg-blue-600/30 text-blue-300 border border-blue-600/50'
                      : 'bg-slate-800 text-slate-600 border border-slate-700'
                  }`}
                >
                  {loadingFeeds.includes(feed) ? '✓' : '○'} {FEED_LABELS[feed]}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Results */}
      {result && (
        <div className="space-y-4 mb-8">
          {/* Verdict */}
          <div className={`card border-l-4 ${
            result.verdict === 'malicious' ? 'border-l-red-500 bg-red-950/20' :
            result.verdict === 'suspicious' ? 'border-l-orange-500 bg-orange-950/20' :
            result.verdict === 'clean' ? 'border-l-green-500 bg-green-950/20' :
            'border-l-slate-500'
          }`}>
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-3">
                  <VerdictBadge verdict={result.verdict} />
                  <span className="text-slate-400 text-sm">Confidence: <span className="text-slate-200 font-medium">{result.confidence}</span></span>
                  <span className="text-slate-500 text-sm">{result.total_feeds_checked} feeds checked</span>
                  {result.cached && <span className="text-xs bg-slate-700 text-slate-400 px-2 py-0.5 rounded">cached</span>}
                </div>
                <div className="font-mono text-slate-300 text-sm mb-3">{result.indicator} <span className="text-slate-500">({result.indicator_type})</span></div>

                {/* AI Summary */}
                <div className="bg-blue-950/30 border border-blue-800/40 rounded-lg p-4 mb-3">
                  <div className="text-xs text-blue-400 font-semibold uppercase tracking-wide mb-1.5">AI Analysis</div>
                  <p className="text-slate-200 text-sm leading-relaxed">{result.ai_summary}</p>
                </div>

                {/* Recommended Action */}
                {result.ai_action && (
                  <div className="bg-amber-950/30 border border-amber-800/40 rounded-lg p-4">
                    <div className="text-xs text-amber-400 font-semibold uppercase tracking-wide mb-1.5">Recommended Action</div>
                    <p className="text-amber-200 text-sm font-medium leading-relaxed">{result.ai_action}</p>
                  </div>
                )}
              </div>
            </div>

            {result.flagged_by.length > 0 && (
              <div className="mt-3 flex flex-wrap gap-1">
                <span className="text-xs text-slate-500">Flagged by:</span>
                {result.flagged_by.map(f => (
                  <span key={f} className="text-xs bg-red-900/40 text-red-300 border border-red-800/40 px-2 py-0.5 rounded">
                    {FEED_LABELS[f] || f}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Feed Results Table */}
          <div className="card">
            <h3 className="section-title">Feed Results</h3>
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-700">
                  <th className="text-left py-2 px-4 table-header">Feed</th>
                  <th className="text-left py-2 px-4 table-header">Result</th>
                  <th className="text-left py-2 px-4 table-header">Details</th>
                </tr>
              </thead>
              <tbody>
                {result.feed_results.map(feed => (
                  <FeedRow key={feed.source} feed={feed} />
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* History */}
      {history.length > 0 && (
        <div className="card">
          <h3 className="section-title">Recent Checks</h3>
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-700">
                <th className="text-left py-2 px-4 table-header">Indicator</th>
                <th className="text-left py-2 px-4 table-header">Type</th>
                <th className="text-left py-2 px-4 table-header">Verdict</th>
                <th className="text-left py-2 px-4 table-header">When</th>
              </tr>
            </thead>
            <tbody>
              {history.map(item => (
                <tr
                  key={item.id}
                  className="border-b border-slate-800 hover:bg-slate-800/30 cursor-pointer"
                  onClick={() => setIndicator(item.indicator)}
                >
                  <td className="py-2.5 px-4 font-mono text-sm text-slate-300">{item.indicator}</td>
                  <td className="py-2.5 px-4 text-slate-400 text-sm capitalize">{item.indicator_type}</td>
                  <td className="py-2.5 px-4"><VerdictBadge verdict={item.verdict} /></td>
                  <td className="py-2.5 px-4 text-slate-500 text-sm">{new Date(item.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
