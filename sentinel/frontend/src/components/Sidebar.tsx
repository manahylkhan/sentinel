import { NavLink } from 'react-router-dom'

const nav = [
  { to: '/', label: 'Dashboard', icon: '◉' },
  { to: '/threat-intel', label: 'Threat Intel', icon: '🔍' },
  { to: '/incidents', label: 'Incidents', icon: '⚠️' },
  { to: '/iocs', label: 'IOC Tracker', icon: '🎯' },
  { to: '/logs', label: 'Log Analyzer', icon: '📋' },
  { to: '/playbooks', label: 'Playbooks', icon: '📖' },
  { to: '/settings', label: 'Settings', icon: '⚙️' },
]

export default function Sidebar() {
  return (
    <aside className="w-56 bg-slate-900 border-r border-slate-800 flex flex-col min-h-screen shrink-0">
      {/* Logo */}
      <div className="px-5 py-5 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center text-white font-bold text-sm">S</div>
          <div>
            <div className="font-bold text-slate-100 text-sm leading-tight">SENTINEL</div>
            <div className="text-slate-500 text-xs">AI Incident Response</div>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-1">
        {nav.map(item => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-blue-600/20 text-blue-400 border border-blue-600/30'
                  : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800'
              }`
            }
          >
            <span className="text-base w-5 text-center">{item.icon}</span>
            {item.label}
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div className="px-5 py-4 border-t border-slate-800">
        <div className="text-xs text-slate-600">v1.0.0 — Pakistan SME Edition</div>
      </div>
    </aside>
  )
}
