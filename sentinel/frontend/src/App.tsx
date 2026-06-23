import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import ThreatIntel from './pages/ThreatIntel'
import IncidentList from './pages/Incidents/IncidentList'
import NewIncident from './pages/Incidents/NewIncident'
import IncidentDetail from './pages/Incidents/IncidentDetail'
import IOCTracker from './pages/IOCTracker'
import LogAnalyzer from './pages/LogAnalyzer'
import PlaybookLibrary from './pages/PlaybookLibrary'
import Settings from './pages/Settings'

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex min-h-screen">
        <Sidebar />
        <main className="flex-1 overflow-auto">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/threat-intel" element={<ThreatIntel />} />
            <Route path="/incidents" element={<IncidentList />} />
            <Route path="/incidents/new" element={<NewIncident />} />
            <Route path="/incidents/:id" element={<IncidentDetail />} />
            <Route path="/iocs" element={<IOCTracker />} />
            <Route path="/logs" element={<LogAnalyzer />} />
            <Route path="/playbooks" element={<PlaybookLibrary />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </main>
      </div>
      <Toaster
        position="top-right"
        toastOptions={{
          style: { background: '#1e293b', color: '#f1f5f9', border: '1px solid #334155' },
          success: { iconTheme: { primary: '#22c55e', secondary: '#fff' } },
          error: { iconTheme: { primary: '#ef4444', secondary: '#fff' } },
        }}
      />
    </BrowserRouter>
  )
}
