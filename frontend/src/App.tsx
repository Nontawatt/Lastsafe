import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import BackupJobs from './pages/BackupJobs'
import Repositories from './pages/Repositories'
import StorageBackends from './pages/StorageBackends'
import History from './pages/History'
import Settings from './pages/Settings'

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="jobs" element={<BackupJobs />} />
          <Route path="repositories" element={<Repositories />} />
          <Route path="storage" element={<StorageBackends />} />
          <Route path="history" element={<History />} />
          <Route path="settings" element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

export default App
