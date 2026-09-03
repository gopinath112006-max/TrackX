import { Routes, Route } from 'react-router-dom'
import { Layout } from './components/Layout'
import { InvestigationProvider } from './hooks/useInvestigation'
import Dashboard from './pages/Dashboard'
import Scenarios from './pages/Scenarios'
import Upload from './pages/Upload'
import Explorer from './pages/Explorer'
import Investigation from './pages/Investigation'
import Timeline from './pages/Timeline'
import Relationships from './pages/Relationships'
import Correlations from './pages/Correlations'
import Findings from './pages/Findings'
import Story from './pages/Story'
import Report from './pages/Report'

export default function App() {
  return (
    <InvestigationProvider>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scenarios" element={<Scenarios />} />
          <Route path="/upload" element={<Upload />} />
          <Route path="/explorer" element={<Explorer />} />
          <Route path="/investigation" element={<Investigation />} />
          <Route path="/timeline" element={<Timeline />} />
          <Route path="/relationships" element={<Relationships />} />
          <Route path="/correlations" element={<Correlations />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/story" element={<Story />} />
          <Route path="/report" element={<Report />} />
        </Routes>
      </Layout>
    </InvestigationProvider>
  )
}