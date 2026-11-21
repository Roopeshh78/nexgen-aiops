import React from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { getToken } from './api'
import Layout from './components/Layout'
import Login from './pages/Login'
import Overview from './pages/Overview'
import Infrastructure from './pages/Infrastructure'
import Network from './pages/Network'
import Application from './pages/Application'
import Security from './pages/Security'
import Cloud from './pages/Cloud'
import Distributed from './pages/Distributed'
import AiopsCentre from './pages/AiopsCentre'
import Anomalies from './pages/Anomalies'
import Rca from './pages/Rca'
import Incidents from './pages/Incidents'
import Predictive from './pages/Predictive'
import Capacity from './pages/Capacity'
import Alerts from './pages/Alerts'
import Collectors from './pages/Collectors'
import Privacy from './pages/Privacy'
import Egress from './pages/Egress'
import Tenants from './pages/Tenants'
import Audit from './pages/Audit'
import Recommendations from './pages/Recommendations'

function Guard({ children }: { children: React.ReactNode }) {
  if (!getToken()) return <Navigate to="/login" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route element={<Guard><Layout /></Guard>}>
        <Route path="/" element={<Overview />} />
        <Route path="/infrastructure" element={<Infrastructure />} />
        <Route path="/network" element={<Network />} />
        <Route path="/application" element={<Application />} />
        <Route path="/security" element={<Security />} />
        <Route path="/cloud" element={<Cloud />} />
        <Route path="/distributed" element={<Distributed />} />
        <Route path="/aiops" element={<AiopsCentre />} />
        <Route path="/anomalies" element={<Anomalies />} />
        <Route path="/rca" element={<Rca />} />
        <Route path="/incidents" element={<Incidents />} />
        <Route path="/predictive" element={<Predictive />} />
        <Route path="/capacity" element={<Capacity />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/collectors" element={<Collectors />} />
        <Route path="/privacy" element={<Privacy />} />
        <Route path="/egress" element={<Egress />} />
        <Route path="/tenants" element={<Tenants />} />
        <Route path="/audit" element={<Audit />} />
        <Route path="/recommendations" element={<Recommendations />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
