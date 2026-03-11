import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import MainLayout from './layouts/MainLayout';
import Dashboard from './pages/Dashboard';
import TrafficAnalysis from './pages/TrafficAnalysis';
import AnomalyDetection from './pages/AnomalyDetection';
import ForensicsLogs from './pages/ForensicsLogs';
import Reports from './pages/Reports';
import About from './pages/About';
import Settings from './pages/Settings';
import Login from './pages/Login';
import Register from './pages/Register';
import AdminPanel from './pages/AdminPanel';

function App() {
  React.useEffect(() => {
    document.body.classList.add('theme-cyber');
    const theme = localStorage.getItem('theme') || 'light';
    if (theme === 'light') {
      document.body.classList.add('light');
    } else {
      document.body.classList.remove('light');
    }
  }, []);

  return (
    <Router>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />

        {/* Standalone Admin route - no sidebar */}
        <Route path="/admin" element={<AdminPanel />} />

        <Route path="*" element={
          <MainLayout>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/traffic" element={<TrafficAnalysis />} />
              <Route path="/anomaly" element={<AnomalyDetection />} />
              <Route path="/forensics" element={<ForensicsLogs />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/about" element={<About />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </MainLayout>
        } />
      </Routes>
    </Router>
  );
}

export default App;
