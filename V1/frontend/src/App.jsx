import React, { useState, useEffect } from 'react';
import StreamlitSidebar from './components/layout/StreamlitSidebar';
import StreamlitDashboard from './components/dashboard/StreamlitDashboard';
import { useWebSocket } from './hooks/useWebSocket';
import { api } from './services/api';

function App() {
  const [alerts, setAlerts] = useState([]);
  const [systemStats, setSystemStats] = useState(null);
  const [modelMetrics, setModelMetrics] = useState(null);

  // Sidebar controls state mirroring Streamlit sidebar controls
  const [filters, setFilters] = useState({
    liveMode: true,
    refreshInterval: 15,
    alertsToShow: 20,
    severities: ['CRITICAL', 'WARNING', 'INFO'],
    attackTypes: [
      'SQL Injection', 'Brute Force', 'DoS Flood',
      'Path Traversal', 'Port Scan', 'Slow-and-Low',
      'Credential Stuffing', 'XSS'
    ]
  });

  // WebSocket Connection
  const { data } = useWebSocket('ws://127.0.0.1:8888/ws/live');

  // Initial Data Fetch
  useEffect(() => {
    const fetchData = async () => {
      try {
        const [initialAlerts, initialMetrics, initialSystem] = await Promise.all([
          api.getAlerts(100),
          api.getModelMetrics(),
          api.getSystem(),
        ]);
        if (initialAlerts) setAlerts(initialAlerts);
        if (initialMetrics) setModelMetrics(initialMetrics);
        if (initialSystem) setSystemStats(initialSystem);
      } catch (e) {
        console.error("Failed to load initial data", e);
      }
    };
    fetchData();
  }, []);

  // Handle Real-time Updates
  useEffect(() => {
    if (!filters.liveMode || !data) return;
    if (data.type === 'new_alert') setAlerts(prev => [data.data, ...prev].slice(0, 500));
    if (data.type === 'system_health') setSystemStats(data.data);
  }, [data, filters.liveMode]);

  return (
    <div className="min-h-screen bg-[#0e1117] text-gray-300 font-sans selection:bg-neon-red/30 selection:text-white">
      {/* Streamlit has a default dark theme background (#0e1117) */}

      <StreamlitSidebar filters={filters} setFilters={setFilters} />

      <main className="pl-[300px] min-h-screen flex justify-center">
        <div className="w-full max-w-[1200px] px-8">
          <StreamlitDashboard
            alerts={alerts}
            systemStats={systemStats}
            modelMetrics={modelMetrics}
            filters={filters}
          />
        </div>
      </main>
    </div>
  );
}

export default App;
