
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { DashboardLayout } from './layouts/DashboardLayout';
import { Overview } from './pages/Overview';
import { Hosts } from './pages/Hosts';
import { Alerts } from './pages/Alerts';
import { GraphExplorer } from './pages/GraphExplorer';
import { AttackLab } from './pages/AttackLab';
import { Experiments } from './pages/Experiments';
import { Settings } from './pages/Settings';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<DashboardLayout />}>
          <Route index element={<Overview />} />
          <Route path="hosts" element={<Hosts />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="graph" element={<GraphExplorer />} />
          <Route path="attack-lab" element={<AttackLab />} />
          <Route path="experiments" element={<Experiments />} />
          <Route path="settings" element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
