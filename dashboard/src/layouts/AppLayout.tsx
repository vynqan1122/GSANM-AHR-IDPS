import { useState } from 'react';
import { LiveEvents } from '../pages/LiveEvents';
import { Incidents } from '../pages/Incidents';
import { Overview } from '../pages/Overview';
import { Responses } from '../pages/Responses';
import { Rules } from '../pages/Rules';
import { SensorHealth } from '../pages/SensorHealth';
import { AlertsPage, AIMonitorPage, SystemHealthPage, WazuhManagerPage } from '../pages/ResearchPages';

type View = 'monitor' | 'investigate' | 'manage';

export function AppLayout() {
  const [view, setView] = useState<View>('monitor');

  return (
    <div className="shell">
      <header>
        <div>
          <h1>AHR-IDPS DVWA Lab</h1>
          <p>Hybrid intrusion detection and response</p>
        </div>
        <nav className="control-nav" aria-label="Dashboard views">
          <button className={view === 'monitor' ? 'active' : ''} onClick={() => setView('monitor')}>Giám sát</button>
          <button className={view === 'investigate' ? 'active' : ''} onClick={() => setView('investigate')}>Điều tra</button>
          <button className={view === 'manage' ? 'active' : ''} onClick={() => setView('manage')}>Quản trị</button>
        </nav>
      </header>
      <div className="dashboard-view">
        {view === 'monitor' && <>
          <Overview />
          <LiveEvents />
          <AlertsPage />
        </>}
        {view === 'investigate' && <>
          <Incidents />
          <Rules />
          <AIMonitorPage />
        </>}
        {view === 'manage' && <>
          <SystemHealthPage />
          <SensorHealth />
          <WazuhManagerPage />
          <Responses />
        </>}
      </div>
    </div>
  );
}
