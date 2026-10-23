import '@fontsource-variable/geist';
import '@fontsource-variable/geist-mono';
import './styles/globals.css';

import { StrictMode, lazy, useMemo, useState, type ReactNode } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClientProvider } from '@tanstack/react-query';
import { RouterProvider, createHashRouter } from 'react-router';
import { Toaster } from 'sonner';
import { PollingContext, queryClient } from './api/query';
import { TooltipProvider } from './components/ui/overlays';
import { AppLayout, NotFound } from './layouts/AppLayout';

const page = <T extends { default: React.ComponentType }>(load: () => Promise<T>) => lazy(load);

const Overview = page(() => import('./pages/Overview').then((m) => ({ default: m.Overview })));
const LiveEvents = page(() => import('./pages/LiveEvents').then((m) => ({ default: m.LiveEvents })));
const NetworkPage = page(() => import('./pages/NetworkPage').then((m) => ({ default: m.NetworkPage })));
const Incidents = page(() => import('./pages/Incidents').then((m) => ({ default: m.Incidents })));
const AttackGraphPage = page(() => import('./pages/ResearchPages').then((m) => ({ default: m.AttackGraphPage })));
const AIMonitor = page(() => import('./pages/AIMonitor').then((m) => ({ default: m.AIMonitor })));
const ContainersPage = page(() => import('./pages/ContainersPage').then((m) => ({ default: m.ContainersPage })));
const Rules = page(() => import('./pages/Rules').then((m) => ({ default: m.Rules })));
const Responses = page(() => import('./pages/Responses').then((m) => ({ default: m.Responses })));
const SystemHealth = page(() => import('./pages/SystemHealth').then((m) => ({ default: m.SystemHealth })));
const Experiments = page(() => import('./pages/ResearchPages').then((m) => ({ default: m.ExperimentsPage })));

// Hash routing: the backend serves /dashboard/ through StaticFiles without an
// SPA fallback, so deep links must live in the fragment.
const router = createHashRouter([
  {
    path: '/',
    element: <AppLayout />,
    children: [
      { index: true, element: <Overview /> },
      { path: 'events', element: <LiveEvents /> },
      { path: 'network', element: <NetworkPage /> },
      { path: 'incidents/:incidentId?', element: <Incidents /> },
      { path: 'attack-graph', element: <AttackGraphPage /> },
      { path: 'ai', element: <AIMonitor /> },
      { path: 'containers', element: <ContainersPage /> },
      { path: 'rules', element: <Rules /> },
      { path: 'responses', element: <Responses /> },
      { path: 'health', element: <SystemHealth /> },
      { path: 'experiments', element: <Experiments /> },
      { path: '*', element: <NotFound /> },
    ],
  },
]);

function Providers({ children }: { children: ReactNode }) {
  const [paused, setPaused] = useState(false);
  const polling = useMemo(() => ({ paused, setPaused }), [paused]);
  return (
    <QueryClientProvider client={queryClient}>
      <PollingContext.Provider value={polling}>
        <TooltipProvider>{children}</TooltipProvider>
        <Toaster theme="dark" position="bottom-right" />
      </PollingContext.Provider>
    </QueryClientProvider>
  );
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Providers>
      <RouterProvider router={router} />
    </Providers>
  </StrictMode>,
);
