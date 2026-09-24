import React from 'react';
import { createRoot } from 'react-dom/client';
import { AppLayout } from './layouts/AppLayout';
import './style.css';

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <AppLayout />
  </React.StrictMode>
);
