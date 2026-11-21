import * as React from 'react';
import { createRoot } from 'react-dom/client';
import { consumeHashToken } from './api.ts';
import { App } from './panel.tsx';

consumeHashToken();

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error('Missing #root container');
}

createRoot(rootElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
