import { StrictMode, type ComponentType } from 'react'
import { createRoot } from 'react-dom/client'
import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import App from './App'
import { RootTransition } from './components/motion/PageTransition'
import './index.css'
import LandingPage from './pages/LandingPage'

// Checker pages load on first visit; the router waits for the chunk before switching pages, so nothing flashes.
const page = (load: () => Promise<{ default: ComponentType }>) => async () => ({ Component: (await load()).default })

const router = createBrowserRouter([
  {
    element: <RootTransition />,
    children: [
      { path: '/', element: <LandingPage /> },
      {
        element: <App />,
        children: [
          { path: 'check', lazy: page(() => import('./pages/CheckPage')) },
          { path: 'report/:id', lazy: page(() => import('./pages/ReportPage')) },
          { path: 'history', lazy: page(() => import('./pages/HistoryPage')) },
          { path: 'verify', lazy: page(() => import('./features/registry/VerifyPage')) },
          { path: 'verify/:id', lazy: page(() => import('./features/registry/VerifyPage')) },
        ],
      },
    ],
  },
])

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
)
