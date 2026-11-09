import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import App from './App'
import VerifyPage from './features/registry/VerifyPage'
import './index.css'
import CheckPage from './pages/CheckPage'
import HistoryPage from './pages/HistoryPage'
import LandingPage from './pages/LandingPage'
import ReportPage from './pages/ReportPage'

const router = createBrowserRouter([
  { path: '/', element: <LandingPage /> },
  {
    element: <App />,
    children: [
      { path: 'check', element: <CheckPage /> },
      { path: 'report/:id', element: <ReportPage /> },
      { path: 'history', element: <HistoryPage /> },
      { path: 'verify', element: <VerifyPage /> },
      { path: 'verify/:id', element: <VerifyPage /> },
    ],
  },
])

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
)
