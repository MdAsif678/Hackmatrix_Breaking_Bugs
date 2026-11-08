import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import App from './App'
import VerifyPage from './features/registry/VerifyPage'
import './index.css'
import HistoryPage from './pages/HistoryPage'
import HomePage from './pages/HomePage'
import ReportPage from './pages/ReportPage'

const router = createBrowserRouter([
  {
    path: '/',
    element: <App />,
    children: [
      { index: true, element: <HomePage /> },
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
