import { StrictMode, type ComponentType } from 'react'
import { createRoot } from 'react-dom/client'
import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import { api } from './api/client'
import App from './App'
import { isStaleBuildError, reloadForNewVersion, RouteError } from './components/RouteError'
import { RootTransition } from './components/motion/PageTransition'
import './index.css'
import LandingPage from './pages/LandingPage'

// Checker pages are separate files. They are fetched in the background soon after the site opens (below), so a
// click on "Check a link" does not wait for a download.
const loaders = {
  check: () => import('./pages/CheckPage'),
  report: () => import('./pages/ReportPage'),
  history: () => import('./pages/HistoryPage'),
  verify: () => import('./features/registry/VerifyPage'),
}
const page = (load: () => Promise<{ default: ComponentType }>) => async () => ({ Component: (await load()).default })

const router = createBrowserRouter([
  {
    element: <RootTransition />,
    // Any failure to load or render a page shows our own screen (and reloads once after a new deploy).
    errorElement: <RouteError />,
    children: [
      { path: '/', element: <LandingPage /> },
      {
        element: <App />,
        children: [
          { path: 'check', lazy: page(loaders.check) },
          { path: 'report/:id', lazy: page(loaders.report) },
          { path: 'history', lazy: page(loaders.history) },
          { path: 'verify', lazy: page(loaders.verify) },
          { path: 'verify/:id', lazy: page(loaders.verify) },
        ],
      },
    ],
  },
])

// A page file that fails to preload (a newer version was deployed while this tab was open): load the new version.
window.addEventListener('vite:preloadError', (event) => {
  if (reloadForNewVersion()) event.preventDefault()
})

// Wake the backend as soon as anyone opens the site. On the free host it sleeps when idle and needs up to a minute
// to start, so this way it is usually awake by the time the visitor runs a check.
api.health().catch(() => {})

// Fetch the checker pages in the background once the landing page has settled.
const prefetch = () =>
  Object.values(loaders).forEach((load) =>
    load().catch((error) => {
      if (isStaleBuildError(error)) reloadForNewVersion()
    }),
  )
if ('requestIdleCallback' in window) window.requestIdleCallback(prefetch, { timeout: 4000 })
else setTimeout(prefetch, 2500)

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
)
