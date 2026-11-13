// What the user sees when a page fails to load or crashes, instead of React Router's developer error. Owner: P1.
// The common case is a stale tab after a new deploy: the old page file names no longer exist, so loading the
// check or report page fails. That is fixed by loading the latest version, which we do once automatically.
import { useEffect } from 'react'
import { Link, useRouteError } from 'react-router-dom'
import { Logo } from './Brand'

const RELOAD_KEY = 'trustlens-reloaded-at'

/** True for "this page's code file could not be loaded" errors (a newer version was deployed). */
export function isStaleBuildError(error: unknown): boolean {
  const text = error instanceof Error ? `${error.name} ${error.message}` : String(error)
  return /dynamically imported module|Importing a module script failed|error loading dynamically imported module|Failed to load module script|ChunkLoadError/i.test(text)
}

/** Reload once to pick up the latest version; never loop (at most once a minute). */
export function reloadForNewVersion(): boolean {
  try {
    const last = Number(sessionStorage.getItem(RELOAD_KEY) || 0)
    if (Date.now() - last < 60_000) return false
    sessionStorage.setItem(RELOAD_KEY, String(Date.now()))
  } catch {
    /* storage blocked: still reload once */
  }
  window.location.reload()
  return true
}

export function RouteError() {
  const error = useRouteError()
  const stale = isStaleBuildError(error)

  useEffect(() => {
    if (stale) reloadForNewVersion()
  }, [stale])

  return (
    <div className="flex min-h-svh flex-col">
      <header className="wrap flex h-[var(--nav)] items-center">
        <Logo />
      </header>
      <main className="wrap flex flex-1 flex-col justify-center pb-24">
        <p className="t-label">{stale ? 'New version available' : 'Something went wrong'}</p>
        <h1 className="t-h2 mt-3 max-w-[22ch]">
          {stale ? 'TrustLens was just updated. Loading the latest version.' : 'This page could not be shown.'}
        </h1>
        <p className="t-lead mt-4 max-w-[52ch]">
          {stale
            ? 'If nothing happens in a few seconds, reload the page.'
            : 'Reload the page to try again. If it keeps happening, start a new check from the home page.'}
        </p>
        <div className="mt-8 flex flex-wrap gap-3">
          <button type="button" className="btn btn-primary" onClick={() => window.location.reload()}>
            Reload the page
          </button>
          <Link to="/" reloadDocument className="btn btn-secondary">
            Go to the home page
          </Link>
        </div>
      </main>
    </div>
  )
}
