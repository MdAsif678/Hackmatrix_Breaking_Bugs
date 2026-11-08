// App shell: header + nav + page outlet. Owner: P1.
import { NavLink, Outlet } from 'react-router-dom'

const navClass = ({ isActive }: { isActive: boolean }) =>
  `rounded-md px-3 py-1.5 text-sm ${isActive ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'}`

export default function App() {
  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur">
        <div className="mx-auto flex max-w-5xl items-center gap-4 px-4 py-3">
          <NavLink to="/" className="text-lg font-bold tracking-tight">
            Trust<span className="text-sky-400">Lens</span>
          </NavLink>
          <nav className="ml-auto flex gap-1">
            <NavLink to="/" end className={navClass}>Investigate</NavLink>
            <NavLink to="/history" className={navClass}>History</NavLink>
            <NavLink to="/verify" className={navClass}>Verify</NavLink>
          </nav>
        </div>
      </header>
      <main className="mx-auto max-w-5xl px-4 py-8">
        <Outlet />
      </main>
      <footer className="mx-auto max-w-5xl px-4 pb-8 text-xs text-slate-600">
        Automated checks can't prove a website is safe. Never share passwords, OTPs or payment details because a
        message asked you to.
      </footer>
    </div>
  )
}
