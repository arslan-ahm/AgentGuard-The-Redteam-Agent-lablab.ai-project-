import { FlaskConical, LayoutDashboard, LogOut, PlusCircle } from 'lucide-react'
import { Link, NavLink, Outlet } from 'react-router'
import { useAuth } from '../auth/context'
import { ThemeToggle } from '../components/ThemeToggle'
import { Button } from '../components/ui/Button'
import { Wordmark } from '../components/Wordmark'

const navClass = ({ isActive }: { isActive: boolean }) =>
  `inline-flex min-h-11 items-center gap-3 rounded-md px-3 text-sm font-medium transition-[color,box-shadow,background-color] ${
    isActive ? 'bg-raised text-accent shadow-neu-inset' : 'neu-soft text-fg-muted hover:text-fg'
  }`

const tabClass = ({ isActive }: { isActive: boolean }) =>
  `label-mono flex min-h-14 flex-col items-center justify-center gap-1 rounded-md transition-[color,box-shadow,background-color] ${
    isActive ? 'bg-raised text-accent shadow-neu-inset' : 'neu text-fg-muted hover:text-fg'
  }`

/**
 * Mock mode must be unmistakable: mock screens never go into the deck, video or README.
 * Shown as a pill in the shell plus a warn-coloured rule.
 */
function MockDataTag() {
  return (
    <span className="label-mono inline-flex items-center gap-1.5 whitespace-nowrap text-warn">
      <FlaskConical aria-hidden="true" className="size-3.5 shrink-0" />
      Mock data
    </span>
  )
}

/**
 * Signed-in shell. One header element that is a top bar on phones and a fixed left sidebar
 * from md up (so there is a single "Main" nav and a single Sign out), plus bottom tabs on phones.
 */
export function AppLayout() {
  const { logout, mockMode } = useAuth()

  return (
    <div className="min-h-dvh md:pl-60">
      <a
        href="#main"
        className="sr-only z-30 rounded-md bg-accent px-3 py-2 text-on-accent focus:not-sr-only focus:absolute focus:top-2 focus:left-2 print:hidden"
      >
        Skip to content
      </a>
      <header
        className={`glass sticky top-0 z-20 rounded-none border-b [--glass-alpha:82%] md:fixed md:inset-y-0 md:left-0 md:w-60 md:border-r md:border-b-0 print:hidden ${
          mockMode ? 'border-b-2 border-warn md:border-r-2 md:border-b-0' : 'border-glass-edge'
        }`}
      >
        <div className="flex items-center gap-2 px-4 py-2 md:h-full md:flex-col md:items-stretch md:gap-6 md:px-4 md:py-6">
          <Link to="/" className="rounded-md px-1 text-fg md:px-3" aria-label="AgentGuard home">
            <Wordmark />
          </Link>
          <nav aria-label="Main" className="hidden md:flex md:flex-col md:gap-2">
            <NavLink to="/" end className={navClass}>
              <LayoutDashboard aria-hidden="true" className="size-4" />
              Scans
            </NavLink>
            <NavLink to="/scans/new" className={navClass}>
              <PlusCircle aria-hidden="true" className="size-4" />
              New scan
            </NavLink>
          </nav>
          <div className="ml-auto flex items-center gap-1 md:mt-auto md:ml-0 md:flex-col md:items-stretch md:gap-3">
            {mockMode && (
              <span className="md:px-3">
                <MockDataTag />
              </span>
            )}
            <div className="flex items-center gap-1 md:justify-between md:border-t md:border-glass-edge md:pt-3">
              <ThemeToggle />
              <Button
                variant="ghost"
                onClick={logout}
                className="min-w-11 px-3"
                icon={<LogOut aria-hidden="true" className="size-4" />}
              >
                <span className="sr-only md:not-sr-only">Sign out</span>
              </Button>
            </div>
          </div>
        </div>
      </header>
      <main
        id="main"
        tabIndex={-1}
        className="mx-auto max-w-7xl px-4 pt-8 pb-28 outline-none sm:px-6 md:pb-10 lg:px-10"
      >
        <Outlet />
      </main>
      {/* Phones and small tablets: the two destinations sit under the thumb. */}
      <nav
        aria-label="Tabs"
        className="glass fixed inset-x-0 bottom-0 z-10 border-t border-glass-edge [--glass-alpha:88%] md:hidden print:hidden"
      >
        <div className="mx-auto grid max-w-md grid-cols-2 gap-2 px-4 pt-2 pb-[max(0.5rem,env(safe-area-inset-bottom))]">
          <NavLink to="/" end className={tabClass}>
            <LayoutDashboard aria-hidden="true" className="size-5" />
            Dashboard
          </NavLink>
          <NavLink to="/scans/new" className={tabClass}>
            <PlusCircle aria-hidden="true" className="size-5" />
            New scan
          </NavLink>
        </div>
      </nav>
    </div>
  )
}
