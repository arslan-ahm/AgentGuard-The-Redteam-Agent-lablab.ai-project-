import { ShieldCheck } from 'lucide-react'

export function Wordmark({ className = '' }: { className?: string }) {
  return (
    <span className={`inline-flex items-center gap-2 font-semibold tracking-tight ${className}`}>
      <ShieldCheck aria-hidden="true" className="size-5 text-accent" />
      AgentGuard
    </span>
  )
}
