// Apply the saved theme before first paint (no flash). Dark is the default.
// A separate file, not an inline script, so the production CSP (script-src 'self') allows it.
try {
  if (localStorage.getItem('agentguard-theme') === 'light') {
    document.documentElement.dataset.theme = 'light'
    document.querySelector('meta[name="theme-color"]').content = '#f6f8fa'
  }
} catch {
  // Storage blocked: keep the dark default.
}
