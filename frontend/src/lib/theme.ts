/** Light / dark theme. Dark is the default; public/theme-init.js restores the choice before paint. */
export type Theme = 'light' | 'dark'

const STORAGE_KEY = 'agentguard-theme'
const THEME_COLOR: Record<Theme, string> = { dark: '#0b0e14', light: '#f6f8fa' }

export function currentTheme(): Theme {
  return document.documentElement.dataset.theme === 'light' ? 'light' : 'dark'
}

/** Applies a theme to <html> and remembers it. */
export function applyTheme(theme: Theme) {
  if (theme === 'light') document.documentElement.dataset.theme = 'light'
  else delete document.documentElement.dataset.theme
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', THEME_COLOR[theme])
  try {
    localStorage.setItem(STORAGE_KEY, theme)
  } catch {
    // Storage blocked: the choice lasts for this page only.
  }
}
