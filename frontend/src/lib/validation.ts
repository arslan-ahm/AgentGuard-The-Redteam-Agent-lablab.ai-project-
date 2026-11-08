/**
 * Client-side checks for the target URL. They only catch typos early: the backend URL policy
 * (DNS resolution, private/metadata ranges, redirects) is the real gate and is never bypassed.
 */
export function validateTargetUrl(value: string): string | null {
  const trimmed = value.trim()
  if (!trimmed) return 'Enter the URL of the site to test.'
  let url: URL
  try {
    url = new URL(trimmed)
  } catch {
    return 'Enter a full URL, for example https://staging.example.com.'
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return 'Only http:// and https:// URLs can be scanned.'
  }
  if (url.username || url.password) {
    return 'Remove the username or password from the URL.'
  }
  if (!url.hostname) return 'Enter a full URL, for example https://staging.example.com.'
  return null
}
