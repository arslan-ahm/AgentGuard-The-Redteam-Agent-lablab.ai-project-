"""qa.accessibility: basic accessibility problems on a page (brief 3, 6.5).

One read-only in-page scan for: images without ``alt``, form fields without a label, links and
buttons with no accessible name, a missing ``<title>``, a missing ``<html lang>`` and clearly
low text contrast (ratio below 3:1, deliberately lenient so it only flags real failures).
Findings use the ``accessibility`` category. Nothing is clicked or submitted.
"""

from __future__ import annotations

from typing import Any

from checks.context import CheckContext
from checks.qa._common import qa_finding, safe_navigate
from checks.security._common import (
    NETWORK_SUMMARY,
    path_of,
    screenshot_or_none,
    snippet,
    target_path_url,
)

CHECK_ID = "qa.accessibility"

MIN_CONTRAST = 3.0

SCAN_JS = """() => {
  const text = el => (el.textContent || '').trim();
  const short = v => String(v || '').slice(0, 80);
  const images = Array.from(document.querySelectorAll('img:not([alt])'))
    .slice(0, 50).map(i => short(i.getAttribute('src')));
  const labelled = i => {
    if (i.getAttribute('aria-label') || i.getAttribute('aria-labelledby')) return true;
    if (i.getAttribute('title')) return true;
    if (i.id && document.querySelector('label[for="' + CSS.escape(i.id) + '"]')) return true;
    return !!i.closest('label');
  };
  const skip = ['hidden', 'submit', 'button', 'image', 'reset'];
  const inputs = Array.from(document.querySelectorAll('input, select, textarea'))
    .filter(i => !skip.includes((i.getAttribute('type') || '').toLowerCase()))
    .filter(i => !labelled(i)).slice(0, 50)
    .map(i => short(i.getAttribute('name') || i.id || i.tagName.toLowerCase()));
  const named = e => text(e) || e.getAttribute('aria-label')
    || e.getAttribute('aria-labelledby') || e.getAttribute('title')
    || (e.querySelector('img[alt]:not([alt=""])') ? 'img' : '');
  const links = Array.from(document.querySelectorAll('a[href]'))
    .filter(a => !named(a)).slice(0, 50).map(a => short(a.getAttribute('href')));
  const buttons = Array.from(document.querySelectorAll('button'))
    .filter(b => !named(b) && !b.value).slice(0, 50)
    .map(b => short(b.id || b.getAttribute('name') || 'button'));
  const parse = c => {
    const m = String(c).match(/rgba?\\(([^)]+)\\)/);
    if (!m) return null;
    const p = m[1].split(',').map(parseFloat);
    return {r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1};
  };
  const lum = c => {
    const f = v => {
      v /= 255;
      return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
    };
    return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
  };
  const backdrop = el => {
    for (let e = el; e; e = e.parentElement) {
      const c = parse(getComputedStyle(e).backgroundColor);
      if (c && c.a > 0.99) return c;
    }
    return {r: 255, g: 255, b: 255, a: 1};
  };
  const contrast = [];
  const els = document.querySelectorAll('p, span, a, li, h1, h2, h3, h4, label, button, td, th');
  for (const el of Array.from(els).slice(0, 300)) {
    if (!Array.from(el.childNodes).some(n => n.nodeType === 3 && n.textContent.trim())) continue;
    const s = getComputedStyle(el);
    if (s.visibility === 'hidden' || s.display === 'none') continue;
    const fg = parse(s.color);
    if (!fg || fg.a < 0.99) continue;
    const a = lum(fg), b = lum(backdrop(el));
    const ratio = (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
    if (ratio < %MIN%) {
      contrast.push({text: short(text(el)).slice(0, 40), ratio: Math.round(ratio * 100) / 100});
    }
    if (contrast.length >= 10) break;
  }
  return {
    images, inputs, links, buttons, contrast,
    lang: (document.documentElement.getAttribute('lang') || '').trim(),
    title: (document.title || '').trim()
  };
}""".replace("%MIN%", str(MIN_CONTRAST))


def _strings(value: Any) -> list[str]:
    return [str(v) for v in value if v is not None][:50] if isinstance(value, list) else []


def _sample(items: list[str], limit: int = 3) -> str:
    shown = ", ".join(repr(snippet(i, 0, len(i), 0)) for i in items[:limit])
    return shown + (f" and {len(items) - limit} more" if len(items) > limit else "")


def analyse(data: dict[str, Any], url: str, evidence: list[str]) -> list[dict[str, Any]]:
    """Findings from the in-page scan result (shape of ``SCAN_JS``)."""
    path = path_of(url)

    def make(
        title: str,
        severity: str,
        steps: list[str],
        impact: str,
        fix: str,
        confidence: float = 0.9,
    ) -> dict[str, Any]:
        return qa_finding(
            check_id=CHECK_ID,
            title=title,
            severity=severity,
            url=url,
            evidence=evidence,
            reproduction=[f"Open {path}", *steps],
            impact=impact,
            recommended_fix=fix,
            confidence=confidence,
            category="accessibility",
        )

    found: list[dict[str, Any]] = []
    images = _strings(data.get("images"))
    if images:
        found.append(
            make(
                f"{len(images)} image(s) without alt text",
                "low",
                [f"Inspect the images: {_sample(images)} have no alt attribute"],
                "Screen reader users get no description of these images.",
                'Add a short descriptive alt text, or alt="" for purely decorative images.',
            )
        )
    inputs = _strings(data.get("inputs"))
    if inputs:
        found.append(
            make(
                f"{len(inputs)} form field(s) without a label",
                "medium",
                [f"Inspect the fields: {_sample(inputs)} have no <label> or aria-label"],
                "Assistive technology cannot tell users what to type, so they may be unable to "
                "complete the form.",
                "Associate every field with a visible <label for=...> (or aria-label).",
            )
        )
    links = _strings(data.get("links"))
    if links:
        found.append(
            make(
                f"{len(links)} link(s) with no text",
                "medium",
                [f"Inspect the links to {_sample(links)}: they have no text or aria-label"],
                "Screen readers announce these links as just 'link', so users cannot tell "
                "where they lead.",
                "Give each link visible text or an aria-label that describes its target.",
            )
        )
    buttons = _strings(data.get("buttons"))
    if buttons:
        found.append(
            make(
                f"{len(buttons)} button(s) with no accessible name",
                "medium",
                [f"Inspect the buttons {_sample(buttons)}: they have no text or aria-label"],
                "Screen readers announce these buttons without a purpose.",
                "Give each button visible text or an aria-label.",
            )
        )
    if not str(data.get("title") or "").strip():
        found.append(
            make(
                "Page has no title",
                "low",
                ["Look at the browser tab: no <title> is set"],
                "Screen reader users and tab switchers cannot identify the page.",
                "Add a short, unique <title> to every page.",
                0.85,
            )
        )
    if not str(data.get("lang") or "").strip():
        found.append(
            make(
                "Page language is not declared",
                "low",
                ["Inspect <html>: it has no lang attribute"],
                "Screen readers may read the page with the wrong pronunciation.",
                'Set the language, for example <html lang="en">.',
                0.85,
            )
        )
    contrast = [c for c in data.get("contrast") or [] if isinstance(c, dict)]
    if contrast:
        worst = ", ".join(f"'{c.get('text', '')}' ({c.get('ratio')}:1)" for c in contrast[:3])
        found.append(
            make(
                f"Low text contrast on {len(contrast)} element(s)",
                "low",
                [f"Inspect the text: {worst}", f"Observe a contrast ratio below {MIN_CONTRAST}:1"],
                "Low-contrast text is hard to read, especially for low-vision users.",
                "Use at least 4.5:1 contrast for body text (WCAG AA).",
                0.7,
            )
        )
    return found


async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
    """Scan the page once and report accessibility problems."""
    url = target_path_url(ctx)
    if await safe_navigate(page, ctx, url) is None:
        return []
    try:
        data = await page.evaluate(SCAN_JS)
    except Exception:  # blocked eval (strict CSP) or detached page: nothing to report
        ctx.record_request({"url": url, "skipped": "page scan could not run"})
        return []
    if not isinstance(data, dict):
        return []
    shots = await screenshot_or_none(ctx, "accessibility")
    return analyse(data, url, [*shots, NETWORK_SUMMARY])
