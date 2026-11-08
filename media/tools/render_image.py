"""Render a product image brief into every export size (PNG master + WebP + JPG).

    uv run --project sandbox-worker python media/tools/render_image.py media/briefs/agentguard-hero.json

The brief (JSON) holds only content; the layout lives in media/templates/<template>.html.
Text, logo and CTA are always real HTML, never generated pixels. AI imagery (ComfyUI) only
fills the optional "background" slot; "product_image" is the real product picture.
Paths in a brief are relative to the repo root.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from pathlib import Path

from playwright.async_api import async_playwright

MEDIA = Path(__file__).resolve().parents[1]
REPO = MEDIA.parent
OUT = MEDIA / "out" / "images"


def asset_uri(value: str) -> str:
    if not value:
        return ""
    path = (REPO / value).resolve()
    if not path.is_file():
        raise SystemExit(f"asset not found: {value}")
    return path.as_uri()


async def render(brief_path: Path) -> list[Path]:
    brief = json.loads(brief_path.read_text(encoding="utf-8"))
    brand = json.loads((MEDIA / "brand.json").read_text(encoding="utf-8"))
    template = MEDIA / "templates" / f"{brief['template']}.html"
    assets = {
        "product_image": asset_uri(brief["product_image"]),
        "background": asset_uri(brief.get("background", "")),
    }
    OUT.mkdir(parents=True, exist_ok=True)
    made: list[Path] = []
    async with async_playwright() as pw:
        browser = await pw.chromium.launch()
        for size in brief["exports"]:
            w, h = (int(n) for n in size.lower().split("x"))
            page = await browser.new_page(viewport={"width": w, "height": h}, device_scale_factor=2)
            await page.goto(template.as_uri())
            await page.evaluate("([b, br, a]) => window.applyBrief(b, br, a)", [brief, brand, assets])
            # Text wider than its box, or anything that ends up outside the canvas.
            overflow = await page.evaluate(
                """() => [...document.querySelectorAll('.brand,h1,.sub,li,.cta,.visual img')].filter(e => {
                    const r = e.getBoundingClientRect();
                    return e.scrollWidth > e.clientWidth + 1 || r.top < -1
                        || r.bottom > innerHeight + 1 || r.right > innerWidth + 1;
                }).map(e => e.textContent || e.tagName)"""
            )
            if overflow:
                raise SystemExit(f"{size}: content overflows or leaves the canvas: {overflow}")
            png = OUT / f"{brief['name']}-{w}x{h}.png"
            await page.screenshot(path=str(png))
            await page.close()
            for ext, args in ((".webp", ["-quality", "88"]), (".jpg", ["-q:v", "3"])):
                subprocess.run(  # noqa: S603 - fixed argv
                    ["ffmpeg", "-y", "-loglevel", "error", "-i", str(png), *args, str(png.with_suffix(ext))],
                    check=True,
                )
            made.append(png)
            print(f"{size}: {png.name} (+ .webp, .jpg)")
        await browser.close()
    return made


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    asyncio.run(render(Path(sys.argv[1])))
