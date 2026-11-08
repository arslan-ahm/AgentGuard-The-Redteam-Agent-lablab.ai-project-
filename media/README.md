# Media pipeline: explainer video + product images

Owner: Arslan. A free, local, token-efficient way to make AgentGuard's marketing media. Claude writes small JSON briefs and occasionally improves a template. Rendering is done by tools, not by Claude.

```
brand.json + reusable templates (built once)
            ↓
Claude writes / edits a JSON brief (script.json, briefs/*.json)
            ↓
optional: ComfyUI generates only backgrounds / textures / props
            ↓
HTML + CSS + SVG composes text, logo, product, character
            ↓
Playwright renders frames / images (headless Chromium)
            ↓
FFmpeg encodes MP4 and exports PNG / WebP / JPG
```

## Stack

| Layer | Tool | Role |
|---|---|---|
| Creative direction | Claude Code | Briefs, layout code, prompt compiling, QC of rendered stills |
| Layout engine | HTML + CSS + SVG | Text, logo, character, badges: always sharp and editable |
| AI imagery (optional) | ComfyUI + open SDXL / FLUX-class models | Only backgrounds, textures, lifestyle scenes; workflows saved as JSON in `comfy/` |
| Product consistency | The real product image + img2img / inpainting | The product itself is never regenerated |
| Rendering | Playwright (from `sandbox-worker`) | HTML to PNG frames at exact sizes |
| Encoding / export | FFmpeg | MP4 (H.264 + AAC), WebP, JPG |
| Narration | Windows speech engine (`tools/tts.ps1`) | Offline voice-over; swap in a recorded voice by replacing the WAVs |
| Upscaling (optional) | Real-ESRGAN via ComfyUI | Selectively, on generated assets only |

ImageMagick isn't needed: FFmpeg does the conversions.

## Explainer video

A friendly, white-themed cartoon explainer (kid-simple words, icons, charts). Our 2D student character never speaks: he learns on screen while a narrator teaches. He reacts with real expressions (curious, confused, surprised, shocked, worried, sad, learning, idea, joy, proud, relieved) and interacts with the content: a chart bar lifts him up, he sits on the AgentGuard card, juggles task cards, peeks into sandboxes, reads with a magnifier.

Story: a question, then the problem with real stats (Verizon DBIR 2025, IBM Cost of a Data Breach 2025), then what teams need, then AgentGuard, then how it works, then the close.

```bash
uv run --project sandbox-worker python media/tools/render_video.py --stills 6,35,80   # review frames first
uv run --project sandbox-worker python media/tools/render_video.py                    # full render
uv run --project sandbox-worker python media/tools/render_video.py --retts            # after editing narration
```

Outputs in `media/explainer/out/`. **Video and voice are separate files**, kept in sync by timing (both start at 0 and have the same length):

| File | What it is |
|---|---|
| `agentguard-explainer.mp4` | Silent video, 1920x1080 30 fps, H.264 (YouTube, editors, Windows players) |
| `agentguard-explainer.webm` | The same silent video, VP9: plays in VS Code and any browser |
| `agentguard-voiceover.wav` / `.m4a` | The narration, same length as the video |
| `agentguard-explainer.srt` | Captions |

To combine them later: `ffmpeg -i agentguard-explainer.mp4 -i agentguard-voiceover.m4a -c copy -shortest final.mp4`.

| File | What to edit |
|---|---|
| `explainer/script.json` | The script: narration, what is on screen, what the student does, his face. Timing follows the voice automatically |
| `explainer/STORYBOARD.md` | Generated from the script with real timings (don't edit by hand) |
| `explainer/stage.html` | The student (poses, faces, effects) and each scene's choreography |
| `tools/render_video.py` | Voice, timeline, frames, video + voice files, decode checks |

**Voice:** Piper (free, offline neural TTS) with the public-domain `en_US-ljspeech-high` voice, downloaded on first run to `media/voices/` (gitignored). The Windows speech engine (`tools/tts.ps1`) is the fallback. To use a real person instead: record one WAV per line as `explainer/build/audio/<scene>_<NN>.wav` (all lines the same mono format) and run the full render without `--retts`. Every scene re-times to the recording.

Every output is fully decoded before it replaces the previous file, so a failed or parallel render never leaves a broken video.

## Product images

```bash
uv run --project sandbox-worker python media/tools/render_image.py media/briefs/agentguard-hero.json
```

Writes `media/out/images/<name>-<W>x<H>.png` (2x master) plus `.webp` and `.jpg` for each size in the brief's `exports`. The renderer warns if any text overflows.

A brief is all you change:

```json
{
  "template": "product_hero",
  "name": "agentguard-hero",
  "headline": "Ship without the surprises",
  "subheadline": "AI-planned QA and security tests in a real browser, each in its own disposable sandbox.",
  "benefits": ["Real Playwright runs", "Evidence for every finding", "Containment first"],
  "cta": "See the demo",
  "product_image": "docs/architecture-diagram.png",
  "background": "",
  "exports": ["1920x1080", "1080x1080", "1080x1350", "1200x628"]
}
```

`background` takes an image generated by ComfyUI (for example `media/comfy/output/studio_gradient_03.png`). Empty means the brand gradient.

### Adding ComfyUI (optional, needs a GPU)

1. Install ComfyUI locally (portable build on Windows) and an open-weight model (SDXL or a FLUX-class model), respecting each model's licence.
2. Save each workflow you use as JSON in `media/comfy/workflows/` (for example `studio_background.json`), so results are reproducible.
3. Generate only backgrounds, shadows, props or scenes. Then point a brief's `background` at the output file and render.

Rules for Claude are in [`media/CLAUDE.md`](CLAUDE.md).
