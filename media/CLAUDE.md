# Media rules (auto-loaded by Claude Code inside media/)

Claude is the art director, layout engineer and prompt compiler here, **not** the image or video generator. Templates are built once; content is a small JSON file that changes often. Edit JSON first, templates rarely.

## Video (explainer)
0. Script first: every line in `explainer/script.json` says what the narrator says, what is on screen, what the student does and his face. The student never speaks. Keep words simple enough for a 5-year-old; every stat needs a named source on screen.
1. Change words, order or timing in `explainer/script.json` only. Narration length drives every scene and caption; never hard-code times in `stage.html` (use line starts and `at(line, "phrase")`).
2. Change visuals in `explainer/stage.html` only when a scene's choreography must change. Keep it deterministic: everything is a pure function of time `T` (no `Date`, no `Math.random`, no CSS animations).
3. Before a full render, render stills (`--stills`) at the moments you changed and look at them: overlaps, text overflow, faces hidden by arms, captions.
4. On-screen text: no em-dashes, real product claims only (SUBMISSION_PACK rule: every claim must be true of the deployed demo).
5. Pronunciation fixes go in a line's `"say"` field (e.g. "Vulture" for Vultr), captions keep the real spelling.

## Product images
1. Never regenerate a full advertisement image.
2. Use an existing template in `templates/`.
3. Create or update a brief in `briefs/` first.
4. Generate only missing visual assets (backgrounds, textures, props) through ComfyUI.
5. Use the supplied product image as is: never alter its shape, label, logo or colour.
6. Keep all readable text in HTML/CSS/SVG, never in generated pixels.
7. Export the PNG master at 2x plus the sizes listed in the brief.
8. Before export, check: text overflow (the renderer warns), contrast, logo legibility, safe margins, product realism.

## Tools
- Python via `uv run --project sandbox-worker ...` (reuses its Playwright + Chromium). JS via Bun only.
- FFmpeg on PATH. Narration: Windows speech engine (`tools/tts.ps1`), offline and free.
- Generated files (`explainer/build`, `explainer/out`, `out/`) are gitignored.
