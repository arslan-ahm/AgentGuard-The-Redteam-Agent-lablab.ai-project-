"""Render the AgentGuard explainer: script -> voice -> timeline -> frames -> video files.

    uv run --project sandbox-worker python media/tools/render_video.py --stills 3,20,60   # review frames
    uv run --project sandbox-worker python media/tools/render_video.py                    # full render
    uv run --project sandbox-worker python media/tools/render_video.py --retts            # redo the voice

Outputs in media/explainer/out/ (video and voice are separate files, kept in sync by timing):
    agentguard-explainer.mp4    silent video, H.264 (YouTube, editors, Windows players)
    agentguard-explainer.webm   silent video, VP9 (plays in VS Code and every browser)
    agentguard-voiceover.wav    the narration, same length as the video (also .m4a)
    agentguard-explainer.srt    captions
    STORYBOARD.md               every line with its timing, what is on screen and the student's acting

The voice is Piper (offline neural TTS, voice from script.json "tts"); the Windows speech engine
is the fallback. The voice's timing drives every scene, so editing script.json re-times all of it.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import shutil
import subprocess
import sys
import wave
from pathlib import Path

from playwright.async_api import async_playwright

MEDIA = Path(__file__).resolve().parents[1]
EXPLAINER = MEDIA / "explainer"
BUILD = EXPLAINER / "build"
AUDIO = BUILD / "audio"
OUT = EXPLAINER / "out"
ICONS = EXPLAINER / "assets" / "icons"
NAME = "agentguard-explainer"


def line_files(data: dict) -> list[tuple[dict, Path]]:
    return [
        (line, AUDIO / f"{scene['id']}_{i:02d}.wav")
        for scene in data["scenes"]
        for i, line in enumerate(scene["lines"])
    ]


def synth_piper(data: dict) -> None:
    tts = data["tts"]
    model = MEDIA / "voices" / f"{tts['voice']}.onnx"
    if not model.exists():
        subprocess.run(  # noqa: S603 - fixed argv
            ["uvx", "--from", "piper-tts", "python", "-m", "piper.download_voices",
             "--download-dir", str(model.parent), tts["voice"]],
            check=True,
        )
    for line, wav in line_files(data):
        subprocess.run(  # noqa: S603 - fixed argv, text on stdin
            ["uvx", "--from", "piper-tts", "piper", "-m", str(model), "-f", str(wav),
             "--length-scale", str(tts.get("length_scale", 1.0))],
            input=line.get("say", line["text"]),
            text=True,
            check=True,
            capture_output=True,
        )


def synth_sapi(script: Path) -> None:
    subprocess.run(  # noqa: S603 - fixed argv
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
         str(MEDIA / "tools" / "tts.ps1"), "-Script", str(script), "-Out", str(AUDIO)],
        check=True,
    )


def ensure_voice(script: Path, force: bool) -> None:
    data = json.loads(script.read_text(encoding="utf-8"))
    if not force and all(wav.exists() for _, wav in line_files(data)):
        return
    shutil.rmtree(AUDIO, ignore_errors=True)
    AUDIO.mkdir(parents=True)
    if data.get("tts", {}).get("engine") == "piper" and shutil.which("uvx"):
        synth_piper(data)
    elif sys.platform == "win32":
        synth_sapi(script)
    else:
        raise SystemExit("no TTS engine: install uv (for Piper) or run on Windows")
    print(f"voice: {len(line_files(data))} lines -> {AUDIO}")


def wav_seconds(path: Path) -> float:
    with wave.open(str(path), "rb") as w:
        return w.getnframes() / w.getframerate()


def build_timeline(script: Path) -> dict:
    """Scene/line start and end times from the real length of each spoken line."""
    data = json.loads(script.read_text(encoding="utf-8"))
    timing = data["timing"]
    t = 0.0
    scenes = []
    for scene in data["scenes"]:
        start = t
        cursor = start + timing["scene_lead_s"]
        lines = []
        for i, line in enumerate(scene["lines"]):
            wav = f"{scene['id']}_{i:02d}.wav"
            dur = wav_seconds(AUDIO / wav)
            lines.append({**line, "start": cursor, "end": cursor + dur, "wav": wav})
            cursor += dur + timing["line_gap_s"]
        end = cursor - timing["line_gap_s"] + timing["scene_tail_s"]
        scenes.append({"id": scene["id"], "title": scene.get("title", scene["id"]), "start": start, "end": end, "lines": lines})
        t = end
    icons = {p.stem: p.read_text(encoding="utf-8") for p in ICONS.glob("*.svg")}
    return {"fps": data["fps"], "duration": t, "scenes": scenes, "icons": icons}


def write_voice(tl: dict, dest: Path) -> None:
    """One mono WAV the length of the video: every line at its start time, silence elsewhere."""
    first = AUDIO / tl["scenes"][0]["lines"][0]["wav"]
    with wave.open(str(first), "rb") as w:
        rate, width = w.getframerate(), w.getsampwidth()
    total = int(math.ceil(tl["duration"] * rate))
    track = bytearray(total * width)
    for scene in tl["scenes"]:
        for line in scene["lines"]:
            with wave.open(str(AUDIO / line["wav"]), "rb") as w:
                if (w.getframerate(), w.getsampwidth(), w.getnchannels()) != (rate, width, 1):
                    raise ValueError(f"{line['wav']}: all lines must share one mono format")
                pcm = w.readframes(w.getnframes())
            at = int(line["start"] * rate) * width
            track[at : at + len(pcm)] = pcm[: max(0, len(track) - at)]
    with wave.open(str(dest), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(width)
        w.setframerate(rate)
        w.writeframes(bytes(track))


def srt_time(s: float) -> str:
    ms = int(round(s * 1000))
    return f"{ms // 3600000:02d}:{ms // 60000 % 60:02d}:{ms // 1000 % 60:02d},{ms % 1000:03d}"


def write_srt(tl: dict, dest: Path) -> None:
    rows = []
    for n, line in enumerate((ln for sc in tl["scenes"] for ln in sc["lines"]), 1):
        rows.append(f"{n}\n{srt_time(line['start'])} --> {srt_time(line['end'] + 0.3)}\n{line['text']}\n")
    dest.write_text("\n".join(rows), encoding="utf-8")


def write_storyboard(tl: dict, dest: Path) -> None:
    out = ["# AgentGuard explainer: storyboard", "",
           "Generated by `media/tools/render_video.py` from `script.json` (edit the JSON, not this file).",
           "The student never speaks: the narrator talks, the student acts and reacts.", "",
           f"Length: {tl['duration']:.1f} s", ""]
    for sc in tl["scenes"]:
        out += [f"## {sc['title']} ({sc['start']:.1f}-{sc['end']:.1f} s)", "",
                "| Time | Narrator says | On screen | Student does | Face |", "|---|---|---|---|---|"]
        for ln in sc["lines"]:
            out.append(f"| {ln['start']:.1f} | {ln['text']} | {ln.get('screen', '')} | {ln.get('student', '')} | {ln.get('face', '')} |")
        out.append("")
    dest.write_text("\n".join(out), encoding="utf-8")


def ffmpeg(*args: str) -> None:
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", *args], check=True)  # noqa: S603


def decodes_cleanly(path: Path) -> str:
    check = subprocess.run(  # noqa: S603 - fixed argv
        ["ffmpeg", "-v", "error", "-i", str(path), "-f", "null", "-"], capture_output=True, text=True
    )
    return "" if check.returncode == 0 and not check.stderr.strip() else check.stderr[:400] or "failed"


def publish(tmp: Path, final: Path) -> None:
    """Swap a finished file into place only if it decodes cleanly from start to end."""
    problem = decodes_cleanly(tmp)
    if problem:
        tmp.unlink(missing_ok=True)
        raise SystemExit(f"{final.name}: new file does not decode cleanly, kept the old one: {problem}")
    os.replace(tmp, final)


async def render(tl: dict, stills: list[float] | None) -> None:
    fps = tl["fps"]
    frames = int(math.ceil(tl["duration"] * fps))
    tag = os.getpid()  # private temp names: parallel runs can't touch each other's files
    async with async_playwright() as pw:
        browser = await pw.chromium.launch()
        page = await browser.new_page(viewport={"width": 1920, "height": 1080})
        await page.goto((EXPLAINER / "stage.html").as_uri())
        if not await page.evaluate("tl => window.setup(tl)", tl):
            raise SystemExit("font did not load (media/explainer/assets/Nunito.ttf)")
        if stills is not None:
            for t in stills:
                await page.evaluate("t => window.renderAt(t)", t)
                dest = BUILD / f"still_{t:06.2f}.png"
                await page.screenshot(path=str(dest))
                print(f"still {t:.2f}s -> {dest.name}")
            await browser.close()
            return
        mp4_tmp = OUT / f"{NAME}.{tag}.partial.mp4"
        enc = subprocess.Popen(  # noqa: S603 - fixed argv
            ["ffmpeg", "-y", "-loglevel", "error", "-f", "image2pipe", "-framerate", str(fps), "-c:v", "mjpeg",
             "-i", "-", "-c:v", "libx264", "-preset", "medium", "-crf", "18", "-pix_fmt", "yuv420p",
             "-movflags", "+faststart", str(mp4_tmp)],
            stdin=subprocess.PIPE,
        )
        assert enc.stdin is not None
        for i in range(frames):
            await page.evaluate("t => window.renderAt(t)", i / fps)
            enc.stdin.write(await page.screenshot(type="jpeg", quality=94))
            if i % (fps * 15) == 0:
                print(f"frame {i}/{frames}", flush=True)
        enc.stdin.close()
        await browser.close()
    if enc.wait() != 0:
        mp4_tmp.unlink(missing_ok=True)
        raise SystemExit("ffmpeg failed")
    publish(mp4_tmp, OUT / f"{NAME}.mp4")
    webm_tmp = OUT / f"{NAME}.{tag}.partial.webm"
    ffmpeg("-i", str(OUT / f"{NAME}.mp4"), "-c:v", "libvpx-vp9", "-b:v", "0", "-crf", "32",
           "-deadline", "good", "-cpu-used", "4", "-row-mt", "1", str(webm_tmp))
    publish(webm_tmp, OUT / f"{NAME}.webm")
    print(f"video: {NAME}.mp4 + .webm ({tl['duration']:.1f}s, {frames} frames, both decode cleanly)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--script", default=str(EXPLAINER / "script.json"))
    parser.add_argument("--stills", help="comma-separated seconds: render PNG stills only")
    parser.add_argument("--retts", action="store_true", help="regenerate the voice")
    args = parser.parse_args()
    script = Path(args.script)
    BUILD.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    ensure_voice(script, args.retts)
    tl = build_timeline(script)
    (BUILD / "timeline.json").write_text(json.dumps({**tl, "icons": sorted(tl["icons"])}, indent=2), encoding="utf-8")
    print(f"timeline: {tl['duration']:.1f}s | " + ", ".join(f"{s['id']} {s['start']:.1f}" for s in tl["scenes"]))
    stills = [float(x) for x in args.stills.split(",")] if args.stills else None
    if stills is None:
        tag = os.getpid()
        wav_tmp = OUT / f"agentguard-voiceover.{tag}.partial.wav"
        write_voice(tl, wav_tmp)
        publish(wav_tmp, OUT / "agentguard-voiceover.wav")
        m4a_tmp = OUT / f"agentguard-voiceover.{tag}.partial.m4a"
        ffmpeg("-i", str(OUT / "agentguard-voiceover.wav"), "-c:a", "aac", "-b:a", "160k", str(m4a_tmp))
        publish(m4a_tmp, OUT / "agentguard-voiceover.m4a")
        write_srt(tl, OUT / f"{NAME}.srt")
        write_storyboard(tl, EXPLAINER / "STORYBOARD.md")
    asyncio.run(render(tl, stills))


if __name__ == "__main__":
    main()
