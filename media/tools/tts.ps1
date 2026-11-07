# Offline narration with the Windows speech engine (free, no network, no API key).
#   powershell -ExecutionPolicy Bypass -File media/tools/tts.ps1 -Script media/explainer/script.json -Out media/explainer/build/audio
# Writes one WAV per narration line: <sceneId>_<NN>.wav (24 kHz, 16-bit, mono).
# A line's optional "say" field is spoken instead of "text" (pronunciation fixes, e.g. "Vulture" for Vultr).
param(
  [Parameter(Mandatory = $true)][string]$Script,
  [Parameter(Mandatory = $true)][string]$Out
)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Speech

$data = Get-Content -LiteralPath $Script -Raw -Encoding utf8 | ConvertFrom-Json
New-Item -ItemType Directory -Force -Path $Out | Out-Null

$synth = New-Object System.Speech.Synthesis.SpeechSynthesizer
$voices = $synth.GetInstalledVoices() | ForEach-Object { $_.VoiceInfo.Name }
if ($data.voice -and ($voices -contains $data.voice)) { $synth.SelectVoice($data.voice) }
else { Write-Warning "voice '$($data.voice)' not installed; using '$($synth.Voice.Name)'" }
if ($null -ne $data.rate) { $synth.Rate = [int]$data.rate }

$format = New-Object System.Speech.AudioFormat.SpeechAudioFormatInfo(
  24000, [System.Speech.AudioFormat.AudioBitsPerSample]::Sixteen, [System.Speech.AudioFormat.AudioChannel]::Mono)

$count = 0
foreach ($scene in $data.scenes) {
  $i = 0
  foreach ($line in $scene.lines) {
    $say = if ($line.say) { $line.say } else { $line.text }
    $file = Join-Path $Out ("{0}_{1:D2}.wav" -f $scene.id, $i)
    $synth.SetOutputToWaveFile($file, $format)
    $synth.Speak($say)
    $synth.SetOutputToNull()
    $i++; $count++
  }
}
$voiceName = $synth.Voice.Name
$synth.Dispose()
Write-Output "narration: $count lines -> $Out (voice: $voiceName)"
