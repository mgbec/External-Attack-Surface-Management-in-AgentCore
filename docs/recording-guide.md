# Recording guide — YouTube screencast with a webcam corner (Windows)

How to record `docs/presentation.html` as a slides video with your webcam in the
bottom-right corner, using free tools. No video-editing experience needed.

---

## What you'll end up with

A 1080p MP4: the slide deck full-screen, your webcam as a small overlay in the
bottom-right, and your narration — ready to upload to YouTube.

The deck already **reserves the bottom-right corner** so no slide content ever
sits behind your camera.

---

## 1. Install the tools

- **OBS Studio** (free, open source) — screen + webcam capture and recording.
  Download from <https://obsproject.com>.
- A **browser** (Chrome/Edge/Firefox) to run the deck full-screen.
- Optional: a USB mic or headset. Even a decent headset beats laptop audio.

---

## 2. Prep the deck

1. Open `docs/presentation.html` in your browser (double-click the file).
2. Press **F** for fullscreen.
3. Useful keys while presenting:
   - **← / → / Space** — move between slides
   - **G** — toggle the dashed **webcam-safe zone** (use it to frame your camera,
     then turn it off before recording)
   - **N** — toggle **presenter notes** on screen (put these on a *second* monitor
     so they don't get recorded; or just use the printed script)
4. Have `docs/narration-script.md` open on a second monitor or on paper.

---

## 3. Set up OBS

**Resolution / FPS**
1. Settings → Video → Base and Output resolution: **1920×1080**. FPS: **30**.
2. Settings → Output → Recording: Format **MP4**, Encoder hardware (NVENC/AMF/QSV)
   if offered, else x264. Quality "Indistinguishable" or bitrate ~12,000 Kbps.

**Sources** (in the Sources panel, bottom-left, click **+**)
1. **Display Capture** (or **Window Capture** targeting the browser) — this is
   your slides. Resize it to fill the whole canvas.
2. **Video Capture Device** — this is your webcam. Then:
   - Right-click it → **Transform → Edit Transform**, or just drag the handles.
   - Scale it to roughly **300×225** px and drag it into the **bottom-right**
     corner, matching the deck's reserved zone (about 40 px in from each edge).
   - Optional: right-click → **Filters → +  → Image Mask/Blend** to round the
     corners, or apply a **Chroma Key** filter if you have a green screen.
3. **Audio Input Capture** — your mic. Watch the audio meter: aim for peaks
   around −12 dB to −6 dB, not pinned to the top.

**Framing tip:** press **G** in the deck to show the dashed box, line your webcam
overlay up inside it, then press **G** again to hide the box before you record.

---

## 4. Do a 20-second test

Record a short clip: talk, click through two slides, stop. Then watch it back and
check:
- Your webcam is in the corner and not covering text.
- Audio is clear and loud enough, no echo/clipping.
- Slides are sharp (text crisp, no scaling blur).

Fix levels/placement before the real take.

---

## 5. Record

1. Click **Start Recording** in OBS.
2. Wait ~2 seconds, then begin slide 1 of the script.
3. Narrate each slide; press **→** at each `[advance]` cue in the script.
4. If you fumble a line, pause, and just repeat the sentence — you can trim it
   later, or simply re-record that slide.
5. At the end, pause ~2 seconds, then **Stop Recording**.

The MP4 lands in the folder set under Settings → Output → Recording Path.

---

## 6. (Optional) Light edit

Any free editor works — **Clipchamp** (built into Windows 11), DaVinci Resolve,
or CapCut. Trim the dead air at the start/end and any fumbles. Export as **MP4,
1080p, 30 fps**.

---

## 7. Upload to YouTube

- **Title:** e.g. "Building a cheap External Attack Surface Management tool on AWS Bedrock AgentCore".
- **Description:** short summary + the repo link:
  <https://github.com/mgbec/External-Attack-Surface-Management-in-AgentCore>
- **Visibility:** start as *Unlisted* to review, then switch to *Public*.
- Add chapters by pasting timestamps from the script's timing table, e.g.:
  ```
  0:00 Intro
  0:25 The problem
  1:00 How it works
  3:50 Architecture & cost
  6:05 Findings, ops, wrap-up
  ```

---

## Troubleshooting

- **Webcam covers content** — you turned the safe zone off but moved the overlay;
  press **G**, realign the camera inside the dashed box, press **G** again.
- **Slides look blurry** — set OBS base *and* output resolution to match your
  monitor (ideally 1920×1080) so there's no rescaling.
- **Echo / room noise** — use a headset mic, and in OBS add **Filters → Noise
  Suppression** on the mic source.
- **Laggy recording** — switch the encoder to hardware (NVENC/QSV/AMF) and drop
  FPS to 30.

---

### Note on AI-generated video

This guide is for recording **your real webcam and voice**. Generating a
synthetic video of a person speaking from a still photo (a "deepfake") is a
different thing and isn't something this project produces.
