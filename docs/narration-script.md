# Narration script — EASM on Bedrock AgentCore

A per-slide script for a YouTube screencast of `docs/presentation.html`, with a
webcam talking-head in the bottom-right corner.

- **Target length:** ~6–7 minutes.
- **Pace:** ~130–140 words/minute. Each slide's block is sized to its timing.
- **Delivery:** conversational, not read-aloud-stiff. The bracketed cues like
  `[advance]` mark when to press → for the next slide.
- `[...]` placeholders (like `[your name]`) are for you to fill in.

> Tip: press **N** in the deck to show these as on-screen presenter notes (on a
> second monitor), and **G** to show the webcam-safe zone while you frame your camera.

---

## Slide 1 — Title  (~0:00–0:25)

Hi, I'm [your name]. In this video I want to walk you through a project I built:
an **External Attack Surface Management tool** — or EASM — that runs on Amazon
Bedrock AgentCore.

The one-line pitch: it finds everything the internet knows about your
organization, before an attacker does — and it does it for pennies. Let's get
into why that matters.

`[advance]`

---

## Slide 2 — The problem  (~0:25–1:00)

Here's the core problem in security: you can't defend what you don't know you own.

Organizations spin up subdomains, staging servers, and cloud resources all the
time, and plenty of them get forgotten — still exposed, with nobody watching.
There's rarely one clean inventory, especially once you factor in multiple teams,
multiple clouds, and acquisitions.

Commercial tools solve this, but they cost thousands a month. I wanted that same
visibility for a tiny fraction of the price.

`[advance]`

---

## Slide 3 — The approach  (~1:00–1:35)

The idea is simple: you give it a seed set — just your root domains, maybe an org
name or a couple of IP ranges — and it expands that into your full asset
inventory.

That's the important bit: you do **not** need a list of assets up front. The
inventory is the *output*, not the input. The tool discovers the assets, scores
how confident it is that each one is really yours, flags exposures, and a small
language model writes the report.

`[advance]`

---

## Slide 4 — Passive discovery  (~1:35–2:25)

So how does it discover things? Entirely through **passive** sources — meaning it
queries third parties and public records, instead of hammering your target
directly.

Certificate Transparency logs are the big one: every public TLS certificate is
logged, and those certs list hostnames, so they reveal subdomains you'd never
find otherwise. DNS resolves those to IPs and catches dangling records. RDAP
tells us who owns an IP block. TLS and HTTP inspection are just normal,
browser-like requests that surface cert problems and missing security headers.

Shodan and Censys are optional, for port data — off by default. The whole thing
is safe by design: no intrusive scanning, just public data and ordinary traffic.

`[advance]`

---

## Slide 5 — The engine  (~2:25–3:00)

Under the hood, discovery is **recursive**. A certificate reveals a subdomain; we
resolve it to an IP; that IP reveals a netblock; a cert's alternate names reveal
even more hostnames — which we feed right back to the start.

It keeps expanding until nothing new turns up. And critically, it's bounded — by
depth, by a max asset count, by timeouts — so a scan always finishes quickly and
stays cheap.

`[advance]`

---

## Slide 6 — Attribution  (~3:00–3:50)

Now the genuinely hard problem. Finding *more* assets is easy. Knowing which ones
**actually belong to you** is the hard part — because these pivots can drag in a
neighbor on shared hosting, or an unrelated domain.

So every asset gets a confidence score between zero and one. A domain you handed
me scores one-point-zero. A hostname from a Certificate Transparency log scores
high. A shared netblock scores lower, because that's weaker evidence. And here's
where multiple seed domains help: if several of your domains independently point
to the same asset, confidence goes up.

Anything below the threshold isn't asserted as yours — it's flagged for a human
to verify. The tool is honest about what it's unsure of.

`[advance]`

---

## Slide 7 — Architecture  (~3:50–4:30)

The architecture splits cleanly into two layers.

The deterministic pipeline — plain Python — does all the hard, objective work:
discovery, deduplication, attribution scoring, and the rule-based findings. That
part spends zero tokens.

The language model, running as a Strands agent on AgentCore Runtime, only sees a
compact summary. Its job is narrow: prioritize the findings, reason about the
low-confidence assets, and write the report. As you can see, the entrypoint is
just a handful of lines — the SDK handles the hosting.

`[advance]`

---

## Slide 8 — Cheap by design  (~4:30–5:05)

Because it's meant to be cheap, I pulled every cost lever toward zero.

Discovery is free. The model is small, and it only sees a summary, so tokens cost
cents. The runtime bills per request, not while idle. And the single biggest
decision: I keep the runtime out of a VPC, which avoids a NAT gateway that would
otherwise quietly bill about thirty-three dollars a month doing nothing. No
browser, no code interpreter, no memory — none of the expensive pieces.

`[advance]`

---

## Slide 9 — Model choice  (~5:05–5:40)

A quick word on the model, because people always ask. I default to a *small*
model — Claude 3.5 Haiku — on purpose.

The reason is that the model does very little. The pipeline produces all the
security facts; the model just triages and writes. That's an easy job, so the
cheapest capable model wins — about a cent per report. It's configurable, so you
can go even cheaper with Nova Lite, or step up to Sonnet for a richer write-up.

And there's a guardrail: the model is not allowed to invent findings. The worst
case is a less polished report — never a fake "all clear."

`[advance]`

---

## Slide 10 — Cost  (~5:40–6:05)

Putting real numbers on it: a single scan is about one and a half cents. A daily
scan of one organization is roughly forty-five cents a month. Even ten domains
scanned daily is a few dollars.

And if you run the scheduled scan on GitHub Actions instead of AgentCore, the
deterministic path uses no model at all — so that's effectively free.

`[advance]`

---

## Slide 11 — Findings  (~6:05–6:25)

What does it actually catch? Expired certificates and dangling DNS records that
enable subdomain takeover — those are the high-severity ones. Exposed databases
and remote-access ports. And lower-severity hygiene issues like missing security
headers. Everything's severity-ranked, and it all lands in a clean HTML or
Markdown report with a diff showing what changed since the last scan.

`[advance]`

---

## Slide 12 — Operating it  (~6:25–6:45)

Operating it is flexible. Run it locally for free while you iterate. Deploy to
AgentCore with basically one command. Or schedule it to run daily and alert you
only when something *new* shows up. There's also CI on GitHub Actions — tests on
every push, and a scheduled scan that uploads the report automatically.

`[advance]`

---

## Slide 13 — Results  (~6:45–7:00)

To prove it works: thirty-three passing unit tests, five free discovery sources,
about a cent per scan, and zero idle cost. I ran it live against a real domain and
it correctly discovered subdomains, IPs, and netblocks with proper attribution.
It's all on GitHub with tests, scheduling, and reporting.

`[advance]`

---

## Slide 14 — Close  (~7:00–7:20)

So that's the project: enterprise-grade attack-surface visibility for near-zero
cost. Multi-seed passive discovery, honest attribution scoring, and a serverless
design on Bedrock AgentCore that's engineered around every cost trap.

Thanks for watching — the repo link is in the description. If this was useful,
give it a like and subscribe, and I'm happy to answer questions in the comments.

`[end]`

---

### Timing summary

| Section | Slides | Running time |
|---|---|---|
| Intro + problem | 1–2 | ~1:00 |
| How it works | 3–6 | ~2:50 |
| Architecture + cost | 7–10 | ~1:35 |
| Findings + ops + close | 11–14 | ~1:35 |
| **Total** | | **~7 minutes** |

Trim the problem and operating slides slightly if you want to land under 6:00.
