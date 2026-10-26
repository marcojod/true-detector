# Project True Detector 0.2

Chrome/Edge (Manifest V3) extension that scans every page you open with a live scanning animation, using local rules plus Gemma 4 through the Gemini API.

## Install
1. Get an API key from Google AI Studio.
2. Open `chrome://extensions`, turn on Developer mode, click **Load unpacked**, pick this folder.
3. The settings page opens on first install: paste the key, click **Test connection**.
4. Open any website. The scan starts by itself; press **Scan this page now** in the popup to run it again.

## The scan (five stages, shown live)
| Stage | What is checked |
|---|---|
| Links & downloads | Every link: raw-IP hosts, `user@host` tricks, look-alike (typosquat / punycode) brand domains, link text vs real target, risky program downloads, `data:` pages, shorteners |
| Page structure & forms | Password/card forms posting to other domains or over http, fake brand login pages, hidden iframes, obfuscated scripts, silent clipboard writes (ClickFix), forced fullscreen/pop-ups/auto-downloads, exit traps, then an AI verdict |
| Text & scam language | All visible text blocks are scored locally (phishing, fake virus alerts, delivery/KYC/crypto-drainer/sextortion/ClickFix wording, Hinglish threats); suspicious blocks go to Gemma |
| Images | Every photo-sized image: metadata is read first (IPTC "trainedAlgorithmicMedia", Midjourney / Stable Diffusion / DALL·E markers = certain), then Gemma vision, with a second-opinion pass on borderline results. Each image gets a live scan frame and an AI / real tag |
| Redirects & traffic | Full redirect chain and third-party / tracker / raw-IP / credential-leak traffic |

## How verdicts are decided
- **Hard evidence cannot be overruled.** If the local engine finds something verified (password form sent to another domain, typosquatted login, silent clipboard write, `user@host` link…), the AI cannot downgrade it.
- **Soft evidence is adjudicated by Gemma**, which can clear false alarms.
- API errors are retried with back-off. If the AI is still unreachable the scan says so ("partial scan") instead of pretending the page is clean.

## Honest limits
No detector can promise 100% detection with zero mistakes: new scams appear daily and AI-image detection is probabilistic. This version reports uncertainty instead of hiding it. Images that cannot be fetched, are vector/tiny, or exceed the per-page limit are listed as not checked.

## Privacy
Page text excerpts, image thumbnails, link/form signal summaries and request summaries are sent to Google's Gemini API for analysis. Form field *names* are inspected, never values. Turn off any check in the popup or settings to stop sending that data.
