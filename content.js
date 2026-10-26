// Project True Detector — page script.
// Runs a staged full-page scan (links → structure → text → images → network) with a live
// scanning animation, then leaves chips on flagged images and a verdict pill in the corner.
(() => {
  if (window.top !== window || window.__tdLoaded || !/^https?:$/.test(location.protocol)) return;
  window.__tdLoaded = true;
  const TD = globalThis.TD;
  const send = (m) => chrome.runtime.sendMessage(m).catch(() => null);
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const withTimeout = (p, ms, fallback) => Promise.race([p, sleep(ms).then(() => fallback)]);

  /* ---------- settings ---------- */
  let cfg = { enabled: true, showScan: "load", maxImages: 40, features: { image: true, scam: true, threat: true, routing: true, traffic: true } };
  const on = (f) => cfg.enabled && cfg.features[f] !== false;
  const cfgReady = chrome.storage.local.get(["enabled", "features", "showScan", "maxImages"]).then((s) => {
    cfg = { ...cfg, ...Object.fromEntries(Object.entries(s).filter(([, v]) => v !== undefined)), features: { ...cfg.features, ...(s.features || {}) } };
  }).catch(() => {});
  chrome.storage.onChanged.addListener((c) => {
    if (c.enabled) cfg.enabled = c.enabled.newValue !== false;
    if (c.features) cfg.features = { ...cfg.features, ...c.features.newValue };
    if (c.showScan) cfg.showScan = c.showScan.newValue;
    if (c.maxImages) cfg.maxImages = c.maxImages.newValue;
  });

  /* ---------- overlay (closed shadow DOM keeps page CSS out) ---------- */
  const host = document.createElement("div");
  host.style.cssText = "all:initial;position:absolute;top:0;left:0;width:0;height:0;overflow:visible;z-index:2147483647";
  const root = host.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = `
    :host{all:initial}
    *{box-sizing:border-box;font:13px/1.4 "Segoe UI Variable Text","Segoe UI",system-ui,sans-serif}
    .mono,.note,.pct,.tag,.hd small{font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace}
    .safe{--c:#34D399}.warning{--c:#FBBF24}.danger{--c:#F87171}.unknown{--c:#7C93A6}

    /* ---- full-page scan effect ---- */
    .fx{position:fixed;inset:0;pointer-events:none;overflow:hidden;opacity:1;transition:opacity .7s ease;--a:#22D3EE}
    .fx.off{opacity:0}
    .fx.end.safe{--a:#34D399}.fx.end.warning{--a:#FBBF24}.fx.end.danger{--a:#F87171}
    .tint{position:absolute;inset:0;background:radial-gradient(ellipse at 50% 0,rgba(34,211,238,.10),transparent 60%),rgba(6,16,26,.10);transition:background .5s}
    .fx.end .tint{background:radial-gradient(ellipse at 50% 50%,transparent 40%,color-mix(in srgb,var(--a) 30%,transparent) 100%)}
    .grid{position:absolute;inset:0;background-image:linear-gradient(rgba(34,211,238,.13) 1px,transparent 1px),linear-gradient(90deg,rgba(34,211,238,.13) 1px,transparent 1px);background-size:44px 44px;-webkit-mask-image:linear-gradient(to bottom,transparent,#000 20%,#000 80%,transparent);mask-image:linear-gradient(to bottom,transparent,#000 20%,#000 80%,transparent);animation:drift 6s linear infinite}
    .fx.end .grid{opacity:.4;animation:none}
    .beam{position:absolute;left:0;right:0;top:0;height:170px;transform:translateY(-170px);background:linear-gradient(to bottom,transparent,rgba(34,211,238,.10) 60%,rgba(34,211,238,.28));animation:sweep 2.8s cubic-bezier(.5,0,.5,1) infinite}
    .beam::after{content:"";position:absolute;left:0;right:0;bottom:0;height:2px;background:#67E8F9;box-shadow:0 0 12px 3px rgba(34,211,238,.9),0 0 40px 8px rgba(34,211,238,.45)}
    .fx.end .beam{animation:none;opacity:0}
    .c{position:absolute;width:34px;height:34px;border:0 solid var(--a);opacity:.9}
    .c.tl{top:12px;left:12px;border-top-width:3px;border-left-width:3px}.c.tr{top:12px;right:12px;border-top-width:3px;border-right-width:3px}
    .c.bl{bottom:12px;left:12px;border-bottom-width:3px;border-left-width:3px}.c.br{bottom:12px;right:12px;border-bottom-width:3px;border-right-width:3px}
    @keyframes sweep{0%{transform:translateY(-170px)}100%{transform:translateY(100vh)}}
    @keyframes drift{to{background-position:0 44px,44px 0}}
    @keyframes spin{to{transform:rotate(360deg)}}
    @keyframes pop{from{opacity:0;transform:translate(-50%,-14px) scale(.97)}to{opacity:1;transform:translate(-50%,0) scale(1)}}
    @keyframes shimmer{from{background-position:0 0}to{background-position:60px 0}}
    @keyframes fscan{from{top:0}to{top:calc(100% - 2px)}}
    @keyframes blink{50%{opacity:.35}}

    /* ---- HUD ---- */
    .hud{position:fixed;top:16px;left:50%;transform:translateX(-50%);width:352px;max-width:calc(100vw - 24px);color:#E6F1F7;background:rgba(9,17,27,.94);-webkit-backdrop-filter:blur(12px);backdrop-filter:blur(12px);border:1px solid color-mix(in srgb,var(--a,#22D3EE) 55%,transparent);border-radius:10px;box-shadow:0 12px 40px rgba(0,0,0,.45),0 0 0 1px rgba(255,255,255,.04) inset,0 0 30px color-mix(in srgb,var(--a,#22D3EE) 18%,transparent);padding:14px 14px 12px;animation:pop .35s ease both;--a:#22D3EE;pointer-events:auto}
    .hud.safe{--a:#34D399}.hud.warning{--a:#FBBF24}.hud.danger{--a:#F87171}.hud.unknown{--a:#7C93A6}
    .hud[hidden],.pill[hidden]{display:none}
    .hd{display:flex;align-items:center;gap:11px}
    .radar{flex:none;width:30px;height:30px;border-radius:50%;border:1.5px solid var(--a);position:relative;overflow:hidden;background:radial-gradient(circle,var(--a) 0 2px,transparent 3px)}
    .radar::before{content:"";position:absolute;inset:0;background:conic-gradient(from 0deg,transparent 0 68%,color-mix(in srgb,var(--a) 85%,transparent));animation:spin 1.1s linear infinite}
    .hud.done .radar::before{animation:none;background:none}
    .hud.done .hd small{white-space:normal}
    .ttl{flex:1;min-width:0}.ttl b{display:block;font-size:14px;letter-spacing:.2px}
    .hd small{display:block;color:#7C93A6;font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .x{border:0;background:none;color:#7C93A6;font-size:18px;line-height:1;cursor:pointer;padding:2px 4px}.x:hover{color:#E6F1F7}
    .bar{height:4px;margin:12px 0 4px;background:rgba(255,255,255,.09);border-radius:2px;overflow:hidden}
    .bar i{display:block;height:100%;width:0;border-radius:2px;background:linear-gradient(90deg,var(--a),#818CF8);transition:width .4s ease}
    .hud:not(.done) .bar i{background-image:repeating-linear-gradient(115deg,rgba(255,255,255,.28) 0 8px,transparent 8px 16px),linear-gradient(90deg,var(--a),#818CF8);background-size:60px 100%,100% 100%;animation:shimmer .8s linear infinite}
    .pct{display:block;text-align:right;color:#7C93A6;font-size:10.5px;margin-bottom:6px}
    .st{display:grid;grid-template-columns:20px 1fr auto;align-items:center;gap:8px;padding:5px 0;border-top:1px solid rgba(255,255,255,.06);color:#7C93A6;transition:color .25s}
    .st.active,.st.ok,.st.warn,.st.bad{color:#E6F1F7}
    .ind{width:16px;height:16px;border-radius:50%;display:grid;place-items:center;font-size:11px;font-weight:700;line-height:1;border:1.5px solid #3B4F61;color:#0A121C}
    .st.active .ind{border-color:rgba(34,211,238,.25);border-top-color:#22D3EE;animation:spin .7s linear infinite}
    .st.ok .ind{background:#34D399;border-color:#34D399}.st.warn .ind{background:#FBBF24;border-color:#FBBF24}.st.bad .ind{background:#F87171;border-color:#F87171}.st.skip .ind{border-style:dashed}
    .st.active .note{color:#67E8F9;animation:blink 1s ease-in-out infinite}.note{font-size:11px;color:#7C93A6}.st.warn .note{color:#FBBF24}.st.bad .note{color:#F87171}.st.ok .note{color:#34D399}
    .res{display:none;margin-top:10px;border-top:1px solid rgba(255,255,255,.1);padding-top:10px}
    .hud.done .res{display:block}
    .res ul{list-style:none;margin:0 0 8px;padding:0;display:flex;flex-direction:column;gap:6px}
    .res li{border-left:3px solid var(--c);padding:2px 0 2px 8px;background:rgba(255,255,255,.04);border-radius:0 4px 4px 0}
    .res li b{display:block;font-size:12.5px}.res li span{color:#9FB3C4;font-size:12px}
    .res p{margin:0 0 8px;color:#9FB3C4;font-size:12px}
    .btns{display:flex;gap:8px}
    .btns button{flex:1;padding:7px 10px;border-radius:6px;border:1px solid var(--a);background:transparent;color:var(--a);font-weight:600;cursor:pointer}
    .btns button:first-child{background:var(--a);color:#06121C}
    button:focus-visible{outline:2px solid #fff;outline-offset:2px}

    /* ---- pill, toasts, chips, image frames ---- */
    .pill{position:fixed;right:16px;bottom:16px;width:42px;height:42px;border-radius:50%;border:1.5px solid var(--a);background:#0A121C;display:grid;place-items:center;cursor:pointer;box-shadow:0 6px 20px rgba(0,0,0,.4),0 0 16px color-mix(in srgb,var(--a) 35%,transparent);--a:#34D399;pointer-events:auto;padding:0}
    .pill.warning{--a:#FBBF24}.pill.danger{--a:#F87171}.pill.unknown{--a:#7C93A6}.pill svg{width:22px;height:22px}
    .toasts{position:fixed;top:16px;right:16px;width:320px;display:flex;flex-direction:column;gap:10px;pointer-events:none}
    .toast{pointer-events:auto;background:#fff;color:#14202B;border:1px solid #D5DDE6;border-left:6px solid var(--c);border-radius:6px;padding:12px 14px;box-shadow:0 6px 24px rgba(20,32,43,.18)}
    .toast b{display:block;font-size:14px;margin-bottom:4px}.toast p{margin:4px 0 0}.toast ul{margin:4px 0 0;padding-left:18px}
    .toast small{color:#5B6B7B}.toast .x{float:right;color:#5B6B7B}
    .toast.safe{--c:#1F9D6B}.toast.warning{--c:#D98A00}.toast.danger{--c:#D64545}.toast.unknown{--c:#5B6B7B}
    .layer{position:absolute;top:0;left:0}
    .chip{position:absolute;border:0;border-radius:4px;padding:3px 8px;color:#fff;background:var(--c);cursor:pointer;font-weight:600;box-shadow:0 2px 8px rgba(0,0,0,.35)}
    .chip.warning{color:#1b1200}
    .pop{position:absolute;width:260px;background:#fff;color:#14202B;border:1px solid #D5DDE6;border-left:6px solid var(--c);border-radius:6px;padding:10px 12px;box-shadow:0 6px 24px rgba(20,32,43,.25)}
    .pop ul{margin:4px 0 0;padding-left:18px}.pop b{display:block}
    .frame{position:absolute;pointer-events:none;overflow:hidden;--c:#22D3EE;border:2px solid var(--c);background:rgba(34,211,238,.07);box-shadow:0 0 18px color-mix(in srgb,var(--c) 55%,transparent),inset 0 0 18px color-mix(in srgb,var(--c) 25%,transparent);transition:opacity .5s,border-color .2s}
    .frame .fl{position:absolute;left:0;right:0;height:2px;background:#67E8F9;box-shadow:0 0 10px 2px rgba(34,211,238,.9);animation:fscan 1s ease-in-out infinite alternate}
    .frame.res .fl{display:none}.frame.res{background:color-mix(in srgb,var(--c) 14%,transparent)}.frame.fade{opacity:0}
    .frame .tag{position:absolute;top:0;left:0;background:var(--c);color:#06121C;font-size:11px;font-weight:700;padding:2px 7px;letter-spacing:.4px}
    @media (prefers-reduced-motion:reduce){.beam,.grid,.radar::before,.st.active .ind,.frame .fl,.bar i,.st.active .note{animation:none!important}.hud{animation:none}.beam{opacity:0}}`;

  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
  const SVGNS = "http://www.w3.org/2000/svg";
  const shield = () => {
    const s = document.createElementNS(SVGNS, "svg"); s.setAttribute("viewBox", "0 0 24 24");
    const p = document.createElementNS(SVGNS, "path"); p.setAttribute("d", "M12 2 4 5v6c0 5 3.4 9.3 8 11 4.6-1.7 8-6 8-11V5z"); p.setAttribute("fill", "none"); p.setAttribute("stroke", "currentColor"); p.setAttribute("stroke-width", "2"); p.setAttribute("stroke-linejoin", "round");
    const c = document.createElementNS(SVGNS, "path"); c.setAttribute("d", "m8.5 12.2 2.4 2.4 4.7-5"); c.setAttribute("fill", "none"); c.setAttribute("stroke", "currentColor"); c.setAttribute("stroke-width", "2"); c.setAttribute("stroke-linecap", "round"); c.setAttribute("stroke-linejoin", "round");
    s.append(p, c); return s;
  };

  const toasts = el("div", "toasts"), layer = el("div", "layer");
  const fx = el("div", "fx off"); fx.append(el("div", "tint"), el("div", "grid"), el("div", "beam"), el("i", "c tl"), el("i", "c tr"), el("i", "c bl"), el("i", "c br"));
  fx.hidden = true;
  root.append(style, fx, toasts, layer);
  document.documentElement.appendChild(host);

  const fill = (box, f) => {
    box.append(el("b", "", f.title || "Result"));
    if (f.reasons?.length) { const ul = el("ul"); f.reasons.slice(0, 3).forEach((r) => ul.append(el("li", "", r))); box.append(ul); }
    if (f.advice) box.append(el("p", "", f.advice));
  };
  const LABEL = { image: "Image check", scam: "Scam check", threat: "Page threat", routing: "Redirect route", traffic: "Traffic watch", error: "True Detector" };
  function toast(f) {
    while (toasts.children.length >= 3) toasts.firstChild.remove();
    const t = el("div", `toast ${f.level}`);
    const x = el("button", "x", "×"); x.onclick = () => t.remove();
    t.append(x, el("small", "", LABEL[f.feature] || "True Detector"));
    fill(t, f);
    toasts.append(t);
    if (f.level !== "danger") setTimeout(() => t.remove(), f.level === "warning" ? 14000 : 8000);
  }

  /* ---------- scan HUD ---------- */
  const STAGES = [["links", "Links & downloads", 10], ["structure", "Page structure & forms", 20], ["text", "Text & scam language", 20], ["images", "Images · AI & edits", 35], ["network", "Redirects & traffic", 15]];
  const hud = (() => {
    let box, bar, pct, title, sub, resBox, rows = {}, state = {}, frac = {}, pill, lastLevel = "safe", last = null;
    const GLYPH = { ok: "✓", warn: "!", bad: "✕", skip: "–", active: "", pending: "" };
    function build() {
      box = el("div", "hud"); box.setAttribute("role", "status"); box.setAttribute("aria-live", "polite");
      const hd = el("div", "hd"), tt = el("div", "ttl");
      title = el("b", "", "Scanning this page…"); sub = el("small", "", location.hostname);
      tt.append(title, sub);
      const x = el("button", "x", "×"); x.setAttribute("aria-label", "Close"); x.onclick = () => { box.hidden = true; };
      hd.append(el("div", "radar"), tt, x);
      bar = el("i"); const b = el("div", "bar"); b.append(bar); pct = el("span", "pct", "0%");
      box.append(hd, b, pct);
      for (const [id, label] of STAGES) {
        const row = el("div", "st pending"), ind = el("span", "ind"), note = el("span", "note", "queued");
        row.append(ind, el("span", "", label), note); box.append(row); rows[id] = { row, ind, note };
      }
      resBox = el("div", "res"); box.append(resBox);
      root.append(box);
      if (!pill) { pill = el("button", "pill"); pill.hidden = true; pill.setAttribute("aria-label", "Show True Detector scan result"); pill.append(shield()); pill.onclick = () => { if (box) box.hidden = !box.hidden; }; root.append(pill); }
    }
    const total = () => STAGES.reduce((n, [id, , w]) => n + (state[id] && state[id] !== "active" && state[id] !== "pending" ? w : (state[id] === "active" ? w * (frac[id] || 0) : 0)), 0);
    const paint = () => { const p = Math.min(100, Math.round(total())); bar.style.width = p + "%"; pct.textContent = p + "%"; };
    return {
      open() {
        if (box) { box.remove(); box = null; rows = {}; }
        state = {}; frac = {}; build(); box.className = "hud"; pill.hidden = true;
        fx.hidden = false; fx.className = "fx"; paint();
      },
      stage(id, st, note) {
        if (!box || !rows[id]) return; state[id] = st; const r = rows[id];
        r.row.className = "st " + st; r.ind.textContent = GLYPH[st] || ""; if (note != null) r.note.textContent = note; paint();
      },
      note(id, note, f) { if (!box || !rows[id]) return; rows[id].note.textContent = note; if (f != null) frac[id] = f; paint(); },
      finish(level, headline, detail, items, onRescan) {
        lastLevel = level;
        if (!box) return;
        box.className = `hud done ${level}`; title.textContent = headline; sub.textContent = detail; bar.style.width = "100%"; pct.textContent = "100%";
        resBox.replaceChildren();
        if (items.length) {
          const ul = el("ul");
          for (const f of items.slice(0, 4)) { const li = el("li"); li.className = f.level; li.append(el("b", "", f.title), el("span", "", (LABEL[f.feature] || "") + (f.reasons && f.reasons[0] ? " — " + f.reasons[0] : ""))); ul.append(li); }
          resBox.append(ul);
        } else resBox.append(el("p", "", "Nothing suspicious was found in the links, text, images or network activity of this page."));
        const btns = el("div", "btns"), a = el("button", "", "Scan again"), c = el("button", "", "Close");
        a.onclick = onRescan; c.onclick = () => { box.hidden = true; };
        btns.append(a, c); resBox.append(btns);
        fx.className = `fx end ${level}`;
        setTimeout(() => fx.classList.add("off"), 1300);
        setTimeout(() => { fx.hidden = true; }, 2100);
        pill.className = "pill " + level; pill.hidden = false;
        if (level === "safe") setTimeout(() => { if (box && box.classList.contains("done") && box.classList.contains("safe")) box.hidden = true; }, 9000);
      },
      closeSilent() { fx.hidden = true; if (box) box.hidden = true; },
      setPill(level) { if (!pill) { build(); box.hidden = true; } pill.className = "pill " + level; pill.hidden = false; }
    };
  })();

  /* ---------- image chips + live scan frames ---------- */
  const chips = new Map(), frames = new Map();
  let placing = false;
  function place() {
    placing = false;
    for (const [img, { c, p }] of chips) {
      if (!img.isConnected) { c.remove(); p.remove(); chips.delete(img); continue; }
      const r = img.getBoundingClientRect(), vis = r.width > 0 && r.height > 0;
      c.style.display = vis ? "" : "none";
      c.style.left = r.left + scrollX + 6 + "px"; c.style.top = r.top + scrollY + 6 + "px";
      p.style.left = r.left + scrollX + 6 + "px"; p.style.top = r.top + scrollY + 36 + "px";
    }
    for (const [img, f] of frames) {
      if (!img.isConnected) { f.remove(); frames.delete(img); continue; }
      const r = img.getBoundingClientRect();
      Object.assign(f.style, { left: r.left + scrollX + "px", top: r.top + scrollY + "px", width: r.width + "px", height: r.height + "px", display: r.width > 0 ? "" : "none" });
    }
    if (frames.size) schedule();
  }
  const schedule = () => { if (!placing) { placing = true; requestAnimationFrame(place); } };
  addEventListener("scroll", schedule, { passive: true }); addEventListener("resize", schedule);
  setInterval(() => chips.size && schedule(), 1500);
  function addChip(img, r) {
    if (chips.has(img)) return;
    const c = el("button", `chip ${r.level}`, `${r.title}${r.score ? ` · ${r.score}%` : ""}`);
    const p = el("div", `pop ${r.level}`); p.hidden = true; fill(p, r);
    c.onclick = () => { p.hidden = !p.hidden; };
    layer.append(c, p); chips.set(img, { c, p }); schedule();
  }
  function frameOn(img) {
    const f = el("div", "frame"); f.append(el("div", "fl"), el("span", "tag", "ANALYZING"));
    layer.append(f); frames.set(img, f); schedule();
    return (r) => {
      const lvl = r && r.level; const flagged = lvl === "warning" || lvl === "danger";
      const color = lvl === "danger" ? "#F87171" : lvl === "warning" ? "#FBBF24" : lvl === "safe" ? "#34D399" : "#7C93A6";
      f.style.setProperty("--c", color); f.classList.add("res");
      f.querySelector(".tag").textContent = !r || r.error ? "NOT CHECKED" : r.skipped ? "SKIPPED" : flagged ? `${r.verdict === "likely_manipulated" ? "EDITED" : "AI"} · ${r.score}%` : lvl === "safe" ? `REAL · ${r.score}%` : "UNSURE";
      setTimeout(() => f.classList.add("fade"), flagged ? 2200 : 1100);
      setTimeout(() => { f.remove(); frames.delete(img); }, flagged ? 2800 : 1700);
    };
  }

  /* ---------- hooks from page-hook.js (MAIN world) ---------- */
  const hooks = new Set(); let notifCount = 0;
  addEventListener("message", (e) => {
    const d = e.data;
    if (e.source !== window || !d || typeof d !== "object") return;
    if (d.__td === "hook" && typeof d.k === "string") hooks.add(d.k);
    if (d.__td === "notif" && on("scam") && notifCount++ < 10) send({ type: "scan-text", text: `${d.title}. ${d.body}`, source: "notification" });
  });

  /* ---------- images ---------- */
  const dataUrl = async (src) => {
    const b = await (await fetch(src)).blob();
    if (b.size > 4e6) return null;
    return new Promise((res) => { const fr = new FileReader(); fr.onload = () => res(fr.result); fr.readAsDataURL(b); });
  };
  async function checkImage(img, src) {
    const msg = { type: "scan-image", src, alt: img.alt || "" };
    if (!/^https?:/.test(src)) { try { msg.dataUrl = await dataUrl(src); if (!msg.dataUrl) return { skipped: "large" }; } catch (e) { return { error: "unreadable" }; } }
    let r = await send(msg);
    if (r && r.error && r.fetchFailed && /^https?:/.test(src)) { // worker could not fetch it: retry with the page's own copy
      try { const d = await dataUrl(src); if (d) r = await send({ ...msg, dataUrl: d }); } catch (e) {}
    }
    return r || { error: "no response" };
  }
  const flaggedLevel = (r) => r && (r.level === "warning" || r.level === "danger");
  const seen = new WeakSet();
  let firstDone = false;
  async function scanImageSilently(img) {
    if (!on("image") || !img.isConnected || scanning) return;
    const src = img.currentSrc || img.src;
    if (!src || img.naturalWidth < 128 || img.naturalHeight < 128) return;
    const r0 = img.getBoundingClientRect();
    if (r0.width < 100 || r0.height < 100 || /\.svg(\?|$)/i.test(src)) return;
    const r = await checkImage(img, src);
    if (flaggedLevel(r)) { addChip(img, r); hud.setPill(r.level === "danger" ? "danger" : "warning"); }
  }
  const io = new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting) { io.unobserve(e.target); scanImageSilently(e.target); } }), { rootMargin: "200px", threshold: 0.25 });
  function consider(img) {
    if (!firstDone || seen.has(img)) return;
    if (!img.complete) { img.addEventListener("load", () => consider(img), { once: true }); return; }
    seen.add(img); io.observe(img);
  }

  /* ---------- page signals ---------- */
  const SKIP = new Set(["SCRIPT", "STYLE", "NOSCRIPT", "TEXTAREA", "INPUT", "CODE", "PRE", "SVG", "SELECT", "OPTION"]);
  const visible = (e) => { try { return e.checkVisibility ? e.checkVisibility({ checkVisibilityCSS: true }) : !!e.offsetParent; } catch (x) { return true; } };
  const regOf = (u) => { try { return TD.reg(new URL(u, location.href).hostname); } catch (e) { return ""; } };
  const hostOf = (u) => { try { return new URL(u, location.href).hostname; } catch (e) { return ""; } };
  function collectSignals(linkInfo) {
    const h = location.hostname, pageReg = TD.reg(h), forms = [...document.forms];
    const cross = (f) => { const a = f.getAttribute("action"); if (!a) return false; try { const u = new URL(a, location.href); return /^https?:$/.test(u.protocol) && TD.reg(u.hostname) !== pageReg; } catch (e) { return false; } };
    const pw = [...document.querySelectorAll("input[type=password]")].filter(visible);
    const card = [...document.querySelectorAll('input[autocomplete^="cc-"],input[name*="card" i],input[id*="card" i],input[name*="cvv" i],input[name*="cvc" i],input[placeholder*="card number" i]')].filter((i) => i.type !== "hidden" && visible(i));
    const hidden = [...document.querySelectorAll("iframe")].filter((i) => {
      const r = i.getBoundingClientRect(), cs = getComputedStyle(i);
      return r.width < 3 || r.height < 3 || cs.display === "none" || cs.visibility === "hidden";
    });
    const inline = [...document.scripts].filter((s) => !s.src).map((s) => s.textContent).join(" ").slice(0, 200000);
    const bodyText = (document.body?.innerText || "").replace(/\s+/g, " ");
    const heads = [document.title, ...[...document.querySelectorAll("h1")].slice(0, 3).map((x) => x.textContent), document.querySelector('meta[property="og:site_name"]')?.content || ""].join(" ");
    const tb = (pw.length || card.length) && bodyText.length < 5000 ? TD.brandsIn(heads).filter((b) => !TD.isOfficial(b, pageReg)) : [];
    let rightClickBlocked = false;
    try { const ev = new MouseEvent("contextmenu", { bubbles: true, cancelable: true }); (document.body || document.documentElement).dispatchEvent(ev); rightClickBlocked = ev.defaultPrevented; } catch (e) {}
    const meta = document.querySelector('meta[http-equiv="refresh" i]')?.content || "";
    const mu = /url\s*=\s*['"]?([^'";]+)/i.exec(meta);
    return {
      url: location.href.slice(0, 300), host: h, https: location.protocol === "https:", title: document.title.slice(0, 120),
      passwordFields: pw.length, cardFields: card.length,
      crossOriginForms: forms.filter(cross).length,
      passwordFormCrossOrigin: forms.some((f) => f.querySelector("input[type=password]") && cross(f)),
      cardFormCrossOrigin: forms.some((f) => f.querySelector('input[autocomplete^="cc-"],input[name*="card" i]') && cross(f)),
      insecureFormAction: forms.some((f) => /^http:/i.test(f.getAttribute("action") || "") && (location.protocol === "https:" || f.querySelector("input[type=password]"))),
      titleBrandMismatch: tb,
      hiddenIframes: hidden.length, hiddenCrossOriginIframes: hidden.filter((i) => hostOf(i.src) && regOf(i.src) !== pageReg).length,
      obfuscatedScriptHits: (inline.match(/eval\(|atob\(|unescape\(|fromCharCode|\\x[0-9a-f]{2}/gi) || []).length,
      mismatchedLinks: linkInfo.counts.mismatch,
      externalScripts: [...document.scripts].filter((s) => s.src && regOf(s.src) !== pageReg).length,
      metaRefreshExternal: !!(mu && regOf(mu[1]) && regOf(mu[1]) !== pageReg),
      rightClickBlocked, hooks: [...hooks],
      links: { score: linkInfo.score, reasons: linkInfo.reasons, hard: linkInfo.hard, total: linkInfo.total, counts: linkInfo.counts },
      textExcerpt: bodyText.slice(0, 3000)
    };
  }

  /* ---------- text blocks ---------- */
  const blockCache = new WeakMap();
  const blockOf = (e) => {
    for (let x = e; x && x !== document.body; x = x.parentElement) {
      if (blockCache.has(x)) return blockCache.get(x);
      const d = getComputedStyle(x).display;
      if (!d.startsWith("inline") && d !== "contents") { blockCache.set(x, x); return x; }
    }
    return document.body;
  };
  function textBlocks() {
    const map = new Map();
    if (!document.body) return map;
    const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    let n, steps = 0;
    while ((n = w.nextNode()) && steps++ < 25000) {
      const t = n.nodeValue.trim();
      if (t.length < 3) continue;
      const p = n.parentElement;
      if (!p || SKIP.has(p.tagName.toUpperCase()) || p.isContentEditable || !visible(p)) continue;
      const b = blockOf(p), cur = map.get(b) || "";
      if (cur.length < 1500) map.set(b, (cur + " " + t).trim());
    }
    return map;
  }

  /* ---------- the staged scan ---------- */
  let scanning = false, lastScan = 0;
  const worstOf = (list) => list.reduce((m, f) => Math.max(m, TD.RANK[f.level] || 0), 0);
  const st = (level) => (level === "danger" ? "bad" : level === "warning" ? "warn" : level === "safe" ? "ok" : "skip");

  async function runScan(o = {}) {
    if (scanning) return;
    scanning = true;
    try { await scanPage(o); } finally { scanning = false; }
  }
  async function scanPage({ manual = false, silent = false } = {}) {
    await cfgReady;
    if (!cfg.enabled) return;
    lastScan = Date.now();
    const showHud = !silent && cfg.showScan !== "never" && (manual || cfg.showScan !== "manual");
    const rep = await send({ type: "reset-scan", url: location.href });
    if (rep && rep.config) { cfg.maxImages = rep.config.maxImages; }
    const found = [], problems = [], counts = { links: 0, blocks: 0, ai: 0, images: 0, flagged: 0 };
    if (showHud) hud.open();
    const stage = async (id, enabled, fn, min = 750) => {
      if (!enabled) { if (showHud) hud.stage(id, "skip", "off"); return; }
      if (showHud) hud.stage(id, "active", "scanning");
      const t0 = Date.now();
      try {
        const out = await fn();
        const rest = showHud ? min - (Date.now() - t0) : 0; if (rest > 0) await sleep(rest);
        if (showHud) hud.stage(id, out.state, out.note);
      } catch (e) { problems.push(`${id} stage failed`); if (showHud) hud.stage(id, "skip", "error"); }
    };
    const note = (r) => { if (r && r.ai === false) problems.push("AI unavailable"); };
    let linkInfo = TD.localLinks([], TD.reg(location.hostname));

    await stage("links", on("threat"), async () => {
      const links = [...document.links].slice(0, 1500).map((a) => ({ href: a.href, text: (a.textContent || "").trim().slice(0, 200) }));
      linkInfo = TD.localLinks(links, TD.reg(location.hostname)); counts.links = links.length;
      const n = linkInfo.level === "safe" ? 0 : linkInfo.reasons.length;
      return { state: st(linkInfo.level), note: n ? `${n} issue${n > 1 ? "s" : ""} · ${links.length} links` : `${links.length} links clean` };
    });

    await stage("structure", on("threat"), async () => {
      const r = await send({ type: "page-signals", signals: collectSignals(linkInfo), force: manual });
      if (!r || r.error) { problems.push("page analysis failed"); return { state: "skip", note: "failed" }; }
      if (r.skipped) return { state: "skip", note: "off" };
      note(r); if (flaggedLevel(r)) found.push(r);
      return { state: st(r.level), note: flaggedLevel(r) ? "suspicious" : r.title && /official/i.test(r.title) ? "official site" : "clean" };
    });

    await stage("text", on("scam"), async () => {
      const blocks = textBlocks(); counts.blocks = blocks.size;
      const cands = [];
      for (const [b, t] of blocks) { if (t.length < 25) continue; const l = TD.localScam(t); if (l.score >= 30 || l.hits.length >= 2) cands.push({ b, t, s: l.score }); }
      cands.sort((a, b) => b.s - a.s);
      const top = cands.slice(0, 12); let flagged = 0, i = 0;
      for (const c of top) {
        if (showHud) hud.note("text", `${++i}/${top.length} checking`, i / top.length);
        const r = await withTimeout(send({ type: "scan-text", text: c.t, source: "page" }), 40000, null);
        counts.ai++; note(r);
        if (flaggedLevel(r)) {
          flagged++; found.push(r);
          c.b.style.outline = `2px solid ${r.level === "danger" ? "#D64545" : "#D98A00"}`; c.b.style.outlineOffset = "2px"; c.b.title = "True Detector: " + r.title;
        }
      }
      return { state: flagged ? (found.some((f) => f.feature === "scam" && f.level === "danger") ? "bad" : "warn") : "ok", note: flagged ? `${flagged} flagged` : `${blocks.size} blocks clean` };
    });

    await stage("images", on("image"), async () => {
      const list = [], srcs = new Set();
      for (const img of document.images) {
        if (!img.complete || img.naturalWidth < 128 || img.naturalHeight < 128) continue;
        const r = img.getBoundingClientRect(); if (r.width < 100 || r.height < 100) continue;
        const src = img.currentSrc || img.src;
        if (!src || srcs.has(src) || /\.svg(\?|$)/i.test(src)) continue;
        srcs.add(src);
        list.push({ img, src, inView: r.bottom > 0 && r.top < innerHeight && r.right > 0 && r.left < innerWidth, area: r.width * r.height });
      }
      list.sort((a, b) => (b.inView - a.inView) || (b.area - a.area));
      const todo = list.slice(0, Math.max(0, cfg.maxImages)), over = list.length - todo.length;
      if (!todo.length) return { state: "ok", note: "no photos" };
      let i = 0, done = 0, real = 0, flag = 0, skip = 0, bad = 0, danger = false;
      const deadline = Date.now() + 150000;
      const worker = async () => {
        while (i < todo.length && Date.now() < deadline) {
          const it = todo[i++]; seen.add(it.img);
          const finish = showHud && it.inView ? frameOn(it.img) : null;
          const r = await withTimeout(checkImage(it.img, it.src), 70000, { error: "timeout" });
          finish && finish(r); note(r); done++;
          if (flaggedLevel(r)) { flag++; if (r.level === "danger") danger = true; addChip(it.img, r); found.push({ ...r, feature: "image" }); }
          else if (r.level === "safe") real++; else if (r.skipped) skip++; else bad++;
          if (showHud) hud.note("images", `${done}/${todo.length} · ${flag} flagged`, done / todo.length);
        }
      };
      await Promise.all([worker(), worker()]);
      counts.images = done; counts.flagged = flag;
      const left = todo.length - done + over;
      if (bad) problems.push(`${bad} image${bad > 1 ? "s" : ""} could not be analyzed`);
      if (left > 0) problems.push(`${left} image${left > 1 ? "s" : ""} not checked (limit ${cfg.maxImages})`);
      return { state: danger ? "bad" : flag ? "warn" : bad ? "skip" : "ok", note: flag ? `${flag} of ${done} flagged` : `${real} real${skip ? ` · ${skip} skipped` : ""}` };
    }, 400);

    await stage("network", on("routing") || on("traffic"), async () => {
      await sleep(600);
      const r = await withTimeout(send({ type: "scan-network" }), 60000, null);
      if (!r || r.error) { problems.push("network analysis failed"); return { state: "skip", note: "failed" }; }
      const parts = [r.routing, r.traffic].filter(Boolean);
      parts.forEach(note); parts.filter(flaggedLevel).forEach((f) => found.push(f));
      const worst = worstOf(parts);
      return { state: worst >= 3 ? "bad" : worst === 2 ? "warn" : "ok", note: worst >= 2 ? "suspicious" : r.routing && r.routing.title === "No redirects" ? "direct · normal" : "normal" };
    });

    // verdict
    found.sort((a, b) => (TD.RANK[b.level] - TD.RANK[a.level]) || (b.score - a.score));
    const worst = worstOf(found), level = worst >= 3 ? "danger" : worst === 2 ? "warning" : "safe";
    const limited = [...new Set(problems)];
    const headline = level === "danger" ? "Threat detected" : level === "warning" ? "Suspicious — be careful" : limited.length ? "No threats found (partial scan)" : "No threats detected";
    const detail = limited.length ? limited.slice(0, 2).join(" · ") : `${counts.links} links · ${counts.blocks} texts · ${counts.images} images`;
    if (showHud) hud.finish(level, headline, detail, found, () => runScan({ manual: true }));
    else if (level !== "safe") { hud.setPill(level); const top = found[0]; if (top) toast(top); }
    else hud.setPill(limited.length ? "unknown" : "safe");
  }

  chrome.runtime.onMessage.addListener((m) => {
    if (m.type === "finding" && !scanning) toast(m.finding);
    if (m.type === "collect") runScan({ manual: true });
  });

  /* ---------- boot + live updates ---------- */
  const start = () => {
    new MutationObserver((muts) => {
      for (const m of muts) for (const n of m.addedNodes) {
        if (n.nodeType !== 1 || n === host) continue;
        if (n.tagName === "IMG") consider(n); else n.querySelectorAll?.("img").forEach(consider);
      }
      schedule();
    }).observe(document.documentElement, { childList: true, subtree: true });
    setTimeout(async () => { await runScan({ manual: false }); firstDone = true; document.querySelectorAll("img").forEach(consider); }, 700);
    let href = location.href, timer;
    setInterval(() => {
      if (location.href === href) return;
      href = location.href; clearTimeout(timer);
      timer = setTimeout(() => runScan({ silent: true }), 1500);
    }, 1000);
  };
  if (document.readyState === "complete") start(); else addEventListener("load", start, { once: true });
})();
