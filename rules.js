// Fast, offline detection engine shared by the service worker and the content script.
// Local rules give instant, deterministic evidence. "hard" evidence can never be
// overruled by the AI; softer evidence is adjudicated by Gemma.
globalThis.TD = (() => {
  const RANK = { unknown: 0, safe: 1, warning: 2, danger: 3 };
  const SLD = new Set(["co", "com", "org", "net", "gov", "ac", "edu", "nic"]);
  const reg = (h) => {
    h = (h || "").toLowerCase();
    const p = h.split(".");
    if (p.length <= 2) return h;
    const [a, b] = p.slice(-2);
    return SLD.has(a) && b.length === 2 ? p.slice(-3).join(".") : p.slice(-2).join(".");
  };
  const tldOf = (h) => (h || "").split(".").pop();
  const ends = (h, list) => list.some((d) => h === d || h.endsWith("." + d));
  const SHORT = ["bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "t.ly", "rb.gy", "tiny.cc", "s.id", "l.wl.co", "lnkd.in", "adf.ly", "bl.ink", "qr.ae", "v.gd", "shorte.st"];
  const TRACK = ["google-analytics.com", "googletagmanager.com", "doubleclick.net", "googlesyndication.com", "facebook.net", "hotjar.com", "clarity.ms", "segment.io", "segment.com", "mixpanel.com", "amplitude.com", "criteo.com", "taboola.com", "outbrain.com", "adnxs.com", "scorecardresearch.com", "analytics.tiktok.com", "bat.bing.com", "fullstory.com", "mouseflow.com", "mc.yandex.ru", "quantserve.com", "hubspot.com", "appsflyer.com"];
  const RISKY_TLD = new Set(["zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "ga", "cf", "work", "support", "rest", "fit", "cam", "icu", "buzz", "monster", "sbs", "cfd", "surf", "bond", "loan", "men", "review", "stream", "download", "win", "bid", "party", "trade", "date", "racing", "accountant", "science", "cyou"]);
  const isShort = (h) => ends(h, SHORT);
  const isTracker = (h) => ends(h, TRACK);
  const isIPv4 = (h) => /^(\d{1,3}\.){3}\d{1,3}$/.test(h);
  const SENSITIVE = /pass|pwd|card|cvv|cvc|otp|ssn|aadhaar|iban|secret|token|pin$/i;
  const lvl = (s) => (s >= 60 ? "danger" : s >= 30 ? "warning" : "safe");
  const EXEC = /\.(exe|msi|scr|bat|cmd|vbs|vbe|jse|jar|apk|lnk|ps1|hta|wsf|cpl|reg|msix|appx|docm|xlsm|pptm|iso|img|crx|xpi)$/i;

  /* ---------- brands: official registrable domains ---------- */
  const BRANDS = {
    paypal: ["paypal.com", "paypal.me", "paypalobjects.com"],
    google: ["google.com", "gmail.com", "youtube.com", "googleapis.com", "gstatic.com", "goo.gl", "withgoogle.com", "googleusercontent.com", "blogspot.com", "ytimg.com"],
    facebook: ["facebook.com", "fb.com", "fb.me", "messenger.com", "fbcdn.net", "meta.com"],
    instagram: ["instagram.com", "cdninstagram.com"],
    whatsapp: ["whatsapp.com", "whatsapp.net", "wa.me"],
    amazon: ["amazon.com", "amazonaws.com", "amzn.to", "a.co", "primevideo.com", "media-amazon.com", "amazonpay.in", "amazon.in", "amazon.co.uk"],
    apple: ["apple.com", "icloud.com", "mzstatic.com", "apple.news"],
    microsoft: ["microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com", "windows.com", "azure.com", "bing.com", "msn.com", "sharepoint.com", "xbox.com", "office365.com", "skype.com", "windows.net", "azureedge.net", "msecnd.net"],
    netflix: ["netflix.com", "nflxso.net", "nflximg.net"],
    linkedin: ["linkedin.com", "licdn.com", "lnkd.in"],
    twitter: ["twitter.com", "x.com", "t.co", "twimg.com"],
    dropbox: ["dropbox.com", "dropboxusercontent.com"],
    github: ["github.com", "githubusercontent.com", "github.io", "githubassets.com"],
    coinbase: ["coinbase.com"],
    binance: ["binance.com", "binance.us"],
    metamask: ["metamask.io"],
    fedex: ["fedex.com"],
    dhl: ["dhl.com", "dhl.de"],
    usps: ["usps.com"],
    chase: ["chase.com", "jpmorganchase.com"],
    wellsfargo: ["wellsfargo.com"],
    bankofamerica: ["bankofamerica.com"],
    hsbc: ["hsbc.com", "hsbc.co.uk", "hsbc.co.in"],
    sbi: ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com", "sbi.bank.in"],
    hdfc: ["hdfcbank.com", "hdfc.com", "hdfcbank.net", "hdfclife.com"],
    icici: ["icicibank.com", "icicidirect.com", "iciciprulife.com"],
    paytm: ["paytm.com", "paytmbank.com"],
    phonepe: ["phonepe.com"],
    flipkart: ["flipkart.com", "flixcart.com"],
    irs: ["irs.gov"]
  };
  const BRAND_NAMES = Object.keys(BRANDS);
  const isOfficial = (brand, r) => {
    if ((BRANDS[brand] || []).includes(r)) return true;
    const label = r.split(".")[0], tld = r.slice(label.length + 1);
    return label === brand && /^(com|[a-z]{2}|co\.[a-z]{2}|com\.[a-z]{2})$/.test(tld);
  };
  const trustedHost = (h) => { const r = reg(h); return BRAND_NAMES.some((b) => (BRANDS[b] || []).includes(r) || isOfficial(b, r)); };
  const lev = (a, b) => {
    const m = a.length, n = b.length; if (!m) return n; if (!n) return m;
    let prev = Array.from({ length: n + 1 }, (_, j) => j);
    for (let i = 1; i <= m; i++) {
      const cur = [i];
      for (let j = 1; j <= n; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = cur;
    }
    return prev[n];
  };
  const deglyph = (s) => s.replace(/rn/g, "m").replace(/vv/g, "w").replace(/[01345\$7]/g, (c) => ({ 0: "o", 1: "l", 3: "e", 4: "a", 5: "s", $: "s", 7: "t" })[c]);
  // Does this hostname imitate or borrow a known brand without being official?
  function brandCheck(host) {
    host = (host || "").toLowerCase();
    if (!host || isIPv4(host)) return null;
    const r = reg(host);
    const tokens = host.replace(/\.[a-z]{2,}$/, "").split(/[.\-_]/).filter(Boolean);
    for (const b of BRAND_NAMES) {
      if (isOfficial(b, r)) continue;
      for (const t of tokens) {
        if (t === "x" || t.length < 3) continue;
        if (t === b) return { kind: "brand", brand: b };
        if (t.length >= 4) {
          const dg = deglyph(t);
          if (t !== b && dg === b) return { kind: "typo", brand: b };
          if (b.length >= 6 && t !== b && Math.abs(t.length - b.length) <= 1 && lev(dg, b) === 1) return { kind: "typo", brand: b };
        }
        const m = t.match(new RegExp("^(my|secure|login|www|verify|online)?" + b + "(bank|pay|secure|login|support|help|care|online|account|verify|update|kyc|wallet|id|service|services|team)$"));
        if (m || new RegExp("^(my|secure|login|verify|online)" + b + "$").test(t)) return { kind: "brand", brand: b };
      }
    }
    return null;
  }
  const brandsIn = (text) => {
    const t = " " + (text || "").toLowerCase().replace(/[^a-z0-9]+/g, " ") + " ";
    return BRAND_NAMES.filter((b) => b.length >= 5 && t.includes(" " + b + " "));
  };

  /* ---------- scam language ---------- */
  const RULES = [
    [/\b(urgent|immediately|right away|within \d+ ?(hours?|hrs?|minutes?|mins?)|last chance|act now|final notice|expires? (today|soon|in)|account (will be )?(blocked|suspended|closed|deactivated|limited|locked)|suspended|legal action|arrest|warrant)\b/i, 20, "pressure or threats"],
    [/\b(otp|one[- ]time (password|code)|password|passcode|cvv|card number|\bpin\b|verify your (account|identity|details|wallet)|confirm your (account|details|identity)|update your (account|payment|billing|details)|kyc|aadhaar|pan card|login (details|credentials)|social security)\b/i, 25, "asks for codes, credentials or ID details"],
    [/\b(you(?:'ve| have)? won|winner|lottery|prize|reward points?|cashback|claim (your|now)|gift ?cards?|double your|guaranteed (profit|returns?)|processing fee|registration fee|loan approved|congratulations)\b/i, 25, "money, prize or investment bait"],
    [/\b(bank|paypal|amazon|flipkart|fedex|dhl|bluedart|india post|customs|income tax|irs|microsoft|apple id|netflix|sbi|hdfc|icici|paytm|phonepe|upi|courier|parcel|package|usps|ups)\b/i, 10, "mentions a trusted brand or service"],
    [/(https?:\/\/|www\.)\S+/i, 10, "contains a link"],
    [/\b(bit\.ly|tinyurl\.com|t\.co|cutt\.ly|rb\.gy|is\.gd|shorturl\.at|t\.ly)\b/i, 15, "uses a shortened link"],
    [/\b(work from home|part[- ]time job|earn (₹|rs\.?|inr|\$)\s?\d|telegram|whatsapp (us|me|number)|tasks? (and|&) commission|like and (subscribe|review) tasks?)\b/i, 20, "job or chat-app recruitment pitch"],
    [/(your (computer|device|pc|phone|system|browser) (is|has been|may be|might be) (infected|hacked|compromised|at risk|damaged)|virus (detected|found|alert|warning)|call (microsoft|apple|windows|support|tech)|toll[- ]?free|do not (close|restart|turn off)|security (alert|warning)|trojan|spyware (detected|found)|\d+ viruses)/i, 35, "fake virus or tech-support alarm"],
    [/\b(western union|moneygram|wire transfer|zelle|cash ?app|bitcoin atm|send (usdt|btc|crypto|bitcoin)|pay (via|using|through|in) (upi|crypto|bitcoin|gift ?cards?)|crypto(currency)? (payment|wallet)|usdt|bitcoin)\b/i, 20, "asks for untraceable payment methods"],
    [/\b(inheritance|beneficiary|next of kin|million (dollars|usd)|transfer of funds|unclaimed (funds?|package)|barrister|lottery commission|dormant account)\b/i, 30, "advance-fee or inheritance scam wording"],
    [/(do not (tell|share|inform)|don'?t tell anyone|keep (this )?(confidential|secret)|between us)/i, 15, "asks you to keep it secret"],
    [/\b(connect (your )?wallet|seed phrase|recovery phrase|secret recovery|private key|airdrop|claim (your )?(tokens?|airdrop)|validate (your )?wallet|wallet (sync|verification|connect)|walletconnect)\b/i, 35, "crypto wallet-drainer wording"],
    [/(\b(package|parcel|shipment|delivery|order)\b.{0,50}\b(held|on hold|undeliverable|could not be delivered|failed|unpaid|customs (fee|charge)|redeliver|reschedule)\b)/i, 25, "fake delivery notice"],
    [/\b(aapka|apka|aapke|tumhara)\s+(account|khata|sim|card|bijli|connection).{0,25}(band|block|suspend|kat|expire)/i, 25, "regional-language account threat"],
    [/\b(tax refund|refund|overpaid|overpayment|you are eligible|compensation|subsidy|government scheme)\b/i, 12, "refund or benefit bait"],
    [/\b(anydesk|teamviewer|quicksupport|remote (access|desktop|support)|screen ?share|install (this )?(app|software))\b/i, 25, "asks for remote access or app install"],
    [/(click (here|the link|below|this link)|tap (here|the link)).{0,30}(verify|confirm|update|unlock|restore|claim|login|log in|sign in|secure)/i, 25, "pushes you to click and verify"],
    [/(windows\s*(key)?\s*\+\s*r|win\s*\+\s*r|⊞\s*\+\s*r|\bpowershell\b|cmd\.exe|\bmshta\b|ctrl\s*\+\s*v.{0,60}(run|terminal|command)|paste.{0,40}(run|terminal|powershell|command prompt)|verify you are (a )?human.{0,80}(press|paste|run))/i, 45, "tells you to run commands (ClickFix attack)"],
    [/(i (have )?(recorded|hacked|accessed)|your (webcam|camera)|your (password|passwords) (is|was|are)|pay .{0,25}(bitcoin|btc)|adult (site|website|video))/i, 25, "sextortion-style blackmail wording"],
    [/\b(are you (available|free) now|i need a favou?r|buy (some )?(steam|apple|google play|amazon) (gift )?cards?|this is your (boss|ceo|manager))\b/i, 30, "boss or friend impersonation"],
    [/\b(earn|make|income|salary)\b.{0,25}(daily|per day|a day|\/day|weekly|per week|from home|without (any )?(experience|investment))/i, 15, "unrealistic income promise"],
    [/\b(\d{2}%|\d0% off|clearance sale|closing down|going out of business|last \d+ (items|pieces)|only \d+ left)\b/i, 8, "pressure-selling language"]
  ];
  function localScam(text) {
    let score = 0; const hits = [];
    for (const [re, w, label] of RULES) if (re.test(text)) { score += w; hits.push(label); }
    score = Math.min(100, score);
    return { score, hits, level: lvl(score) };
  }

  /* ---------- links and downloads ---------- */
  const looksDomain = /^(https?:\/\/)?([a-z0-9-]+\.)+[a-z]{2,}(\/\S*)?$/i;
  function localLinks(links, pageReg) {
    const c = { ip: 0, at: 0, puny: 0, short: 0, tld: 0, exec: 0, execBad: 0, dataHtml: 0, mismatch: 0, typo: 0, brand: 0 };
    const bad = [];
    for (const { href, text } of links) {
      let u; try { u = new URL(href); } catch (e) { continue; }
      if (u.protocol === "data:" && /^data:text\/html/i.test(href)) { c.dataHtml++; continue; }
      if (!/^https?:$/.test(u.protocol)) continue;
      const h = u.hostname.toLowerCase(), r = reg(h), ext = r !== pageReg;
      const risky = RISKY_TLD.has(tldOf(h));
      const bc = ext ? brandCheck(h) : null;
      let flagged = false;
      if (ext && isIPv4(h)) { c.ip++; flagged = true; }
      if (u.username) { c.at++; flagged = true; }
      if (h.includes("xn--")) { c.puny++; flagged = true; }
      if (isShort(h)) c.short++;
      if (ext && risky) c.tld++;
      if (bc) { bc.kind === "typo" ? c.typo++ : c.brand++; flagged = true; }
      if (EXEC.test(u.pathname)) { c.exec++; if (isIPv4(h) || isShort(h) || risky || bc) { c.execBad++; flagged = true; } }
      const t = (text || "").trim().toLowerCase();
      if (t && !t.includes(" ") && !/[…]|\.\.\./.test(t) && looksDomain.test(t)) {
        const th = t.replace(/^https?:\/\//, "").replace(/^www\./, "").split(/[\/?#]/)[0];
        if (th && reg(th) !== r) { c.mismatch++; flagged = true; }
      }
      if (flagged && bad.length < 5) bad.push(h);
    }
    let score = 0, hard = false; const reasons = [];
    const add = (n, t, h) => { score += n; reasons.push(t); if (h) hard = true; };
    if (c.typo) add(40, `${c.typo} link(s) to look-alike brand domains (${bad.slice(0, 2).join(", ")})`, true);
    if (c.brand) add(20, `${c.brand} link(s) borrow a brand name on an unofficial domain`);
    if (c.at) add(30, `${c.at} link(s) hide the real host behind a username@ trick`, true);
    if (c.execBad) add(40, `${c.execBad} risky program download link(s) from suspicious hosts`, true);
    else if (c.exec) add(15, `${c.exec} direct program/script download link(s)`);
    if (c.dataHtml) add(30, "links that open embedded HTML pages (data: URLs)", true);
    if (c.ip) add(25, `${c.ip} link(s) point to raw IP addresses`);
    if (c.puny) add(15, `${c.puny} link(s) use look-alike (punycode) domains`);
    if (c.mismatch >= 3) add(25, `${c.mismatch} links show one address but go to another`);
    else if (c.mismatch) add(12, `${c.mismatch} link(s) show one address but go to another`);
    if (c.short >= 3) add(10, `${c.short} link-shortener URLs`);
    if (c.tld >= 3) add(10, `${c.tld} links to high-abuse domain endings`);
    score = Math.min(100, score);
    return { score, level: lvl(score), reasons, hard, total: links.length, counts: c };
  }

  /* ---------- redirects ---------- */
  function localRouting(chain) {
    const urls = chain.map((c) => c.url);
    const hosts = urls.map((u) => { try { return new URL(u).hostname; } catch (e) { return ""; } });
    const regs = [...new Set(hosts.map(reg))];
    const hops = chain.length - 1;
    let score = 0, hard = false; const reasons = [];
    const add = (n, t, h) => { score += n; reasons.push(t); if (h) hard = true; };
    if (hops >= 3) add(25, `${hops} redirects before the final page`);
    else if (hops === 2) add(10, "2 redirects before the final page");
    if (regs.length >= 3) add(25, `passes through ${regs.length} different domains: ${regs.slice(0, 4).join(" → ")}`);
    if (hosts.slice(0, -1).some(isShort)) add(15, "starts from a link shortener");
    if (hosts.some(isIPv4)) add(30, "a hop uses a raw IP address");
    if (urls.some((u) => u.startsWith("http:"))) add(10, "a hop is not encrypted (http)");
    if (urls.some((u) => { try { return !!new URL(u).username; } catch (e) { return false; } })) add(30, "a link hides its real host behind a username@ trick", true);
    if (hosts.some((h) => h.includes("xn--"))) add(25, "look-alike (punycode) domain in the path");
    const last = hosts[hosts.length - 1], bc = brandCheck(last);
    if (bc && hops >= 1) add(bc.kind === "typo" ? 40 : 20, `final site ${last} ${bc.kind === "typo" ? "imitates" : "borrows the name of"} ${bc.brand}`, bc.kind === "typo");
    if (hops >= 1 && RISKY_TLD.has(tldOf(last))) add(10, `final site uses high-abuse ending .${tldOf(last)}`);
    if (chain.some((c) => c.client)) add(10, "page-triggered (JavaScript/meta) redirect");
    score = Math.min(100, score);
    return { score, level: lvl(score), reasons, hard };
  }

  /* ---------- traffic ---------- */
  function localTraffic(tr) {
    const hosts = Object.entries(tr.third);
    const trackers = hosts.filter(([, e]) => e.tracker).length;
    let score = 0, hard = false; const reasons = [];
    const add = (n, t, h) => { score += n; reasons.push(t); if (h) hard = true; };
    for (const s of tr.sensitive.slice(0, 2)) add(55, `form fields (${s.keys.join(", ")}) were posted to third-party host ${s.host}`, true);
    if (tr.ips.length) add(30, `requests to raw IP addresses: ${tr.ips.slice(0, 3).join(", ")}`);
    if (tr.insecure > 0) add(15, `${tr.insecure} unencrypted request(s) from an https page`);
    if (hosts.length > 30) add(20, `${hosts.length} third-party domains contacted`);
    else if (hosts.length > 15) add(10, `${hosts.length} third-party domains contacted`);
    if (trackers >= 6) add(15, `${trackers} known tracking services`);
    score = Math.min(100, score);
    return { score, level: lvl(score), reasons, hard };
  }

  /* ---------- page structure ---------- */
  function localThreat(sig) {
    let score = 0, hard = false; const items = [];
    const add = (n, t, h) => { score += n; items.push([n + (h ? 100 : 0), t]); if (h) hard = true; };
    const host = (sig.host || "").toLowerCase(), bc = brandCheck(host), sens = sig.passwordFields || sig.cardFields;
    if (isIPv4(host)) add(sig.passwordFields ? 45 : 25, "site is served from a raw IP address", !!sig.passwordFields);
    if (host.includes("xn--")) add(25, "look-alike (punycode) domain");
    if (bc && bc.kind === "typo") add(sens ? 70 : 40, `domain imitates ${bc.brand}${sens ? " and asks for credentials or payment" : ""}`, true);
    else if (bc) add(25, `domain uses the name "${bc.brand}" but is not an official ${bc.brand} domain`, !!sens);
    if (RISKY_TLD.has(tldOf(host))) add(10, `high-abuse domain ending .${tldOf(host)}`);
    if (host.split(".").length >= 5) add(10, "unusually deep subdomain chain");
    if (sig.passwordFields && !sig.https) add(40, "password field on an unencrypted page", true);
    if (sig.cardFields && !sig.https) add(45, "card details requested on an unencrypted page", true);
    if (sig.passwordFormCrossOrigin) add(35, "login form sends the password to a different domain", true);
    if (sig.cardFormCrossOrigin) add(30, "payment form submits to a different domain");
    if (sig.insecureFormAction) add(25, "a form submits over an unencrypted connection", true);
    if (sig.titleBrandMismatch && sig.titleBrandMismatch.length && sens) add(55, `login/payment page presents itself as ${sig.titleBrandMismatch[0]} but is hosted on ${host}`, true);
    if (sig.hiddenCrossOriginIframes) add(20, "hidden iframe loading another domain");
    else if (sig.hiddenIframes >= 2) add(10, "several hidden iframes");
    if (sig.obfuscatedScriptHits >= 15) add(25, "heavily obfuscated inline scripts");
    else if (sig.obfuscatedScriptHits >= 3) add(10, "obfuscated inline scripts");
    if (sig.mismatchedLinks >= 2) add(10, "link text shows one address but points to another");
    if (sig.metaRefreshExternal) add(20, "page auto-redirects to another domain");
    if (sig.links && sig.links.score) { score += Math.min(45, sig.links.score); sig.links.reasons.forEach((r) => items.push([sig.links.hard ? 90 : 15, r])); if (sig.links.hard) hard = true; }
    const hk = new Set(sig.hooks || []);
    if (hk.has("clipboard-write")) add(40, "silently copies text to your clipboard (ClickFix-style attack)", true);
    if (hk.has("auto-download")) add(35, "starts a file download without a click", true);
    if (hk.has("fullscreen")) add(15, "forces fullscreen without a click");
    if (hk.has("popup")) add(15, "opens pop-up windows without a click");
    if (hk.has("beforeunload")) add(8, "tries to stop you from leaving the page");
    if (sig.rightClickBlocked) add(5, "disables right-click");
    score = Math.min(100, score);
    const reasons = items.sort((x, y) => y[0] - x[0]).map((x) => x[1]);
    return { score, level: lvl(score), reasons, hard };
  }

  /* ---------- combine AI verdict with local evidence ---------- */
  function merge(ai, loc) {
    if (!ai) return { level: loc.level, score: loc.score, reasons: loc.reasons.slice(0, 6), ai: false };
    let { level, score } = ai, reasons = [...(ai.reasons || [])];
    if (level === "unknown") { level = loc.level; score = Math.max(score, loc.score); }
    else if (loc.hard && RANK[loc.level] > RANK[level]) {
      level = loc.level; score = Math.max(score, loc.score);
      reasons = [...loc.reasons.slice(0, 3), ...reasons];
    }
    return { ...ai, level, score, reasons: [...new Set(reasons)].slice(0, 6), ai: true };
  }

  return { RANK, reg, isShort, isTracker, isIPv4, SENSITIVE, lvl, localScam, localLinks, localRouting, localTraffic, localThreat, brandCheck, brandsIn, isOfficial, trustedHost, merge, BRAND_NAMES };
})();
