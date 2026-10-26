const $ = (s) => document.querySelector(s);
const h = (tag, props = {}, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") e.className = v; else if (k === "on") Object.entries(v).forEach(([a, b]) => e.addEventListener(a, b)); else e.setAttribute(k, v);
  }
  for (const k of kids.flat()) if (k != null) e.append(k);
  return e;
};
const FEATURES = [
  ["image", "Image check", "AI-generated or edited photos"],
  ["scam", "Scam messages", "Page text and notifications"],
  ["threat", "Page threats", "Phishing and hidden risks"],
  ["routing", "Redirect routes", "Where a link really goes"],
  ["traffic", "Traffic watch", "Third parties and data leaks"]
];
const RANK = { unknown: 0, safe: 1, warning: 2, danger: 3 };
let tabId, last = {};
const flagged = (f) => f.level === "warning" || f.level === "danger";

function featureNote(key, tab) {
  const fl = tab.findings.filter((f) => f.feature === key && flagged(f)).length;
  if (key === "image") return tab.stats.images ? `${tab.stats.images} checked · ${tab.stats.imagesFlagged} flagged` : "Waiting for images";
  if (key === "traffic") return fl ? "Unusual traffic" : tab.traffic.requests ? `${tab.traffic.thirdDomains} third-party domains` : "Waiting";
  if (key === "routing") return tab.chain.length > 1 ? `${tab.chain.length - 1} redirect(s)${fl ? " · suspicious" : ""}` : "No redirects";
  if (fl) return `${fl} flagged`;
  return tab.ran[key] || tab.findings.some((f) => f.feature === key) ? "No issues found" : "Watching";
}
function render({ tab, settings }) {
  const worst = tab.findings.reduce((m, f) => Math.max(m, RANK[f.level] || 0), 0);
  const level = !settings.enabled ? "unknown" : worst >= 3 ? "danger" : worst === 2 ? "warning" : worst === 1 || tab.ran.routing || tab.ran.traffic ? "safe" : "unknown";
  const text = !settings.enabled ? "Paused" : { danger: "Dangerous", warning: "Be careful", safe: "Nothing suspicious found", unknown: "Waiting for the page" }[level];
  const sig = JSON.stringify([settings, tab.findings.map((f) => [f.key, f.ts]), tab.stats, tab.chain.length, tab.traffic, tab.url]);
  if (sig === last.sig) return;
  last.sig = sig;
  $("#verdict").className = "verdict " + level;
  $("#status").textContent = text;
  $("#host").textContent = tab.host || "Open a normal web page to start";
  $("#master").checked = settings.enabled;
  $("#keybar").hidden = settings.hasKey;

  const box = $("#features"); box.replaceChildren();
  for (const [key, name, desc] of FEATURES) {
    const cb = h("input", { type: "checkbox", "aria-label": name, on: { change: async (e) => {
      const { features = {} } = await chrome.storage.local.get("features");
      await chrome.storage.local.set({ features: { ...settings.features, ...features, [key]: e.target.checked } });
    } } });
    cb.checked = settings.features[key] !== false;
    const isFlag = tab.findings.some((f) => f.feature === key && flagged(f));
    box.append(h("div", { class: "row" }, h("div", { class: "t" }, h("b", {}, name), h("small", { class: isFlag ? "flag" : "" }, featureNote(key, tab)), h("small", {}, " — " + desc)), h("label", { class: "switch" }, cb, h("span"))));
  }
  const list = $("#findings"); list.replaceChildren();
  const items = [...tab.findings].filter((f) => f.feature !== "error" || f.force).sort((a, b) => (RANK[b.level] - RANK[a.level]) || (b.ts - a.ts)).slice(0, 12);
  if (!items.length) list.append(h("div", { class: "empty" }, "Nothing flagged yet. True Detector keeps watching as you browse."));
  for (const f of items) {
    list.append(h("details", { class: f.level },
      h("summary", {}, f.title || "Result", h("span", {}, (FEATURES.find((x) => x[0] === f.feature) || [0, "True Detector"])[1] + (f.score ? ` · ${f.score}` : ""))),
      f.reasons?.length ? h("ul", {}, f.reasons.map((r) => h("li", {}, r))) : null,
      f.advice ? h("p", {}, f.advice) : null,
      f.excerpt ? h("p", { class: "ex" }, f.excerpt) : null));
  }
}
async function refresh() {
  const st = await chrome.runtime.sendMessage({ type: "get-state", tabId });
  if (st && st.tab) render(st);
}
$("#master").addEventListener("change", (e) => chrome.storage.local.set({ enabled: e.target.checked }).then(refresh));
$("#scan").addEventListener("click", async (e) => {
  e.target.textContent = "Starting scan…";
  await chrome.runtime.sendMessage({ type: "analyze-page", tabId });
  window.close(); // close the popup so the scan animation on the page is visible
});
for (const id of ["opts", "keybtn"]) $("#" + id).addEventListener("click", () => chrome.runtime.openOptionsPage());
(async () => {
  [{ id: tabId }] = await chrome.tabs.query({ active: true, currentWindow: true });
  await refresh(); setInterval(refresh, 1500);
})();
