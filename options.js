const $ = (s) => document.querySelector(s);
const D = { apiKey: "", model: "gemma-4-31b-it", enabled: true, maxImages: 40, showScan: "load", features: { image: true, scam: true, threat: true, routing: true, traffic: true } };
const say = (t) => { $("#msg").textContent = t; };
(async () => {
  const s = await chrome.storage.local.get(D);
  const f = { ...D.features, ...(s.features || {}) };
  $("#key").value = s.apiKey; $("#model").value = s.model; $("#max").value = s.maxImages; $("#showScan").value = s.showScan; $("#enabled").checked = s.enabled;
  document.querySelectorAll("[data-f]").forEach((c) => { c.checked = f[c.dataset.f] !== false; });
})();
async function save() {
  const features = {};
  document.querySelectorAll("[data-f]").forEach((c) => { features[c.dataset.f] = c.checked; });
  await chrome.storage.local.set({ apiKey: $("#key").value.trim(), model: $("#model").value.trim() || D.model, maxImages: Math.max(0, +$("#max").value || 0), showScan: $("#showScan").value, enabled: $("#enabled").checked, features });
}
$("#save").addEventListener("click", async () => { await save(); say("Saved."); });
$("#test").addEventListener("click", async () => {
  await save(); say("Testing…");
  const r = await chrome.runtime.sendMessage({ type: "test" });
  say(r && r.ok ? "Connected to Gemma." : "Failed: " + ((r && r.error) || "no response"));
});
