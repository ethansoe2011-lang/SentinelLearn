// popup.js — reads session stats from chrome.storage.session
// and checks if the Flask backend is reachable.

const BACKEND_PING = "http://localhost:5000/api/logs?limit=1";

async function init() {
  // Load session stats from background service worker
  const stored = await chrome.storage.session.get("sentinelStats");
  const stats = stored.sentinelStats || { total: 0, threats: 0, safe: 0, lastEvent: null };

  document.getElementById("numTotal").textContent  = stats.total;
  document.getElementById("numSafe").textContent   = stats.safe;
  document.getElementById("numThreat").textContent = stats.threats;

  if (stats.lastEvent) {
    const le = stats.lastEvent;
    const label = le.type === "url" ? "URL" : "File";
    const verdict = le.verdict === "THREAT" ? "⚠ THREAT" : "✓ Safe";
    const shortVal = le.value.length > 40 ? le.value.slice(0, 40) + "…" : le.value;
    document.getElementById("lastEvent").innerHTML =
      `Last event: <span>${verdict} — ${label}: ${shortVal}</span>`;
  }

  // Ping backend to check if it is online
  try {
    const res = await fetch(BACKEND_PING);
    if (res.ok) {
      document.getElementById("statusDot").classList.remove("offline");
      document.getElementById("statusText").textContent = "Backend online ✓";
    } else {
      throw new Error("non-200");
    }
  } catch {
    document.getElementById("statusDot").classList.add("offline");
    document.getElementById("statusText").textContent = "Backend offline — start Flask";
  }
}

document.getElementById("clearBtn").addEventListener("click", async () => {
  await chrome.storage.session.set({
    sentinelStats: { total: 0, threats: 0, safe: 0, lastEvent: null }
  });
  document.getElementById("numTotal").textContent  = 0;
  document.getElementById("numSafe").textContent   = 0;
  document.getElementById("numThreat").textContent = 0;
  document.getElementById("lastEvent").innerHTML   = "Last event: <span>Cleared</span>";
});

init();
