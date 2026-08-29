// =============================================================================
// SentinelLearn Monitor — background.js (Manifest V3 Service Worker)
// =============================================================================
// Monitors real browser URL navigations and file downloads.
// Sends events to the SentinelLearn Flask backend for AI threat analysis.
// Results are saved to activity_log.jsonl and appear in the Dashboard log panel.
// =============================================================================

const BACKEND_URL = "http://localhost:5000/api/activity-check";

// ── Trusted domain whitelist ──────────────────────────────────────────────────
// Navigations to these domains are SKIPPED to avoid spamming the AI with noise
// from everyday trusted sites. Add or remove entries as needed.
const TRUSTED_DOMAINS = [
  "google.com", "www.google.com",
  "youtube.com", "www.youtube.com",
  "github.com", "www.github.com",
  "stackoverflow.com",
  "localhost", "127.0.0.1",
  "chrome://", "chrome-extension://",
  "about:", "newtab",
  "accounts.google.com",
  "microsoft.com", "www.microsoft.com",
  "bing.com", "www.bing.com",
];

// ── Session stats (stored in chrome.storage.session) ─────────────────────────
let sessionStats = { total: 0, threats: 0, safe: 0, lastEvent: null };

async function loadStats() {
  const stored = await chrome.storage.session.get("sentinelStats");
  if (stored.sentinelStats) sessionStats = stored.sentinelStats;
}

async function saveStats() {
  await chrome.storage.session.set({ sentinelStats: sessionStats });
}

// ── Helper: is this URL trusted / should we skip it? ─────────────────────────
function isTrusted(url) {
  if (!url) return true;
  try {
    const { hostname, protocol } = new URL(url);
    if (protocol === "chrome:" || protocol === "chrome-extension:" || protocol === "about:") return true;
    return TRUSTED_DOMAINS.some(d => hostname === d || hostname.endsWith("." + d));
  } catch {
    return true; // malformed URL — skip
  }
}

// ── Core: send activity to Sentinel backend ───────────────────────────────────
async function sendToSentinel(type, value) {
  try {
    const res = await fetch(BACKEND_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type, value, source: "browser_extension" }),
    });

    if (!res.ok) {
      console.warn("[Sentinel] Backend returned HTTP", res.status);
      return;
    }

    const data = await res.json();
    if (data.status === "success") {
      sessionStats.total++;
      if (data.verdict === "THREAT") {
        sessionStats.threats++;
        // Show a browser notification for real threats
        chrome.notifications.create({
          type: "basic",
          iconUrl: "icons/icon48.png",
          title: "⚠ Sentinel: Threat Detected",
          message: `${type === "url" ? "URL" : "File"}: ${value}\n${data.analysis.slice(0, 100)}...`,
          priority: 2,
        });
      } else {
        sessionStats.safe++;
      }
      sessionStats.lastEvent = { type, value, verdict: data.verdict, ts: new Date().toISOString() };
      await saveStats();
    }
  } catch (err) {
    // Backend offline or unreachable — fail silently, do not crash service worker
    console.warn("[Sentinel] Could not reach backend:", err.message);
  }
}

// ── Listener 1: Real URL navigation ──────────────────────────────────────────
// Fires when a tab finishes loading a new URL.
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") return;
  const url = tab.url || "";
  if (isTrusted(url)) return;

  console.log("[Sentinel] URL navigation detected:", url);
  sendToSentinel("url", url);
});

// ── Listener 2: Real file download ───────────────────────────────────────────
// Fires the moment a download is created (before it completes).
chrome.downloads.onCreated.addListener((downloadItem) => {
  const filename = downloadItem.filename || downloadItem.url || "unknown_file";
  // Extract just the filename from the full path
  const shortName = filename.split(/[\\/]/).pop() || filename;
  console.log("[Sentinel] Download detected:", shortName);
  sendToSentinel("file", shortName);
});

// ── Init ─────────────────────────────────────────────────────────────────────
loadStats();
console.log("[Sentinel] SentinelLearn Monitor service worker started.");
