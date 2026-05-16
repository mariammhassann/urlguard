// ─────────────────────────────────────────────────────────────
// URLGuard — Background Service Worker
// Handles: VirusTotal API, Google Safe Browsing API,
//          context menus, rate limiting, history storage
// ─────────────────────────────────────────────────────────────

const VT_BASE  = 'https://www.virustotal.com/api/v3';
const GSB_BASE = 'https://safebrowsing.googleapis.com/v4';

// VirusTotal free tier: 4 req/min → 1 every 15 seconds
const VT_MIN_INTERVAL_MS = 15_000;
let lastVTRequestAt = 0;

// In-memory cache (cleared on service-worker restart; that's fine)
const scanCache = {};

// ═══════════════════════════════════════════════════════════════
// SETUP
// ═══════════════════════════════════════════════════════════════

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'ug-scan-link',
    title: '🛡️ URLGuard: Scan this link',
    contexts: ['link']
  });
  chrome.contextMenus.create({
    id: 'ug-scan-page',
    title: '🛡️ URLGuard: Scan this page URL',
    contexts: ['page']
  });
});

// ═══════════════════════════════════════════════════════════════
// CONTEXT MENU
// ═══════════════════════════════════════════════════════════════

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (!tab?.id) return;
  const url = info.menuItemId === 'ug-scan-link' ? info.linkUrl : info.pageUrl;
  if (!url) return;

  const settings = await getSettings();
  if (!settings.vtApiKey && !settings.gsbApiKey) {
    safeSend(tab.id, { type: 'UG_NO_KEYS', url });
    return;
  }

  safeSend(tab.id, { type: 'UG_SCAN_STARTED', url, source: 'contextmenu' });

  try {
    const result = await fullScan(url, settings);
    await appendHistory(url, result);
    safeSend(tab.id, { type: 'UG_SCAN_RESULT', url, result, source: 'contextmenu' });
  } catch (err) {
    safeSend(tab.id, {
      type: 'UG_SCAN_RESULT',
      url,
      result: { verdict: 'error', error: err.message },
      source: 'contextmenu'
    });
  }
});

// ═══════════════════════════════════════════════════════════════
// MESSAGE HANDLER (from content scripts & popup)
// ═══════════════════════════════════════════════════════════════

chrome.runtime.onMessage.addListener((msg, sender, respond) => {
  const tabId = sender.tab?.id;

  // Content script sends a batch of URLs to auto-scan
  if (msg.type === 'UG_BATCH_SCAN') {
    getSettings().then(settings => {
      if (settings.vtApiKey || settings.gsbApiKey) {
        runBatch(msg.urls, tabId, settings);
      }
    });
    respond({ queued: true });
    return true;
  }

  // Popup clears history
  if (msg.type === 'UG_CLEAR_HISTORY') {
    chrome.storage.local.set({ ugHistory: [] }, () => respond({ ok: true }));
    return true;
  }

  return false;
});

// ═══════════════════════════════════════════════════════════════
// BATCH SCAN STRATEGY
//   1) GSB batch check — one API call for ALL urls (fast)
//   2) VT single checks — rate-limited, only for flagged urls
//      (or all, if GSB key is absent)
// ═══════════════════════════════════════════════════════════════

async function runBatch(urls, tabId, settings) {
  const toScan = urls.filter(u => !scanCache[u]);

  if (!toScan.length) {
    // All cached — push results immediately
    urls.forEach(url => {
      if (scanCache[url]) safeSend(tabId, { type: 'UG_SCAN_RESULT', url, result: scanCache[url] });
    });
    return;
  }

  // ── Step 1: GSB batch (all at once, very fast) ─────────────
  if (settings.gsbApiKey) {
    try {
      const gsbMap = await batchGSB(toScan, settings.gsbApiKey);
      for (const [url, gsb] of Object.entries(gsbMap)) {
        const partial = { safeBrowsing: gsb, verdict: gsb.isSafe ? 'safe' : 'malicious' };
        scanCache[url] = partial;
        await appendHistory(url, partial);
        safeSend(tabId, { type: 'UG_SCAN_RESULT', url, result: partial });
      }
    } catch (e) {
      console.warn('[URLGuard] GSB batch error:', e.message);
    }
  }

  // ── Step 2: VT for suspicious/malicious (rate-limited) ─────
  if (settings.vtApiKey) {
    // If no GSB, scan all (up to 10); if GSB present, only re-check flagged ones
    const vtTargets = settings.gsbApiKey
      ? toScan.filter(u => scanCache[u]?.verdict !== 'safe').slice(0, 5)
      : toScan.slice(0, 10);

    for (const url of vtTargets) {
      await enforceVTRateLimit();
      try {
        const vt = await vtLookup(url, settings.vtApiKey);
        const existing = scanCache[url] || {};
        const updated = { ...existing, virusTotal: vt, verdict: computeVerdict({ ...existing, virusTotal: vt }) };
        scanCache[url] = updated;
        await appendHistory(url, updated);
        safeSend(tabId, { type: 'UG_SCAN_RESULT', url, result: updated });
      } catch (e) {
        console.warn('[URLGuard] VT error for', url, e.message);
      }
    }
  }
}

// ═══════════════════════════════════════════════════════════════
// FULL SCAN (context menu — single URL, both APIs in parallel)
// ═══════════════════════════════════════════════════════════════

async function fullScan(url, settings) {
  if (scanCache[url]) return scanCache[url];

  const result = { url, timestamp: Date.now() };
  const tasks = [];

  if (settings.vtApiKey) {
    tasks.push(
      enforceVTRateLimit()
        .then(() => vtLookup(url, settings.vtApiKey))
        .then(r  => { result.virusTotal = r; })
        .catch(e => { result.virusTotal = { error: e.message }; })
    );
  }
  if (settings.gsbApiKey) {
    tasks.push(
      singleGSB(url, settings.gsbApiKey)
        .then(r  => { result.safeBrowsing = r; })
        .catch(e => { result.safeBrowsing = { error: e.message }; })
    );
  }

  await Promise.all(tasks);
  result.verdict = computeVerdict(result);
  scanCache[url] = result;
  return result;
}

// ═══════════════════════════════════════════════════════════════
// VIRUSTOTAL API
// ═══════════════════════════════════════════════════════════════

async function enforceVTRateLimit() {
  const wait = VT_MIN_INTERVAL_MS - (Date.now() - lastVTRequestAt);
  if (wait > 0) await delay(wait);
  lastVTRequestAt = Date.now();
}

async function vtLookup(url, apiKey) {
  // VT uses base64url of the URL as the resource ID
  const id = btoa(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  let res = await fetch(`${VT_BASE}/urls/${id}`, {
    headers: { 'x-apikey': apiKey }
  });

  if (res.status === 404) {
    // Not in VT database → submit for fresh scan
    return await vtSubmitAndPoll(url, apiKey);
  }
  if (!res.ok) throw new Error(`VT ${res.status}: ${res.statusText}`);

  const data = await res.json();
  return parseVTReport(data.data?.attributes);
}

async function vtSubmitAndPoll(url, apiKey) {
  const form = new URLSearchParams({ url });
  const subRes = await fetch(`${VT_BASE}/urls`, {
    method: 'POST',
    headers: { 'x-apikey': apiKey, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form.toString()
  });
  if (!subRes.ok) throw new Error(`VT submit ${subRes.status}`);

  const subData = await subRes.json();
  const analysisId = subData.data?.id;
  if (!analysisId) throw new Error('VT: no analysis ID returned');

  // Poll up to 4 times (20 sec total)
  for (let i = 0; i < 4; i++) {
    await delay(5_000);
    await enforceVTRateLimit();
    const pollRes = await fetch(`${VT_BASE}/analyses/${analysisId}`, {
      headers: { 'x-apikey': apiKey }
    });
    if (!pollRes.ok) continue;
    const pollData = await pollRes.json();
    if (pollData.data?.attributes?.status === 'completed') {
      return parseVTAnalysis(pollData.data.attributes);
    }
  }
  return { pending: true, message: 'Analysis queued — check VirusTotal directly for full results.' };
}

function parseVTReport(attrs) {
  if (!attrs) return { error: 'No data in VT response' };
  const s = attrs.last_analysis_stats || {};
  const engines = attrs.last_analysis_results || {};
  return buildVTSummary(s, engines, {
    reputation: attrs.reputation,
    categories: attrs.categories,
    lastScan: attrs.last_analysis_date
  });
}

function parseVTAnalysis(attrs) {
  if (!attrs) return { error: 'No data in VT analysis' };
  return buildVTSummary(attrs.stats || {}, attrs.results || {}, {});
}

function buildVTSummary(stats, engines, extras) {
  const mal  = stats.malicious   || 0;
  const sus  = stats.suspicious  || 0;
  const harm = stats.harmless    || 0;
  const unk  = stats.undetected  || 0;
  const total = mal + sus + harm + unk;

  const flagged = Object.entries(engines)
    .filter(([, v]) => ['malicious', 'suspicious'].includes(v.category))
    .map(([name, v]) => ({ name, verdict: v.category, detail: v.result }));

  return { malicious: mal, suspicious: sus, harmless: harm, undetected: unk, total, flagged, ...extras };
}

// ═══════════════════════════════════════════════════════════════
// GOOGLE SAFE BROWSING API
// ═══════════════════════════════════════════════════════════════

async function batchGSB(urls, apiKey) {
  const res = await fetch(`${GSB_BASE}/threatMatches:find?key=${apiKey}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(buildGSBBody(urls))
  });
  if (!res.ok) throw new Error(`GSB ${res.status}`);
  const data = await res.json();
  const matches = data.matches || [];

  const result = {};
  for (const url of urls) {
    const hits = matches.filter(m => m.threat.url === url);
    result[url] = {
      isSafe: hits.length === 0,
      threats: hits.map(m => ({ type: m.threatType, platform: m.platformType }))
    };
  }
  return result;
}

async function singleGSB(url, apiKey) {
  const map = await batchGSB([url], apiKey);
  return map[url];
}

function buildGSBBody(urls) {
  return {
    client: { clientId: 'urlguard-extension', clientVersion: '1.0.0' },
    threatInfo: {
      threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: urls.map(url => ({ url }))
    }
  };
}

// ═══════════════════════════════════════════════════════════════
// VERDICT
// ═══════════════════════════════════════════════════════════════

function computeVerdict({ virusTotal: vt, safeBrowsing: gsb } = {}) {
  const gsbThreat = gsb && !gsb.isSafe && (gsb.threats?.length > 0);
  const vtMal = vt?.malicious || 0;
  const vtSus = vt?.suspicious || 0;

  if (gsbThreat || vtMal > 2) return 'malicious';
  if (vtMal > 0 || vtSus > 3) return 'suspicious';
  return 'safe';
}

// ═══════════════════════════════════════════════════════════════
// STORAGE & UTILITIES
// ═══════════════════════════════════════════════════════════════

async function appendHistory(url, result) {
  return new Promise(resolve => {
    chrome.storage.local.get('ugHistory', d => {
      const history = d.ugHistory || [];
      const idx = history.findIndex(e => e.url === url);
      const entry = { url, verdict: result.verdict || 'error', ts: Date.now() };
      if (idx >= 0) history[idx] = entry;
      else history.unshift(entry);
      if (history.length > 500) history.length = 500;
      chrome.storage.local.set({ ugHistory: history }, resolve);
    });
  });
}

async function getSettings() {
  return new Promise(resolve =>
    chrome.storage.sync.get(['vtApiKey', 'gsbApiKey', 'autoScan'], d =>
      resolve({
        vtApiKey:  d.vtApiKey  || '',
        gsbApiKey: d.gsbApiKey || '',
        autoScan:  d.autoScan !== false
      })
    )
  );
}

function safeSend(tabId, msg) {
  try { chrome.tabs.sendMessage(tabId, msg); } catch (_) {}
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }
