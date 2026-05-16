// URLGuard — Popup Script

const ICONS = {
  safe: '✅', suspicious: '⚠️', malicious: '🚨', error: '❌', pending: '🔍'
};

function timeAgo(ts) {
  const diff = Date.now() - ts;
  if (diff < 60_000)   return 'just now';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

function renderHistory(history) {
  const list = document.getElementById('historyList');
  if (!history.length) {
    list.innerHTML = `
      <div class="empty">
        <div class="empty-icon">🔎</div>
        <div class="empty-text">No URLs scanned yet.<br>Right-click any link and choose<br><em>"URLGuard: Scan this link"</em></div>
      </div>`;
    return;
  }

  list.innerHTML = history.slice(0, 60).map(item => {
    const label = (item.verdict || 'unknown');
    const labelCap = label.charAt(0).toUpperCase() + label.slice(1);
    const short = item.url.length > 46 ? item.url.slice(0, 43) + '…' : item.url;
    return `
      <div class="h-item" title="${item.url}">
        <span class="h-icon">${ICONS[item.verdict] || '❓'}</span>
        <div class="h-body">
          <div class="h-url">${short}</div>
          <div class="h-verdict h-verdict--${item.verdict}">${labelCap}</div>
        </div>
        <span class="h-time">${timeAgo(item.ts)}</span>
      </div>`;
  }).join('');
}

// ── Load API key status ──────────────────────────────────────
chrome.storage.sync.get(['vtApiKey', 'gsbApiKey'], data => {
  const hasVT  = !!data.vtApiKey;
  const hasGSB = !!data.gsbApiKey;

  const vtPill  = document.getElementById('vtPill');
  const gsbPill = document.getElementById('gsbPill');
  const warn    = document.getElementById('warnBanner');

  vtPill.textContent  = hasVT  ? '✓ Configured' : 'Not set';
  vtPill.className    = `key-pill key-pill--${hasVT  ? 'ok' : 'missing'}`;
  gsbPill.textContent = hasGSB ? '✓ Configured' : 'Not set';
  gsbPill.className   = `key-pill key-pill--${hasGSB ? 'ok' : 'missing'}`;

  if (!hasVT && !hasGSB) warn.classList.add('visible');
});

// ── Load scan history ────────────────────────────────────────
chrome.storage.local.get('ugHistory', data => {
  renderHistory(data.ugHistory || []);
});

// ── Clear history ────────────────────────────────────────────
document.getElementById('btnClear').addEventListener('click', () => {
  chrome.storage.local.set({ ugHistory: [] }, () => renderHistory([]));
});

// ── Open options ─────────────────────────────────────────────
document.getElementById('btnSettings').addEventListener('click', () => {
  chrome.runtime.openOptionsPage();
});
document.getElementById('warnLink')?.addEventListener('click', () => {
  chrome.runtime.openOptionsPage();
});
