// ─────────────────────────────────────────────────────────────
// URLGuard — Content Script
// Injects shield badges on links, shows floating detail panels,
// handles auto-scan and context-menu scan results
// ─────────────────────────────────────────────────────────────

// url → [HTMLElement, ...]
const linkMap = new Map();
// url → { status, result }
const stateMap = new Map();

let activePanel = null;
let isInitialized = false;

// ═══════════════════════════════════════════════════════════════
// INIT
// ═══════════════════════════════════════════════════════════════

(async function init() {
  if (isInitialized) return;
  isInitialized = true;

  const settings = await getSettings();
  if (!settings.vtApiKey && !settings.gsbApiKey) return; // no keys → nothing to do

  collectLinks();

  if (settings.autoScan) {
    const urls = [...linkMap.keys()].slice(0, 80); // respect rate limits
    if (urls.length) {
      urls.forEach(url => applyBadges(url, 'scanning'));
      chrome.runtime.sendMessage({ type: 'UG_BATCH_SCAN', urls });
    }
  }
})();

function collectLinks() {
  document.querySelectorAll('a[href]').forEach(el => {
    const href = el.href;
    if (!href || !/^https?:\/\//.test(href)) return;
    if (!linkMap.has(href)) linkMap.set(href, []);
    linkMap.get(href).push(el);
  });
}

async function getSettings() {
  return new Promise(r =>
    chrome.storage.sync.get(['vtApiKey', 'gsbApiKey', 'autoScan'], d =>
      r({ vtApiKey: d.vtApiKey || '', gsbApiKey: d.gsbApiKey || '', autoScan: d.autoScan !== false })
    )
  );
}

// ═══════════════════════════════════════════════════════════════
// BADGE MANAGEMENT
// ═══════════════════════════════════════════════════════════════

function applyBadges(url, status, result = null) {
  stateMap.set(url, { status, result });

  // Get stored elements + catch any newly added elements
  const stored = linkMap.get(url) || [];
  document.querySelectorAll('a[href]').forEach(el => {
    if (el.href === url && !stored.includes(el)) stored.push(el);
  });
  if (!linkMap.has(url)) linkMap.set(url, stored);

  stored.forEach(el => injectBadge(el, url, status, result));
}

function injectBadge(el, url, status, result) {
  const existing = el.querySelector('.ug-badge');
  if (existing) existing.remove();

  const badge = document.createElement('span');
  badge.className = `ug-badge ug-status--${status}`;
  badge.setAttribute('data-ug-url', url);
  badge.setAttribute('title', buildTooltip(status, result));
  badge.innerHTML = shieldSVG(status);

  if (status !== 'scanning') {
    badge.style.cursor = 'pointer';
    badge.addEventListener('click', e => {
      e.preventDefault();
      e.stopPropagation();
      togglePanel(url, status, result, badge);
    });
  }

  el.appendChild(badge);
}

// ═══════════════════════════════════════════════════════════════
// FLOATING DETAIL PANEL
// ═══════════════════════════════════════════════════════════════

function togglePanel(url, status, result, anchor) {
  if (activePanel) {
    const wasUrl = activePanel.dataset.ugPanelUrl;
    activePanel.remove();
    activePanel = null;
    if (wasUrl === url) return; // same badge → just close
  }

  const panel = buildPanel(url, status, result);
  document.body.appendChild(panel);
  activePanel = panel;
  positionPanel(panel, anchor);

  // Close on outside click
  setTimeout(() => {
    const onOutside = e => {
      if (!panel.contains(e.target) && !e.target.classList.contains('ug-badge')) {
        panel.remove();
        if (activePanel === panel) activePanel = null;
        document.removeEventListener('click', onOutside, true);
      }
    };
    document.addEventListener('click', onOutside, true);
  }, 60);
}

function positionPanel(panel, anchor) {
  const rect   = anchor.getBoundingClientRect();
  const scrollY = window.scrollY;
  const scrollX = window.scrollX;

  let top  = rect.bottom + scrollY + 8;
  let left = rect.left + scrollX;

  // Clamp horizontally
  const maxLeft = window.innerWidth - 335;
  left = Math.max(8, Math.min(left, maxLeft));

  // Flip above if not enough space below
  if (rect.bottom + 300 > window.innerHeight) {
    top = rect.top + scrollY - 310;
  }

  panel.style.top  = `${top}px`;
  panel.style.left = `${left}px`;
}

function buildPanel(url, status, result) {
  const panel = document.createElement('div');
  panel.className = `ug-panel ug-panel--${status}`;
  panel.dataset.ugPanelUrl = url;

  const META = {
    safe:      { emoji: '✅', label: 'Safe',      color: '#4ade80' },
    suspicious:{ emoji: '⚠️', label: 'Suspicious', color: '#fbbf24' },
    malicious: { emoji: '🚨', label: 'Malicious',  color: '#f87171' },
    scanning:  { emoji: '🔍', label: 'Scanning…',  color: '#60a5fa' },
    error:     { emoji: '❌', label: 'Error',       color: '#94a3b8' }
  };
  const meta = META[status] || { emoji: '❓', label: status, color: '#888' };
  const shortUrl = url.length > 58 ? url.slice(0, 55) + '…' : url;

  panel.innerHTML = `
    <div class="ug-ph">
      <div class="ug-ph-brand">
        ${shieldSVG(status)}
        <span class="ug-ph-title">URLGuard</span>
      </div>
      <button class="ug-close-btn" title="Close">✕</button>
    </div>
    <div class="ug-pb">
      <div class="ug-verdict ug-verdict--${status}">
        <span>${meta.emoji}</span>
        <span class="ug-verdict-text">${meta.label}</span>
      </div>
      <div class="ug-url-display" title="${url}">${shortUrl}</div>
      ${buildSourcesHTML(result)}
    </div>
  `;

  panel.querySelector('.ug-close-btn').addEventListener('click', () => {
    panel.remove();
    if (activePanel === panel) activePanel = null;
  });

  // Expand/collapse logic for flagged engines list
  panel.querySelectorAll('.ug-toggle-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const target = panel.querySelector(`[data-toggle-target="${btn.dataset.toggleId}"]`);
      if (!target) return;
      const hidden = target.classList.toggle('ug-hidden');
      btn.textContent = hidden ? `▶ Show ${btn.dataset.count} engine${btn.dataset.count > 1 ? 's' : ''} flagged` : '▲ Hide details';
    });
  });

  return panel;
}

function buildSourcesHTML(result) {
  if (!result) return '';
  const vt  = result.virusTotal;
  const gsb = result.safeBrowsing;
  if (!vt && !gsb) return '';

  let html = '<div class="ug-sources">';

  // ── VirusTotal card ──
  if (vt) {
    if (vt.error) {
      html += `<div class="ug-src-card"><div class="ug-src-title">🔬 VirusTotal</div><div class="ug-err-text">${vt.error}</div></div>`;
    } else if (vt.pending) {
      html += `<div class="ug-src-card"><div class="ug-src-title">🔬 VirusTotal</div><div class="ug-pending-text">⏳ ${vt.message}</div></div>`;
    } else {
      const pct   = vt.total > 0 ? Math.round((vt.malicious / vt.total) * 100) : 0;
      const isBad = vt.malicious > 0;
      const uniqueId = 'vt-' + Math.random().toString(36).slice(2);

      let flaggedRows = '';
      if (vt.flagged?.length > 0) {
        flaggedRows = vt.flagged.slice(0, 10).map(f => `
          <div class="ug-engine-row">
            <span class="ug-engine-name">${escHtml(f.name)}</span>
            <span class="ug-engine-badge ug-engine-badge--${f.verdict}">${f.verdict}</span>
          </div>
        `).join('');
        if (vt.flagged.length > 10) {
          flaggedRows += `<div class="ug-more-text">+${vt.flagged.length - 10} more engines</div>`;
        }
      }

      html += `
        <div class="ug-src-card">
          <div class="ug-src-header">
            <span class="ug-src-title">🔬 VirusTotal</span>
            <span class="ug-src-pill ug-src-pill--${isBad ? 'bad' : 'ok'}">
              ${vt.malicious}/${vt.total} engines
            </span>
          </div>
          <div class="ug-bar-track">
            <div class="ug-bar-fill ug-bar-fill--${isBad ? 'bad' : 'ok'}" style="width:${pct}%"></div>
          </div>
          <div class="ug-stats-row">
            <span class="ug-stat ug-stat--mal">● ${vt.malicious} malicious</span>
            <span class="ug-stat ug-stat--sus">● ${vt.suspicious} suspicious</span>
            <span class="ug-stat ug-stat--ok">● ${vt.harmless} clean</span>
          </div>
          ${vt.flagged?.length > 0 ? `
            <button class="ug-toggle-btn" data-toggle-id="${uniqueId}" data-count="${vt.flagged.length}">
              ▶ Show ${vt.flagged.length} engine${vt.flagged.length > 1 ? 's' : ''} flagged
            </button>
            <div class="ug-engines-list ug-hidden" data-toggle-target="${uniqueId}">
              ${flaggedRows}
            </div>
          ` : `<div class="ug-clean-text">✓ No engines flagged this URL</div>`}
          ${vt.reputation !== undefined ? `<div class="ug-reputation">Reputation score: <strong>${vt.reputation}</strong></div>` : ''}
        </div>
      `;
    }
  }

  // ── Safe Browsing card ──
  if (gsb) {
    if (gsb.error) {
      html += `<div class="ug-src-card"><div class="ug-src-title">🛡️ Safe Browsing</div><div class="ug-err-text">${gsb.error}</div></div>`;
    } else {
      const threatRows = (gsb.threats || []).map(t => `
        <div class="ug-engine-row">
          <span class="ug-engine-name">${escHtml(t.type)}</span>
          <span class="ug-engine-badge ug-engine-badge--malicious">${escHtml(t.platform)}</span>
        </div>
      `).join('');

      html += `
        <div class="ug-src-card">
          <div class="ug-src-header">
            <span class="ug-src-title">🛡️ Google Safe Browsing</span>
            <span class="ug-src-pill ug-src-pill--${gsb.isSafe ? 'ok' : 'bad'}">
              ${gsb.isSafe ? 'Clean' : 'Threat detected'}
            </span>
          </div>
          ${!gsb.isSafe && gsb.threats?.length ? `<div class="ug-engines-list">${threatRows}</div>` : ''}
          ${gsb.isSafe ? `<div class="ug-clean-text">✓ No threats detected</div>` : ''}
        </div>
      `;
    }
  }

  html += '</div>';
  return html;
}

// ═══════════════════════════════════════════════════════════════
// CORNER NOTIFICATION (page scans / no-element matches)
// ═══════════════════════════════════════════════════════════════

function showCornerNotif(url, status, message = '') {
  const existing = document.getElementById('ug-corner-notif');
  if (existing) existing.remove();

  const META = {
    safe:      { emoji: '✅', label: 'Safe' },
    suspicious:{ emoji: '⚠️', label: 'Suspicious' },
    malicious: { emoji: '🚨', label: 'Malicious' },
    scanning:  { emoji: '🔍', label: 'Scanning…' },
    error:     { emoji: '❌', label: 'Error' }
  };
  const meta = META[status] || { emoji: '❓', label: status };
  const shortUrl = url.length > 50 ? url.slice(0, 47) + '…' : url;

  const notif = document.createElement('div');
  notif.id = 'ug-corner-notif';
  notif.className = `ug-corner-notif ug-corner-notif--${status}`;
  notif.innerHTML = `
    <div class="ug-cn-hdr">
      <span>${shieldSVG(status)} <strong>URLGuard</strong></span>
      <button class="ug-close-btn" title="Dismiss">✕</button>
    </div>
    <div class="ug-cn-verdict">${meta.emoji} ${meta.label}</div>
    <div class="ug-cn-url">${shortUrl}</div>
    ${message ? `<div class="ug-cn-msg">${message}</div>` : ''}
  `;

  document.body.appendChild(notif);
  notif.querySelector('.ug-close-btn').addEventListener('click', () => notif.remove());

  if (status !== 'scanning') setTimeout(() => notif?.remove(), 10_000);
}

// ═══════════════════════════════════════════════════════════════
// MESSAGE LISTENER
// ═══════════════════════════════════════════════════════════════

chrome.runtime.onMessage.addListener(msg => {
  if (msg.type === 'UG_SCAN_STARTED') {
    const { url, source } = msg;
    if (source === 'contextmenu') {
      showCornerNotif(url, 'scanning');
    } else {
      applyBadges(url, 'scanning');
    }
  }

  if (msg.type === 'UG_SCAN_RESULT') {
    const { url, result, source } = msg;
    const status = result.verdict || 'error';

    if (source === 'contextmenu') {
      // Update any matching link badges AND show/update corner notif
      showCornerNotif(url, status);
      applyBadges(url, status, result);
      // If there's a panel open for this URL, refresh it
      if (activePanel?.dataset.ugPanelUrl === url) {
        activePanel.remove();
        activePanel = null;
      }
    } else {
      applyBadges(url, status, result);
    }
  }

  if (msg.type === 'UG_NO_KEYS') {
    showCornerNotif(msg.url, 'error', 'No API keys set. Open URLGuard settings to configure.');
  }
});

// ═══════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════

function shieldSVG(status) {
  const colors = {
    safe: '#22c55e', suspicious: '#f59e0b',
    malicious: '#ef4444', scanning: '#60a5fa', error: '#64748b'
  };
  const fill = colors[status] || '#888';
  const spin = status === 'scanning' ? ' class="ug-spin-wrap"' : '';
  return `<span${spin}><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="12" height="12" fill="${fill}" style="display:inline-block;vertical-align:middle"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg></span>`;
}

function buildTooltip(status, result) {
  if (status === 'scanning') return 'URLGuard: Scanning…';
  let tip = `URLGuard: ${status.charAt(0).toUpperCase() + status.slice(1)}`;
  const vt = result?.virusTotal;
  const gsb = result?.safeBrowsing;
  if (vt?.total) tip += ` | VT ${vt.malicious}/${vt.total}`;
  if (gsb)       tip += ` | GSB ${gsb.isSafe ? 'clean' : 'threat'}`;
  tip += '\nClick for full report';
  return tip;
}

function escHtml(str) {
  return String(str).replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])
  );
}
