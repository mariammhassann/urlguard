// URLGuard — Options Script

// ── Load saved settings ──────────────────────────────────────
chrome.storage.sync.get(['vtApiKey', 'gsbApiKey', 'autoScan'], data => {
  if (data.vtApiKey)  document.getElementById('vtKey').value  = data.vtApiKey;
  if (data.gsbApiKey) document.getElementById('gsbKey').value = data.gsbApiKey;
  document.getElementById('autoScan').checked = data.autoScan !== false;
});

// ── Save ─────────────────────────────────────────────────────
document.getElementById('btnSave').addEventListener('click', () => {
  const settings = {
    vtApiKey:  document.getElementById('vtKey').value.trim(),
    gsbApiKey: document.getElementById('gsbKey').value.trim(),
    autoScan:  document.getElementById('autoScan').checked
  };

  chrome.storage.sync.set(settings, () => {
    const toast = document.getElementById('toast');
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 2500);
  });
});

// ── Show/hide password toggles ───────────────────────────────
document.querySelectorAll('.toggle-eye').forEach(btn => {
  btn.addEventListener('click', () => {
    const input = document.getElementById(btn.dataset.target);
    input.type = input.type === 'password' ? 'text' : 'password';
    btn.textContent = input.type === 'password' ? '👁' : '🙈';
  });
});
