(() => {
  const root = document.getElementById('harika-pairing-status');
  if (!root || root.dataset.state !== 'checking') return;
  let attempts = 0;
  async function poll() {
    try {
      const response = await fetch(root.dataset.url, { method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ action: 'harika_pairing_status', _wpnonce: root.dataset.nonce }), signal: AbortSignal.timeout(15000) });
      if (!response.ok) throw new Error();
      const value = await response.json();
      if (typeof value.message !== 'string' || typeof value.state !== 'string') throw new Error();
      root.querySelector('[data-message]').textContent = value.message;
      root.querySelector('[data-identity]').textContent = [value.organization, value.website].filter(x => typeof x === 'string').join(' · ');
      root.dataset.state = value.state;
      // Render actions from the same persisted state as the final status.
      if (value.state !== 'checking') { window.location.reload(); return; }
      if (value.state === 'checking' && ++attempts < 75) setTimeout(poll, 4000);
    } catch {
      root.querySelector('[data-message]').textContent = 'Der Status ist derzeit nicht überprüfbar. Bitte erneut prüfen.';
    }
  }
  setTimeout(poll, 2000);
})();
