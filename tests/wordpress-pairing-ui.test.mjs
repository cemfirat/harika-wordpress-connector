import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const source = readFileSync(new URL('../wordpress/assets/harika-pairing.js', import.meta.url), 'utf8');
function browser(response, initial = 'checking') {
  const timers = [], message = {}, identity = {};
  const root = { dataset: { state: initial, url: '/wp-admin/admin-ajax.php', nonce: 'test-nonce' },
    querySelector: selector => selector === '[data-message]' ? message : identity };
  let reloads = 0;
  vm.runInNewContext(source, { document: { getElementById: () => root }, URLSearchParams, AbortSignal,
    setTimeout: (callback, delay) => timers.push({ callback, delay }),
    window: { location: { reload: () => { reloads++; } } },
    fetch: async (url, request) => {
      assert.equal(url, '/wp-admin/admin-ajax.php');
      assert.equal(request.credentials, 'same-origin');
      assert.equal(request.cache, 'no-store');
      if (response instanceof Error) throw response;
      return { ok: true, json: async () => response };
    } });
  return { root, message, identity, timers, reloads: () => reloads };
}

test('terminal pairing status refreshes server-rendered actions instead of leaving a cancel-attempt button', async () => {
  for (const state of ['verified', 'failed', 'revoked', 'not_verified']) {
    const page = browser({ state, message: state, organization: 'Example', website: 'example.test' });
    await page.timers.shift().callback();
    assert.equal(page.reloads(), 1, state);
    assert.equal(page.timers.length, 0, 'No further poll races against refreshed actions');
  }
});
test('pending proof keeps polling without refreshing the page', async () => {
  const page = browser({ state: 'checking', message: 'Prüfung läuft', organization: 'Example', website: 'example.test' });
  await page.timers.shift().callback();
  assert.equal(page.reloads(), 0);
  assert.equal(page.message.textContent, 'Prüfung läuft');
  assert.equal(page.identity.textContent, 'Example · example.test');
  assert.equal(page.timers[0].delay, 4000);
});
test('network or malformed status stays visibly unverifiable without a reload loop', async () => {
  for (const response of [new Error('offline'), { state: 'verified' }]) {
    const page = browser(response);
    await page.timers.shift().callback();
    assert.equal(page.reloads(), 0);
    assert.match(page.message.textContent, /nicht überprüfbar/);
    assert.equal(page.timers.length, 0);
  }
});
test('already settled pages do not start another polling or reload cycle', () => {
  assert.equal(browser({}, 'verified').timers.length, 0);
});
