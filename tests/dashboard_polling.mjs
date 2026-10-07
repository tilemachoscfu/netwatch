// Isolated DOM regression: no HTTP requests, credentials, or production writes.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../netwatch/web/static/app.js', import.meta.url), 'utf8');
const classes = () => ({
  values: new Set(['offline']),
  toggle(value, enabled) { enabled ? this.values.add(value) : this.values.delete(value); },
});
const badges = [0, 1].map(() => ({textContent: 'MONITOR STOPPED OR STALE', classList: classes()}));
const health = {textContent: 'Stopped, starting, or stale'};
let healthy = true;
const callbacks = [];
const document = {
  hidden: false,
  body: {dataset: {refresh: 'true'}},
  // Editing must not prevent live health updates or cause a page reload.
  activeElement: {tagName: 'INPUT'},
  querySelectorAll(selector) {
    if (selector === '[data-monitor-badge]') return badges;
    if (selector === '[data-monitor-health]') return [health];
    return [];
  },
  querySelector(selector) { return selector === '[data-monitor-health]' ? health : null; },
};
vm.runInNewContext(source, {
  document,
  window: {setInterval(callback) { callbacks.push(callback); }, location: {
    reload() { assert.fail('Editing a form must not reload the page'); },
  }},
  async fetch(url) {
    assert.equal(url, '/api/summary');
    return {ok: true, async json() { return {monitor_healthy: healthy, security: {}}; }};
  },
});
callbacks[0]();
await callbacks[1]();
assert.equal(health.textContent, 'Healthy');
for (const badge of badges) {
  assert.equal(badge.textContent, 'MONITORING');
  assert(badge.classList.values.has('online'));
  assert(!badge.classList.values.has('offline'));
}
healthy = false;
await callbacks[1]();
assert.equal(health.textContent, 'Stopped, starting, or stale');
for (const badge of badges) {
  assert.equal(badge.textContent, 'MONITOR STOPPED OR STALE');
  assert(badge.classList.values.has('offline'));
  assert(!badge.classList.values.has('online'));
}
console.log('Dashboard polling regression passed: healthy and stale badges, editing preserved.');
