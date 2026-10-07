// Dependency-free UI behaviour tests; no browser, HTTP, credentials, or inventory writes.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../netwatch/web/static/app.js', import.meta.url), 'utf8');
const now = Date.parse('2026-10-05T10:00:00Z');
class Clock extends Date { static now() { return now; } }
function node(tag, text = '', attrs = {}) {
  const values = new Set();
  return {
    tagName: tag, textContent: text, dataset: {}, dateTime: '', title: '', open: false,
    hasAttribute(name) { return Object.hasOwn(attrs, name); },
    addEventListener(type, callback) { this[type] = callback; },
    classList: {values, toggle(name, enabled) { enabled ? values.add(name) : values.delete(name); }},
  };
}
const seen = node('TIME', '2026-10-05 09:56:00');
seen.dateTime = '2026-10-05T09:56:00+00:00';
seen.title = seen.dateTime + ' UTC';
const latest = node('TIME', 'Not scanned yet');
const successful = node('TIME', 'No successful scan recorded');
const invalid = node('TIME', 'Unknown'); invalid.dateTime = 'malformed';
const health = [node('P'), node('STRONG', '', {'data-compact-health': ''})];
const dot = node('SPAN');
const fullReasons = [node('UL'), node('UL')];
const compact = node('UL', '', {'data-compact-reasons': ''});
for (const list of [...fullReasons, compact]) list.replaceChildren = function (...children) { this.children = children; };
const filters = node('DETAILS', '', {'data-responsive-details': ''}); filters.dataset.disclosureKey = 'filters';
const activeFilters = node('DETAILS', '', {'data-responsive-details': '', 'data-keep-open': ''}); activeFilters.dataset.disclosureKey = 'active-filters';
const group = node('DETAILS', '', {'data-responsive-details': ''}); group.dataset.disclosureKey = 'group';
const explanation = node('DETAILS'); explanation.dataset.disclosureKey = 'explanation';
const details = [filters, activeFilters, group, explanation];
const preferences = new Map([['netwatch-ui:group', 'open']]);
const query = {matches: true, addEventListener(_event, callback) { this.changed = callback; }};
const banner = {classList: {remove() {}, add() {}}};
const status = node('STRONG'); status.closest = () => banner;
const calls = [];
let payload = {
  monitor_healthy: true,
  last_scan: {completed_at: '2026-10-05T09:59:00+00:00'},
  security: {status: 'ATTENTION', last_successful_scan: {completed_at: '2026-10-05T09:58:00+00:00'},
    reasons: ['3 UNKNOWN device(s) awaiting manual review.', '1 new UNKNOWN device(s) in the last 24 hours.']},
};
const selectors = {
  '[data-relative-time]': [seen, latest, invalid],
  '[data-disclosure-key]': details,
  '[data-last-scan]': [latest],
  '[data-successful-scan]': [successful],
  '[data-monitor-health]': health,
  '[data-monitor-dot]': [dot],
  '[data-security-reasons], [data-compact-reasons]': [...fullReasons, compact],
};
const document = {
  hidden: false, body: {dataset: {refresh: 'true'}}, activeElement: {tagName: 'INPUT'},
  querySelectorAll(selector) { return selectors[selector] || []; },
  querySelector(selector) { return selector === '[data-security-status]' ? status : null; },
  createElement(tag) { return node(tag); },
};
const sandbox = {
  Date: Clock, document,
  window: {
    matchMedia(value) { assert.equal(value, '(max-width:700px)'); return query; },
    sessionStorage: {getItem(key) { return preferences.get(key) || null; }, setItem(key, value) { preferences.set(key, value); }},
    setInterval(callback) { calls.push(callback); },
    location: {reload() { assert.fail('An active form must not reload'); }},
  },
  async fetch(url, options) {
    assert.equal(url, '/api/summary'); assert.equal(options.credentials, 'same-origin');
    return {ok: true, async json() { return payload; }};
  },
};
vm.createContext(sandbox); vm.runInContext(source, sandbox);
assert.equal(seen.textContent, '4 min ago'); assert(seen.title.includes('09:56:00'));
assert.equal(invalid.textContent, 'Unknown');
assert(!filters.open); assert(activeFilters.open); assert(group.open); assert(!explanation.open);
filters.open = true; filters.toggle(); assert.equal(preferences.get('netwatch-ui:filters'), 'open');
filters.open = false; sandbox.setupDisclosures(); assert(filters.open, 'Disclosure survives a page refresh');
calls[0](); await calls[1]();
assert.equal(latest.textContent, '1 min ago'); assert(latest.title.includes('09:59:00'));
assert.equal(successful.textContent, '2026-10-05 09:58:00 UTC');
assert(health.every(item => item.textContent === 'Healthy')); assert(dot.classList.values.has('healthy'));
assert.equal(compact.children[0].textContent, '3 devices need review');
assert.equal(compact.children[1].textContent, '1 new unknown in 24h');
assert(fullReasons.every(list => list.children[0].textContent === payload.security.reasons[0]));
query.matches = false; query.changed();
assert.equal(seen.textContent, '2026-10-05 09:56:00');
assert.equal(latest.textContent, '2026-10-05 09:59:00');
assert(filters.open && group.open, 'Desktop groups and filters remain expanded');
for (const [value, expected] of [
  ['2026-10-05T09:59:59Z', 'Just now'], ['2026-10-05T09:59:00Z', '1 min ago'],
  ['2026-10-05T09:00:00Z', '1 hr ago'], ['2026-10-04T10:00:00Z', '1 day ago'],
  ['2026-10-03T10:00:00Z', '2 days ago'], ['bad', null], ['2026-10-05T11:00:00Z', null],
]) assert.equal(sandbox.relativeTime(value), expected);
query.matches = true;
sandbox.window.sessionStorage.getItem = () => { throw new Error('Disabled'); };
sandbox.window.sessionStorage.setItem = () => { throw new Error('Disabled'); };
sandbox.setupDisclosures(); filters.toggle();
assert(!filters.open && activeFilters.open, 'Disabled storage does not break mobile controls');
payload = {...payload, monitor_healthy: false, security: {...payload.security, status: 'ALERT',
  reasons: ['1 BLOCKED device(s) currently online.', '<img src=x onerror=alert(1)>']}};
await calls[1]();
assert.equal(status.textContent, 'ALERT');
assert(dot.classList.values.has('unhealthy')); assert(!dot.classList.values.has('healthy'));
assert.equal(compact.children[0].textContent, '1 blocked device online');
assert.equal(health[1].textContent, 'Needs attention');
assert.equal(compact.children[1].textContent, '<img src=x onerror=alert(1)>');
console.log('Mobile UI tests passed: relative/exact times, all health displays, reasons, disclosures, editing and storage fallback.');
