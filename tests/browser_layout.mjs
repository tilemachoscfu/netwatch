// Optional layout check: Node 22+ and Firefox WebDriver BiDi on loopback.
// Use an isolated fixture dashboard, never production credentials or inventory.
// Pytest never launches a browser or scans a network.
import assert from 'node:assert/strict';

const socket = new WebSocket('ws://127.0.0.1:9223/session');
await new Promise((resolve, reject) => {
  socket.addEventListener('open', resolve, {once: true});
  socket.addEventListener('error', reject, {once: true});
});
let sequence = 0;
const pending = new Map();
socket.addEventListener('message', ({data}) => {
  const result = JSON.parse(data);
  const callback = pending.get(result.id);
  if (!callback) return;
  pending.delete(result.id);
  if (result.type === 'error') callback.reject(new Error(result.message));
  else callback.resolve(result.result);
});
function command(method, params) {
  const id = ++sequence;
  return new Promise((resolve, reject) => {
    pending.set(id, {resolve, reject});
    socket.send(JSON.stringify({id, method, params}));
  });
}
const timeout = setTimeout(() => {socket.close(); process.exit(1);}, 60000);
let activeSession = false;
try {
  await command('session.new', {capabilities: {alwaysMatch: {}}});
  activeSession = true;
  const {context} = await command('browsingContext.create', {type: 'tab'});
  const fixtureUrl = process.env.NETWATCH_LAYOUT_URL || 'http://127.0.0.1:18765';
  for (const width of [360, 390, 430, 1200, 1800]) {
    for (const path of ['/', '/devices', '/unknown', '/device/1', '/events']) {
    await command('browsingContext.setViewport', {context, viewport: {width, height: 1000}});
    await command('browsingContext.navigate', {
      context, url: fixtureUrl + path, wait: 'complete',
    });
    const result = await command('script.evaluate', {
      target: {context}, awaitPromise: false,
      expression: `JSON.stringify({
        width: innerWidth,
        scrollWidth: document.documentElement.scrollWidth,
        counters: [...document.querySelectorAll('.metric')].filter(element =>
          getComputedStyle(element).display !== 'none').map(element => {
          const rect = element.getBoundingClientRect();
          return {left: rect.left, right: rect.right};
        }),
        cards: [...document.querySelectorAll('.responsive-table tr')].every(element =>
          ['block', 'grid'].includes(getComputedStyle(element).display)),
        navigation: [...document.querySelectorAll('.mobile-navigation a')].map(element => {
          const rect = element.getBoundingClientRect();
          return {width: rect.width, height: rect.height};
        }),
        touchTargets: [...document.querySelectorAll('.button, button, .window-links a, .filters-disclosure>summary, .map-group>summary')].filter(element => element.getClientRects().length).map(element => {
          const rect = element.getBoundingClientRect();
          return {width: rect.width, height: rect.height};
        }),
        desktopTable: document.querySelector('.inventory-table table') &&
          getComputedStyle(document.querySelector('.inventory-table table')).display,
        unknownCards: [...document.querySelectorAll('.unknown-card')].map(element => {
          const rect = element.getBoundingClientRect();
          return {left: rect.left, right: rect.right};
        })
      })`,
    });
    assert.equal(result.type, 'success');
    const geometry = JSON.parse(result.result.value);
    console.log(JSON.stringify(geometry));
    assert.equal(geometry.counters.length, path === '/' ? (width <= 700 ? 6 : 8) :
      ['/devices', '/unknown'].includes(path) ? 6 : 0);
    assert.ok(geometry.scrollWidth <= geometry.width + 1, 'page must not overflow horizontally');
    for (const counter of geometry.counters) {
      assert.ok(counter.left >= 0 && counter.right <= geometry.width + 1,
        'all counters must fit the viewport');
    }
    if (width <= 700) {
      assert.ok(geometry.cards, 'mobile tables must render as readable cards');
      for (const target of [...geometry.navigation, ...geometry.touchTargets]) {
        assert.ok(target.width >= 44 && target.height >= 44, 'mobile controls need 44px touch targets');
      }
    } else if (geometry.desktopTable) assert.equal(geometry.desktopTable, 'table');
    for (const card of geometry.unknownCards) {
      assert.ok(card.left >= 0 && card.right <= geometry.width + 1);
    }
    }
  }
} finally {
  if (activeSession) await command('session.end', {});
  clearTimeout(timeout);
  socket.close();
}
