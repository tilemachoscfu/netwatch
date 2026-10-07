'use strict';
const mobileQuery = typeof window.matchMedia === 'function' ? window.matchMedia('(max-width:700px)') : null;
const isMobile = () => Boolean(mobileQuery?.matches);
function relativeTime(value, now = Date.now()) {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return null;
  const seconds = Math.floor((now - parsed) / 1000);
  if (seconds < -60) return null;
  if (seconds < 60) return 'Just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} hr ago`;
  const days = Math.floor(seconds / 86400);
  return `${days} ${days === 1 ? 'day' : 'days'} ago`;
}
function updateTimes() {
  for (const time of document.querySelectorAll('[data-relative-time]')) {
    if (!time.dataset.exactTime) time.dataset.exactTime = time.textContent;
    time.textContent = (isMobile() && relativeTime(time.dateTime)) || time.dataset.exactTime;
  }
}
function compactReason(value) {
  return value
    .replace('UNKNOWN device(s) awaiting manual review.', 'devices need review')
    .replace('new UNKNOWN device(s) in the last 24 hours.', 'new unknown in 24h')
    .replace('BLOCKED device(s) currently online.', 'blocked devices online')
    .replace('high-priority security event(s) need review.', 'high-priority events need review')
    .replace('security event(s) need review.', 'events need review')
    .replace('Monitor stopped, starting, or stale; observations may be outdated.', 'Monitor needs attention')
    .replace('No new unknown or blocked activity requiring attention.', 'No activity requiring attention')
    .replace(/^1 devices /, '1 device ')
    .replace(/^1 blocked devices /, '1 blocked device ')
    .replace(/^1 high-priority events /, '1 high-priority event ')
    .replace(/^1 events /, '1 event ');
}
function writeScan(selector, value, fallback, suffix = '') {
  for (const element of document.querySelectorAll(selector)) {
    const exact = value ? value.slice(0, 19).replace('T', ' ') + suffix : fallback;
    element.textContent = exact;
    if (element.tagName === 'TIME') {
      element.dateTime = value || '';
      element.title = value ? value + ' UTC' : fallback;
      element.dataset.exactTime = exact;
    }
  }
}
function setupDisclosures() {
  for (const detail of document.querySelectorAll('[data-disclosure-key]')) {
    if (!isMobile() && detail.hasAttribute('data-responsive-details')) {
      detail.open = true;
      continue;
    }
    if (isMobile()) {
      let saved = null;
      try { saved = window.sessionStorage.getItem('netwatch-ui:' + detail.dataset.disclosureKey); } catch { /* Optional UI preference only. */ }
      detail.open = detail.hasAttribute('data-keep-open') || saved === 'open';
    }
  }
}
for (const detail of document.querySelectorAll('[data-disclosure-key]')) {
  detail.addEventListener('toggle', () => {
    if (!isMobile()) return;
    try { window.sessionStorage.setItem('netwatch-ui:' + detail.dataset.disclosureKey, detail.open ? 'open' : 'closed'); } catch { /* Storage can be disabled. */ }
  });
}
setupDisclosures();
updateTimes();
mobileQuery?.addEventListener('change', () => { setupDisclosures(); updateTimes(); });
if (document.body.dataset.refresh === 'true') {
  const editing = () => ['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName);
  window.setInterval(() => { if (!document.hidden && !editing()) window.location.reload(); }, 30000);
  window.setInterval(async () => {
    if (document.hidden) return;
    updateTimes();
    try {
      const response = await fetch('/api/summary', {credentials: 'same-origin'});
      if (!response.ok) return;
      const summary = await response.json();
      const values = {...summary, ...summary.security};
      for (const counter of document.querySelectorAll('[data-count]')) {
        const key = counter.dataset.count;
        counter.textContent = values[key];
        const metric = counter.closest('.metric');
        metric?.classList.toggle('metric-warning', key === 'unknown' && values[key] > 0);
        metric?.classList.toggle('metric-alert', key === 'blocked' && values[key] > 0);
      }
      writeScan('[data-last-scan]', summary.last_scan?.completed_at, 'Not scanned yet');
      for (const health of document.querySelectorAll('[data-monitor-health]')) {
        health.textContent = summary.monitor_healthy ? 'Healthy'
          : health.hasAttribute?.('data-compact-health') ? 'Needs attention' : 'Stopped, starting, or stale';
      }
      for (const dot of document.querySelectorAll('[data-monitor-dot]')) {
        dot.classList.toggle('healthy', summary.monitor_healthy);
        dot.classList.toggle('unhealthy', !summary.monitor_healthy);
      }
      for (const badge of document.querySelectorAll('[data-monitor-badge]')) {
        badge.textContent = summary.monitor_healthy ? 'MONITORING' : 'MONITOR STOPPED OR STALE';
        badge.classList.toggle('online', summary.monitor_healthy);
        badge.classList.toggle('offline', !summary.monitor_healthy);
      }
      writeScan('[data-successful-scan]', summary.security.last_successful_scan?.completed_at, 'No successful scan recorded', ' UTC');
      const status = document.querySelector('[data-security-status]');
      if (status) {
        status.textContent = summary.security.status;
        const banner = status.closest('.security-status');
        banner.classList.remove('secure', 'attention', 'alert');
        banner.classList.add(summary.security.status.toLowerCase());
        for (const list of document.querySelectorAll('[data-security-reasons], [data-compact-reasons]')) {
          list.replaceChildren(...summary.security.reasons.map(reason => {
            const item = document.createElement('li');
            item.textContent = list.hasAttribute('data-compact-reasons') ? compactReason(reason) : reason;
            return item;
          }));
        }
      }
      updateTimes();
    } catch { /* Keep the last readable state during a transient connection failure. */ }
  }, 10000);
} else {
  window.setInterval(() => { if (!document.hidden) updateTimes(); }, 30000);
}

for (const form of document.querySelectorAll('[data-investigation-form]')) {
  form.addEventListener('submit', () => {
    form.querySelector('button').disabled = true;
    form.querySelector('[data-investigation-status]').textContent = 'Investigating evidence…';
  });
}
