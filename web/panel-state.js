import { moveFocusFrom } from './focus.js';
/* Last-success metadata belongs to a panel, not to its newest failed attempt.
 * Callers use the route/request guards before publishing any transition here. */
export function panelState(host, label, retry) {
  const title = label.charAt(0).toUpperCase() + label.slice(1);
  let value, at = null, context = '', requested = '', error = null, pending = false;
  host.innerHTML = '<div class="panel-state" role="status" aria-live="polite"><span data-panel-message></span><button type="button" class="panel-retry">Retry</button></div>';
  const note = host.querySelector('.panel-state');
  const message = host.querySelector('[data-panel-message]');
  const button = host.querySelector('button');
  button.textContent = `Retry ${label}`;
  button.addEventListener('click', () => { Promise.resolve().then(retry).catch(() => {}); });
  function paint(loading) {
    const oldContext = at && requested !== context;
    host.hidden = !error && at !== null && !oldContext;
    note.className = `panel-state${error || oldContext ? ' is-stale' : ''}`;
    button.hidden = !error;
    const age = at ? Math.max(0, Math.floor((Date.now() - at.getTime()) / 1000)) : 0;
    const history = at
      ? ` Showing last successful data${context ? ` for ${context}` : ''}, updated ${at.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC')} (${age < 60 ? `${age}s` : `${Math.floor(age / 60)}m`} ago).`
      : ' No successful data yet.';
    message.textContent = error
      ? `${title}: ${loading ? 'retrying after a refresh failure' : 'refresh failed'}. ${(error.message || 'Request unavailable').replace(/[.!?]+$/, '')}.${history}`
      : `${title}: loading${requested ? ` ${requested}` : ''}.${at ? history : ''}`;
  }
  return {
    get hasValue() { return at !== null; },
    get value() { return value; },
    get context() { return context; },
    get failed() { return error !== null; },
    get pending() { return pending; },
    start(description = '') { pending = true; requested = description; paint(true); },
    success(payload, description = '') {
      pending = false; moveFocusFrom(host); value = payload; at = new Date(); context = description; requested = description; error = null; paint(false);
    },
    failure(cause, description = '') { pending = false; error = cause; requested = description; paint(false); },
  };
}
