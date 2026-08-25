/* Endlessh Dashboard — shell, router, session, shared helpers. */

export const API_BASE = 'api';
const THEME_KEY = 'endlessh-theme';
const MACHINES_KEY = 'endlessh-machines';
const CSRF_HEADER = 'X-CSRF-Token';

export const WINDOWS = ['24h', '7d', '30d', '90d'];
const DEFAULT_WINDOW = '24h';
export const THEME_DARK = 'dark';
export const THEME_LIGHT = 'light';
export const THEME_SYSTEM = 'system';

const STATUS_OK = 'ok';
const STATUS_DEGRADED = 'degraded';
export const STATUS_DOWN = 'down';
export const STATUS_DISABLED = 'disabled';

export const ATTACKER_TRAPPED = 'trapped';

const DEFAULT_REFRESH_SECONDS = 15;
const MIN_REFRESH_SECONDS = 5;
const MAX_REFRESH_SECONDS = 300;
const TOAST_MS = 5000;
const DEFAULT_ROUTE = 'overview';

const PAGES = {
  overview: () => import('./overview.js'),
  machines: () => import('./machines.js'),
  attackers: () => import('./attackers.js'),
  settings: () => import('./settings.js'),
};

// Routes that no longer exist, and where they went. #/backups was a page in its
// own right until backups moved onto the settings page; a bookmark or an old
// link should land where the feature actually lives rather than silently
// falling back to the overview.
const MOVED_ROUTES = { backups: 'settings' };

/* ---------------- utilities ---------------- */

const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

export function esc(value) {
  if (value === null || value === undefined) return '';
  return String(value).replace(/[&<>"']/g, (ch) => ESCAPES[ch]);
}

export function qs(params) {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue;
    search.set(key, String(value));
  }
  const text = search.toString();
  return text ? '?' + text : '';
}

const ICONS = {
  chevronDown: { vb: 16, body: '<path d="M4 6l4 4 4-4"/>' },
  chevronLeft: { vb: 16, body: '<path d="M10 12L6 8l4-4"/>' },
  sortDown: { vb: 16, body: '<path d="M8 3v10M4 9l4 4 4-4"/>' },
  sortUp: { vb: 16, body: '<path d="M8 13V3M4 7l4-4 4 4"/>' },
  search: { vb: 24, body: '<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>' },
  plus: { vb: 24, body: '<path d="M12 5v14M5 12h14"/>' },
  pencil: { vb: 24, body: '<path d="M4 20h4L18.5 9.5a2.5 2.5 0 0 0-3.5-3.5L4 16.5V20z"/>' },
  trash: { vb: 24, body: '<path d="M4 7h16M10 7V5h4v2M6.5 7l.9 12.1a1 1 0 0 0 1 .9h7.2a1 1 0 0 0 1-.9L17.5 7"/>' },
  download: { vb: 24, body: '<path d="M12 4v11M8 11l4 4 4-4M5 20h14"/>' },
  upload: { vb: 24, body: '<path d="M12 16V5M8 9l4-4 4 4M5 20h14"/>' },
  restore: { vb: 24, body: '<path d="M4 12a8 8 0 1 0 2.4-5.7M4 4.5V9h4.5"/>' },
  refresh: { vb: 24, body: '<path d="M20 12a8 8 0 1 1-2.4-5.7M20 4.5V9h-4.5"/>' },
  logout: { vb: 24, body: '<path d="M16 17l5-5-5-5M21 12H9M12 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h6"/>' },
  server: { vb: 24, body: '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>' },
  alert: { vb: 24, body: '<path d="M12 4l8.5 15h-17z"/><path d="M12 10v4M12 17h.01"/>' },
  check: { vb: 24, body: '<path d="M4 12.5l5 5L20 6.5"/>' },
  info: { vb: 24, body: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 8h.01"/>' },
  archive: { vb: 24, body: '<rect x="3" y="4" width="18" height="5" rx="1.5"/><path d="M5 9v10a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V9M10 13h4"/>' },
};

export function icon(name, size = 16) {
  const spec = ICONS[name];
  if (!spec) return '';
  return `<svg width="${size}" height="${size}" viewBox="0 0 ${spec.vb} ${spec.vb}" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${spec.body}</svg>`;
}

/* ---------------- formatting ---------------- */

const MINUTE = 60;
const HOUR = 3600;
const DAY = 86400;

export function fmtDuration(totalSeconds) {
  const seconds = Math.max(0, Math.round(Number(totalSeconds) || 0));
  if (seconds < MINUTE) return `${seconds}s`;
  const days = Math.floor(seconds / DAY);
  const hours = Math.floor((seconds % DAY) / HOUR);
  const minutes = Math.floor((seconds % HOUR) / MINUTE);
  const rest = seconds % MINUTE;
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${String(minutes).padStart(2, '0')}m`;
  return `${minutes}m ${String(rest).padStart(2, '0')}s`;
}

const BYTE_UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
const BYTE_STEP = 1024;

export function fmtBytes(value) {
  let bytes = Math.max(0, Number(value) || 0);
  let unit = 0;
  while (bytes >= BYTE_STEP && unit < BYTE_UNITS.length - 1) {
    bytes /= BYTE_STEP;
    unit += 1;
  }
  const decimals = unit === 0 || bytes >= 100 ? 0 : 1;
  return `${bytes.toFixed(decimals)} ${BYTE_UNITS[unit]}`;
}

export function fmtNumber(value) {
  return Number(value || 0).toLocaleString();
}

export function fmtRelative(timestamp) {
  if (!timestamp) return 'never';
  const then = new Date(timestamp).getTime();
  if (Number.isNaN(then)) return 'never';
  const seconds = Math.round((Date.now() - then) / 1000);
  if (seconds < 5) return 'just now';
  if (seconds < 0) return 'just now';
  return `${fmtShortDuration(seconds)} ago`;
}

export function fmtShortDuration(totalSeconds) {
  const seconds = Math.max(0, Math.round(totalSeconds));
  if (seconds < MINUTE) return `${seconds}s`;
  if (seconds < HOUR) return `${Math.floor(seconds / MINUTE)}m`;
  if (seconds < DAY) return `${Math.floor(seconds / HOUR)}h`;
  return `${Math.floor(seconds / DAY)}d`;
}

export function fmtDateTime(timestamp) {
  if (!timestamp) return '—';
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  });
}

export function fmtDelta(value, formatter) {
  const number = Number(value) || 0;
  const sign = number < 0 ? '−' : '+';
  return `${sign}${formatter(Math.abs(number))}`;
}

/* ---------------- api ---------------- */

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

let session = null;

export function getSession() {
  return session;
}

export async function api(path, options = {}) {
  const { method = 'GET', body, allowAuthRedirect = true } = options;
  const init = { method, credentials: 'same-origin', headers: {} };

  // A FormData body goes as it is, with no Content-Type of ours: only the
  // browser knows the multipart boundary it has to name in that header.
  if (body instanceof FormData) {
    init.body = body;
  } else if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  if (method !== 'GET' && session && session.csrf_token) {
    init.headers[CSRF_HEADER] = session.csrf_token;
  }

  let response;
  try {
    response = await fetch(API_BASE + path, init);
  } catch (cause) {
    throw new ApiError('Cannot reach the dashboard server.', 0);
  }

  if (response.status === 401) {
    if (allowAuthRedirect) showLogin();
    throw new ApiError('Your session has expired. Please sign in again.', 401);
  }
  if (response.status === 204) return null;

  const isJson = (response.headers.get('Content-Type') || '').includes('json');
  const payload = isJson ? await response.json().catch(() => null) : null;

  if (!response.ok) {
    const message = (payload && payload.error) || `Request failed (${response.status})`;
    throw new ApiError(message, response.status);
  }
  return payload;
}

/* ---------------- toasts ---------------- */

export function toast(message, kind = 'info') {
  const host = document.getElementById('toasts');
  const live = document.getElementById('live');
  const node = document.createElement('div');
  node.className = `toast ${kind}`;
  const glyph = kind === 'error' ? 'alert' : kind === 'success' ? 'check' : 'info';
  node.innerHTML = `${icon(glyph, 16)}<span>${esc(message)}</span>`;
  host.appendChild(node);
  if (live) live.textContent = message;
  setTimeout(() => node.remove(), TOAST_MS);
}

/* ---------------- modal ---------------- */

export function openModal({ title, content, submitLabel = 'Save', cancelLabel = 'Cancel', danger = false, secondary = null, onSubmit }) {
  const dialog = document.getElementById('modal');
  dialog.innerHTML = '';

  const form = document.createElement('form');
  form.noValidate = true;
  form.innerHTML = `
    <div class="modal-head"><h2 class="modal-title" id="modal-title">${esc(title)}</h2></div>
    <div class="modal-body"></div>
    <div class="modal-foot">
      ${secondary ? `<button type="button" class="btn" data-secondary>${esc(secondary.label)}</button>` : ''}
      <button type="button" class="btn" data-close>${esc(cancelLabel)}</button>
      <button type="submit" class="btn ${danger ? 'btn-danger' : 'btn-primary'}">${esc(submitLabel)}</button>
    </div>`;

  const bodyHost = form.querySelector('.modal-body');
  if (typeof content === 'string') bodyHost.innerHTML = content;
  else if (content) bodyHost.appendChild(content);

  const submitButton = form.querySelector('button[type="submit"]');
  form.querySelector('[data-close]').addEventListener('click', () => dialog.close());

  const secondaryButton = form.querySelector('[data-secondary]');
  if (secondaryButton) {
    secondaryButton.addEventListener('click', async () => {
      secondaryButton.disabled = true;
      try {
        await secondary.onClick(form, secondaryButton);
      } finally {
        secondaryButton.disabled = false;
      }
    });
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!form.reportValidity()) return;
    submitButton.disabled = true;
    try {
      const done = await onSubmit(form);
      if (done !== false) dialog.close();
    } finally {
      submitButton.disabled = false;
    }
  });

  dialog.appendChild(form);
  dialog.showModal();
  const firstField = form.querySelector('input, select, textarea');
  if (firstField) firstField.focus();
  else submitButton.focus();
  return dialog;
}

export function confirmModal({ title, message, confirmLabel = 'Confirm', danger = true }) {
  return new Promise((resolve) => {
    let confirmed = false;
    const dialog = openModal({
      title,
      content: message,
      submitLabel: confirmLabel,
      danger,
      onSubmit: () => {
        confirmed = true;
        return true;
      },
    });
    dialog.addEventListener('close', () => resolve(confirmed), { once: true });
  });
}

/* ---------------- shared page helpers ---------------- */

export function renderError(container, error, retry) {
  container.innerHTML = `
    <div class="alert" role="alert">
      ${icon('alert', 18)}
      <span>${esc(error && error.message ? error.message : 'Something went wrong.')}</span>
      ${retry ? '<button type="button" class="btn btn-sm" data-retry>Try again</button>' : ''}
    </div>`;
  const button = container.querySelector('[data-retry]');
  if (button) button.addEventListener('click', retry);
}

export function emptyState({ title, text, actionLabel, glyph = 'server' }) {
  return `
    <div class="empty">
      ${icon(glyph, 28)}
      <p class="empty-title">${esc(title)}</p>
      <p class="empty-text">${esc(text)}</p>
      ${actionLabel ? `<button type="button" class="btn btn-primary" data-empty-action>${esc(actionLabel)}</button>` : ''}
    </div>`;
}

export function statusBadge(status) {
  const map = {
    [STATUS_OK]: ['badge-ok', 'Healthy'],
    [STATUS_DEGRADED]: ['badge-warn', 'Degraded'],
    [STATUS_DOWN]: ['badge-danger', 'Down'],
    [STATUS_DISABLED]: ['', 'Disabled'],
  };
  const [cls, label] = map[status] || ['', status || 'unknown'];
  return `<span class="badge ${cls}">${esc(label)}</span>`;
}

export function statusDot(status) {
  const map = {
    [STATUS_OK]: 'dot-ok',
    [STATUS_DEGRADED]: 'dot-amber',
    [STATUS_DOWN]: 'dot-danger',
    [STATUS_DISABLED]: 'dot-muted',
  };
  return `<span class="dot dot-lg ${map[status] || 'dot-muted'}" aria-hidden="true"></span>`;
}

// PALETTE_SIZE is how many distinct colours the series palette holds before
// everything left over is folded into one "other" colour. The donut and the map
// both rank countries by connections and colour them with paletteClass, so a
// country carries the same colour in both.
export const PALETTE_SIZE = 8;

export function paletteClass(rank) {
  return rank >= 0 && rank < PALETTE_SIZE ? `s-${rank + 1}` : 's-other';
}

/* ---------------- theme ---------------- */

export function getThemePref() {
  const stored = localStorage.getItem(THEME_KEY);
  return stored === THEME_DARK || stored === THEME_LIGHT ? stored : THEME_SYSTEM;
}

export function setThemePref(pref) {
  if (pref === THEME_SYSTEM) localStorage.removeItem(THEME_KEY);
  else localStorage.setItem(THEME_KEY, pref);
  applyTheme();
  document.dispatchEvent(new CustomEvent('theme-changed'));
}

function applyTheme() {
  const pref = getThemePref();
  const root = document.documentElement;
  if (pref === THEME_SYSTEM) root.removeAttribute('data-theme');
  else root.setAttribute('data-theme', pref);
}

/* ---------------- machine selection ---------------- */

let machines = [];
let selected = readSelected();

// An absent key means "never chosen", which reports on every machine. A stored
// empty list means the person deliberately deselected everything, which is a
// different thing and must not silently report on everything instead.
function readSelected() {
  const raw = localStorage.getItem(MACHINES_KEY);
  if (raw === null) return null;
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.map(Number).filter((id) => Number.isFinite(id)) : null;
  } catch (error) {
    return null;
  }
}

function writeSelected() {
  if (selected === null) localStorage.removeItem(MACHINES_KEY);
  else localStorage.setItem(MACHINES_KEY, JSON.stringify(selected));
}

// effectiveSelection is what the dashboard actually reports on: every machine
// when nothing was ever chosen, otherwise exactly what is ticked.
function effectiveSelection() {
  return selected === null ? machines.map((machine) => machine.id) : selected;
}

// How "nothing is ticked" survives a query string. An empty machines= reads as
// "not specified" and reports on every machine, which is the opposite, so the
// deselected-everything case has to send an id instead — one no machine can
// hold. Machine ids come from SQLite AUTOINCREMENT and start at 1, which is the
// whole reason 0 matches nothing. resolveMachines in internal/api/server.go
// stands on the same fact from the other side; neither comment survives alone.
const NO_MACHINES = '0';

export function machinesParam() {
  if (selected === null) return '';
  return selected.length ? selected.join(',') : NO_MACHINES;
}

// seriesIndexForMachine keeps a machine on one colour everywhere: the chart only
// carries the machines the dashboard currently reports on, so its own ordering
// would repaint a machine as soon as the selection changed.
export function seriesIndexForMachine(machineId, fallbackIndex) {
  const index = machines.findIndex((machine) => machine.id === machineId);
  return index < 0 ? fallbackIndex : index;
}

// applySelection records the new selection without redrawing the cards, so the
// checkbox the person just operated keeps the focus.
function applySelection(ids) {
  selected = ids.slice();
  writeSelected();
  paintSelectionSummary();
  document.dispatchEvent(new CustomEvent('machines-changed'));
}

export async function loadMachines() {
  machines = await api('/machines');
  if (selected !== null) {
    const known = new Set(machines.map((machine) => machine.id));
    const pruned = selected.filter((id) => known.has(id));
    if (pruned.length !== selected.length) {
      selected = pruned;
      writeSelected();
    }
  }
  renderSidebar();
  return machines;
}

/* ---------------- sidebar ---------------- */

const SPARK_BUCKETS = 12;
const SPARK_WIDTH = 100;
const SPARK_HEIGHT = 22;
const SPARK_GAP = 2;
const SPARK_FLOOR = 0.1;
const SPARK_MIN_OPACITY = 0.3;
const SPARK_OPACITY_RANGE = 0.55;
const SERIES_COUNT = 3;

function activityValues(machine) {
  const raw = Array.isArray(machine.activity) ? machine.activity : [];
  const values = [];
  for (let index = 0; index < SPARK_BUCKETS; index += 1) {
    const value = Number(raw[index]);
    values.push(Number.isFinite(value) && value > 0 ? value : 0);
  }
  return values;
}

// sparkline scales each machine against its own peak so a quiet machine still
// shows its shape, and falls back to a flat faint row when nothing happened.
function sparkline(machine, index) {
  const values = activityValues(machine);
  const peak = Math.max(...values);
  const barWidth = (SPARK_WIDTH - SPARK_GAP * (SPARK_BUCKETS - 1)) / SPARK_BUCKETS;

  const bars = values.map((value, bucket) => {
    const scaled = peak > 0 ? value / peak : 0;
    const fraction = Math.max(SPARK_FLOOR, scaled);
    const height = fraction * SPARK_HEIGHT;
    const opacity = SPARK_MIN_OPACITY + SPARK_OPACITY_RANGE * scaled;
    return `<rect x="${(bucket * (barWidth + SPARK_GAP)).toFixed(2)}" y="${(SPARK_HEIGHT - height).toFixed(2)}" width="${barWidth.toFixed(2)}" height="${height.toFixed(2)}" rx="1" fill-opacity="${opacity.toFixed(2)}"></rect>`;
  }).join('');

  return `<svg class="spark spark-${(index % SERIES_COUNT) + 1}" viewBox="0 0 ${SPARK_WIDTH} ${SPARK_HEIGHT}" preserveAspectRatio="none" aria-hidden="true" focusable="false">${bars}</svg>`;
}

function unreachableFor(machine) {
  const since = machine.last_ok_at ? new Date(machine.last_ok_at).getTime() : NaN;
  if (!Number.isFinite(since)) return 'unreachable since the dashboard started';
  return `unreachable for ${fmtShortDuration((Date.now() - since) / 1000)}`;
}

function machineCardBody(machine, index) {
  if (machine.status === STATUS_DOWN) {
    return `
      <span class="mcard-bad">${esc(unreachableFor(machine))}</span>
      <span class="mcard-note">last data kept</span>`;
  }
  if (machine.status === STATUS_DISABLED) {
    return '<span class="mcard-note">not scraped while disabled</span>';
  }
  const trapped = Number(machine.trapped_now) || 0;
  return `
    <span class="mcard-count">
      <span class="mcard-num${trapped > 0 ? ' amber' : ''}">${esc(fmtNumber(trapped))}</span>
      <span>trapped now</span>
    </span>
    ${sparkline(machine, index)}
    <span class="mcard-note">scraped ${esc(fmtRelative(machine.last_scrape_at))}</span>`;
}

function machineCard(machine, index) {
  return `
    <div class="mcard${machine.status === STATUS_DOWN ? ' down' : ''}">
      <div class="mcard-top">
        <input type="checkbox" class="mcard-check" value="${machine.id}"
          aria-label="Include ${esc(machine.name)} in the dashboard"
          ${effectiveSelection().includes(machine.id) ? 'checked' : ''}>
        ${statusDot(machine.status)}
        <a class="mcard-link" href="#/machines/${machine.id}">${esc(machine.name)}</a>
        <span class="mcard-port mono">:${esc(machine.port)}</span>
      </div>
      ${machineCardBody(machine, index)}
    </div>`;
}

function paintSelectionSummary() {
  const count = document.getElementById('side-count');
  if (!count) return;
  // The count states what the dashboard is actually reporting on, which is why
  // it reads from the effective selection rather than the stored one.
  const active = effectiveSelection();
  count.textContent = `${active.length} of ${machines.length}`;
  const everySelected = machines.length > 0 && active.length === machines.length;
  document.getElementById('side-all').setAttribute('aria-pressed', String(everySelected));
  document.getElementById('side-none').setAttribute('aria-pressed', String(active.length === 0));
}

function renderSidebar() {
  const list = document.getElementById('side-list');
  if (!list) return;

  paintSelectionSummary();

  if (!machines.length) {
    list.innerHTML = '<p class="side-empty">No machines registered yet.</p>';
    return;
  }

  // A background refresh redraws the whole list, so the reading position of a
  // long sidebar has to be put back by hand.
  const scrollTop = list.scrollTop;
  list.innerHTML = machines.map(machineCard).join('');
  list.scrollTop = scrollTop;

  list.querySelectorAll('.mcard-check').forEach((box) => {
    box.addEventListener('change', () => {
      const ids = Array.from(list.querySelectorAll('.mcard-check:checked')).map((input) => Number(input.value));
      applySelection(ids);
    });
  });
}

function setEveryCheckbox(checked) {
  document.querySelectorAll('.mcard-check').forEach((box) => {
    box.checked = checked;
  });
  applySelection(checked ? machines.map((machine) => machine.id) : []);
}

/* ---------------- window selection ---------------- */

let activeWindow = DEFAULT_WINDOW;

export function getWindow() {
  return activeWindow;
}

export function setWindow(value) {
  if (!WINDOWS.includes(value)) return;
  activeWindow = value;
  document.dispatchEvent(new CustomEvent('window-changed'));
}

export function windowLabel(value = activeWindow) {
  return `the last ${value}`;
}

/* ---------------- auto refresh ---------------- */

const refreshers = new Set();
let refreshTimer = null;
let refreshSeconds = DEFAULT_REFRESH_SECONDS;

export function onRefresh(callback) {
  refreshers.add(callback);
  return () => refreshers.delete(callback);
}

function runRefresh() {
  if (document.hidden) return;
  // No session means the login screen is showing; refreshing would only bounce
  // an unauthenticated request and reset whatever the user is typing.
  if (!session) return;
  // Refresh redraws whole subtrees, which would drop focus and any half-typed
  // value, so a user who is actively using a control keeps what they have.
  if (isUserBusy()) return;
  loadMachines().catch(() => {});
  refreshers.forEach((callback) => {
    try {
      callback();
    } catch (error) {
      /* a failing page refresh must not stop the others */
    }
  });
}

function startRefreshTimer() {
  stopRefreshTimer();
  const period = refreshSeconds * 1000;
  const delay = period - (Date.now() % period);
  refreshTimer = setTimeout(() => {
    runRefresh();
    refreshTimer = setInterval(runRefresh, period);
  }, delay);
}

function stopRefreshTimer() {
  if (refreshTimer === null) return;
  clearTimeout(refreshTimer);
  clearInterval(refreshTimer);
  refreshTimer = null;
}

function setRefreshCadence(seconds) {
  const value = Number(seconds);
  if (!Number.isFinite(value) || value <= 0) return;
  refreshSeconds = Math.min(MAX_REFRESH_SECONDS, Math.max(MIN_REFRESH_SECONDS, Math.round(value)));
  startRefreshTimer();
}

/* ---------------- router ---------------- */

export function navigate(hash) {
  if (location.hash === hash) renderRoute();
  else location.hash = hash;
}

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, '');
  const parts = raw.split('/').filter(Boolean);
  if (parts.length && MOVED_ROUTES[parts[0]]) {
    const moved = MOVED_ROUTES[parts[0]];
    // Rewrite the address rather than only resolving it, so a stale bookmark
    // corrects itself and the URL never disagrees with the page on screen.
    // replaceState keeps it out of the history, so Back still goes back.
    history.replaceState(null, '', `#/${moved}`);
    return { name: moved, param: null };
  }
  if (parts.length && !PAGES[parts[0]]) {
    // An in-page anchor such as the skip link, not a route. Stay on the current
    // page rather than throwing the user back to the default one.
    return { name: currentRoute || DEFAULT_ROUTE, param: currentParam };
  }
  const name = PAGES[parts[0]] ? parts[0] : DEFAULT_ROUTE;
  return { name, param: parts[1] || null };
}

// isUserBusy reports whether the person is mid-interaction with a control, in
// which case a background redraw would take the focus or the text away.
function isUserBusy() {
  const active = document.activeElement;
  if (!active || active === document.body) return false;
  if (document.querySelector('dialog[open]')) return true;
  // A focused chart or map bubble is a reading position as much as a half-typed
  // field is: redrawing under it would drop the keyboard user back to the body.
  return ['INPUT', 'SELECT', 'TEXTAREA'].includes(active.tagName)
    || active.isContentEditable
    || active.matches('[tabindex="0"]');
}

let currentRoute = null;
let currentParam = null;

async function renderRoute() {
  const { name, param } = parseHash();
  currentRoute = name;
  currentParam = param;
  refreshers.clear();

  document.querySelectorAll('.nav-link').forEach((link) => {
    if (link.dataset.route === name) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  });

  const view = document.getElementById('view');
  view.innerHTML = '';
  const mount = document.createElement('div');
  mount.className = 'view';
  view.appendChild(mount);

  try {
    const module = await PAGES[name]();
    if (currentRoute !== name || !mount.isConnected) return;
    await module.render(mount, param);
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) return;
    renderError(mount, error, () => renderRoute());
  }
}

/* ---------------- auth ---------------- */

const appRoot = () => document.getElementById('app');
const authRoot = () => document.getElementById('auth');

// signOutAfterPasswordChange is called by the Settings page: the server has
// already destroyed every session, so the UI must stop pretending to be signed
// in rather than letting the next request fail with a bare 401.
export function signOutAfterPasswordChange() {
  session = null;
  showLogin('Your password was changed. Sign in again.');
}

function showLogin(message) {
  session = null;
  stopRefreshTimer();
  refreshers.clear();
  document.getElementById('boot').hidden = true;
  appRoot().hidden = true;
  authRoot().hidden = false;
  document.getElementById('login-form').hidden = false;
  document.getElementById('force-form').hidden = true;
  const errorNode = document.getElementById('login-error');
  errorNode.hidden = !message;
  errorNode.textContent = message || '';
  document.getElementById('login-user').focus();
}

function showForcedChange() {
  document.getElementById('boot').hidden = true;
  appRoot().hidden = true;
  authRoot().hidden = false;
  document.getElementById('login-form').hidden = true;
  document.getElementById('force-form').hidden = false;
  document.getElementById('force-current').focus();
}

async function startApp() {
  document.getElementById('boot').hidden = true;
  authRoot().hidden = true;
  appRoot().hidden = false;

  try {
    await loadMachines();
  } catch (error) {
    if (!(error instanceof ApiError && error.status === 401)) toast(error.message, 'error');
  }

  api('/settings')
    .then((settings) => setRefreshCadence(settings.scrape_interval_seconds))
    .catch(() => setRefreshCadence(DEFAULT_REFRESH_SECONDS));

  startRefreshTimer();
  renderRoute();
}

async function bootstrap() {
  try {
    session = await api('/session', { allowAuthRedirect: false });
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      showLogin();
      return;
    }
    document.getElementById('boot').innerHTML = '';
    renderError(document.getElementById('boot'), error, () => bootstrap());
    return;
  }
  if (session.must_change_password) showForcedChange();
  else startApp();
}

function wireAuthForms() {
  const loginForm = document.getElementById('login-form');
  const loginError = document.getElementById('login-error');

  loginForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!loginForm.reportValidity()) return;
    const button = loginForm.querySelector('button[type="submit"]');
    button.disabled = true;
    loginError.hidden = true;
    try {
      session = await api('/login', {
        method: 'POST',
        allowAuthRedirect: false,
        body: {
          username: document.getElementById('login-user').value,
          password: document.getElementById('login-pass').value,
        },
      });
      document.getElementById('login-pass').value = '';
      if (session.must_change_password) showForcedChange();
      else startApp();
    } catch (error) {
      loginError.textContent = error.status === 401 ? 'Wrong username or password.' : error.message;
      loginError.hidden = false;
    } finally {
      button.disabled = false;
    }
  });

  const forceForm = document.getElementById('force-form');
  const forceError = document.getElementById('force-error');

  forceForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!forceForm.reportValidity()) return;
    const next = document.getElementById('force-new').value;
    const confirmValue = document.getElementById('force-confirm').value;
    forceError.hidden = true;
    if (next !== confirmValue) {
      forceError.textContent = 'The two new passwords do not match.';
      forceError.hidden = false;
      return;
    }
    const button = forceForm.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      await api('/password', {
        method: 'POST',
        allowAuthRedirect: false,
        body: {
          current_password: document.getElementById('force-current').value,
          new_password: next,
        },
      });
      forceForm.reset();
      // Changing the password invalidates every session, this one included, so
      // there is nothing left to resume: send the user back to a clean sign-in.
      session = null;
      showLogin();
      toast('Password updated. Sign in with your new password.', 'success');
    } catch (error) {
      forceError.textContent = error.message;
      forceError.hidden = false;
    } finally {
      button.disabled = false;
    }
  });
}

async function logout() {
  try {
    await api('/logout', { method: 'POST', allowAuthRedirect: false });
  } catch (error) {
    /* the session is gone either way */
  }
  showLogin('You have been signed out.');
}

/* ---------------- shell wiring ---------------- */

const DRAWER_OPEN_CLASS = 'open';

function isDrawerOpen() {
  return document.getElementById('sidebar').classList.contains(DRAWER_OPEN_CLASS);
}

function setDrawer(open) {
  document.getElementById('sidebar').classList.toggle(DRAWER_OPEN_CLASS, open);
  document.getElementById('scrim').hidden = !open;
  document.getElementById('drawer-btn').setAttribute('aria-expanded', String(open));
}

function wireSidebar() {
  const drawerButton = document.getElementById('drawer-btn');
  drawerButton.innerHTML = icon('server', 16);
  drawerButton.addEventListener('click', () => setDrawer(!isDrawerOpen()));

  document.getElementById('scrim').addEventListener('click', () => setDrawer(false));
  document.getElementById('side-all').addEventListener('click', () => setEveryCheckbox(true));
  document.getElementById('side-none').addEventListener('click', () => setEveryCheckbox(false));

  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape' || !isDrawerOpen()) return;
    setDrawer(false);
    drawerButton.focus();
  });
}

function init() {
  applyTheme();
  wireAuthForms();
  wireSidebar();

  document.getElementById('logout-btn').innerHTML = icon('logout', 16);
  document.getElementById('logout-btn').addEventListener('click', logout);

  window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => {
    if (getThemePref() === THEME_SYSTEM) applyTheme();
  });

  // The skip link points at the main region so it still works without
  // JavaScript, but moving focus directly avoids writing a non-route hash into
  // the address bar at all.
  document.querySelector('.skip-link')?.addEventListener('click', (event) => {
    event.preventDefault();
    document.getElementById('view')?.focus();
  });

  window.addEventListener('hashchange', () => {
    setDrawer(false);
    renderRoute();
  });
  document.addEventListener('machines-changed', () => renderRoute());
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) runRefresh();
  });

  bootstrap();
}

init();
