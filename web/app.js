import { updateWithFocus, focusHeading } from './focus.js';
import { attackerState, attackerHash } from './navigation.js';
import { panelState } from './panel-state.js';
import { latestRequests, isAbortError, serializedRefresh } from './requests.js';
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
const STATUS_STALE = 'stale';
const STATUS_NEVER = 'never_scraped';
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
  grip: { vb: 24, body: '<circle cx="9" cy="6" r="1.4"/><circle cx="15" cy="6" r="1.4"/><circle cx="9" cy="12" r="1.4"/><circle cx="15" cy="12" r="1.4"/><circle cx="9" cy="18" r="1.4"/><circle cx="15" cy="18" r="1.4"/>' },
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
    year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'UTC', timeZoneName: 'short',
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
let loggingOut = false;

export function getSession() {
  return session;
}

export async function api(path, options = {}) {
  const { method = 'GET', body, allowAuthRedirect = true, signal } = options;
  const init = { method, signal, credentials: 'same-origin', headers: {} };
  signal?.throwIfAborted();
  const requestSession = session;

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
    signal?.throwIfAborted();
    if (isAbortError(cause)) throw cause;
    throw new ApiError('Cannot reach the dashboard server.', 0);
  }

  signal?.throwIfAborted();
  if (response.status === 401) {
    if (allowAuthRedirect && requestSession === session) showLogin();
    throw new ApiError('Your session has expired. Please sign in again.', 401);
  }
  if (response.status === 204) return null;

  const isJson = (response.headers.get('Content-Type') || '').includes('json');
  const payload = isJson ? await response.json().catch(() => null) : null;

  signal?.throwIfAborted();
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
    [STATUS_STALE]: ['badge-warn', 'Stale'],
    [STATUS_NEVER]: ['', 'No successful scrape'],
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
    [STATUS_STALE]: 'dot-amber',
    [STATUS_NEVER]: 'dot-muted',
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

// How many colours a machine can be given. Larger than PALETTE_SIZE, which
// bounds the ranked country colours on the map and the donut: those are derived
// and only ever need enough to tell the busiest few apart, while a machine
// colour is chosen by hand and wants real variety. Mirrors registry.PaletteSize
// and the .s-N classes in app.css; all three move together.
export const MACHINE_PALETTE_SIZE = 16;

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

// The order the operator dragged the sidebar into lives on the server, in the
// machines table, not in this browser. There is one administrator and one
// dashboard: an arrangement that only applied on the laptop it was made on
// would look forgotten every time the phone was opened. `machines` therefore
// arrives already ordered, and the sidebar simply draws it.
//
// Reordering is applied here first and saved afterwards, so a drag lands
// instantly rather than waiting on a round trip; if the save fails the list is
// reloaded from the server, which is the only thing that can say what the order
// really is.
async function persistMachineOrder() {
  const ids = machines.map((machine) => machine.id);
  try {
    await api('/machines/order', { method: 'PUT', body: { machine_ids: ids } });
  } catch (error) {
    if (error.status === 401) return;
    toast('Could not save the new order.', 'error');
    await loadMachines();
    renderSidebar();
  }
}

// moveMachine shifts one machine by delta places. Returns where it landed, so
// the caller can say so out loud for anyone not watching the sidebar.
function moveMachine(machineId, delta) {
  const from = machines.findIndex((machine) => machine.id === machineId);
  const to = from + delta;
  if (from < 0 || to < 0 || to >= machines.length) return null;
  machines.splice(to, 0, machines.splice(from, 1)[0]);
  persistMachineOrder();
  return { position: to + 1, total: machines.length };
}

// dropMachineOn moves the dragged machine to where the one it was dropped on
// sits, pushing that one along rather than swapping the two: a swap is what
// people expect least from a list they are dragging within.
function dropMachineOn(draggedId, targetId) {
  if (draggedId === targetId) return false;
  const from = machines.findIndex((machine) => machine.id === draggedId);
  const to = machines.findIndex((machine) => machine.id === targetId);
  if (from < 0 || to < 0) return false;
  machines.splice(to, 0, machines.splice(from, 1)[0]);
  persistMachineOrder();
  return true;
}

// effectiveSelection is what the dashboard actually reports on: every machine
// when nothing was ever chosen, otherwise exactly what is ticked.
function effectiveSelection() {
  return selected === null ? machines.map((machine) => machine.id) : selected;
}

// How "nothing is ticked" survives a query string. An empty machines= reads as
// "not specified" and reports on enabled machines, which is the opposite, so the
// deselected-everything case has to send an id instead — one no machine can
// hold. Machine ids come from SQLite AUTOINCREMENT and start at 1, which is the
// whole reason 0 matches nothing. resolveMachines in internal/api/server.go
// stands on the same fact from the other side; neither comment survives alone.
const NO_MACHINES = '0';

export function machinesParam() {
  const ids = effectiveSelection();
  return ids.length ? ids.join(',') : NO_MACHINES;
}

// machineColour is the palette class a machine is drawn in, everywhere: the chart only
// carries the machines the dashboard currently reports on, so its own ordering
// would repaint a machine as soon as the selection changed.
export function machineColour(machineId, fallbackIndex = 0) {
  const machine = machines.find((candidate) => candidate.id === machineId);
  if (machine && machine.colour) return machine.colour;
  // Only for a machine registered before colours were stored, or one the list
  // has not caught up with. Ranked by id rather than by position, so even the
  // fallback cannot move when the sidebar is dragged.
  const ranked = machines.map((candidate) => candidate.id).sort((left, right) => left - right);
  const index = ranked.indexOf(machineId);
  return paletteClass((index < 0 ? fallbackIndex : index) % PALETTE_SIZE);
}

// applySelection records the new selection without redrawing the cards, so the
// checkbox the person just operated keeps the focus.
function applySelection(ids) {
  selected = ids.slice();
  writeSelected();
  paintSelectionSummary();
  document.dispatchEvent(new CustomEvent('machines-changed'));
}

// currentMachines is the list as it was last loaded. Views read this instead of
// fetching a copy each: the refresh tick loads it once for all of them before
// calling any, and the first mount happens after startApp has loaded it, so a
// view asking again would only repeat a request that has just been answered.
//
// Anything that has just changed the list itself must not wait for the next
// tick — those paths call loadMachines directly.
export function currentMachines() {
  return machines;
}

const machineRequests = latestRequests();
let machineState = null;
export function machineListKnown() { return Boolean(machineState?.hasValue && !machineState.failed); }
export async function loadMachines() {
  if (!session || loggingOut) return machines;
  if (!machineState) {
    const host = document.createElement('div');
    host.id = 'side-refresh-state'; host.className = 'side-refresh-state';
    document.getElementById('side-list').before(host);
    machineState = panelState(host, 'machines', () => runRefresh());
  }
  const request = machineRequests.begin();
  machineState.start('registered machines');
  try {
    const loaded = await api('/machines', { signal: request.signal });
    if (!request.isCurrent() || !session) return machines;
    machines = loaded;
    machineState.success(loaded, 'registered machines');
    if (selected !== null) {
      const known = new Set(machines.map((machine) => machine.id));
      const pruned = selected.filter((id) => known.has(id));
      if (pruned.length !== selected.length) { selected = pruned; writeSelected(); }
    }
    renderSidebar();
    return machines;
  } catch (error) {
    if (request.isCurrent() && !isAbortError(error) && error.status !== 401) machineState.failure(error, 'registered machines');
    throw error;
  }
}

/* ---------------- sidebar ---------------- */

const SPARK_BUCKETS = 12;
const SPARK_WIDTH = 100;
const SPARK_HEIGHT = 22;
const SPARK_GAP = 2;
const SPARK_FLOOR = 0.1;
const SPARK_MIN_OPACITY = 0.3;
const SPARK_OPACITY_RANGE = 0.55;

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
// shows its shape; unknown or incomplete observations are shaded.
function sparkline(machine, index) {
  const values = activityValues(machine);
  const peak = Math.max(...values);
  const barWidth = (SPARK_WIDTH - SPARK_GAP * (SPARK_BUCKETS - 1)) / SPARK_BUCKETS;

  const bars = values.map((value, bucket) => {
    const scaled = peak > 0 ? value / peak : 0;
    const fraction = Math.max(SPARK_FLOOR, scaled);
    const height = fraction * SPARK_HEIGHT;
    const opacity = SPARK_MIN_OPACITY + SPARK_OPACITY_RANGE * scaled;
    if (machine.activity_coverage?.[bucket] !== 'complete' && value === 0) return `<rect x="${(bucket * (barWidth + SPARK_GAP)).toFixed(2)}" y="0" width="${barWidth.toFixed(2)}" height="${SPARK_HEIGHT}" class="spark-gap"></rect>`;
    const gap = machine.activity_coverage?.[bucket] !== 'complete' ? `<rect x="${(bucket * (barWidth + SPARK_GAP)).toFixed(2)}" y="0" width="${barWidth.toFixed(2)}" height="${SPARK_HEIGHT}" class="spark-gap"></rect>` : '';
    return gap + `<rect x="${(bucket * (barWidth + SPARK_GAP)).toFixed(2)}" y="${(SPARK_HEIGHT - height).toFixed(2)}" width="${barWidth.toFixed(2)}" height="${height.toFixed(2)}" rx="1" fill="currentColor" fill-opacity="${opacity.toFixed(2)}"></rect>`;
  }).join('');

  // The same palette class the chart and the map use, keyed to the machine
  // rather than to where it currently sits: dragging a card must move it, not
  // repaint it. It carried its own three-colour cycle over the display index
  // before, so the first and fourth cards in the sidebar were the same blue.
  const colour = machineColour(machine.id, index);
  return `<svg class="spark ${esc(colour)}" viewBox="0 0 ${SPARK_WIDTH} ${SPARK_HEIGHT}" preserveAspectRatio="none" aria-hidden="true" focusable="false">${bars}</svg>`;
}

function unreachableFor(machine) {
  const since = machine.last_ok_at ? new Date(machine.last_ok_at).getTime() : NaN;
  if (!Number.isFinite(since)) return 'unreachable since the dashboard started';
  return `unreachable for ${fmtShortDuration((Date.now() - since) / 1000)}`;
}

function machineCardBody(machine, index) {
  if (machine.status === STATUS_STALE || machine.status === STATUS_NEVER) {
    return `<span class="mcard-note">${machine.status === STATUS_STALE ? 'stale · last success ' + esc(fmtRelative(machine.last_ok_at)) : 'no successful scrape yet'}</span><span class="mcard-note">${machine.last_scrape_at ? 'last attempt ' + esc(fmtRelative(machine.last_scrape_at)) : 'waiting for first attempt'} · retained data kept</span>`;
  }
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
      <span title="Distinct IPs with recent sampled counter growth">recently active IPs</span>
    </span>
    ${sparkline(machine, index)}
    <span class="mcard-note">success ${esc(fmtRelative(machine.last_ok_at))} · gaps shaded</span>`;
}

function machineCard(machine, index) {
  return `
    <div class="mcard${machine.status === STATUS_DOWN ? ' down' : ''}" data-machine="${machine.id}">
      <div class="mcard-top">
        <button type="button" class="mcard-grip" draggable="true" data-grip="${machine.id}"
          aria-label="Reorder ${esc(machine.name)}. Drag, or press the up and down arrow keys."
          title="Drag to reorder">${icon('grip', 14)}</button>
        <input type="checkbox" class="mcard-check" value="${machine.id}"
          aria-label="Include ${esc(machine.name)} in the dashboard${machine.enabled ? '' : ' (disabled history)'}"
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

  return updateWithFocus(list, () => {
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

  wireReordering(list);
  });
}

// Redraw after a reorder and put the keyboard back where it was. Without this
// the card moves out from under the focus and the next arrow press goes
// nowhere, which makes keyboard reordering unusable after the first step.
function renderSidebarKeepingGripFocus(machineId) {
  renderSidebar();
  const grip = document.querySelector(`.mcard-grip[data-grip="${machineId}"]`);
  if (grip) grip.focus();
}

function announce(message) {
  const live = document.getElementById('live');
  if (live) live.textContent = message;
}

// draggedId is the machine being dragged, or null. It sits at module scope
// because the refresh tick has to be able to see it: a redraw during a drag
// replaces the very element under the pointer, and the browser cancels the drag.
let draggedId = null;

// wireReordering gives the sidebar both ways to reorder: dragging for a pointer,
// and the arrow keys for anyone who cannot drag — a mouse-only affordance would
// put the feature out of reach of keyboard and screen-reader users entirely.
function wireReordering(list) {
  // Every render rewires from scratch, and a drag that was in flight died with
  // the elements it began on. Clearing here is what stops a drag whose grip no
  // longer exists from leaving the flag set and freezing refresh for good.
  draggedId = null;

  const clearDropStyling = () => {
    list.querySelectorAll('.mcard').forEach((card) => card.classList.remove('drop-target', 'dragging'));
  };

  list.querySelectorAll('.mcard-grip').forEach((grip) => {
    const machineId = Number(grip.dataset.grip);

    grip.addEventListener('dragstart', (event) => {
      draggedId = machineId;
      // Some browsers refuse to start a drag with no payload set.
      event.dataTransfer.setData('text/plain', String(machineId));
      event.dataTransfer.effectAllowed = 'move';
      grip.closest('.mcard').classList.add('dragging');
    });

    grip.addEventListener('dragend', () => {
      draggedId = null;
      clearDropStyling();
    });

    grip.addEventListener('keydown', (event) => {
      const delta = event.key === 'ArrowUp' ? -1 : event.key === 'ArrowDown' ? 1 : 0;
      if (!delta) return;
      // The arrows would otherwise scroll the sidebar out from under the card.
      event.preventDefault();
      const moved = moveMachine(machineId, delta);
      if (!moved) return;
      const name = machines.find((machine) => machine.id === machineId);
      announce(`${name ? name.name : 'Machine'} moved to position ${moved.position} of ${moved.total}.`);
      renderSidebarKeepingGripFocus(machineId);
    });
  });

  list.querySelectorAll('.mcard').forEach((card) => {
    card.addEventListener('dragover', (event) => {
      if (draggedId === null) return;
      event.preventDefault();
      event.dataTransfer.dropEffect = 'move';
      if (Number(card.dataset.machine) !== draggedId) card.classList.add('drop-target');
    });

    card.addEventListener('dragleave', () => card.classList.remove('drop-target'));

    card.addEventListener('drop', (event) => {
      event.preventDefault();
      const targetId = Number(card.dataset.machine);
      const moving = draggedId;
      draggedId = null;
      clearDropStyling();
      if (moving !== null && dropMachineOn(moving, targetId)) renderSidebar();
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

export function onRefresh(callback, signal = currentView?.signal) {
  if (signal?.aborted) return () => {};
  refreshers.add(callback);
  const remove = () => { refreshers.delete(callback); signal?.removeEventListener('abort', remove); };
  signal?.addEventListener('abort', remove, { once: true });
  return remove;
}

const refreshRound = serializedRefresh();
function runRefresh() {
  return refreshRound(async () => {
    if (document.hidden) return;
    // No session means the login screen is showing; refreshing would only bounce
    // an unauthenticated request and reset whatever the user is typing.
    if (!session || loggingOut) return;
    // Refresh redraws whole subtrees, which would drop focus and any half-typed
    // value, so a user who is actively using a control keeps what they have.
    if (isUserBusy()) return;
    // Awaited, so the views that follow read a list that is already current and
    // ask for it none more times between them.
    const view = currentView;
    const callbacks = [...refreshers];
    await loadMachines().catch(() => {});
    if (!session || view !== currentView || view?.signal.aborted) return;
    await Promise.allSettled(callbacks.map((callback) => Promise.resolve().then(() => {
      if (refreshers.has(callback) && view === currentView && !view?.signal.aborted) return callback();
    })));
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
  const [path, search = ''] = raw.split('?');
  const query = new URLSearchParams(search);
  const parts = path.split('/').filter(Boolean);
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
  return { name, param: parts[1] || null, query };
}

// isUserBusy reports whether the person is mid-interaction with a control, in
// which case a background redraw would take the focus or the text away.
function isUserBusy() {
  // A drag in flight comes first, because the browser parks focus on the body
  // for the duration of one — so every test below would say nobody is busy at
  // the exact moment a redraw would cancel what they are doing.
  if (draggedId !== null) return true;

  const active = document.activeElement;
  if (!active || active === document.body) return false;
  if (document.querySelector('dialog[open]')) return true;
  // A held grip is mid-reorder before any key is pressed. It is a <button>, so
  // it is natively focusable and matches none of the tests below.
  if (active.classList.contains('mcard-grip')) return true;
  return ['INPUT', 'SELECT', 'TEXTAREA'].includes(active.tagName)
    || active.isContentEditable;
}

let currentView = null;
let currentRoute = null;
let currentParam = null;

async function renderRoute({focus = true} = {}) {
  currentView?.dispose();
  refreshers.clear();
  if (!session || loggingOut) return;
  const viewScope = latestRequests();
  currentView = viewScope;
  const { name, param, query = new URLSearchParams() } = parseHash();
  if (name === 'attackers') {
    if (WINDOWS.includes(query.get('window'))) activeWindow = query.get('window');
    if (query.has('machines')) {
      const ids = query.get('machines').split(',').filter(id => /^[1-9]\d*$/.test(id)).map(Number).filter(Number.isSafeInteger);
      const known = new Set(machines.map(machine => machine.id));
      selected = [...new Set(ids)].filter(id => !machineListKnown() || known.has(id));
      writeSelected(); renderSidebar();
    }
  }
  currentRoute = name;
  currentParam = param;

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
    if (viewScope !== currentView || viewScope.signal.aborted || !mount.isConnected) return;
    const rendering = module.render(mount, param, viewScope.signal, query);
    const heading = focus && !isDrawerOpen() ? focusHeading(mount) : null;
    await rendering;
    if (heading && !heading.isConnected && viewScope === currentView && !viewScope.signal.aborted && document.activeElement === document.body) focusHeading(mount);
  } catch (error) {
    if (viewScope !== currentView || viewScope.signal.aborted || isAbortError(error)) return;
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
  setDrawer(false, {restore:false});
  loggingOut = false;
  currentView?.dispose();
  currentView = null;
  machineRequests.cancel();
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
  const startingSession = session;
  document.getElementById('boot').hidden = true;
  authRoot().hidden = true;
  appRoot().hidden = false;

  try {
    await loadMachines();
  } catch (error) {
    if (!isAbortError(error) && session === startingSession && !loggingOut && !(error instanceof ApiError && error.status === 401)) toast(error.message, 'error');
  }

  if (!session || loggingOut || session !== startingSession) return;
  api('/settings')
    .then((settings) => { if (session === startingSession && !loggingOut) setRefreshCadence(settings.scrape_interval_seconds); })
    .catch(() => { if (session === startingSession && !loggingOut) setRefreshCadence(DEFAULT_REFRESH_SECONDS); });

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
  loggingOut = true;
  currentView?.dispose();
  machineRequests.cancel();
  stopRefreshTimer();
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

const drawerMedia = window.matchMedia('(max-width: 900px)');
let drawerReturn = null;
function setDrawer(open, {restore = true} = {}) {
  const sidebar = document.getElementById('sidebar');
  const button = document.getElementById('drawer-btn');
  const wasOpen = isDrawerOpen();
  open = Boolean(open && drawerMedia.matches);
  if (open && !wasOpen) drawerReturn = document.activeElement;
  sidebar.classList.toggle(DRAWER_OPEN_CLASS, open);
  sidebar.setAttribute('role', open ? 'dialog' : 'complementary');
  if (open) sidebar.setAttribute('aria-modal','true'); else sidebar.removeAttribute('aria-modal');
  document.getElementById('drawer-close').hidden = !open;
  document.getElementById('scrim').hidden = !open;
  button.setAttribute('aria-expanded', String(open));
  for (const node of document.querySelectorAll('.topbar,#view,.skip-link')) node.inert = open;
  if (open && !wasOpen) document.getElementById('drawer-close').focus();
  else if (wasOpen && restore && drawerMedia.matches) (drawerReturn?.isConnected ? drawerReturn : button).focus({preventScroll:true});
}

function wireSidebar() {
  const drawerButton = document.getElementById('drawer-btn');
  drawerButton.innerHTML = icon('server', 16);
  drawerButton.addEventListener('click', () => setDrawer(!isDrawerOpen()));

  document.getElementById('drawer-close').addEventListener('click', () => setDrawer(false));
  drawerMedia.addEventListener('change', () => {
    const closeFocused = document.activeElement === document.getElementById('drawer-close');
    setDrawer(false, {restore:drawerMedia.matches});
    if (closeFocused && !drawerMedia.matches) document.getElementById('side-all').focus();
  });

  document.getElementById('scrim').addEventListener('click', () => setDrawer(false));
  document.getElementById('side-all').addEventListener('click', () => setEveryCheckbox(true));
  document.getElementById('side-none').addEventListener('click', () => setEveryCheckbox(false));

  document.addEventListener('keydown', (event) => {
    if (!isDrawerOpen() || !drawerMedia.matches) return;
    if (event.key === 'Escape') { event.preventDefault(); setDrawer(false); return; }
    if (event.key !== 'Tab') return;
    const sidebar = document.getElementById('sidebar');
    const controls = [...sidebar.querySelectorAll('button,a[href],input,select,textarea,[tabindex="0"]')]
      .filter(node => !node.disabled && node.getClientRects().length);
    const first = controls[0], last = controls.at(-1);
    if (event.shiftKey && (document.activeElement === first || !sidebar.contains(document.activeElement))) { event.preventDefault(); last?.focus(); }
    else if (!event.shiftKey && (document.activeElement === last || !sidebar.contains(document.activeElement))) { event.preventDefault(); first?.focus(); }
  });
  document.addEventListener('focusin', event => {
    if (isDrawerOpen() && drawerMedia.matches && !document.getElementById('sidebar').contains(event.target)) document.getElementById('drawer-close').focus();
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
    setDrawer(false, {restore:false});
    renderRoute();
  });
  document.addEventListener('machines-changed', () => {
    if (parseHash().name === 'attackers') {
      const query = parseHash().query;
      const state = attackerState(query);
      const previous = (query?.get('machines') || '0').split(',').sort().join(',');
      const next = machinesParam().split(',').sort().join(',');
      if (previous !== next) state.page = 1;
      history.replaceState(history.state,'',attackerHash(state,machinesParam(),getWindow()));
    }
    renderRoute({focus:false});
  });
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) runRefresh();
  });

  bootstrap();
}

init();
