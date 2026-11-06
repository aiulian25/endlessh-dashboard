import { updateWithFocus } from './focus.js';
import { attackerState, rememberAttackers } from './navigation.js';
import { panelState } from './panel-state.js';
import { latestRequests, isAbortError } from './requests.js';
import { countrySummaryLabel } from './country.js';
import { activityLabel, activityNote, scrapeNote, CUMULATIVE_NOTE, CONNECTION_TIME_NOTE } from './metric-notes.js';
import { rangeParams } from './time-range.js';
/* Attackers page plus the shared attackers-table renderer. */

import {
  api, qs, esc, icon, onRefresh, emptyState,
  fmtDuration, fmtNumber, fmtRelative, fmtDateTime,
  machinesParam, getWindow, currentMachines, ATTACKER_TRAPPED,
} from './app.js';

const PER_PAGE = 50;
const SEARCH_DEBOUNCE_MS = 300;
const TOP_COUNTRIES = 5;

const SORT_TRAPPED = 'trapped_seconds';
const SORT_LAST_SEEN = 'last_seen';
const SORT_FIRST_SEEN = 'first_seen';
const SORT_CONNECTIONS = 'connections';

const STATUS_FILTERS = [
  { value: '', label: 'Status: all' },
  { value: 'trapped', label: 'Status: recently active' },
  { value: 'gave_up', label: 'Status: no recent measured activity' },
  { value: 'unknown', label: 'Status: activity time unknown' },
];

// Only ever the ISO code. The badge is a fixed-width chip, and a tarpit's own
// labels carry a country name but never a code — falling back to the name put
// "United Kingdom" in a two-character box and pushed it over the address beside
// it. The country is not lost: the location column beside this one begins with
// it, and the whole column hides itself when no row has a code to show.
function countryBadgeText(row) {
  return row.country_code || '';
}

function statusCell(row) {
  return `<span class="badge activity-badge ${row.status === ATTACKER_TRAPPED ? 'badge-warn' : ''}">${esc(activityLabel(row.status))}</span>`;
}

const COLUMNS = {
  country: {
    label: 'Ctry',
    optional: (row) => countryBadgeText(row),
    // The badge is two characters wide, so it shows the code whenever there is
    // one and keeps the full name on the title for anyone who wants it.
    cell: (row) => {
      const text = countryBadgeText(row);
      if (!text) return '';
      return `<span class="ctry" title="${esc(row.country || text)}">${esc(text)}</span>`;
    },
  },
  ip: { label: 'Client IP', cls: 'mono', cell: (row) => esc(row.ip) },
  location: {
    label: 'Location',
    optional: (row) => row.location,
    cls: 'wrap',
    cell: (row) => esc(row.location),
  },
  isp: {
    label: 'ISP',
    optional: (row) => row.isp,
    cls: 'wrap',
    cell: (row) => esc(row.isp),
  },
  machine: { label: 'Machine', cell: (row) => esc(row.machine_name) },
  trapped: { label: 'Connection time (cumulative)', sort: SORT_TRAPPED, cls: 'mono', cell: (row) => `${esc(fmtDuration(row.trapped_seconds))}${row.has_undated_history ? '<span title="Includes undated imported or legacy history">*</span>' : ''}` },
  connections: { label: 'Connections (cumulative)', sort: SORT_CONNECTIONS, cls: 'mono num', cell: (row) => `${esc(fmtNumber(row.connections))}${row.has_undated_history ? '<span title="Includes undated imported or legacy history">*</span>' : ''}` },
  first_seen: { label: 'First observed', sort: SORT_FIRST_SEEN, cell: (row) => `<span title="${esc(fmtDateTime(row.first_seen))}">${row.first_observation_known === false ? 'Earlier observation unknown' : esc(fmtRelative(row.first_seen))}</span>` },
  last_seen: { label: 'Last observed', sort: SORT_LAST_SEEN, cell: (row) => `<span title="${esc(fmtDateTime(row.last_seen))}">${esc(fmtRelative(row.last_seen))}</span>` },
  last_activity: { label: 'Last measured activity', sort: 'last_activity', cell: (row) => row.last_measured_activity_at ? `<span title="${esc(fmtDateTime(row.last_measured_activity_at))}">${esc(fmtRelative(row.last_measured_activity_at))}</span>` : 'Unknown' },
  status: { label: 'Status', cell: statusCell },
};

function isNumeric(column) {
  return (column.cls || '').split(' ').includes('num');
}

function headerCell(key, column, state) {
  if (!column.sort || !state.onSort) {
    return `<th scope="col" class="${isNumeric(column) ? 'num' : ''}">${esc(column.label)}</th>`;
  }
  const active = state.sort === column.sort;
  const ariaSort = active ? (state.order === 'asc' ? 'ascending' : 'descending') : 'none';
  const glyph = icon(active && state.order === 'asc' ? 'sortUp' : 'sortDown', 10);
  return `<th scope="col" aria-sort="${ariaSort}" class="${isNumeric(column) ? 'num' : ''}">
      <button type="button" class="sort-btn" data-sort="${esc(column.sort)}" data-active="${active}">${esc(column.label)}${glyph}</button>
    </th>`;
}

export function renderAttackersTable(host, rows, state = {}) {
  const keys = (state.columns || Object.keys(COLUMNS)).filter((key) => {
    const column = COLUMNS[key];
    if (!column) return false;
    if (!column.optional) return true;
    return rows.some((row) => column.optional(row));
  });

  if (!rows.length) {
    host.innerHTML = emptyState({
      title: 'No attackers match',
      text: 'No retained machine/IP rows match this filter. Widen the range or clear the filters.',
      glyph: 'search',
    });
    return;
  }

  const body = rows.map((row) => `
    <tr>${keys.map((key) => {
      const column = COLUMNS[key];
      return `<td class="${column.cls || ''}">${column.cell(row)}</td>`;
    }).join('')}</tr>`).join('');

  host.innerHTML = `
    <div class="table-wrap">
      <table class="tbl">
        <thead><tr>${keys.map((key) => headerCell(key, COLUMNS[key], state)).join('')}</tr></thead>
        <tbody>${body}</tbody>
      </table>
    </div>`;

  if (!state.onSort) return;
  host.querySelectorAll('[data-sort]').forEach((button) => {
    button.addEventListener('click', () => state.onSort(button.dataset.sort));
  });
}

/* ---------------- page ---------------- */

const PAGE_COLUMNS = ['country', 'ip', 'location', 'isp', 'machine', 'trapped', 'connections', 'first_seen', 'last_activity', 'last_seen', 'status'];

export async function render(mount, param, routeSignal, query = new URLSearchParams()) {
  const requests = latestRequests(routeSignal);
  const countryRequests = latestRequests(routeSignal);
  const state = attackerState(query);

  mount.innerHTML = `
    <div class="page-head">
      <h1 class="page-title">Attackers</h1>
      <span class="page-sub" id="attackers-note">Loading…</span>
    </div>
    <p class="filters-note" id="attackers-scope"></p>
    <div class="filters">
      <div class="search">
        ${icon('search', 15)}
        <input id="attackers-q" type="search" placeholder="Search by IP…" aria-label="Search attackers by IP prefix" autocapitalize="none" spellcheck="false">
      </div>
      <select class="select select-inline" id="attackers-basis" aria-label="Choose range time basis">
        <option value="activity">Range: measured activity</option>
        <option value="observed">Range: exporter observation</option>
      </select>
      <select class="select select-inline" id="attackers-country" aria-label="Filter by country"></select>
      <select class="select select-inline" id="attackers-status" aria-label="Filter by status">
        ${STATUS_FILTERS.map((option) => `<option value="${esc(option.value)}">${esc(option.label)}</option>`).join('')}
      </select>
    </div>
    <p class="filters-note" id="attackers-metric-note"></p>
    <details class="metric-details"><summary>About activity, totals and dates</summary><p class="filters-note">${esc(CUMULATIVE_NOTE)} ${esc(CONNECTION_TIME_NOTE)} Positive sampled growth identifies a recently active IP. IP addresses can represent several connections or people. Country counts are distinct IPs across selected machines and the chosen range/basis, before search and status filters. Dates use UTC.</p></details>
    <div id="attackers-country-state"></div>
    <p class="filters-note" id="attackers-country-empty" hidden>No known countries in this range and time basis.</p>
    <div class="chips" id="attackers-chips"></div>
    <div id="attackers-row-state"></div>
    <div class="card" id="attackers-card">
      <div class="card-pad"><div class="skeleton w60"></div></div>
    </div>`;

  const note = mount.querySelector('#attackers-note');
  const card = mount.querySelector('#attackers-card');
  const chips = mount.querySelector('#attackers-chips');
  const basisSelect = mount.querySelector('#attackers-basis');
  const countrySelect = mount.querySelector('#attackers-country');
  const statusSelect = mount.querySelector('#attackers-status');
  const searchInput = mount.querySelector('#attackers-q');
  searchInput.value = state.q; basisSelect.value = state.basis; statusSelect.value = state.status;
  const ids = machinesParam().split(',');
  const names = currentMachines().filter(machine => ids.includes(String(machine.id)))
    .map(machine => `${machine.name}${machine.enabled ? '' : ' (disabled history)'}`);
  mount.querySelector('#attackers-scope').textContent = `Scope: ${names.length ? names.join(', ') : machinesParam() === '0' ? 'no machines selected' : 'selected machines'}. Range: ${getWindow()}.`;


  let countries = [];
  countrySelect.innerHTML = '<option value="">Country: all</option>';
  const rowState = panelState(mount.querySelector('#attackers-row-state'), 'attacker rows', () => load());
  const countryState = panelState(mount.querySelector('#attackers-country-state'), 'country choices', () => loadCountries());
  const describe = context => `${context.range.window}, ${context.basis === 'observed' ? 'exporter observations' : 'measured activity'}`;

  let activeRange = rangeParams(getWindow());
  const load = async (range = activeRange) => {
    clearTimeout(debounce);
    const request = requests.begin();
    if (!request.isCurrent()) return;
    rememberAttackers(state, machinesParam(), getWindow());
    const context = Object.freeze({ ...state, machines: machinesParam(), range: { ...range } });
    const description = `${describe(context)}, ${sortLabel(context.sort)}, page ${context.page}${context.q ? `, search ${context.q}` : ''}${context.country ? `, country ${context.country.replace(/^(code|name):/, '')}` : ''}${context.status ? `, ${activityLabel(context.status)}` : ''}`;
    rowState.start(description);
    try {
      const data = await api('/attackers' + qs({
        machines: context.machines,
        ...context.range,
        basis: context.basis,
        q: context.q,
        country_key: context.country,
        status: context.status,
        sort: context.sort,
        order: context.order,
        page: context.page,
        per_page: PER_PAGE,
      }), { signal: request.signal });
      if (!request.isCurrent()) return;
      state.total = data.total;
      paint(data, context);
      rowState.success(data, description);
    } catch (error) {
      if (!request.isCurrent() || isAbortError(error)) return;
      if (error.status === 401) return;
      rowState.failure(error, description);
      if (!rowState.hasValue) { card.innerHTML = ''; note.textContent = ''; }
    }
  };

  const paint = (data, context) => updateWithFocus(card, () => {
    const rows = data.rows || [];
    const first = rows.length ? (data.page - 1) * data.per_page + 1 : 0;
    const last = (data.page - 1) * data.per_page + rows.length;
    note.textContent = `${fmtNumber(data.total)} machine/IP ${data.total === 1 ? 'row' : 'rows'} · ${fmtNumber(data.distinct_ips)} distinct ${data.distinct_ips === 1 ? 'IP' : 'IPs'} · sorted by ${sortLabel(context.sort)}`;
    mount.querySelector('#attackers-metric-note').textContent = `${context.basis === 'observed' ? 'Range selects exporter observations, including unchanged samples.' : 'Range selects last measured counter growth.'} ${activityNote(data.activity?.threshold_seconds)} ${scrapeNote(data.activity)} UTC ${data.from} → ${data.to} (end excluded).`;

    card.innerHTML = '<div id="attackers-table"></div><div class="card-foot" id="attackers-foot"></div>';
    renderAttackersTable(card.querySelector('#attackers-table'), rows, {
      columns: PAGE_COLUMNS,
      sort: context.sort,
      order: context.order,
      onSort: (key) => {
        if (state.sort === key) state.order = state.order === 'desc' ? 'asc' : 'desc';
        else {
          state.sort = key;
          state.order = 'desc';
        }
        state.page = 1;
        load();
      },
    });

    const maxPage = Math.max(1, Math.ceil(data.total / data.per_page));
    card.querySelector('#attackers-foot').innerHTML = `
      <span class="filters-note grow">Showing ${fmtNumber(first)}–${fmtNumber(last)} of ${fmtNumber(data.total)}</span>
      <div class="pagination">
        <button type="button" class="btn btn-sm" data-prev ${data.page <= 1 ? 'disabled' : ''}>Prev</button>
        <button type="button" class="btn btn-sm btn-primary" data-next ${data.page >= maxPage ? 'disabled' : ''}>Next</button>
      </div>`;

    card.querySelector('[data-prev]').addEventListener('click', () => {
      state.page = Math.max(1, state.page - 1);
      load();
    });
    card.querySelector('[data-next]').addEventListener('click', () => {
      state.page = Math.min(maxPage, state.page + 1);
      load();
    });
  }, requests.signal);

  const paintChips = () => {
    if (!countries.length) {
      chips.innerHTML = '';
      return;
    }
    const top = countries.slice(0, TOP_COUNTRIES);
    const rest = countries.length - top.length;
    chips.innerHTML = top.map((entry) => `
      <button type="button" class="chip" data-country="${esc(entry.country_key)}" aria-pressed="${state.country === entry.country_key}">
        ${esc(countrySummaryLabel(entry))} · ${esc(fmtNumber(entry.count))} ${entry.count === 1 ? 'IP' : 'IPs'}
      </button>`).join('')
      + (rest > 0 ? `<span class="chip ghost">+${fmtNumber(rest)} more</span>` : '');

    chips.querySelectorAll('[data-country]').forEach((chip) => {
      chip.addEventListener('click', () => {
        state.country = state.country === chip.dataset.country ? '' : chip.dataset.country;
        state.page = 1;
        countrySelect.value = state.country;
        paintChips();
        load();
      });
    });
  };

  const loadCountries = async (range = activeRange) => {
    const request = countryRequests.begin();
    if (!request.isCurrent()) return;
    const context = { machines: machinesParam(), range: { ...range }, basis: state.basis };
    countryState.start(describe(context));
    try {
      const loaded = (await api('/attackers/countries' + qs({ machines: context.machines, ...context.range, basis: context.basis }), { signal: request.signal }) || [])
        .filter((entry) => entry.country);
      if (!request.isCurrent()) return;
      countries = loaded;
      countryState.success(loaded, describe(context));
      mount.querySelector('#attackers-country-empty').hidden = loaded.length !== 0;
    } catch (error) {
      if (!request.isCurrent() || isAbortError(error)) return;
      countryState.failure(error, describe(context));
      mount.querySelector('#attackers-country-empty').hidden = true;
      return;
    }
    countrySelect.innerHTML = ['<option value="">Country: all</option>']
      .concat(countries.map((entry) => `<option value="${esc(entry.country_key)}">${esc(countrySummaryLabel(entry))} · ${esc(fmtNumber(entry.count))} ${entry.count === 1 ? 'IP' : 'IPs'}</option>`))
      .concat(state.country && !countries.some(entry => entry.country_key === state.country) ? [`<option value="${esc(state.country)}">Selected country: ${esc(state.country.replace(/^(code|name):/, ''))} (no count in this range)</option>`] : [])
      .join('');
    countrySelect.value = state.country;
    countrySelect.hidden = countries.length === 0 && !state.country;
    paintChips();
  };

  let debounce = null;
  requests.signal.addEventListener('abort', () => clearTimeout(debounce), { once: true });
  searchInput.addEventListener('input', () => {
    requests.cancel();
    state.q = searchInput.value.trim();
    state.page = 1;
    rememberAttackers(state, machinesParam(), getWindow());
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      if (requests.signal.aborted) return;
      load();
    }, SEARCH_DEBOUNCE_MS);
  });

  countrySelect.addEventListener('change', () => {
    state.country = countrySelect.value;
    state.page = 1;
    paintChips();
    load();
  });

  basisSelect.addEventListener('change', () => { state.basis = basisSelect.value; state.page = 1; reload(); });

  statusSelect.addEventListener('change', () => {
    state.status = statusSelect.value;
    state.page = 1;
    load();
  });

  const reload = async () => {
    activeRange = rangeParams(getWindow());
    await Promise.all([loadCountries(activeRange), load(activeRange)]);
  };
  onRefresh(reload, requests.signal);
  await reload();
}

function sortLabel(sort) {
  if (sort === SORT_LAST_SEEN) return 'last observed';
  if (sort === SORT_FIRST_SEEN) return 'first observed';
  if (sort === SORT_CONNECTIONS) return 'cumulative connections';
  if (sort === 'last_activity') return 'last measured activity';
  return 'cumulative connection time';
}
