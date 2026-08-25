/* Attackers page plus the shared attackers-table renderer. */

import {
  api, qs, esc, icon, onRefresh, renderError, emptyState,
  fmtDuration, fmtNumber, fmtRelative, fmtDateTime,
  machinesParam, getWindow, ATTACKER_TRAPPED,
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
  { value: 'trapped', label: 'Status: trapped' },
  { value: 'gave_up', label: 'Status: gave up' },
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
  const trapped = row.status === ATTACKER_TRAPPED;
  return `<span class="badge ${trapped ? 'badge-danger' : ''}">${trapped ? 'Trapped' : 'Gave up'}</span>`;
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
  trapped: { label: 'Time trapped', sort: SORT_TRAPPED, cls: 'mono', cell: (row) => esc(fmtDuration(row.trapped_seconds)) },
  connections: { label: 'Connections', sort: SORT_CONNECTIONS, cls: 'mono num', cell: (row) => esc(fmtNumber(row.connections)) },
  first_seen: { label: 'First seen', sort: SORT_FIRST_SEEN, cell: (row) => `<span title="${esc(fmtDateTime(row.first_seen))}">${esc(fmtRelative(row.first_seen))}</span>` },
  last_seen: { label: 'Last seen', sort: SORT_LAST_SEEN, cell: (row) => `<span title="${esc(fmtDateTime(row.last_seen))}">${esc(fmtRelative(row.last_seen))}</span>` },
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
      text: 'Nothing has been trapped for this filter yet. Widen the range or clear the filters.',
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

const PAGE_COLUMNS = ['country', 'ip', 'location', 'isp', 'machine', 'trapped', 'connections', 'first_seen', 'last_seen', 'status'];

export async function render(mount) {
  const state = {
    q: '',
    country: '',
    status: '',
    sort: SORT_TRAPPED,
    order: 'desc',
    page: 1,
    total: 0,
  };

  mount.innerHTML = `
    <div class="page-head">
      <h1 class="page-title">Attackers</h1>
      <span class="page-sub" id="attackers-note">Loading…</span>
    </div>
    <div class="filters">
      <div class="search">
        ${icon('search', 15)}
        <input id="attackers-q" type="search" placeholder="Search by IP…" aria-label="Search attackers by IP prefix" autocapitalize="none" spellcheck="false">
      </div>
      <select class="select select-inline" id="attackers-country" aria-label="Filter by country"></select>
      <select class="select select-inline" id="attackers-status" aria-label="Filter by status">
        ${STATUS_FILTERS.map((option) => `<option value="${esc(option.value)}">${esc(option.label)}</option>`).join('')}
      </select>
    </div>
    <div class="chips" id="attackers-chips"></div>
    <div class="card" id="attackers-card">
      <div class="card-pad"><div class="skeleton w60"></div></div>
    </div>`;

  const note = mount.querySelector('#attackers-note');
  const card = mount.querySelector('#attackers-card');
  const chips = mount.querySelector('#attackers-chips');
  const countrySelect = mount.querySelector('#attackers-country');
  const statusSelect = mount.querySelector('#attackers-status');
  const searchInput = mount.querySelector('#attackers-q');

  let countries = [];

  const load = async () => {
    try {
      const data = await api('/attackers' + qs({
        machines: machinesParam(),
        window: getWindow(),
        q: state.q,
        country: state.country,
        status: state.status,
        sort: state.sort,
        order: state.order,
        page: state.page,
        per_page: PER_PAGE,
      }));
      state.total = data.total;
      paint(data);
    } catch (error) {
      if (error.status === 401) return;
      renderError(card, error, load);
      note.textContent = '';
    }
  };

  const paint = (data) => {
    const rows = data.rows || [];
    const first = rows.length ? (data.page - 1) * data.per_page + 1 : 0;
    const last = (data.page - 1) * data.per_page + rows.length;
    note.textContent = `${fmtNumber(data.total)} attackers · sorted by ${sortLabel(state.sort)}`;

    card.innerHTML = '<div id="attackers-table"></div><div class="card-foot" id="attackers-foot"></div>';
    renderAttackersTable(card.querySelector('#attackers-table'), rows, {
      columns: PAGE_COLUMNS,
      sort: state.sort,
      order: state.order,
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
  };

  const paintChips = () => {
    if (!countries.length) {
      chips.innerHTML = '';
      return;
    }
    const top = countries.slice(0, TOP_COUNTRIES);
    const rest = countries.length - top.length;
    chips.innerHTML = top.map((entry) => `
      <button type="button" class="chip" data-country="${esc(entry.country)}" aria-pressed="${state.country === entry.country}">
        ${esc(entry.country)} · ${esc(fmtNumber(entry.count))}
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

  const loadCountries = async () => {
    try {
      countries = (await api('/attackers/countries' + qs({ machines: machinesParam(), window: getWindow() })) || [])
        .filter((entry) => entry.country);
    } catch (error) {
      countries = [];
    }
    countrySelect.innerHTML = ['<option value="">Country: all</option>']
      .concat(countries.map((entry) => `<option value="${esc(entry.country)}">${esc(entry.country)} · ${esc(fmtNumber(entry.count))}</option>`))
      .join('');
    countrySelect.value = state.country;
    countrySelect.hidden = countries.length === 0;
    paintChips();
  };

  let debounce = null;
  searchInput.addEventListener('input', () => {
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      state.q = searchInput.value.trim();
      state.page = 1;
      load();
    }, SEARCH_DEBOUNCE_MS);
  });

  countrySelect.addEventListener('change', () => {
    state.country = countrySelect.value;
    state.page = 1;
    paintChips();
    load();
  });

  statusSelect.addEventListener('change', () => {
    state.status = statusSelect.value;
    state.page = 1;
    load();
  });

  onRefresh(load);
  await Promise.all([loadCountries(), load()]);
}

function sortLabel(sort) {
  if (sort === SORT_LAST_SEEN) return 'last seen';
  if (sort === SORT_FIRST_SEEN) return 'first seen';
  if (sort === SORT_CONNECTIONS) return 'connections';
  return 'time trapped';
}
