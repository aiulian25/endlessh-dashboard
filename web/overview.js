/* Overview page: stat cards, activity chart, country donut, origin map, top attackers. */

import {
  api, qs, esc, onRefresh, renderError, emptyState, navigate,
  fmtDuration, fmtBytes, fmtNumber, fmtDelta, fmtRelative,
  machinesParam, getWindow, setWindow, windowLabel, WINDOWS,
  currentMachines,
} from './app.js';
import { renderChart, renderLegend } from './chart.js';
import { renderDonut } from './donut.js';
import { renderMap } from './map.js';
import { renderAttackersTable } from './attackers.js';

const TOP_ROWS = 5;
const TOP_COLUMNS = ['country', 'ip', 'location', 'machine', 'trapped', 'connections', 'status'];
const STAT_CARDS = 6;
const NO_VALUE = '—';

function statCard(label, value, note, options = {}) {
  const valueClass = `stat-value${options.accent ? ' amber' : ''}${options.ip ? ' ip' : ''}`;
  return `
    <div class="card stat">
      <span class="stat-label">${esc(label)}</span>
      <span class="${valueClass}">${esc(value)}</span>
      <span class="stat-delta">${esc(note)}</span>
    </div>`;
}

function statSkeleton() {
  return `
    <div class="card stat">
      <div class="skeleton w60"></div>
      <div class="skeleton tall w80"></div>
      <div class="skeleton w40"></div>
    </div>`;
}

// /api/overview carries no connection total, so the card adds up the very
// buckets the chart beside it draws: same machines, same window, one figure.
function connectionsIn(timeseries) {
  const series = (timeseries && timeseries.series) || [];
  return series.reduce((total, entry) => total
    + (entry.points || []).reduce((sum, point) => sum + (Number(point.opens) || 0), 0), 0);
}

function countriesNote(count) {
  if (!count) return 'no country known yet';
  return `from ${fmtNumber(count)} ${count === 1 ? 'country' : 'countries'}`;
}

function latestAttackerCard(latest) {
  if (!latest) return statCard('Latest attacker', NO_VALUE, 'nothing caught yet');
  const place = latest.location || latest.country || 'unknown location';
  return statCard('Latest attacker', latest.ip, `${place} · ${fmtRelative(latest.at)}`, { ip: true });
}

export async function render(mount) {
  mount.innerHTML = `
    <div class="grid-stats grid-stats-6" id="ov-stats">${statSkeleton().repeat(STAT_CARDS)}</div>
    <div class="grid-geo" id="ov-geo-row">
      <div class="card card-pad" id="ov-chart-card">
        <div class="card-head flush">
          <h2 class="card-title">Attacker time trapped</h2>
          <div class="legend" id="ov-legend"></div>
          <div class="seg" id="ov-range" role="group" aria-label="Time range"></div>
        </div>
        <div id="ov-chart"><div class="skeleton block"></div></div>
      </div>
      <div class="card card-pad" id="ov-donut-card" hidden>
        <div class="card-head flush">
          <h2 class="card-title">Attacks by country</h2>
        </div>
        <div id="ov-donut"></div>
      </div>
    </div>
    <div class="card card-pad" id="ov-map-card" hidden>
      <div class="card-head flush">
        <h2 class="card-title">Where the attacks come from</h2>
        <span class="map-note" id="ov-map-note"></span>
      </div>
      <div id="ov-map"></div>
    </div>
    <div class="card" id="ov-geo-off" hidden>${emptyState({
      title: 'No geography for these machines yet',
      text: 'Attack origins need a geography source: the labels the tarpit publishes itself, a local MaxMind database, or the optional online lookups. Settings shows which source is active.',
      actionLabel: 'Open settings',
      glyph: 'info',
    })}</div>
    <div class="card" id="ov-top">
      <div class="card-head">
        <h2 class="card-title">Top attackers</h2>
        <a href="#/attackers">View all</a>
      </div>
      <div class="card-pad"><div class="skeleton w60"></div></div>
    </div>`;

  const stats = mount.querySelector('#ov-stats');
  const chartHost = mount.querySelector('#ov-chart');
  const legendHost = mount.querySelector('#ov-legend');
  const rangeHost = mount.querySelector('#ov-range');
  const geoRow = mount.querySelector('#ov-geo-row');
  const donutCard = mount.querySelector('#ov-donut-card');
  const donutHost = mount.querySelector('#ov-donut');
  const mapCard = mount.querySelector('#ov-map-card');
  const mapHost = mount.querySelector('#ov-map');
  const mapNote = mount.querySelector('#ov-map-note');
  const geoOffCard = mount.querySelector('#ov-geo-off');
  const topCard = mount.querySelector('#ov-top');

  geoOffCard.querySelector('[data-empty-action]').addEventListener('click', () => navigate('#/settings'));

  const paintRange = () => {
    rangeHost.innerHTML = WINDOWS.map((value) => `
      <button type="button" data-window="${value}" aria-pressed="${value === getWindow()}">${value}</button>`).join('');
    rangeHost.querySelectorAll('[data-window]').forEach((button) => {
      button.addEventListener('click', () => {
        setWindow(button.dataset.window);
        paintRange();
        load();
      });
    });
  };

  const paintStats = (overview, connections) => {
    stats.innerHTML = [
      statCard('Connections', fmtNumber(connections), `in ${windowLabel()}`),
      statCard('Time wasted', fmtDuration(overview.time_wasted_seconds),
        `${fmtDelta(overview.time_wasted_delta_seconds, fmtDuration)} in ${windowLabel()}`),
      statCard('Junk data sent', fmtBytes(overview.bytes_sent),
        `${fmtDelta(overview.bytes_sent_delta, fmtBytes)} in ${windowLabel()}`),
      statCard('Unique attackers', fmtNumber(overview.unique_attackers), countriesNote(overview.countries)),
      statCard('Trapped right now', fmtNumber(overview.trapped_now),
        `across ${fmtNumber(overview.machine_count)} machine${overview.machine_count === 1 ? '' : 's'}`, { accent: true }),
      latestAttackerCard(overview.latest_attacker),
    ].join('');
  };

  // Geography is optional everywhere, so an install with none is told so once
  // rather than shown two empty frames.
  const paintGeography = (points, countries) => {
    donutCard.hidden = !countries.length;
    mapCard.hidden = !points.length;
    geoOffCard.hidden = Boolean(points.length || countries.length);
    geoRow.classList.toggle('solo', !countries.length);

    if (countries.length) renderDonut(donutHost, countries);
    if (!points.length) return;
    mapNote.textContent = `bubble size = connections · last ${getWindow()}`;
    renderMap(mapHost, points);
  };

  const paintTop = (attackers) => {
    topCard.innerHTML = `
      <div class="card-head">
        <h2 class="card-title">Top attackers</h2>
        <a href="#/attackers">View all ${esc(fmtNumber(attackers.total))}</a>
      </div>
      <div id="ov-top-table"></div>`;
    renderAttackersTable(topCard.querySelector('#ov-top-table'), attackers.rows || [], { columns: TOP_COLUMNS });
  };

  const showEmpty = () => {
    stopRefresh();
    mount.innerHTML = `<div class="card">${emptyState({
      title: 'No machines registered yet',
      text: 'Add the first endlessh-go machine you want to watch. The dashboard scrapes its Prometheus metrics endpoint and starts collecting history straight away.',
      actionLabel: 'Add your first machine',
    })}</div>`;
    mount.querySelector('[data-empty-action]').addEventListener('click', () => navigate('#/machines'));
  };

  const load = async () => {
    try {
      const machines = currentMachines();
      if (!machines.length) {
        showEmpty();
        return;
      }

      const params = { machines: machinesParam(), window: getWindow() };
      const [overview, timeseries, attackers, points, countries] = await Promise.all([
        api('/overview' + qs(params)),
        api('/timeseries' + qs(params)),
        api('/attackers' + qs({ ...params, sort: 'trapped_seconds', order: 'desc', page: 1, per_page: TOP_ROWS })),
        // Geography is an optional extra: a server that cannot answer for it
        // should cost the page its map, not its numbers.
        api('/geo/points' + qs(params)).catch(() => []),
        api('/geo/countries' + qs(params)).catch(() => []),
      ]);

      paintStats(overview, connectionsIn(timeseries));
      renderLegend(legendHost, timeseries.series || []);
      renderChart(chartHost, timeseries, { label: 'Attacker time trapped', format: fmtDuration });
      paintGeography(points || [], countries || []);
      paintTop(attackers);
    } catch (error) {
      if (error.status === 401) return;
      stopRefresh();
      mount.innerHTML = '';
      renderError(mount, error, () => render(mount));
    }
  };

  paintRange();
  const stopRefresh = onRefresh(load);
  await load();
}
