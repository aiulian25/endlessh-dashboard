import { updateWithFocus } from './focus.js';
import { panelState } from './panel-state.js';
import { latestRequests, isAbortError } from './requests.js';
import { activityNote, scrapeNote, CONNECTION_TIME_NOTE } from './metric-notes.js';
import { rangeParams, seriesTotals } from './time-range.js';
/* Overview page: stat cards, activity chart, country donut, origin map, top attackers. */

import {
  api, qs, esc, onRefresh, emptyState, navigate,
  fmtDuration, fmtBytes, fmtNumber, fmtDelta, fmtRelative,
  machinesParam, getWindow, setWindow, windowLabel, WINDOWS,
  currentMachines, machineListKnown,
} from './app.js';
import { renderChart, renderLegend, coverageNote } from './chart.js';
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

function countriesNote(count) {
  if (!count) return 'no country known yet';
  return `from ${fmtNumber(count)} ${count === 1 ? 'country' : 'countries'}`;
}

function latestAttackerCard(latest) {
  if (!latest) return statCard('Latest measured activity', NO_VALUE, 'no measured activity yet');
  const place = latest.location || latest.country || 'unknown location';
  return statCard('Latest measured activity', latest.ip, `${place} · ${fmtRelative(latest.at)}`, { ip: true });
}

export async function render(mount, param, routeSignal) {
  const requests = latestRequests(routeSignal);
  const units = Object.fromEntries(['metrics', 'top', 'map', 'countries'].map(key => [key, latestRequests(requests.signal)]));
  let emptyView = false;
  mount.innerHTML = `
    <h1 class="sr-only">Overview</h1>
    <p class="filters-note" id="ov-activity-note"></p>
    <details class="metric-details"><summary>About sampled activity and totals</summary><p class="filters-note">Positive counter growth identifies a recently active IP. One address can represent several connections or people. Cumulative time and bytes cover dashboard history across selected machines. ${esc(CONNECTION_TIME_NOTE)}</p></details>
    <p class="filters-note" id="ov-coverage-note"></p>
    <div class="grid-stats grid-stats-6" id="ov-stats">${statSkeleton().repeat(STAT_CARDS)}</div>
    <div id="ov-summary-state"></div>
    <div class="grid-geo" id="ov-geo-row">
      <div class="card card-pad" id="ov-chart-card">
        <div class="card-head flush">
          <h2 class="card-title">Sampled connection time</h2>
          <div class="legend" id="ov-legend"></div>
          <div class="seg" id="ov-range" role="group" aria-label="Time range"></div>
        </div>
        <div id="ov-chart-state"></div>
        <div id="ov-chart"><div class="skeleton block"></div></div>
      </div>
      <div class="card card-pad" id="ov-donut-card" hidden>
        <div class="card-head flush">
          <h2 class="card-title">Cumulative connections by country</h2>
        </div>
        <p class="filters-note">Known-country rows with measured growth in the selected range; values include earlier cumulative history.</p>
        <div id="ov-country-state"></div>
        <div id="ov-donut"></div>
      </div>
    </div>
    <div class="card card-pad" id="ov-map-card" hidden>
      <div class="card-head flush">
        <h2 class="card-title">Where the attacks come from</h2>
        <span class="map-note" id="ov-map-note"></span>
      </div>
      <div id="ov-map-state"></div>
      <div id="ov-map"></div>
    </div>
    <div class="card" id="ov-geo-off" hidden>${emptyState({
      title: 'No geography in this range',
      text: 'No known locations or countries were returned for these machines and this range. Exporter labels, a local MaxMind database or optional online lookups can provide geography. Settings shows which sources are active.',
      actionLabel: 'Open settings',
      glyph: 'info',
    })}</div>
    <div id="ov-top-state"></div>
    <div class="card" id="ov-top">
      <div class="card-head">
        <h2 class="card-title">Top cumulative machine/IP rows</h2>
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

  const paintStats = (overview, totals, context) => {
    mount.querySelector('#ov-activity-note').textContent = `${activityNote(overview.activity?.threshold_seconds)} ${scrapeNote(overview.activity)}`;
    stats.innerHTML = [
      statCard('Connections opened', fmtNumber(totals.opens), `recorded in ${windowLabel(context.window)}`),
      statCard('Connection time (cumulative)', fmtDuration(overview.time_wasted_seconds),
        `${fmtDelta(totals.trapped_seconds, fmtDuration)} recorded in ${windowLabel(context.window)}`),
      statCard('Bytes sent (cumulative)', fmtBytes(overview.bytes_sent),
        `${fmtDelta(totals.bytes_sent, fmtBytes)} recorded in ${windowLabel(context.window)}`),
      statCard('Distinct IPs in range', fmtNumber(overview.unique_attackers), countriesNote(overview.countries)),
      statCard('Recently active IPs', fmtNumber(overview.trapped_now),
        `sampled across ${fmtNumber(overview.machine_count)} machine${overview.machine_count === 1 ? '' : 's'}`, { accent: true }),
      latestAttackerCard(overview.latest_attacker),
    ].join('');
  };

  // Empty is authoritative only when both geography requests succeeded for
  // the same range. A failure never becomes a configuration diagnosis.
  const paintGeographyVisibility = () => {
    const sameContext = pointsState.context === countriesState.context;
    geoOffCard.hidden = !(pointsState.hasValue && countriesState.hasValue &&
      !pointsState.failed && !countriesState.failed && !pointsState.pending && !countriesState.pending && sameContext &&
      !pointsState.value.length && !countriesState.value.length);
    mapCard.hidden = pointsState.hasValue && !pointsState.failed && !pointsState.pending && !pointsState.value.length;
    donutCard.hidden = countriesState.hasValue && !countriesState.failed && !countriesState.pending && !countriesState.value.length;
    geoRow.classList.toggle('solo', donutCard.hidden || !countriesState.value?.length);
  };

  const paintTop = (attackers) => {
    topCard.innerHTML = `
      <div class="card-head">
        <h2 class="card-title">Top cumulative machine/IP rows</h2>
        <a href="#/attackers">View all ${esc(fmtNumber(attackers.total))} rows</a>
      </div>
      <div id="ov-top-table"></div>`;
    const scope = document.createElement('p'); scope.className = 'filters-note card-pad'; scope.textContent = `${attackers.distinct_ips ?? '—'} distinct ${attackers.distinct_ips === 1 ? 'IP' : 'IPs'} across ${attackers.total} matching machine/IP ${attackers.total === 1 ? 'row' : 'rows'}. Values are retained cumulative totals; * includes undated history.`; topCard.append(scope);
    renderAttackersTable(topCard.querySelector('#ov-top-table'), attackers.rows || [], { columns: TOP_COLUMNS });
  };

  const summaryState = panelState(mount.querySelector('#ov-summary-state'), 'summary', () => load(['summary']));
  const chartState = panelState(mount.querySelector('#ov-chart-state'), 'chart', () => load(['chart']));
  const topState = panelState(mount.querySelector('#ov-top-state'), 'top attackers', () => load(['top']));
  const pointsState = panelState(mount.querySelector('#ov-map-state'), 'map', () => load(['map']));
  const countriesState = panelState(mount.querySelector('#ov-country-state'), 'countries', () => load(['countries']));

  const load = async (only = ['summary', 'chart', 'top', 'map', 'countries']) => {
    if (requests.signal.aborted) return;
    if (emptyView) {
      if (machineListKnown() && !currentMachines().length) return;
      requests.dispose();
      return render(mount, param, routeSignal);
    }
    const context = Object.freeze({ window: getWindow(), machines: machinesParam() });
    const description = windowLabel(context.window);
    if (machineListKnown() && !currentMachines().length) {
      emptyView = true;
      mount.innerHTML = `<div class="card">${emptyState({title:'No machines registered yet',text:'Add the first endlessh-go machine you want to watch.',actionLabel:'Add your first machine'})}</div>`;
      mount.querySelector('[data-empty-action]').addEventListener('click', () => navigate('#/machines'));
      return;
    }
    const params = { machines: context.machines, ...rangeParams(context.window) };
    const wanted = new Set(only);
    if (wanted.has('summary') || wanted.has('chart')) { wanted.add('summary'); wanted.add('chart'); }
    const metricsRequest = wanted.has('summary') ? units.metrics.begin() : null;
    const overview = wanted.has('summary') ? api('/overview' + qs(params), { signal: metricsRequest.signal }) : null;
    const timeseries = wanted.has('summary') || wanted.has('chart') ? api('/timeseries' + qs(params), { signal: metricsRequest.signal }) : null;
    const accept = async (request, state, promise, paint) => {
      state.start(description);
      paintGeographyVisibility();
      try {
        const data = await promise;
        if (!request.isCurrent()) return;
        const region = state === summaryState ? stats : state === chartState ? chartHost : state === topState ? topCard : state === pointsState ? mapHost : donutHost;
        updateWithFocus(region, () => {
          if (!request.isCurrent()) return;
          paint(data); state.success(data, description); paintGeographyVisibility();
        }, requests.signal);
      } catch (error) {
        if (!request.isCurrent() || isAbortError(error) || error.status === 401) return;
        state.failure(error, description);
        if (!state.hasValue) {
          if (state === summaryState) stats.innerHTML = '';
          if (state === chartState) chartHost.innerHTML = '';
          if (state === topState) topCard.innerHTML = '<div class="card-pad">Top attackers unavailable.</div>';
        }
      } finally {
        if (request.isCurrent()) paintGeographyVisibility();
      }
    };
    const tasks = [];
    if (wanted.has('summary')) tasks.push(accept(metricsRequest, summaryState, Promise.all([overview, timeseries]), ([data, series]) => paintStats(data, seriesTotals(series), context)));
    if (wanted.has('chart')) tasks.push(accept(metricsRequest, chartState, timeseries, data => {
      mount.querySelector('#ov-coverage-note').textContent = coverageNote(data);
      renderLegend(legendHost, data.series || []);
      renderChart(chartHost, data, { label:'Sampled connection time (connection-seconds)',format:fmtDuration });
    }));
    const panel = (key, state, path, paint) => {
      if (!wanted.has(key)) return;
      const request = units[key].begin();
      const result = api(path, {signal:request.signal}).then(data => {
        if ((key === 'map' || key === 'countries') && !Array.isArray(data)) throw new Error('Invalid geography response.');
        return data;
      });
      tasks.push(accept(request, state, result, paint));
    };
    panel('top', topState, '/attackers' + qs({...params,sort:'trapped_seconds',order:'desc',page:1,per_page:TOP_ROWS}), paintTop);
    panel('map', pointsState, '/geo/points' + qs(params), data => {
      mapNote.textContent = `bubble size = retained cumulative connections · IPs with measured growth in ${context.window}`;
      renderMap(mapHost, data || []);
    });
    panel('countries', countriesState, '/geo/countries' + qs(params), data => renderDonut(donutHost,data || []));
    // Failed first loads replace skeletons, while prior successful payloads stay.
    // A failed linked summary must not leave its sibling request outside the refresh round.
    await Promise.allSettled([...tasks, overview, timeseries]);
    if (requests.signal.aborted) return;
    if (summaryState.failed && !summaryState.hasValue) stats.innerHTML = '';
    if (chartState.failed && !chartState.hasValue) chartHost.innerHTML = '';
    if (topState.failed && !topState.hasValue) topCard.innerHTML = '<div class="card-pad">Top attackers unavailable.</div>';
    paintGeographyVisibility();
  };

  paintRange();
  onRefresh(() => load(), requests.signal);
  await load();
}
