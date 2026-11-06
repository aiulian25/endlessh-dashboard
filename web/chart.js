import { CONNECTION_TIME_NOTE } from './metric-notes.js';
import { rangeNote } from './time-range.js';
/* Hand-rolled stacked-area chart for the /api/timeseries payload. No dependencies. */

import { esc, fmtDuration, machineColour } from './app.js';

const VIEW_W = 1000;
const VIEW_H = 220;
const GRID_LINES = [0.25, 0.5, 0.75];
const OPACITY_STEPS = 6;
const AXIS_LABELS = 5;
const SR_ROW_LIMIT = 60;
const NICE_STEPS = [1, 2, 2.5, 5, 10];
const SHORT_SPAN_MS = 36 * 3600 * 1000;

// A machine keeps the same colour whichever machines are shown; machineColour
// owns that. index is only the fallback for a machine whose colour is not known
// here yet.
function seriesClass(entry, index) {
  return machineColour(entry.machine_id, index);
}

export function renderLegend(host, series) {
  host.innerHTML = series.map((entry, index) => `
    <span class="legend-item">
      <span class="legend-swatch ${esc(seriesClass(entry, index))}"></span>
      <span>${esc(entry.machine_name)}</span>
    </span>`).join('');
}

function niceMax(value) {
  if (!(value > 0)) return 1;
  const exponent = Math.pow(10, Math.floor(Math.log10(value)));
  const mantissa = value / exponent;
  const step = NICE_STEPS.find((candidate) => mantissa <= candidate) || 10;
  return step * exponent;
}

function areaPath(values, max) {
  const count = values.length;
  const stepX = count > 1 ? VIEW_W / (count - 1) : VIEW_W;
  const toY = (value) => VIEW_H - (Math.max(0, value) / max) * VIEW_H;

  let path = `M0,${toY(values[0]).toFixed(2)}`;
  for (let i = 1; i < count; i += 1) {
    const x0 = (i - 1) * stepX;
    const x1 = i * stepX;
    const control = stepX / 3;
    path += ` C${(x0 + control).toFixed(2)},${toY(values[i - 1]).toFixed(2)} ${(x1 - control).toFixed(2)},${toY(values[i]).toFixed(2)} ${x1.toFixed(2)},${toY(values[i]).toFixed(2)}`;
  }
  return `${path} L${VIEW_W},${VIEW_H} L0,${VIEW_H} Z`;
}

function timeFormatter(fromMs, toMs) {
  const short = toMs - fromMs <= SHORT_SPAN_MS;
  const options = short
    ? { hour: '2-digit', minute: '2-digit' }
    : { month: 'short', day: 'numeric' };
  const formatter = new Intl.DateTimeFormat(undefined, { ...options, timeZone: 'UTC' });
  return (date) => formatter.format(date);
}

function fullTimeFormatter() {
  return new Intl.DateTimeFormat(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'UTC',
  });
}

export function coverageDescription(point) {
  const status = point?.coverage;
  let text = status === 'complete' ? 'Observed at expected cadence'
    : status === 'incomplete' ? 'Incomplete observation coverage' : 'Observation coverage unknown';
  if (point?.uncertain_from && point?.uncertain_to) text += `; recovered delta timing uncertain: ${point.uncertain_from} → ${point.uncertain_to} (UTC)`;
  return text;
}
export function coverageNote(data) {
  const points = (data?.series || []).flatMap((entry) => entry.points || []);
  return points.some((point) => point.coverage !== 'complete' || point.uncertain_from) || !points.length
    ? 'Window totals are recorded subtotals: some intervals have incomplete or unknown observations, and recovery timing may extend into earlier intervals.'
    : 'Window totals come from intervals observed at the expected cadence; counter events are timed only between samples.';
}

const COVERAGE_NOTE = 'Shading marks incomplete or unknown observation coverage across selected machines. Values remain recorded subtotals in collection buckets; recovery may span earlier buckets, with no distribution inferred.';

export function renderChart(host, data, options = {}) {
  const metric = options.metric || 'trapped_seconds';
  const format = options.format || fmtDuration;
  const label = options.label || 'Sampled connection time (connection-seconds)';

  const series = (data && Array.isArray(data.series) ? data.series : []).filter(
    (entry) => Array.isArray(entry.points) && entry.points.length,
  );

  if (!series.length) {
    host.innerHTML = `<p class="empty-text chart-empty">No data for this range yet.</p><p class="filters-note">${esc(rangeNote(data))} ${metric === 'trapped_seconds' ? esc(CONNECTION_TIME_NOTE) : ''}</p>`;
    return;
  }

  const points = series[0].points;
  const count = points.length;
  const times = points.map((point) => new Date(point.t));
  const fromMs = new Date(data.from || points[0].t).getTime();
  const toMs = new Date(data.to || points[count - 1].to || points[count - 1].t).getTime();

  const values = series.map((entry) => entry.points.map((point) => Number(point[metric]) || 0));
  const cumulative = [];
  for (let s = 0; s < series.length; s += 1) {
    const previous = cumulative[s - 1];
    cumulative[s] = values[s].map((value, i) => value + (previous ? previous[i] : 0));
  }

  const total = cumulative[cumulative.length - 1];
  const max = niceMax(Math.max(...total));

  const uncertainBins = points.map((_, i) => series.some(entry => entry.points[i]?.coverage !== 'complete' || entry.points[i]?.uncertain_from));
  const shading = uncertainBins.map((uncertain, i) => uncertain ? `<rect class="coverage-gap" x="${(i * VIEW_W / count).toFixed(2)}" y="0" width="${(VIEW_W / count + 0.1).toFixed(2)}" height="${VIEW_H}"></rect>` : '').join('');
  const areas = [];
  for (let s = series.length - 1; s >= 0; s -= 1) {
    const step = Math.min(s, OPACITY_STEPS - 1);
    areas.push(`<path class="area ${esc(seriesClass(series[s], s))} o-${step}" d="${areaPath(cumulative[s], max)}"></path>`);
  }

  const grid = GRID_LINES.map((fraction) => {
    const y = (VIEW_H * fraction).toFixed(0);
    return `<line class="grid-line" x1="0" y1="${y}" x2="${VIEW_W}" y2="${y}" stroke-width="1" vector-effect="non-scaling-stroke"></line>`;
  }).join('');

  const formatAxis = timeFormatter(fromMs, toMs);
  const formatFull = fullTimeFormatter();
  const axisIndexes = [];
  for (let i = 0; i < AXIS_LABELS; i += 1) {
    axisIndexes.push(Math.round((count - 1) * (i / (AXIS_LABELS - 1))));
  }
  const axis = axisIndexes.map((index) => {
    const text = formatAxis(times[index]);
    return `<span>${esc(text)}</span>`;
  }).join('');

  const interval = (index) => `${formatFull.format(times[index])} → ${points[index].to ? formatFull.format(new Date(points[index].to)) : formatFull.format(times[index])} UTC${points[index].partial ? ' (partial bucket)' : ''}`;
  const describedTitle = `${label}, stacked per machine. ${rangeNote(data)} ${COVERAGE_NOTE}`;

  const stride = Math.max(1, Math.ceil(count / SR_ROW_LIMIT));
  const srRows = [];
  for (let i = 0; i < count; i += stride) {
    const cells = series.map((entry, s) => `<td>${esc(format(values[s][i]))} recorded; ${esc(coverageDescription(entry.points[i]))}</td>`).join('');
    srRows.push(`<tr><th scope="row">${esc(interval(i))}</th>${cells}<td>${esc(format(total[i]))}</td></tr>`);
  }

  host.innerHTML = `
    <p class="filters-note">${esc(rangeNote(data))} ${metric === 'trapped_seconds' ? esc(CONNECTION_TIME_NOTE) : ''}</p>
    <p class="filters-note">${esc(COVERAGE_NOTE)}</p>
    <div class="chart">
      <div class="chart-plot">
        <span class="chart-ymax">scale max ${esc(format(max))}</span>
        <svg class="chart-svg" viewBox="0 0 ${VIEW_W} ${VIEW_H}" preserveAspectRatio="none" role="img" aria-label="${esc(describedTitle)}">
          ${grid}
          ${areas.join('')}
          ${shading}
          <line class="chart-cursor" x1="0" y1="0" x2="0" y2="${VIEW_H}" stroke-width="1" stroke-dasharray="4 4" vector-effect="non-scaling-stroke"></line>
        </svg>
        <div class="chart-hit" tabindex="0" role="group" aria-label="Inspect chart values with the left and right arrow keys"></div>
        <div class="chart-tip" hidden></div>
      </div>
      <div class="chart-axis">${axis}</div>
      <div class="sr-only"><table>
        <caption>${esc(describedTitle)}${stride > 1 ? ` (every ${stride} buckets)` : ''}</caption>
        <thead><tr><th scope="col">Time</th>${series.map((entry) => `<th scope="col">${esc(entry.machine_name)}</th>`).join('')}<th scope="col">Recorded subtotal</th></tr></thead>
        <tbody>${srRows.join('')}</tbody>
      </table></div>
    </div>`;

  const plot = host.querySelector('.chart-plot');
  const hit = host.querySelector('.chart-hit');
  const tip = host.querySelector('.chart-tip');
  const cursor = host.querySelector('.chart-cursor');
  let activeIndex = -1;

  const showIndex = (index) => {
    if (index < 0 || index >= count) return;
    activeIndex = index;
    const rows = series.map((entry, s) => `
      <div class="chart-tip-row">
        <span class="legend-swatch ${esc(seriesClass(entry, s))}"></span>
        <span class="chart-tip-name">${esc(entry.machine_name)}</span>
        <span class="chart-tip-val">${entry.points[index]?.coverage !== 'complete' && values[s][index] === 0 ? '— (recorded 0)' : esc(format(values[s][index]))}</span>
      </div><div class="chart-coverage-note">${esc(coverageDescription(entry.points[index]))}</div>`).join('');
    tip.innerHTML = `
      <div class="chart-tip-time">${esc(interval(index))}</div>
      ${rows}
      <div class="chart-tip-row chart-tip-total">
        <span class="chart-tip-name">Recorded subtotal</span>
        <span class="chart-tip-val">${esc(format(total[index]))}</span>
      </div>`;
    tip.hidden = false;

    const width = plot.clientWidth;
    const ratio = count > 1 ? index / (count - 1) : 0;
    const x = ratio * width;
    cursor.setAttribute('x1', String(ratio * VIEW_W));
    cursor.setAttribute('x2', String(ratio * VIEW_W));
    cursor.style.visibility = 'visible';
    const tipWidth = tip.offsetWidth;
    tip.style.left = `${Math.max(0, Math.min(width - tipWidth, x - tipWidth / 2))}px`;
    tip.style.top = '4px';
  };

  const hide = () => {
    tip.hidden = true;
    cursor.style.visibility = 'hidden';
    activeIndex = -1;
  };

  hit.addEventListener('mousemove', (event) => {
    const rect = plot.getBoundingClientRect();
    const ratio = rect.width ? (event.clientX - rect.left) / rect.width : 0;
    showIndex(Math.round(Math.max(0, Math.min(1, ratio)) * (count - 1)));
  });
  hit.addEventListener('mouseleave', hide);
  hit.addEventListener('blur', hide);
  hit.addEventListener('focus', () => showIndex(activeIndex < 0 ? count - 1 : activeIndex));
  hit.addEventListener('keydown', (event) => {
    if (event.key === 'ArrowLeft') showIndex(Math.max(0, (activeIndex < 0 ? count - 1 : activeIndex) - 1));
    else if (event.key === 'ArrowRight') showIndex(Math.min(count - 1, (activeIndex < 0 ? 0 : activeIndex) + 1));
    else if (event.key === 'Home') showIndex(0);
    else if (event.key === 'End') showIndex(count - 1);
    else return;
    event.preventDefault();
  });
}
