/* Hand-rolled stacked-area chart for the /api/timeseries payload. No dependencies. */

import { esc, fmtDuration, seriesIndexForMachine } from './app.js';

const VIEW_W = 1000;
const VIEW_H = 220;
const GRID_LINES = [0.25, 0.5, 0.75];
const SERIES_COUNT = 3;
const OPACITY_STEPS = 6;
const AXIS_LABELS = 5;
const SR_ROW_LIMIT = 60;
const NICE_STEPS = [1, 2, 2.5, 5, 10];
const SHORT_SPAN_MS = 36 * 3600 * 1000;
const NOW_TOLERANCE_MS = 5 * 60 * 1000;

// A machine keeps the same colour whichever machines are being shown, so the
// swatch matches the sparkline on its sidebar card.
function seriesClass(entry, index) {
  return `s-${(seriesIndexForMachine(entry.machine_id, index) % SERIES_COUNT) + 1}`;
}

export function renderLegend(host, series) {
  host.innerHTML = series.map((entry, index) => `
    <span class="legend-item">
      <span class="legend-swatch ${seriesClass(entry, index)}"></span>
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
  const formatter = new Intl.DateTimeFormat(undefined, options);
  return (date) => formatter.format(date);
}

function fullTimeFormatter() {
  return new Intl.DateTimeFormat(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  });
}

export function renderChart(host, data, options = {}) {
  const metric = options.metric || 'trapped_seconds';
  const format = options.format || fmtDuration;
  const label = options.label || 'Attacker activity';

  const series = (data && Array.isArray(data.series) ? data.series : []).filter(
    (entry) => Array.isArray(entry.points) && entry.points.length,
  );

  if (!series.length) {
    host.innerHTML = '<p class="empty-text chart-empty">No data for this range yet.</p>';
    return;
  }

  const points = series[0].points;
  const count = points.length;
  const times = points.map((point) => new Date(point.t));
  const fromMs = times[0].getTime();
  const toMs = times[count - 1].getTime();

  const values = series.map((entry) => entry.points.map((point) => Number(point[metric]) || 0));
  const cumulative = [];
  for (let s = 0; s < series.length; s += 1) {
    const previous = cumulative[s - 1];
    cumulative[s] = values[s].map((value, i) => value + (previous ? previous[i] : 0));
  }

  const total = cumulative[cumulative.length - 1];
  const max = niceMax(Math.max(...total));

  const areas = [];
  for (let s = series.length - 1; s >= 0; s -= 1) {
    const step = Math.min(s, OPACITY_STEPS - 1);
    areas.push(`<path class="area ${seriesClass(series[s], s)} o-${step}" d="${areaPath(cumulative[s], max)}"></path>`);
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
  const isLive = Date.now() - toMs < NOW_TOLERANCE_MS;
  const axis = axisIndexes.map((index, position) => {
    const last = position === AXIS_LABELS - 1;
    const text = last && isLive ? 'now' : formatAxis(times[index]);
    return `<span>${esc(text)}</span>`;
  }).join('');

  const describedTitle = `${label} from ${formatFull.format(times[0])} to ${formatFull.format(times[count - 1])}, stacked per machine`;

  const stride = Math.max(1, Math.ceil(count / SR_ROW_LIMIT));
  const srRows = [];
  for (let i = 0; i < count; i += stride) {
    const cells = series.map((entry, s) => `<td>${esc(format(values[s][i]))}</td>`).join('');
    srRows.push(`<tr><th scope="row">${esc(formatFull.format(times[i]))}</th>${cells}<td>${esc(format(total[i]))}</td></tr>`);
  }

  host.innerHTML = `
    <div class="chart">
      <div class="chart-plot">
        <span class="chart-ymax">peak ${esc(format(max))}</span>
        <svg class="chart-svg" viewBox="0 0 ${VIEW_W} ${VIEW_H}" preserveAspectRatio="none" role="img" aria-label="${esc(describedTitle)}">
          ${grid}
          ${areas.join('')}
          <line class="chart-cursor" x1="0" y1="0" x2="0" y2="${VIEW_H}" stroke-width="1" stroke-dasharray="4 4" vector-effect="non-scaling-stroke"></line>
        </svg>
        <div class="chart-hit" tabindex="0" role="group" aria-label="Inspect chart values with the left and right arrow keys"></div>
        <div class="chart-tip" hidden></div>
      </div>
      <div class="chart-axis">${axis}</div>
      <div class="sr-only"><table>
        <caption>${esc(describedTitle)}${stride > 1 ? ` (every ${stride} buckets)` : ''}</caption>
        <thead><tr><th scope="col">Time</th>${series.map((entry) => `<th scope="col">${esc(entry.machine_name)}</th>`).join('')}<th scope="col">Total</th></tr></thead>
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
        <span class="legend-swatch ${seriesClass(entry, s)}"></span>
        <span class="chart-tip-name">${esc(entry.machine_name)}</span>
        <span class="chart-tip-val">${esc(format(values[s][index]))}</span>
      </div>`).join('');
    tip.innerHTML = `
      <div class="chart-tip-time">${esc(formatFull.format(times[index]))}</div>
      ${rows}
      <div class="chart-tip-row chart-tip-total">
        <span class="chart-tip-name">Total</span>
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
