import { countrySummaryLabel } from './country.js';
/* "Attacks by country" donut for the /api/geo/countries payload. */

import { esc, fmtNumber, paletteClass, PALETTE_SIZE } from './app.js';

const SIZE = 220;
const CENTRE = SIZE / 2;
const OUTER_RADIUS = 88;
const INNER_RADIUS = 62;
const FULL_TURN = Math.PI * 2;
// A slice covering the whole turn would start and end on the same point, which
// draws nothing at all, so the last hair of the circle is left open.
const MAX_SWEEP = FULL_TURN - 0.0001;
const PERCENT_SCALE = 100;
const OTHER_LABEL = 'Other';
const UNKNOWN_COUNTRY = 'Unknown';

function countryName(entry) {
  return countrySummaryLabel(entry) || UNKNOWN_COUNTRY;
}

function connectionsOf(entry) {
  return Number(entry.connections) || 0;
}

// bucket keeps the top countries apart and folds the long tail into one slice,
// because a ring of forty hairlines says less than eight slices and an "Other".
function bucket(countries) {
  const ordered = [...countries].sort((left, right) => connectionsOf(right) - connectionsOf(left));
  const top = ordered.slice(0, PALETTE_SIZE).map((entry, index) => ({
    label: countryName(entry),
    value: connectionsOf(entry),
    colour: paletteClass(index),
  }));

  const tail = ordered.slice(PALETTE_SIZE).reduce((sum, entry) => sum + connectionsOf(entry), 0);
  if (tail <= 0) return top;
  return [...top, { label: OTHER_LABEL, value: tail, colour: paletteClass(PALETTE_SIZE) }];
}

function pointOn(radius, angle) {
  const x = CENTRE + radius * Math.sin(angle);
  const y = CENTRE - radius * Math.cos(angle);
  return `${x.toFixed(2)} ${y.toFixed(2)}`;
}

function ringSlice(from, to) {
  const large = to - from > Math.PI ? 1 : 0;
  return `M${pointOn(OUTER_RADIUS, from)}`
    + `A${OUTER_RADIUS} ${OUTER_RADIUS} 0 ${large} 1 ${pointOn(OUTER_RADIUS, to)}`
    + `L${pointOn(INNER_RADIUS, to)}`
    + `A${INNER_RADIUS} ${INNER_RADIUS} 0 ${large} 0 ${pointOn(INNER_RADIUS, from)}Z`;
}

function percent(value, total) {
  return total > 0 ? Math.round((value / total) * PERCENT_SCALE) : 0;
}

function countryWord(count) {
  return count === 1 ? 'country' : 'countries';
}

export function renderDonut(host, countries) {
  const rows = (countries || []).filter((entry) => connectionsOf(entry) > 0);
  if (!rows.length) {
    host.innerHTML = '';
    return;
  }

  const segments = bucket(rows);
  const total = segments.reduce((sum, segment) => sum + segment.value, 0);

  let angle = 0;
  const slices = segments.map((segment) => {
    const sweep = Math.min(MAX_SWEEP, (segment.value / total) * FULL_TURN);
    const path = ringSlice(angle, angle + sweep);
    angle += sweep;
    return `<path class="donut-seg ${segment.colour}" d="${path}"></path>`;
  }).join('');

  const legend = segments.map((segment) => `
    <div class="lg-row">
      <span class="legend-swatch ${segment.colour}"></span>
      <span class="lg-name">${esc(segment.label)}</span>
      <span class="lg-val mono">${esc(fmtNumber(segment.value))}</span>
      <span class="lg-pct mono">${esc(percent(segment.value, total))}%</span>
    </div>`).join('');

  const summary = `Share of retained cumulative connections among known-country rows in range: ${fmtNumber(rows.length)} ${countryWord(rows.length)}, ${fmtNumber(total)} cumulative connections`;

  const srRows = segments.map((segment) => `
    <tr>
      <th scope="row">${esc(segment.label)}</th>
      <td>${esc(fmtNumber(segment.value))}</td>
      <td>${esc(percent(segment.value, total))}%</td>
    </tr>`).join('');

  host.innerHTML = `
    <div class="donut">
      <svg class="donut-svg" viewBox="0 0 ${SIZE} ${SIZE}" role="img" aria-label="${esc(summary)}">
        ${slices}
        <text class="donut-count" x="${CENTRE}" y="${CENTRE - 6}" text-anchor="middle">${esc(fmtNumber(rows.length))}</text>
        <text class="donut-unit" x="${CENTRE}" y="${CENTRE + 16}" text-anchor="middle">${countryWord(rows.length)}</text>
      </svg>
      <div class="donut-legend">${legend}</div>
      <div class="sr-only"><table>
        <caption>${esc(summary)}</caption>
        <thead>
          <tr>
            <th scope="col">Country</th>
            <th scope="col">Cumulative connections</th>
            <th scope="col">Share</th>
          </tr>
        </thead>
        <tbody>${srRows}</tbody>
      </table></div>
    </div>`;
}
