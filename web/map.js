import { countrySummaryLabel } from './country.js';
/* World map of attacker origins for the /api/geo/points payload.
 *
 * The outline ships with the app, so the map draws with no tile server and no
 * request that could tell a third party who is looking at this dashboard. */

import { esc, fmtNumber, fmtDuration, paletteClass } from './app.js';
import { WORLD_PATH, WORLD_VIEWBOX, project } from './world.js';

const MIN_RADIUS = 2.5;
const MAX_RADIUS = 14;
const SR_ROWS = 12;
const TIP_GAP = 10;
const UNKNOWN_COUNTRY = 'Unknown';

function countryName(point) {
  return countrySummaryLabel(point) || UNKNOWN_COUNTRY;
}

function countryKey(point) {
  return point.country_key || point.country_code || point.country || '';
}

function connectionsOf(point) {
  return Number(point.connections) || 0;
}

// rankCountries orders countries by connections, so the busiest origin takes the
// first palette colour here and in the donut beside it.
function rankCountries(points) {
  const totals = new Map();
  points.forEach((point) => {
    const key = countryKey(point);
    totals.set(key, (totals.get(key) || 0) + connectionsOf(point));
  });
  const ordered = [...totals.entries()].sort((left, right) => right[1] - left[1]);
  return new Map(ordered.map(([key], index) => [key, index]));
}

// Area carries the value, not radius: a bubble drawn twice as wide reads as four
// times the connections. The floor keeps a single-connection origin visible and
// large enough to hit with a pointer, which is the one place this lies.
function radiusFor(connections, peak) {
  if (!(peak > 0)) return MIN_RADIUS;
  return Math.max(MIN_RADIUS, MAX_RADIUS * Math.sqrt(Math.max(0, connections) / peak));
}

function plural(count, word, pluralWord = word + 's') {
  return `${fmtNumber(count)} ${Number(count) === 1 ? word : pluralWord}`;
}

function bubbleLabel(point) {
  return `${countryName(point)}: ${plural(point.attackers, 'distinct IP')}, ${plural(point.connections, 'cumulative connection')}`;
}

function screenReaderTable(points, caption) {
  const rows = [...points]
    .sort((left, right) => connectionsOf(right) - connectionsOf(left))
    .slice(0, SR_ROWS)
    .map((point) => `
      <tr>
        <th scope="row">${esc(countryName(point))}</th>
        <td>${esc(fmtNumber(point.attackers))}</td>
        <td>${esc(fmtNumber(point.connections))}</td>
        <td>${esc(fmtDuration(point.trapped_seconds))}</td>
      </tr>`).join('');

  // The table is wrapped rather than hidden itself: a table ignores the 1px
  // width of .sr-only and lays out at its content width, which would widen the
  // page sideways. A block wrapper clips it and keeps the semantics intact.
  return `
    <div class="sr-only"><table>
      <caption>${esc(caption)}</caption>
      <thead>
        <tr>
          <th scope="col">Country</th>
          <th scope="col">Distinct IPs at this place</th>
          <th scope="col">Cumulative connections</th>
          <th scope="col">Cumulative connection time</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table></div>`;
}

export function renderMap(host, points) {
  const placed = (points || []).filter(
    (point) => Number.isFinite(Number(point.lat)) && Number.isFinite(Number(point.lon)),
  );

  if (!placed.length) {
    host.innerHTML = '';
    return;
  }

  const ranks = rankCountries(placed);
  const peak = Math.max(...placed.map(connectionsOf));

  // Bubbles are drawn biggest first so a small origin inside a busy region is
  // still on top and still reachable with the pointer.
  const bubbles = placed
    .map((point, index) => ({ point, index, radius: radiusFor(connectionsOf(point), peak) }))
    .sort((left, right) => right.radius - left.radius)
    .map(({ point, index, radius }) => {
      const { x, y } = project(Number(point.lat), Number(point.lon));
      const colour = paletteClass(ranks.has(countryKey(point)) ? ranks.get(countryKey(point)) : -1);
      return `<circle class="map-bubble ${colour}" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${radius.toFixed(2)}"
        tabindex="0" data-point="${index}" aria-label="${esc(bubbleLabel(point))}"></circle>`;
    }).join('');

  const summary = `Displayed locations: ${plural(placed.length, 'shown place')} in ${plural(ranks.size, 'country', 'countries')}`;

  host.innerHTML = `
    <div class="map">
      <svg class="map-svg" viewBox="0 0 ${WORLD_VIEWBOX.width} ${WORLD_VIEWBOX.height}" role="img" aria-label="${esc(summary)}">
        <rect class="map-sea" width="${WORLD_VIEWBOX.width}" height="${WORLD_VIEWBOX.height}" rx="8"></rect>
        <path class="map-land" d="${WORLD_PATH}"></path>
        ${bubbles}
      </svg>
      <div class="map-tip" hidden></div>
      ${screenReaderTable(placed, `Retained cumulative connection totals for IPs with measured growth in the selected range. ${summary}.`)}
    </div>`;

  const frame = host.querySelector('.map');
  const svg = host.querySelector('.map-svg');
  const tip = host.querySelector('.map-tip');

  const hide = () => {
    tip.hidden = true;
  };

  const show = (circle) => {
    const point = placed[Number(circle.dataset.point)];
    if (!point) return;

    tip.innerHTML = `
      <div class="map-tip-name">${esc(countryName(point))}</div>
      <div class="map-tip-row"><span>Distinct IPs at this place</span><span>${esc(fmtNumber(point.attackers))}</span></div>
      <div class="map-tip-row"><span>Cumulative connections</span><span>${esc(fmtNumber(point.connections))}</span></div>
      <div class="map-tip-row"><span>Cumulative connection time</span><span>${esc(fmtDuration(point.trapped_seconds))}</span></div>`;
    tip.hidden = false;

    const frameBox = frame.getBoundingClientRect();
    const bubbleBox = circle.getBoundingClientRect();
    const centre = bubbleBox.left + bubbleBox.width / 2 - frameBox.left - tip.offsetWidth / 2;
    tip.style.left = `${Math.max(0, Math.min(frameBox.width - tip.offsetWidth, centre))}px`;
    tip.style.top = `${Math.max(0, bubbleBox.top - frameBox.top - tip.offsetHeight - TIP_GAP)}px`;
  };

  const bubbleFrom = (event) => event.target.closest && event.target.closest('.map-bubble');

  svg.addEventListener('mouseover', (event) => {
    const circle = bubbleFrom(event);
    if (circle) show(circle);
  });
  svg.addEventListener('mouseout', hide);
  // focusin/focusout rather than focus/blur: these bubble, so one pair of
  // listeners covers every circle however many there are.
  svg.addEventListener('focusin', (event) => {
    const circle = bubbleFrom(event);
    if (circle) show(circle);
  });
  svg.addEventListener('focusout', hide);
}
