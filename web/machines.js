/* Machines page: registry table, add/edit/delete dialogs, and a per-machine drill-down. */

import {
  api, qs, esc, icon, toast, onRefresh, renderError, emptyState, openModal, confirmModal,
  fmtDuration, fmtNumber, fmtRelative, fmtDateTime,
  loadMachines, statusBadge, statusDot, navigate,
  getWindow, setWindow, WINDOWS, STATUS_DOWN,
  MACHINE_PALETTE_SIZE,
} from './app.js';
import { renderChart, renderLegend } from './chart.js';
import { renderAttackersTable } from './attackers.js';

const DEFAULT_PORT = 2112;
const DEFAULT_METRICS_PATH = '/metrics';
const DRILL_ROWS = 25;
const DRILL_COLUMNS = ['country', 'ip', 'location', 'trapped', 'connections', 'last_seen', 'status'];

const FIELD_HINTS = [
  { field: 'host', keywords: ['host', 'address', 'resolve', 'loopback', 'private', 'dns'] },
  { field: 'port', keywords: ['port'] },
  { field: 'metrics_path', keywords: ['path', 'metrics'] },
  { field: 'group_label', keywords: ['group', 'label'] },
  { field: 'colour', keywords: ['colour', 'color'] },
  { field: 'name', keywords: ['name'] },
];

function fieldForMessage(message) {
  const text = String(message || '').toLowerCase();
  const hit = FIELD_HINTS.find((hint) => hint.keywords.some((keyword) => text.includes(keyword)));
  return hit ? hit.field : null;
}

// One swatch per palette slot. Radios rather than buttons: a colour choice is
// exactly a single-selection group, so the arrow keys move through it and a
// screen reader announces it as a choice without any custom key handling.
function colourSwatches(current) {
  const chosen = current || '';
  return Array.from({ length: MACHINE_PALETTE_SIZE }, (unused, index) => {
    const slot = `s-${index + 1}`;
    return `
      <label class="swatch">
        <input type="radio" name="colour" value="${slot}" class="sr-only"
          ${chosen === slot ? 'checked' : ''} aria-label="Colour ${index + 1}">
        <span class="swatch-dot ${slot}" aria-hidden="true"></span>
      </label>`;
  }).join('');
}

function formMarkup(machine) {
  const value = (key, fallback = '') => esc(machine && machine[key] !== undefined && machine[key] !== null ? machine[key] : fallback);
  const enabled = !machine || machine.enabled !== false;
  return `
    <div class="form-grid">
      <div class="field span-2">
        <label for="mf-name">Name</label>
        <input class="input" id="mf-name" name="name" value="${value('name')}" required maxlength="64" autocomplete="off">
        <p class="field-error" data-error-for="name" hidden></p>
      </div>
      <div class="field span-2">
        <label for="mf-host">Host</label>
        <input class="input" id="mf-host" name="host" value="${value('host')}" required autocapitalize="none" spellcheck="false" autocomplete="off">
        <p class="field-hint">Hostname or IP of the machine running endlessh-go.</p>
        <p class="field-error" data-error-for="host" hidden></p>
      </div>
      <div class="field">
        <label for="mf-port">Port</label>
        <input class="input" id="mf-port" name="port" type="number" min="1" max="65535" value="${value('port', DEFAULT_PORT)}" required>
        <p class="field-error" data-error-for="port" hidden></p>
      </div>
      <div class="field">
        <label for="mf-path">Metrics path</label>
        <input class="input" id="mf-path" name="metrics_path" value="${value('metrics_path', DEFAULT_METRICS_PATH)}" required autocapitalize="none" spellcheck="false">
        <p class="field-error" data-error-for="metrics_path" hidden></p>
      </div>
      <div class="field span-2">
        <label for="mf-group">Group label</label>
        <input class="input" id="mf-group" name="group_label" value="${value('group_label')}" autocomplete="off">
        <p class="field-error" data-error-for="group_label" hidden></p>
      </div>
      <div class="field span-2">
        <span class="field-label" id="mf-colour-label">Colour</span>
        <div class="swatches" role="radiogroup" aria-labelledby="mf-colour-label" id="mf-colour">
          ${colourSwatches(value('colour'))}
        </div>
        <p class="field-hint">${machine ? 'Used on this machine\u2019s card, its sparkline and its line on the chart.'
          : 'Leave it and an unused colour is chosen for you.'}</p>
        <p class="field-error" data-error-for="colour" hidden></p>
      </div>
      <div class="field span-2">
        <label class="switch"><input type="checkbox" id="mf-enabled" ${enabled ? 'checked' : ''}> Scrape this machine</label>
      </div>
    </div>
    <p class="probe-result" data-probe-result hidden></p>
    <p class="form-error" data-form-error hidden></p>`;
}

function readForm(form) {
  return {
    name: form.querySelector('#mf-name').value.trim(),
    host: form.querySelector('#mf-host').value.trim(),
    port: Number(form.querySelector('#mf-port').value),
    metrics_path: form.querySelector('#mf-path').value.trim(),
    group_label: form.querySelector('#mf-group').value.trim(),
    enabled: form.querySelector('#mf-enabled').checked,
    // Empty when nothing is picked, which the server reads as "choose one for
    // me" and fills with a slot no other machine is using.
    colour: form.querySelector('input[name="colour"]:checked')?.value || '',
  };
}

function clearErrors(form) {
  form.querySelectorAll('[data-error-for]').forEach((node) => {
    node.hidden = true;
    node.textContent = '';
  });
  form.querySelectorAll('.input').forEach((input) => input.removeAttribute('aria-invalid'));
  const box = form.querySelector('[data-form-error]');
  box.hidden = true;
  box.textContent = '';
}

function showApiError(form, message) {
  const field = fieldForMessage(message);
  const target = field ? form.querySelector(`[data-error-for="${field}"]`) : null;
  if (target) {
    target.textContent = message;
    target.hidden = false;
    const input = target.closest('.field').querySelector('.input');
    input.setAttribute('aria-invalid', 'true');
    input.focus();
    return;
  }
  const box = form.querySelector('[data-form-error]');
  box.textContent = message;
  box.hidden = false;
}

// testConnection asks the server to scrape the target once, using the same code
// path a real scrape takes, so a machine can be proved reachable before it is
// saved rather than turning into a red row afterwards.
async function testConnection(form, button) {
  const result = form.querySelector('[data-probe-result]');
  const label = button.textContent;
  clearErrors(form);
  button.textContent = 'Testing…';
  result.hidden = false;
  result.className = 'probe-result';
  result.textContent = 'Contacting the host…';

  try {
    const probe = await api('/machines/test', { method: 'POST', body: readForm(form) });
    result.className = 'probe-result ok';
    result.textContent = probe.message;
  } catch (error) {
    if (error.status === 401) return;
    result.className = 'probe-result bad';
    result.textContent = error.message;
  } finally {
    button.textContent = label;
  }
}

// Exported so the sidebar's "Add machine" button opens this very dialog rather
// than growing a second copy of the same form.
function machineDialog(machine, onDone) {
  const editing = Boolean(machine);
  openModal({
    title: editing ? `Edit ${machine.name}` : 'Add machine',
    content: formMarkup(machine),
    submitLabel: editing ? 'Save changes' : 'Add machine',
    secondary: { label: 'Test connection', onClick: testConnection },
    onSubmit: async (form) => {
      clearErrors(form);
      const body = readForm(form);
      try {
        const saved = editing
          ? await api(`/machines/${machine.id}`, { method: 'PUT', body })
          : await api('/machines', { method: 'POST', body });
        toast(editing ? `${saved.name} updated.` : `${saved.name} added.`, 'success');
        onDone();
        return true;
      } catch (error) {
        if (error.status === 401) return true;
        showApiError(form, error.message);
        return false;
      }
    },
  });
}

/* ---------------- list ---------------- */

function machineRow(machine) {
  const failing = machine.status === STATUS_DOWN || machine.consecutive_failures > 0;
  return `
    <tr>
      <td class="strong">
        <a href="#/machines/${machine.id}">${esc(machine.name)}</a>
        ${failing && machine.last_error ? `<div class="health-meta bad">${esc(machine.last_error)}</div>` : ''}
      </td>
      <td class="mono">${esc(machine.host)}:${esc(machine.port)}</td>
      <td class="mono">${esc(machine.metrics_path)}</td>
      <td>${esc(machine.group_label || '')}</td>
      <td>${statusDot(machine.status)} ${statusBadge(machine.status)}</td>
      <td class="mono num">${esc(fmtNumber(machine.trapped_now))}</td>
      <td><span title="${esc(fmtDateTime(machine.last_scrape_at))}">${esc(fmtRelative(machine.last_scrape_at))}</span></td>
      <td>
        <span class="row-actions">
          <button type="button" class="row-btn" data-edit="${machine.id}" aria-label="Edit ${esc(machine.name)}">${icon('pencil', 15)}</button>
          <button type="button" class="row-btn danger" data-delete="${machine.id}" aria-label="Delete ${esc(machine.name)}">${icon('trash', 15)}</button>
        </span>
      </td>
    </tr>`;
}

async function renderList(mount) {
  mount.innerHTML = `
    <div class="page-head">
      <h1 class="page-title">Machines</h1>
      <button type="button" class="btn btn-primary" id="add-machine">${icon('plus', 16)} Add machine</button>
    </div>
    <div class="card" id="machines-card">
      <div class="card-pad"><div class="skeleton w60"></div></div>
    </div>`;

  const card = mount.querySelector('#machines-card');

  const load = async () => {
    try {
      const machines = await loadMachines();
      paint(machines);
    } catch (error) {
      if (error.status === 401) return;
      renderError(card, error, load);
    }
  };

  const paint = (machines) => {
    if (!machines.length) {
      card.innerHTML = emptyState({
        title: 'No machines registered yet',
        text: 'Add the first endlessh-go machine you want to watch. You need its host, the port its Prometheus metrics listen on, and the metrics path.',
        actionLabel: 'Add your first machine',
      });
      card.querySelector('[data-empty-action]').addEventListener('click', () => machineDialog(null, load));
      return;
    }

    card.innerHTML = `
      <div class="table-wrap">
        <table class="tbl">
          <thead><tr>
            <th scope="col">Machine</th>
            <th scope="col">Host</th>
            <th scope="col">Metrics path</th>
            <th scope="col">Group</th>
            <th scope="col">Status</th>
            <th scope="col" class="num">Trapped now</th>
            <th scope="col">Last scrape</th>
            <th scope="col"><span class="sr-only">Actions</span></th>
          </tr></thead>
          <tbody>${machines.map(machineRow).join('')}</tbody>
        </table>
      </div>`;

    card.querySelectorAll('[data-edit]').forEach((button) => {
      button.addEventListener('click', () => {
        const machine = machines.find((entry) => entry.id === Number(button.dataset.edit));
        machineDialog(machine, load);
      });
    });

    card.querySelectorAll('[data-delete]').forEach((button) => {
      button.addEventListener('click', async () => {
        const machine = machines.find((entry) => entry.id === Number(button.dataset.delete));
        const ok = await confirmModal({
          title: `Delete ${machine.name}?`,
          message: `<p>The dashboard stops scraping <strong>${esc(machine.name)}</strong> and its stored history is removed. Attackers seen only on this machine disappear from the tables.</p><p>This cannot be undone.</p>`,
          confirmLabel: 'Delete machine',
        });
        if (!ok) return;
        try {
          await api(`/machines/${machine.id}`, { method: 'DELETE' });
          toast(`${machine.name} deleted.`, 'success');
          load();
        } catch (error) {
          if (error.status !== 401) toast(error.message, 'error');
        }
      });
    });
  };

  mount.querySelector('#add-machine').addEventListener('click', () => machineDialog(null, load));
  onRefresh(load);
  await load();
}

/* ---------------- drill-down ---------------- */

async function renderDetail(mount, id) {
  mount.innerHTML = `
    <div class="page-head">
      <a href="#/machines" class="btn btn-ghost btn-sm">${icon('chevronLeft', 14)} All machines</a>
    </div>
    <div class="card card-pad"><div class="skeleton w40"></div></div>`;

  const load = async () => {
    try {
      const machines = await loadMachines();
      const machine = machines.find((entry) => entry.id === id);
      if (!machine) {
        mount.innerHTML = `<div class="card">${emptyState({
          title: 'Machine not found',
          text: 'It may have been deleted from another session.',
          actionLabel: 'Back to machines',
        })}</div>`;
        mount.querySelector('[data-empty-action]').addEventListener('click', () => navigate('#/machines'));
        return;
      }

      const params = { machines: String(id), window: getWindow() };
      const [timeseries, attackers] = await Promise.all([
        api('/timeseries' + qs(params)),
        api('/attackers' + qs({ ...params, sort: 'trapped_seconds', order: 'desc', page: 1, per_page: DRILL_ROWS })),
      ]);

      mount.innerHTML = `
        <div class="page-head">
          <a href="#/machines" class="btn btn-ghost btn-sm">${icon('chevronLeft', 14)} All machines</a>
        </div>
        <div class="page-head">
          <h1 class="page-title">${statusDot(machine.status)} ${esc(machine.name)}</h1>
          ${statusBadge(machine.status)}
          <span class="page-sub mono">${esc(machine.host)}:${esc(machine.port)}${esc(machine.metrics_path)}</span>
        </div>
        ${machine.last_error ? `<div class="alert" role="status">${icon('alert', 18)}<span>${esc(machine.last_error)}</span></div>` : ''}
        <div class="grid-stats">
          <div class="card stat"><span class="stat-label">Trapped now</span><span class="stat-value amber">${esc(fmtNumber(machine.trapped_now))}</span><span class="stat-delta neutral">live sessions</span></div>
          <div class="card stat"><span class="stat-label">Last scrape</span><span class="stat-value">${esc(fmtRelative(machine.last_scrape_at))}</span><span class="stat-delta neutral">${esc(fmtDateTime(machine.last_scrape_at))}</span></div>
          <div class="card stat"><span class="stat-label">Last success</span><span class="stat-value">${esc(fmtRelative(machine.last_ok_at))}</span><span class="stat-delta neutral">${esc(fmtNumber(machine.consecutive_failures))} failures in a row</span></div>
          <div class="card stat"><span class="stat-label">Group</span><span class="stat-value">${esc(machine.group_label || '—')}</span><span class="stat-delta neutral">${machine.enabled ? 'Scraping enabled' : 'Scraping disabled'}</span></div>
        </div>
        <div class="card card-pad">
          <div class="card-head flush">
            <h2 class="card-title">Attacker time trapped</h2>
            <div class="legend" id="md-legend"></div>
            <div class="seg" id="md-range" role="group" aria-label="Time range"></div>
          </div>
          <div id="md-chart"></div>
        </div>
        <div class="card">
          <div class="card-head">
            <h2 class="card-title">Attackers on this machine</h2>
            <a href="#/attackers">View all ${esc(fmtNumber(attackers.total))}</a>
          </div>
          <div id="md-table"></div>
        </div>`;

      renderLegend(mount.querySelector('#md-legend'), timeseries.series || []);
      renderChart(mount.querySelector('#md-chart'), timeseries, { label: `Attacker time trapped on ${machine.name}`, format: fmtDuration });
      renderAttackersTable(mount.querySelector('#md-table'), attackers.rows || [], { columns: DRILL_COLUMNS });

      const rangeHost = mount.querySelector('#md-range');
      rangeHost.innerHTML = WINDOWS.map((value) => `
        <button type="button" data-window="${value}" aria-pressed="${value === getWindow()}">${value}</button>`).join('');
      rangeHost.querySelectorAll('[data-window]').forEach((button) => {
        button.addEventListener('click', () => {
          setWindow(button.dataset.window);
          load();
        });
      });
    } catch (error) {
      if (error.status === 401) return;
      mount.innerHTML = '';
      renderError(mount, error, load);
    }
  };

  onRefresh(load);
  await load();
}

export async function render(mount, param) {
  const id = Number(param);
  if (Number.isFinite(id) && param) await renderDetail(mount, id);
  else await renderList(mount);
}
