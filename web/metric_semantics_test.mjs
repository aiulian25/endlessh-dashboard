import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { activityLabel, activityNote, scrapeNote, CONNECTION_TIME_NOTE, CUMULATIVE_NOTE } from './metric-notes.js';

test('sampled statuses and units do not infer sessions or disconnect events', () => {
  assert.equal(activityLabel('trapped'), 'Recently active');
  assert.equal(activityLabel('gave_up'), 'No recent measured activity');
  assert.equal(activityLabel('unknown'), 'Activity time unknown');
  assert.match(activityNote(34), /34 s/);
  assert.match(activityNote(2.5), /2.5 s/);
  assert.match(CONNECTION_TIME_NOTE, /connection-seconds.*exceed wall-clock/);
  assert.match(CUMULATIVE_NOTE, /machine\/IP.*range selects rows/);
  const context = scrapeNote({ evaluated_at:'2026-11-05T12:00:00Z',oldest_success_at:'2026-11-05T11:50:00Z',newest_success_at:'2026-11-05T11:59:55Z',unobserved_machines:1,failed_latest_scrapes:1 });
  assert.match(context, /5–600 s/);
  assert.match(context, /without a successful scrape/);
  assert.match(context, /attempt failed; retained readings/);
});

test('row renderer retains cumulative values and unknown activity for imports', async () => {
  const source = process.env.ATTACKERS_TEST_SOURCE
    ? await readFile(process.env.ATTACKERS_TEST_SOURCE, 'utf8')
    : await readFile(new URL('./attackers.js', import.meta.url), 'utf8');
  const module = new vm.SourceTextModule(source);
  const notes = new vm.SourceTextModule(await readFile(new URL('./metric-notes.js', import.meta.url), 'utf8'));
  const focus = new vm.SourceTextModule(await readFile(new URL('./focus.js', import.meta.url), 'utf8'));
  const navigation = new vm.SourceTextModule(await readFile(new URL('./navigation.js', import.meta.url), 'utf8'));
  const panel = new vm.SourceTextModule(await readFile(new URL('./panel-state.js', import.meta.url), 'utf8'));
  const requests = new vm.SourceTextModule(await readFile(new URL('./requests.js', import.meta.url), 'utf8'));
  const country = new vm.SourceTextModule(await readFile(new URL('./country.js', import.meta.url), 'utf8'));
  const range = new vm.SourceTextModule(await readFile(new URL('./time-range.js', import.meta.url), 'utf8'));
  const names = ['api','qs','esc','icon','onRefresh','renderError','emptyState','fmtDuration','fmtNumber','fmtRelative','fmtDateTime','machinesParam','getWindow','currentMachines','ATTACKER_TRAPPED'];
  const app = new vm.SyntheticModule(names, function () {
    for (const name of names) this.setExport(name, name === 'ATTACKER_TRAPPED' ? 'trapped' : (v) => String(v ?? ''));
  });
  await module.link((name) => name === './app.js' ? app : name === './metric-notes.js' ? notes : name === './country.js' ? country : name === './requests.js' ? requests : name === './panel-state.js' ? panel : name === './navigation.js' ? navigation : name === './focus.js' ? focus : range);
  await module.evaluate();
  const host = { innerHTML:'', querySelectorAll:() => [] };
  const rows = ['trapped','gave_up','unknown'].map((status,i) => ({status, ip:'2001:db8:1234:5678:abcd:ef01:2345:6789',machine_name:`machine-${i}`,connections:55,trapped_seconds:999999999,has_undated_history:i===2,last_measured_activity_at:i===2?null:'2026-11-05T12:00:00Z'}));
  module.namespace.renderAttackersTable(host,rows);
  assert.match(host.innerHTML, /Recently active/);
  assert.match(host.innerHTML, /No recent measured activity/);
  assert.match(host.innerHTML, /Activity time unknown/);
  assert.match(host.innerHTML, /Connections \(cumulative\)/);
  assert.match(host.innerHTML, /Connection time \(cumulative\)/);
  assert.match(host.innerHTML, /undated imported or legacy/);
  assert.match(host.innerHTML, /999999999/);
  assert.doesNotMatch(host.innerHTML, /Gave up|>Trapped<|live sessions/);
});

test('shared absolute timestamp formatter distinguishes repeated local DST hours', async () => {
  const app = await readFile(new URL('./app.js', import.meta.url), 'utf8');
  const source = app.slice(app.indexOf('export function fmtDateTime'),app.indexOf('export function fmtDelta'));
  const module = new vm.SourceTextModule(source);await module.link(() => {});await module.evaluate();
  const first=module.namespace.fmtDateTime('2024-11-03T01:30:00-04:00');
  const second=module.namespace.fmtDateTime('2024-11-03T01:30:00-05:00');
  assert.notEqual(first,second);assert.match(first,/UTC/);assert.match(second,/UTC/);
});
