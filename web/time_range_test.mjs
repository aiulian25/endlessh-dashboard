import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { rangeParams, rangeNote, seriesTotals } from './time-range.js';

test('one cutoff survives offset/DST input and can be shared unchanged', () => {
  const first = rangeParams('7d', new Date('2024-10-27T01:30:30+01:00'));
  const second = rangeParams('7d', new Date('2024-10-27T01:30:30+00:00'));
  assert.equal(first.as_of, '2024-10-27T00:30:30.000Z');
  assert.equal(second.as_of, '2024-10-27T01:30:30.000Z');
  const chart = { ...first, machines: '1' };
  const summary = { ...first, machines: '1' };
  assert.deepEqual(chart, summary);
  assert.match(rangeNote({ from: first.as_of, to: second.as_of }), /UTC.*end excluded.*round forward/);
});

test('chart presents partial UTC intervals in text and keyboard tooltips', async () => {
  const chart = new vm.SourceTextModule(await readFile(new URL('./chart.js', import.meta.url), 'utf8'));
  const range = new vm.SourceTextModule(await readFile(new URL('./time-range.js', import.meta.url), 'utf8'));
  const notes = new vm.SourceTextModule(await readFile(new URL('./metric-notes.js', import.meta.url), 'utf8'));
  const app = new vm.SyntheticModule(['esc', 'fmtDuration', 'machineColour'], function () {
    this.setExport('esc', (v) => String(v ?? ''));
    this.setExport('fmtDuration', (v) => String(v));
    this.setExport('machineColour', () => 'amber');
  });
  await chart.link((name) => name === './app.js' ? app : name === './metric-notes.js' ? notes : range);
  await chart.evaluate();
  const elements = Object.fromEntries(['.chart-plot', '.chart-hit', '.chart-tip', '.chart-cursor'].map((key) => [key, {
    style: {}, handlers: {}, clientWidth: 1000, offsetWidth: 100,
    addEventListener(name, fn) { this.handlers[name] = fn; }, setAttribute() {},
  }]));
  const host = { innerHTML: '', querySelector: (key) => elements[key] };
  const data = { from: '2024-03-31T12:02:00Z', to: '2024-03-31T12:03:00Z', bucket_seconds: 3600,
    series: [{ machine_id: 1, machine_name: 'one', points: [{ t: '2024-03-31T12:02:00Z', to: '2024-03-31T12:03:00Z', partial: true, trapped_seconds: 30 }] }] };
  chart.namespace.renderChart(host, data);
  assert.match(host.innerHTML, /partial bucket/);
  assert.match(host.innerHTML, /2024-03-31T12:03:00Z/);
  assert.doesNotMatch(host.innerHTML, />now</);
  elements['.chart-hit'].handlers.focus();
  assert.match(elements['.chart-tip'].innerHTML, /12:02/);
  assert.match(elements['.chart-tip'].innerHTML, /12:03/);
  assert.match(elements['.chart-tip'].innerHTML, /UTC.*partial bucket/);
  assert.equal(elements['.chart-tip'].hidden, false);
  chart.namespace.renderChart(host, { from: data.from, to: data.from, series: [] });
  assert.match(host.innerHTML, /No data for this range/);
  assert.match(host.innerHTML, /end excluded/);
});

test('visible window deltas are the sums of the plotted response', () => {
  const data = { series: [
    { points: [{ opens: 2, bytes_sent: 30, trapped_seconds: 1.5, partial: true }] },
    { points: [{ opens: 3, bytes_sent: 40, trapped_seconds: 2.5 }] },
  ] };
  assert.deepEqual(seriesTotals(data), { opens: 5, bytes_sent: 70, trapped_seconds: 4 });
  assert.deepEqual(seriesTotals({ series: [] }), { opens: 0, bytes_sent: 0, trapped_seconds: 0 });
});
