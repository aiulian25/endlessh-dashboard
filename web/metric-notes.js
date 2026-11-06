/* Descriptions of sampled counters; all numeric activity semantics stay server-owned. */
export const CONNECTION_TIME_NOTE = 'Connection time sums connection-seconds across concurrent connections and can exceed wall-clock time.';
export const CUMULATIVE_NOTE = 'Row values are retained cumulative totals per machine/IP, including undated imports; the range selects rows, not per-IP window deltas. * marks undated imported or legacy history.';

export function activityLabel(status) {
  if (status === 'trapped') return 'Recently active';
  if (status === 'gave_up') return 'No recent measured activity';
  return 'Activity time unknown';
}
export function activityNote(seconds) {
  const threshold = Number(seconds);
  const value = Number.isFinite(threshold) && threshold > 0
    ? threshold.toLocaleString(undefined, { maximumFractionDigits: 9 }) + ' s'
    : 'unknown';
  return `Recent-activity threshold: ${value} (2× scrape interval). First-import activity time is unknown.`;
}
export function scrapeNote(activity) {
  if (!activity) return 'Successful scrape age unknown.';
  const now = new Date(activity.evaluated_at).getTime();
  const age = (stamp) => Math.max(0, Math.floor((now - new Date(stamp).getTime()) / 1000));
  let text = 'Successful scrape age unknown';
  if (activity.oldest_success_at && activity.newest_success_at) {
    const oldest = age(activity.oldest_success_at), newest = age(activity.newest_success_at);
    text = `Successful scrape age: ${newest === oldest ? oldest : `${newest}–${oldest}`} s`;
  }
  if (activity.unobserved_machines) text += ` · ${activity.unobserved_machines} ${activity.unobserved_machines === 1 ? 'machine' : 'machines'} without a successful scrape`;
  if (activity.failed_latest_scrapes) text += ` · ${activity.failed_latest_scrapes} latest ${activity.failed_latest_scrapes === 1 ? 'attempt' : 'attempts'} failed; retained readings shown`;
  if (activity.disabled_machines) text += ` · ${activity.disabled_machines} ${activity.disabled_machines === 1 ? 'machine' : 'machines'} disabled`;
  return text + '.';
}
