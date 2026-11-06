/* One immutable cutoff per group of related requests. UTC avoids DST ambiguity. */
export function rangeParams(windowValue, asOf = new Date()) {
  return { window: windowValue, as_of: asOf.toISOString() };
}

export function rangeNote(data) {
  if (!data?.from || !data?.to) return '';
  return `UTC ${data.from} → ${data.to} (end excluded). Minute boundaries round forward; edge buckets may be partial and the current minute may still change.`;
}

// All visible window deltas come from the same response as the plotted points.
export function seriesTotals(data) {
  const totals = { opens: 0, bytes_sent: 0, trapped_seconds: 0 };
  for (const entry of data?.series || []) {
    for (const point of entry.points || []) {
      for (const metric of Object.keys(totals)) totals[metric] += Number(point[metric]) || 0;
    }
  }
  return totals;
}
