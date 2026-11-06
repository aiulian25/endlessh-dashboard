// Name-only groups stay distinct from code-backed identities, even if labels match.
export function countrySummaryLabel(entry) {
  const label = entry.country || entry.country_code || '';
  if (entry.country_key?.startsWith('name:')) return `${label} (name only)`;
  return entry.country_code && label !== entry.country_code ? `${label} (${entry.country_code})` : label;
}
