/* Redraw a region without losing its semantic keyboard position. */
const pending = new WeakMap();
export function focusHeading(root) {
  const target = root.matches?.('h1,h2,[data-focus-heading]') ? root : root.querySelector('h1,h2,[data-focus-heading]') || root;
  target.setAttribute('tabindex', '-1');
  target.focus({preventScroll:true});
  return target;
}
export function moveFocusFrom(host) {
  if (typeof document === 'undefined' || !host.contains(document.activeElement)) return;
  focusHeading(host.closest('.card,aside') || host.parentElement);
}
function identity(node) {
  const attributes = ['id','data-focus-key','data-sort','data-prev','data-next','data-window','data-country','data-grip','data-edit','data-delete','href'];
  for (const attribute of attributes) if (node.hasAttribute(attribute)) return [attribute,node.getAttribute(attribute)];
  if (node.matches('input[type="checkbox"]')) return ['value',node.value];
  if (node.matches('h1,h2,[data-focus-heading]')) return ['heading',''];
  return null;
}
export function updateWithFocus(root, paint, signal) {
  if (typeof document === 'undefined') return paint();
  if (signal?.aborted) return;
  const active = document.activeElement;
  const inside = root.contains(active);
  // Keep a chart's inspected bucket/bubble until focus leaves that region.
  // Only its latest publication waits; other panels and fetches keep updating.
  if (inside && active.matches('.chart-hit,.map-bubble')) {
    const existing = pending.get(root);
    if (existing) { existing.paint = paint; return; }
    const item = {paint};
    const clear = () => { root.removeEventListener('focusout',flush); signal?.removeEventListener('abort',clear); pending.delete(root); };
    const flush = () => queueMicrotask(() => {
      if (root.contains(document.activeElement)) return;
      const latest = pending.get(root); clear();
      if (!signal?.aborted) latest?.paint();
    });
    pending.set(root,item);
    root.addEventListener('focusout',flush);
    signal?.addEventListener('abort',clear,{once:true});
    return;
  }
  const key = inside ? identity(active) : null;
  paint();
  if (!inside || active.isConnected || signal?.aborted) return;
  let replacement;
  if (key?.[0] === 'heading') { focusHeading(root); return; }
  if (key) replacement = [...root.querySelectorAll(`[${key[0]}]`)].find(node => node.getAttribute(key[0]) === key[1]);
  if (replacement && !replacement.disabled && replacement.getClientRects().length) replacement.focus({preventScroll:true});
  else focusHeading(root);
}
