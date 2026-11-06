/* A route owns a lifetime; each loader owns its latest request generation. */
export function latestRequests(parentSignal) {
  const lifetime = new AbortController();
  let current = null;
  let generation = 0;
  const cancel = () => { generation++; current?.abort(); };
  const dispose = () => {
    cancel();
    lifetime.abort();
    parentSignal?.removeEventListener('abort', dispose);
  };
  if (parentSignal?.aborted) dispose();
  else parentSignal?.addEventListener('abort', dispose, { once: true });
  return {
    signal: lifetime.signal, cancel, dispose,
    begin() {
      cancel();
      const version = generation;
      const controller = new AbortController();
      current = controller;
      if (lifetime.signal.aborted) controller.abort();
      return {
        signal: controller.signal,
        isCurrent: () => !lifetime.signal.aborted && !controller.signal.aborted && version === generation,
      };
    },
  };
}

export function isAbortError(error) { return error?.name === 'AbortError'; }

// One round at a time; a rejected callback cannot strand the gate or its peers.
export function serializedRefresh() {
  let running = null;
  return (work) => {
    if (running) return running;
    running = Promise.resolve().then(work).catch(() => {}).finally(() => { running = null; });
    return running;
  };
}
