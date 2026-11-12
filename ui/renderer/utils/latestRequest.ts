import { useCallback, useEffect, useRef } from 'react';

/**
 * Keeps only the newest of several overlapping requests.
 *
 * `begin()` starts a new request: it cancels the one before it and returns `isCurrent()`, which is false as soon
 * as another request has begun (or the component has gone). A late reply must check it before it sets any state,
 * so an older answer can never overwrite a newer one.
 *
 *   const latest = useLatestRequest();
 *   const run = async () => { const { signal, isCurrent } = latest.begin(); const r = await call(signal); if (!isCurrent()) return; setData(r); };
 */
export interface LatestRequest {
  begin: () => { signal: AbortSignal; isCurrent: () => boolean };
  cancel: () => void;
}

export function createLatestRequest(): LatestRequest & { dispose: () => void } {
  let seq = 0;
  let ctl: AbortController | null = null;
  let disposed = false;
  return {
    begin() {
      ctl?.abort();
      ctl = new AbortController();
      const mine = ++seq;
      const signal = ctl.signal;
      return { signal, isCurrent: () => !disposed && mine === seq };
    },
    cancel() {
      seq++;
      ctl?.abort();
    },
    dispose() {
      disposed = true;
      ctl?.abort();
    },
  };
}

export function useLatestRequest(): LatestRequest {
  const ref = useRef<ReturnType<typeof createLatestRequest> | null>(null);
  if (!ref.current) ref.current = createLatestRequest();
  useEffect(() => () => ref.current?.dispose(), []);
  return {
    begin: useCallback(() => ref.current!.begin(), []),
    cancel: useCallback(() => ref.current!.cancel(), []),
  };
}
