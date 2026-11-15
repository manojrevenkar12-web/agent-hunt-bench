import type { ReactNode } from "react";

export function Skeleton({ rows }: { rows: number }) {
  return (
    <div className="state" aria-busy="true" aria-label="Loading the console">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="skeleton" />
      ))}
    </div>
  );
}

export function ErrorRetry({ error, onRetry }: { error: Error; onRetry: () => void }) {
  return (
    <div className="state" role="alert">
      <p>The console data did not load: {error.message}.</p>
      <p className="muted small">Run <code>python scripts/readme.py</code> to write web/public/data/console.json, then retry.</p>
      <button onClick={onRetry}>Retry</button>
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="state muted">{children}</div>;
}

export const minutes = (m: number | null) => (m === null ? "–" : m >= 120 ? `${(m / 60).toFixed(1)} h` : `${Math.round(m)} min`);
export const share = (x: number, digits = 0) => `${(x * 100).toFixed(digits)}%`;
