import { useState } from "react";
import type { Console, Detection } from "../../shared/types";
import { Empty } from "../../shared/ui";
import "./detections.css";

const SOURCES = ["all", "idp", "saas", "agent", "cloud", "edr"] as const;
const SOURCE_NAMES: Record<string, string> = { all: "All", idp: "Identity", saas: "Documents", agent: "Agents", cloud: "Cloud", edr: "Endpoint" };

/** Each detection's false alerts a day on attack-free history against the budget it has to hold to merge. */
export function Detections({ data }: { data: Console }) {
  const [source, setSource] = useState<(typeof SOURCES)[number]>("all");
  const rows = data.detections.filter((d) => source === "all" || d.source === source).sort((a, b) => b.backtest_per_day / b.budget - a.backtest_per_day / a.budget || a.id.localeCompare(b.id));
  return (
    <section className="section" aria-labelledby="det-title">
      <header>
        <h2 id="det-title">Detections, and the budget each one holds</h2>
        <p>
          Each detection is a file with examples it must fire on and stay quiet on, replayed on a week of attack-free history before it merges. The bar is its
          false alerts a day against its budget.
        </p>
      </header>
      <div className="det-filter" role="tablist" aria-label="Log source">
        {SOURCES.map((s) => (
          <button key={s} role="tab" aria-selected={s === source} onClick={() => setSource(s)}>
            {SOURCE_NAMES[s]}
          </button>
        ))}
      </div>
      {rows.length === 0 ? <Empty>No detection reads this source yet.</Empty> : <ul className="det-list sheet">{rows.map((d) => <Row key={d.id} d={d} />)}</ul>}
    </section>
  );
}

function Row({ d }: { d: Detection }) {
  const used = Math.min(1, d.backtest_per_day / d.budget);
  const ok = d.within_budget && d.examples_pass;
  return (
    <li className="det-row">
      <div className="det-name">
        <span>{d.title}</span>
        <span className="tiny muted">
          <code>{d.id}</code>, {d.kind.replace("_", " ")}, {d.technique}, {d.severity}
        </span>
      </div>
      <div className="det-budget" aria-label={`${d.backtest_per_day} false alerts a day, budget ${d.budget}`}>
        <span className="det-budget-track">
          <span className={`det-budget-used ${ok ? "" : "over"}`} style={{ width: `${used * 100}%` }} />
        </span>
        <span className="tiny num muted">
          {d.backtest_per_day} of {d.budget} a day
        </span>
      </div>
      <span className="num small det-hits">
        {d.true} of {d.alerts} from attacks
      </span>
    </li>
  );
}
