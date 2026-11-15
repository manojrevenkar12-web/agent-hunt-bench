import type { Console } from "../../shared/types";
import "./checker.css";

/** The same model draws, read alone and trusted, or read with context and checked. */
export function Checker({ data }: { data: Console }) {
  const alone = data.designs.llm_triage;
  const checked = data.designs.platform;
  const rows: { label: string; alone: string; checked: string }[] = [
    { label: "Reports the model wrote", alone: `${alone.reports}`, checked: `${checked.reports}` },
    { label: "Reports that failed the claim check and went to a person", alone: "not checked", checked: `${checked.failed_checks}` },
    { label: "Escalations resting on a claim the evidence does not hold", alone: `${alone.unsupported_claims_relied_on}`, checked: `${checked.unsupported_claims_relied_on}` },
    { label: "Closures resting on such a claim", alone: `${alone.closed_on_unsupported_report}`, checked: `${checked.closed_on_unsupported_report}` },
    { label: "Alerts from real attacks the model closed", alone: `${alone.attack_alerts_closed_by_model}`, checked: `${checked.attack_alerts_closed_by_model}` },
  ];
  return (
    <section className="section" aria-labelledby="checker-title">
      <header>
        <h2 id="checker-title">The model is assumed to make things up</h2>
        <p>
          Every report names the events and values it relies on. Code looks each one up before the verdict counts, and the model may never close a critical
          alert. The checker verifies citations, not reasoning.
        </p>
      </header>
      <table className="checker sheet">
        <thead>
          <tr>
            <th scope="col" />
            <th scope="col">Model alone, trusted</th>
            <th scope="col">With context, checked</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.label}>
              <th scope="row">{r.label}</th>
              <td className="num">{r.alone}</td>
              <td className="num">{r.checked}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
