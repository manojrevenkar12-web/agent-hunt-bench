import { useState } from "react";
import { Case } from "../features/case/Case";
import { Checker } from "../features/checker/Checker";
import { Detections } from "../features/detections/Detections";
import { Race } from "../features/race/Race";
import { useConsole } from "../shared/api";
import type { Console, DesignKey } from "../shared/types";
import { ErrorRetry, Skeleton, share } from "../shared/ui";

export function App() {
  const q = useConsole();
  const [design, setDesign] = useState<DesignKey>("platform");
  return (
    <main className="page">
      <header className="masthead">
        <h1>Hunt bench</h1>
        <p>
          Detection and response for a simulated SaaS company, scored against attacks whose truth only the simulation knows: which ones a person confirmed, and
          whether in time.
        </p>
        {q.data && <Summary data={q.data} />}
      </header>
      {q.isPending && <Skeleton rows={8} />}
      {q.isError && <ErrorRetry error={q.error} onRetry={() => q.refetch()} />}
      {q.data && (
        <>
          <Race data={q.data} design={design} onDesign={setDesign} />
          <Checker data={q.data} />
          <Detections data={q.data} />
          <Case data={q.data} />
          <Heldout data={q.data} />
        </>
      )}
    </main>
  );
}

function Summary({ data }: { data: Console }) {
  const e = data.environment;
  const gain = data.paired_before_impact.platform_vs_detection_as_code;
  return (
    <p className="small">
      {e.people} people, {e.days} days, {e.events.toLocaleString("en")} events, {e.campaigns} attack campaigns ({e.quiet_variants} quiet). Against reviewed
      detections sent straight to people, the full platform stops an extra {share(gain.difference, 1)} of the campaigns before impact (90% interval {share(gain.low, 1)} to{" "}
      {share(gain.high, 1)}).
    </p>
  );
}

function Heldout({ data }: { data: Console }) {
  const h = data.heldout;
  return (
    <section className="section" aria-labelledby="held-title">
      <header>
        <h2 id="held-title">Held-out environment</h2>
        {h ? (
          <p>
            Run once with the settings dev ended on: {h.environment.people} people, {h.environment.quiet_variants} of {h.environment.campaigns} campaigns quiet. The
            platform stopped {h.designs.platform.before_impact} of {h.environment.campaigns} before impact; detection as code alone stopped{" "}
            {h.designs.detection_as_code.before_impact}. The findings are in docs/heldout.md.
          </p>
        ) : (
          <p>Not run yet. It runs once, after dev is settled, and the gate does not move afterwards.</p>
        )}
      </header>
    </section>
  );
}
