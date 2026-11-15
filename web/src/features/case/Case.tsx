import { AnimatePresence, motion as m } from "framer-motion";
import { useState } from "react";
import { motion } from "../../app/theme";
import type { Console } from "../../shared/types";
import { minutes } from "../../shared/ui";
import "./case.css";

/** One account takeover as the platform handled it, in the order things happened. */
export function Case({ data }: { data: Console }) {
  const e = data.example_case;
  const [open, setOpen] = useState(false);
  const steps: { at: number; text: string; tone: string }[] = [];
  const seen = new Set<string>();
  for (const a of e.alerts) {
    if (seen.has(a.rule)) continue;
    seen.add(a.rule);
    steps.push({ at: a.ts - e.start, text: `${a.rule} fires (${a.severity}, ${a.technique})`, tone: "alert" });
  }
  if (e.person) {
    steps.push({
      at: e.person.handled_at - e.start,
      text: `A person ${e.person.page ? "is paged" : "takes it from the queue"} and ${e.person.verdict === "incident" ? "confirms an incident" : "closes it"}`,
      tone: "person",
    });
  }
  steps.push({ at: e.impact_at - e.start, text: "The bulk export the attacker was working towards", tone: "impact" });
  steps.sort((a, b) => a.at - b.at);
  return (
    <section className="section" aria-labelledby="case-title">
      <header>
        <h2 id="case-title">One case, start to finish</h2>
        <p>
          {e.campaign} became {e.case}. Times are from the attacker's first step.
        </p>
      </header>
      <div className="sheet case">
        <ol className="case-steps">
          {steps.map((s) => (
            <li key={`${s.at}-${s.text}`} className={`case-step ${s.tone}`}>
              <span className="num small case-at">{minutes(s.at)}</span>
              <span>{s.text}</span>
            </li>
          ))}
        </ol>
        <button className="case-toggle small" aria-expanded={open} onClick={() => setOpen(!open)}>
          {open ? "Hide the model's claims and the playbook" : "Show the model's claims and the playbook"}
        </button>
        <AnimatePresence initial={false}>
          {open && (
            <m.div className="case-detail" initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={motion.enter}>
              <h3 className="small">Claims, each checked against the event store: {e.report.check_ok ? "all found" : e.report.problems.join("; ")}</h3>
              <ul className="small">
                {e.report.claims.map((c) => (
                  <li key={`${c.eid}-${c.field}`}>
                    <code>{c.eid}</code> {c.field} = <code>{String(c.value)}</code>
                  </li>
                ))}
              </ul>
              <h3 className="small">Containment planned at confirmation, in dry run</h3>
              <ul className="small">
                {e.playbook.map((s) => (
                  <li key={s.action}>
                    {s.action.replaceAll("_", " ")} on {s.system}
                  </li>
                ))}
              </ul>
            </m.div>
          )}
        </AnimatePresence>
      </div>
    </section>
  );
}
