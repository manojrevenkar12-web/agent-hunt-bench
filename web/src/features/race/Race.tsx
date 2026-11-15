import { motion as m } from "framer-motion";
import { axis, motion, position } from "../../app/theme";
import type { CampaignRow, Console, DesignKey } from "../../shared/types";
import { DESIGNS } from "../../shared/types";
import { minutes } from "../../shared/ui";
import "./race.css";

/** Every campaign as a lane from the attacker's first step to impact, with where a person got to it under the chosen design. */
export function Race({ data, design, onDesign }: { data: Console; design: DesignKey; onDesign: (d: DesignKey) => void }) {
  const score = data.designs[design];
  const kinds = Object.keys(data.kinds);
  const n = data.environment.campaigns;
  return (
    <section className="section" aria-labelledby="race-title">
      <header>
        <h2 id="race-title">Each attack, from its first step to its impact</h2>
        <p>
          A lane per campaign. The bar runs until the data leaves or the files are encrypted; the mark is when a person confirmed it under the design you
          pick. Time runs on a log scale.
        </p>
      </header>
      <div className="race-controls" role="radiogroup" aria-label="Design">
        {DESIGNS.map((d) => (
          <button key={d} role="radio" aria-checked={d === design} className="race-choice" onClick={() => onDesign(d)}>
            {d === design && <m.span layoutId="choice" className="race-choice-fill" transition={motion.spring} />}
            <span className="race-choice-text">{data.names[d]}</span>
          </button>
        ))}
      </div>
      <div className="race-grid">
        <div className="sheet race-sheet">
          <div className="race-axis" aria-hidden="true">
            {axis.ticks.map((t) => (
              <span key={t.minutes} className="race-tick tiny muted" style={{ left: `${position(t.minutes) * 100}%` }}>
                {t.label}
              </span>
            ))}
          </div>
          {kinds.map((k) => (
            <div key={k} className="race-group">
              <h3 className="race-kind small">{data.kinds[k]}</h3>
              {score.campaigns
                .filter((c) => c.kind === k)
                .map((c, i) => (
                  <Lane key={c.campaign} c={c} index={i} />
                ))}
            </div>
          ))}
          <ul className="race-legend tiny">
            <li><span className="dot stopped" /> confirmed before impact</li>
            <li><span className="dot late" /> confirmed after impact</li>
            <li><span className="dot held" /> agent send held at once</li>
            <li><span className="bar-key" /> first step to impact</li>
          </ul>
        </div>
        <aside className="race-totals" aria-live="polite">
          <Total big={`${score.before_impact} of ${n}`} label="stopped before impact" />
          <Total big={`${score.items_per_day}`} label="cases a day for people" />
          <Total big={minutes(score.median_minutes_to_person)} label="median time to a person" />
          <Total big={`${score.unsupported_claims_relied_on + score.closed_on_unsupported_report}`} label="unchecked model claims relied on" />
        </aside>
      </div>
    </section>
  );
}

function Total({ big, label }: { big: string; label: string }) {
  return (
    <div className="race-total">
      <m.span key={big} className="race-total-big num" initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={motion.enter}>
        {big}
      </m.span>
      <span className="small muted">{label}</span>
    </div>
  );
}

function Lane({ c, index }: { c: CampaignRow; index: number }) {
  const end = position(c.impact_minutes) * 100;
  const at = c.prevented_by_hold ? c.minutes_to_detect : c.minutes_to_person;
  const tone = c.prevented_by_hold ? "held" : c.before_impact ? "stopped" : "late";
  const label = c.prevented_by_hold
    ? `held at ${minutes(c.minutes_to_detect)}`
    : c.caught
      ? `${minutes(c.minutes_to_person)}, impact at ${minutes(c.impact_minutes)}`
      : "never confirmed";
  return (
    <div className="race-lane" title={`${c.campaign}: ${label}`}>
      <span className="race-name tiny muted">
        {c.campaign.replace(/^.*-/, "#")}
        {c.variant ? " quiet" : ""}
      </span>
      <div className="race-track">
        <m.div className="race-bar" initial={{ scaleX: 0 }} animate={{ scaleX: 1 }} transition={{ ...motion.enter, delay: index * motion.stagger }} style={{ width: `${end}%` }} />
        <span className="race-impact" style={{ left: `${end}%` }} />
        {at !== null && (
          <m.span
            className={`race-mark ${tone}`}
            aria-label={label}
            layout
            style={{ left: `${position(at) * 100}%` }}
            transition={motion.spring}
          />
        )}
        {at === null && <span className="race-missed tiny">never confirmed</span>}
      </div>
    </div>
  );
}
