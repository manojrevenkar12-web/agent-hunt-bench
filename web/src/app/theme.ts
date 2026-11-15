/** Motion and scale settings shared by the features. Visual values live in tokens.css. */
export const motion = {
  spring: { type: "spring", stiffness: 260, damping: 30 } as const,
  enter: { duration: 0.45, ease: [0.2, 0.7, 0.2, 1] as const },
  stagger: 0.012,
};

/** The race strip's time axis: logarithmic, so five minutes and two days both have room. */
export const axis = {
  maxMinutes: 3 * 24 * 60,
  ticks: [
    { minutes: 5, label: "5 min" },
    { minutes: 60, label: "1 h" },
    { minutes: 6 * 60, label: "6 h" },
    { minutes: 24 * 60, label: "1 day" },
    { minutes: 2 * 24 * 60, label: "2 days" },
  ],
};

export const position = (minutes: number) => Math.log1p(Math.max(0, minutes)) / Math.log1p(axis.maxMinutes);
