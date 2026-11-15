export type DesignKey = "siem_basic" | "detection_as_code" | "llm_triage" | "platform";

export interface CampaignRow {
  campaign: string;
  kind: string;
  variant: boolean;
  detected: boolean;
  caught: boolean;
  before_impact: boolean;
  prevented_by_hold: boolean;
  minutes_to_detect: number | null;
  minutes_to_person: number | null;
  impact_minutes: number;
  attack_alerts_closed_by_model: number;
  stages_seen: string[];
}

export interface Score {
  name: DesignKey;
  campaigns: CampaignRow[];
  caught: number;
  before_impact: number;
  median_minutes_to_person: number | null;
  alerts_per_day: number;
  cases_per_day: number;
  items_per_day: number;
  pages_per_day: number;
  precision: number | null;
  reports: number;
  failed_checks: number;
  unsupported_claims_relied_on: number;
  closed_on_unsupported_report: number;
  closed_by_model: number;
  attack_alerts_closed_by_model: number;
  holds: number;
  benign_holds: number;
}

export interface Detection {
  id: string;
  title: string;
  kind: string;
  source: string;
  technique: string;
  severity: string;
  alerts: number;
  true: number;
  campaigns: number;
  backtest_per_day: number;
  budget: number;
  within_budget: boolean;
  examples_pass: boolean;
}

export interface ExampleCase {
  campaign: string;
  case: string;
  start: number;
  impact_at: number;
  alerts: { rule: string; severity: string; technique: string; ts: number; events: number }[];
  report: { escalate: boolean; claims: { eid: string; field: string; value: unknown }[]; check_ok: boolean; problems: string[] };
  person: { reason: string; page: boolean; handled_at: number; verdict: string } | null;
  playbook: { action: string; system: string; target: string; status: string }[];
}

export interface Console {
  environment: { name: string; people: number; days: number; evaluated_days: number; events: number; campaigns: number; quiet_variants: number };
  designs: Record<DesignKey, Score>;
  names: Record<DesignKey, string>;
  kinds: Record<string, string>;
  paired_before_impact: Record<string, { difference: number; low: number; high: number }>;
  detections: Detection[];
  graph: { identifiers_per_person: number; renamed_hosts: number; renamed_hosts_owner_learned: number };
  example_case: ExampleCase;
  heldout: { environment: Console["environment"]; designs: Record<DesignKey, Score> } | null;
}

export const DESIGNS: DesignKey[] = ["siem_basic", "detection_as_code", "llm_triage", "platform"];
