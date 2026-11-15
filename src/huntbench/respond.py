"""Containment playbooks. Each detection family maps to the calls a responder would make. Playbooks print the calls
they would make; they run only with an approver named and dry-run switched off. The one exception is holding an agent's
outbound send, which is reversible and is the only action taken before a person looks."""

from __future__ import annotations

from dataclasses import dataclass

from .cases import Case
from .graph import Graph

PLAYBOOK = {
    "idp": [("revoke_sessions", "identity provider", True), ("require_mfa_reenrol", "identity provider", True)],
    "saas": [("suspend_external_links", "workspace", True), ("lock_account", "workspace", True)],
    "agent": [("hold_agent_egress", "agent gateway", True), ("revoke_agent_token", "agent gateway", True)],
    "cloud": [("deactivate_access_key", "cloud IAM", True), ("revert_snapshot_sharing", "cloud", True)],
    "edr": [("isolate_host", "endpoint", True), ("rotate_credentials", "identity provider", True)],
}


@dataclass
class Step:
    action: str
    system: str
    target: str
    reversible: bool
    status: str = "planned"


def plan(case: Case, graph: Graph | None) -> list[Step]:
    steps: list[Step] = []
    hosts = graph.profile(case.entity)["devices"] if graph and case.entity in graph.people else []
    for src in case.sources:
        for action, system, reversible in PLAYBOOK.get(src, []):
            target = ", ".join(hosts) if action == "isolate_host" and hosts else case.entity
            steps.append(Step(action, system, target, reversible))
    return steps


def execute(steps: list[Step], dry_run: bool, approver: str | None) -> list[Step]:
    """Nothing runs without a named approver; in dry-run the steps come back marked as what would have run."""
    if dry_run or not approver:
        return [Step(s.action, s.system, s.target, s.reversible, "dry-run") for s in steps]
    raise NotImplementedError("connect the systems' clients here; this repository only plans")
