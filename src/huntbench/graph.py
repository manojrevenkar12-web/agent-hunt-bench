"""The context graph: one person behind an email, a numeric user id, a directory short name, a device, a CI key and a
productivity agent. Every log source names people its own way; detections and triage reason about the person.

Built only from what the company exports (the directory, the device inventory, the agent registry) and the logs."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

RAW_KEY = {"idp": "actor_email", "saas": "user_id", "agent": "agent_id", "cloud": "principal", "edr": "hostname"}


@dataclass
class Graph:
    people: dict[str, dict] = field(default_factory=dict)  # email -> directory row
    by_uid: dict[int, str] = field(default_factory=dict)
    by_sam: dict[str, str] = field(default_factory=dict)
    by_local: dict[str, str] = field(default_factory=dict)
    by_host: dict[str, str] = field(default_factory=dict)
    by_serial: dict[str, str] = field(default_factory=dict)
    by_agent: dict[str, str] = field(default_factory=dict)
    seen_hosts: dict[str, Counter] = field(default_factory=dict)  # hostname -> accounts that used it, learned from logs

    @classmethod
    def build(cls, directory: list[dict], inventory: list[dict], agents: list[dict]) -> Graph:
        g = cls()
        for d in directory:
            g.people[d["email"]] = d
            g.by_uid[d["user_id"]] = d["email"]
            g.by_local[d["email"].split("@")[0]] = d["email"]
            if d["sam"]:
                g.by_sam[d["sam"]] = d["email"]
        for i in inventory:
            g.by_host[i["hostname"]] = i["owner_email"]
            g.by_serial[i["serial"]] = i["owner_email"]
        for a in agents:
            if a["on_behalf_of"] in g.by_uid:
                g.by_agent[a["agent_id"]] = g.by_uid[a["on_behalf_of"]]
        return g

    def account(self, name: str | None) -> str | None:
        """An email for whatever an account is called: the email itself, its local part, or the directory short name."""
        if not name:
            return None
        if name in self.people:
            return name
        return self.by_sam.get(name) or self.by_local.get(name)

    def resolve(self, e: dict) -> str | None:
        """The person who acted in an event, or None when nothing links it to the directory."""
        src = e["src"]
        if src == "idp":
            return e["actor_email"] if e["actor_email"] in self.people else None
        if src == "saas":
            return self.by_uid.get(e["user_id"])
        if src == "agent":
            return self.by_uid.get(e.get("on_behalf_of")) or self.by_agent.get(e["agent_id"])
        if src == "cloud":
            tail = e["principal"].split("/")[-1]
            return self.account(tail[:-3] if tail.endswith("-ci") else tail)
        if src == "edr":  # the account that ran the process, not the owner of the machine it ran on
            return self.account(e.get("user")) or self.by_host.get(e["hostname"])
        return None

    def learn(self, events: list[dict], until: int) -> Graph:
        """Learn who normally uses each machine from endpoint history, for machines renamed since the inventory was taken."""
        for e in events:
            if e["ts"] >= until:
                break
            if e["src"] == "edr" and e["process"] != "sshd":
                who = self.account(e.get("user"))
                if who:
                    self.seen_hosts.setdefault(e["hostname"], Counter())[who] += 1
        return self

    def device_owner(self, hostname: str) -> str | None:
        if hostname in self.by_host:
            return self.by_host[hostname]
        seen = self.seen_hosts.get(hostname)
        return seen.most_common(1)[0][0] if seen else None

    def enrich(self, e: dict) -> dict:
        actor = self.resolve(e)
        out = {"actor": actor, "actor_status": self.people.get(actor, {}).get("status") if actor else None}
        if e["src"] == "edr":
            owner = self.device_owner(e["hostname"])
            out["on_others_device"] = owner is not None and actor is not None and owner != actor
        return out

    def profile(self, email: str) -> dict:
        d = self.people.get(email, {})
        return {
            "email": email,
            "department": d.get("department"),
            "status": d.get("status"),
            "last_day": d.get("last_day"),
            "devices": sorted(h for h, o in self.by_host.items() if o == email),
            "agent": next((a for a, o in self.by_agent.items() if o == email), None),
        }


def raw_key(e: dict) -> str:
    """How a SIEM without the graph groups events: by whatever identifier each source happens to carry."""
    return f"{e['src']}:{e[RAW_KEY[e['src']]]}"
