"""The live model: the prompt built from a context packet, and the parse of what comes back. The evaluation runs the
same pipeline with a simulated model in the world, so the platform code does not change between the two."""

from __future__ import annotations

import json
import os

from .settings import ROOT

PROMPT = (ROOT / "prompts" / "triage.md").read_text()


def _fence(text: str) -> str:
    """Log content cannot close the evidence block it sits in."""
    return text.replace("</evidence>", "<\\/evidence>").replace("<evidence>", "<\\evidence>")


def build_prompt(packet: dict) -> str:
    return (
        PROMPT.replace("{person}", json.dumps(packet["person"], indent=1))
        .replace("{case}", json.dumps(packet["case"], indent=1))
        .replace("{recent}", json.dumps(packet["recent_cases"], indent=1))
        .replace("{events}", _fence("\n".join(json.dumps(e, sort_keys=True) for e in packet["events"])))
    )


def parse(text: str) -> dict:
    """The model's answer, or a report that fails the checker if the answer is not the JSON asked for."""
    start, end = text.find("{"), text.rfind("}")
    try:
        out = json.loads(text[start : end + 1])
    except (ValueError, TypeError):
        return {"escalate": True, "summary": "unparseable answer", "claims": []}
    claims = [c for c in out.get("claims", []) if isinstance(c, dict)]
    return {"escalate": bool(out.get("escalate", True)), "summary": str(out.get("summary", "")), "claims": claims}


class AnthropicTriager:
    """Calls the Anthropic API. Used only when a key is set; the tests and the evaluation never call it."""

    def __init__(self, model: str = "claude-sonnet-5-5", max_tokens: int = 800):
        import anthropic  # optional dependency

        self.client, self.model, self.max_tokens = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"]), model, max_tokens

    def __call__(self, packet: dict) -> dict:
        msg = self.client.messages.create(model=self.model, max_tokens=self.max_tokens, messages=[{"role": "user", "content": build_prompt(packet)}])
        return parse("".join(b.text for b in msg.content if getattr(b, "type", "") == "text"))
