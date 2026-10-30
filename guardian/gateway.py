"""The Guardian: one object an agent framework calls at two moments.

  g.inspect(text, source)        before the agent reads untrusted text (a web page, an email, a file, a tool's output)
  g.authorize(tool, args, cost)  before the agent runs a tool

It never acts on its own: it only answers allow / block / ask. It cannot run commands, send anything or change its own
rules, so it has nothing to "go rogue" with. Every answer is appended to an audit log.

Taint: once untrusted text that looks like an injection has been read in this session, every tool that can move data out
(egress_tools in the policy) needs a human's approval, even if the policy would normally allow it. This is what stops the
classic attack where a web page tells the agent to send your files somewhere.
"""
from __future__ import annotations

import json
import time
from functools import wraps
from pathlib import Path

from guardian.detect import Detection, HeuristicDetector
from guardian.policy import ALLOW, ASK, BLOCK, Decision, Policy

UNTRUSTED = {"web", "email", "file", "tool_output", "document", "unknown"}


class Blocked(Exception):
    def __init__(self, decision: Decision):
        super().__init__(decision.reason)
        self.decision = decision


class Guardian:
    def __init__(self, policy: Policy | dict | str, detector=None, audit_log: str | None = None, kill_switch: str | None = None):
        self.policy = policy if isinstance(policy, Policy) else Policy.load(policy)
        self.detector = detector or HeuristicDetector()
        self.audit_log = Path(audit_log) if audit_log else None
        self.kill_switch = Path(kill_switch) if kill_switch else None
        self.tainted_by: list[str] = []          # sources that delivered a suspected injection this session

    def inspect(self, text: str, source: str = "unknown") -> Detection:
        d = self.detector.score(text)
        if d.flagged and source in UNTRUSTED:
            self.tainted_by.append(source)
        self._log("inspect", {"source": source, "score": d.score, "flagged": d.flagged, "reasons": d.reasons, "chars": len(text)})
        return d

    def authorize(self, tool: str, args: dict | None = None, cost_usd: float = 0.0) -> Decision:
        if self.kill_switch and self.kill_switch.exists():
            d = Decision(BLOCK, "kill switch is on: every action is stopped", "kill_switch")
        else:
            d = self.policy.check(tool, args, cost_usd)
            if d.verdict == ALLOW and self.tainted_by and tool in self.policy.egress_tools:
                d = Decision(ASK, f"this session read a suspected injection (from {self.tainted_by[-1]}), so sending data out needs approval", "taint")
        self._log("authorize", {"tool": tool, "args": {k: str(v)[:200] for k, v in (args or {}).items()}, "verdict": d.verdict, "reason": d.reason, "rule": d.rule})
        return d

    def guard(self, tool: str, approve=None, cost_usd: float = 0.0):
        """Decorator for a tool function: blocked calls raise Blocked; 'ask' calls go to approve(tool, args, decision) -> bool."""
        def wrap(fn):
            @wraps(fn)
            def inner(**kwargs):
                d = self.authorize(tool, kwargs, cost_usd)
                if d.verdict == BLOCK or (d.verdict == ASK and not (approve and approve(tool, kwargs, d))):
                    raise Blocked(d)
                return fn(**kwargs)
            return inner
        return wrap

    def _log(self, kind: str, data: dict) -> None:
        if self.audit_log:
            self.audit_log.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_log.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"t": round(time.time(), 3), "kind": kind, **data}) + "\n")
