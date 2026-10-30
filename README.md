<p align="center"><img src="assets/logo.svg" width="140" alt="The Guardian"></p>

<h1 align="center">The Guardian</h1>

<p align="center">A guard for AI agents: rules decide what an agent may do, and a detector reads untrusted text before the agent does.</p>

---

AI agents read web pages, emails and files, and they run tools. Any text they read can carry instructions written by
someone else (prompt injection), and a fooled agent can leak files, send messages or run commands. The Guardian sits
between the agent and the world and answers one question each time: **allow, block, or ask a human?**

It is built so it cannot go rogue itself: it never acts. It cannot run a command, send anything or change its own rules.
It only returns a decision and writes it to an audit log.

## How it works

```
untrusted text ──► inspect() ──► detector score ──► taints the session if it looks like an injection
agent wants a tool ──► authorize() ──► policy rules + taint + kill switch ──► allow / block / ask
```

1. **Policy (plain code, no model):** which tools exist, which folders and websites they may touch, forbidden command
   patterns, which tools need human approval, actions per minute, a daily spending cap. Unknown tools are blocked.
2. **Detector:** scores untrusted text for injection. `HeuristicDetector` (readable rules, no download) is the baseline;
   a small fine-tuned classifier (`ModelDetector`) is next, held to the marks in [PASS_MARKS.md](PASS_MARKS.md).
3. **Taint:** after a suspected injection is read, any tool that can move data out needs approval, even if the policy
   would normally allow it. That stops "this web page told the agent to send your files somewhere".
4. **Kill switch:** create a file (path you choose) and every action is blocked until it is deleted.
5. **Audit log:** every inspection and decision as one JSON line.

## Use

```python
from guardian import Guardian

g = Guardian({
    "tools": {
        "read_file":  {"paths": ["./workspace/**"]},
        "write_file": {"paths": ["./workspace/**"], "ask": True},
        "http_get":   {"domains": ["api.github.com", "*.wikipedia.org"]},
        "send_email": {"allow": False},
    },
    "limits": {"actions_per_minute": 30, "usd_per_day": 5},
}, audit_log="guardian-audit.jsonl", kill_switch="STOP")

page = fetch(url)
g.inspect(page, source="web")                     # before the agent reads it
decision = g.authorize("http_get", {"url": next_url})
if decision.verdict == "allow": ...
elif decision.verdict == "ask": ...               # show decision.reason to a human

@g.guard("read_file")                             # or wrap the tool itself; blocked calls raise Blocked
def read_file(path): ...
```

Score any detector on labelled data (`{"text": ..., "label": 0 or 1}` per line):

```powershell
.\.venv\Scripts\python.exe -m guardian.evaluate path\to\labelled.jsonl
```

## Status

| Part | State |
|---|---|
| Policy, taint, kill switch, audit log, tool decorator | Working, 6 tests |
| Heuristic detector | Working baseline, not yet measured on public data |
| Test bench (catch rate, false alarms, catch rate at a fixed false-alarm rate) | Working |
| Trained detector | Next: fine-tune a small open model on public injection datasets on a laptop GPU, compare with Prompt Guard 2 |
| HTTP service and agent-framework adapters | Later |

No guard catches everything. The goal is a measured catch rate at a low, published false-alarm rate, and rules that
limit the damage when something slips through.

## Develop

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e . pytest
.\.venv\Scripts\python.exe -m pytest -q
```
