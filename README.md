<p align="center"><img src="assets/logo.svg" width="140" alt="Blue Guardian"></p>

<h1 align="center">Blue Guardian</h1>

<p align="center">A guard for AI agents: rules decide what an agent may do, and a detector reads untrusted text before the agent does.</p>

---

AI agents read web pages, emails and files, and they run tools. Any text they read can carry instructions written by
someone else (prompt injection), and a fooled agent can leak files, send messages or run commands. Blue Guardian sits
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
2. **Detector:** scores untrusted text for injection. `ModelDetector` is blue-guardian-v4, a fine-tuned multilingual classifier
   ([model card](https://huggingface.co/niharpatel2545/blue-guardian-v4)); `HeuristicDetector` (readable rules, no download) is the
   fallback. Every version is held to marks written before it was trained: [PASS_MARKS.md](PASS_MARKS.md).
3. **Taint:** after a suspected injection is read, any tool that can move data out needs approval, even if the policy
   would normally allow it. That stops "this web page told the agent to send your files somewhere".
4. **Kill switch:** create a file (path you choose) and every action is blocked until it is deleted.
5. **Audit log:** every inspection and decision as one JSON line.

## Install

```powershell
pip install "blue-guardian[model] @ git+https://github.com/NiharPatel2545/Blue-Guardian"   # rules + the trained detector
pip install "blue-guardian @ git+https://github.com/NiharPatel2545/Blue-Guardian"          # rules + keyword detector only, no torch
```

## Use

```python
from blue_guardian import Guardian, ModelDetector

g = Guardian({
    "tools": {
        "read_file":  {"paths": ["./workspace/**"]},
        "write_file": {"paths": ["./workspace/**"], "ask": True},
        "http_get":   {"domains": ["api.github.com", "*.wikipedia.org"]},
        "send_email": {"allow": False},
    },
    "limits": {"actions_per_minute": 30, "usd_per_day": 5},
}, detector=ModelDetector(),                    # downloads blue-guardian-v4 (about 600 MB) once; leave out for the keyword rules
   audit_log="blue-guardian-audit.jsonl", kill_switch="STOP")

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
.\.venv\Scripts\python.exe -m blue_guardian.evaluate path\to\labelled.jsonl
```

## How good is the detector

Scored once per model on 7,601 texts in 8 languages from sources never used in training (details and every pass mark in
[PASS_MARKS.md](PASS_MARKS.md)):

| Model | Attacks caught at 2% false alarms | False alarms at its own threshold |
|---|---|---|
| Keyword rules | 5.6% | 0.0% |
| blue-guardian-v2 | 36.0% | 2.5% |
| blue-guardian-v3 | 45.1% | 10.8% |
| **blue-guardian-v4** | **76.5%** | **2.1%** |
| ProtectAI deberta-v3 prompt-injection v2 | 83.4% | 0.1% |

14.7 ms per text on a laptop GPU, about 33 ms on a laptop CPU for short texts.

Honest limits: still behind ProtectAI's model; weak on attacks hidden in agent tool output (InjecAgent 21.5% caught), which is
why the rule layer (taint, approvals, allowlists) matters; the test set was partly seen when choosing v4's data, so treat 76.5% as
an upper bound. No guard catches everything: the goal is a measured catch rate at a low, published false-alarm rate, and rules
that limit the damage when something slips through.

| Part | State |
|---|---|
| Policy, taint, kill switch, audit log, tool decorator | Working, 6 tests |
| Trained detector (blue-guardian-v4) | Released; passes its pass marks; Prompt Guard 2 comparison pending |
| Next detector | Agent-style indirect attacks, scored on a never-used test source |
| HTTP service and agent-framework adapters | Later |

## Reproduce

```powershell
.\.venv\Scripts\python.exe -I scripts\prepare_data.py          # builds train / tune / test sets from data/raw (sources in PASS_MARKS.md)
.\.venv\Scripts\python.exe -I scripts\train.py --base jhu-clsp/mmBERT-base --epochs 3 --out models/blue-guardian-v4
.\.venv\Scripts\python.exe -I scripts\score.py --model models/blue-guardian-v4 --data data/fresh_test.jsonl
```

## Licence

Code: MIT. Model weights: CC BY-SA 4.0 (one training set, Dolly-15k, is CC BY-SA); see the model card.

## Develop

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e . pytest
.\.venv\Scripts\python.exe -m pytest -q
```
