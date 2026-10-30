"""Test bench: score a detector on labelled examples and report what matters for a guard.

  catch rate      share of attacks it flags
  false alarms    share of normal text it flags (each one interrupts a real user, so this is the number to keep low)
  catch rate at a fixed false-alarm rate (default 2%): the fair way to compare two detectors

Data: JSON lines {"text": "...", "label": 1 for attack / 0 for normal, "category": "...", "source": "..."}.
    python -m guardian.evaluate path/to/labelled.jsonl
"""
from __future__ import annotations

import json
import sys
import time
from collections import defaultdict
from pathlib import Path


def load(path: str) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text("utf-8").splitlines() if line.strip()]


def evaluate(detector, examples: list[dict], target_fpr: float = 0.02) -> dict:
    t0 = time.perf_counter()
    scored = [(detector.score(e["text"]), e) for e in examples]
    ms = 1000 * (time.perf_counter() - t0) / max(len(examples), 1)
    att = [d for d, e in scored if e["label"] == 1]
    ben = [d for d, e in scored if e["label"] == 0]
    caught = sum(d.flagged for d in att)
    alarms = sum(d.flagged for d in ben)
    # threshold that keeps false alarms at or below the target, then the catch rate it gives
    ben_scores = sorted((d.score for d in ben), reverse=True)
    allowed = int(target_fpr * len(ben_scores))
    thr = (ben_scores[allowed] + 1e-9) if ben_scores and allowed < len(ben_scores) else 0.0
    caught_at = sum(d.score > thr for d in att) if ben_scores else caught
    cats = defaultdict(lambda: [0, 0])
    for d, e in scored:
        c = cats[(e.get("category") or ("attack" if e["label"] else "normal"), e["label"])]
        c[0] += d.flagged; c[1] += 1
    return {
        "detector": getattr(detector, "name", type(detector).__name__), "examples": len(examples),
        "attacks": len(att), "normal": len(ben),
        "catch_rate": round(caught / len(att), 3) if att else None,
        "false_alarm_rate": round(alarms / len(ben), 3) if ben else None,
        f"catch_rate_at_{int(target_fpr * 100)}pct_false_alarms": round(caught_at / len(att), 3) if att else None,
        "ms_per_text": round(ms, 3),
        "by_category": {f"{k[0]} ({'attack' if k[1] else 'normal'})": f"{v[0]}/{v[1]} flagged" for k, v in sorted(cats.items())},
        "missed": [e["text"][:120] for d, e in scored if e["label"] == 1 and not d.flagged][:10],
        "false_alarms": [e["text"][:120] for d, e in scored if e["label"] == 0 and d.flagged][:10],
    }


def main() -> None:
    from guardian.detect import HeuristicDetector
    if len(sys.argv) < 2:
        sys.exit("usage: python -m guardian.evaluate labelled.jsonl  (lines of {\"text\": ..., \"label\": 0 or 1})")
    path = sys.argv[1]
    print(json.dumps(evaluate(HeuristicDetector(), load(path)), indent=2))


if __name__ == "__main__":
    main()
