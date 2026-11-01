"""Scores detectors on the held-out test set (once per candidate) and prints the numbers the pass marks need,
overall and per source.
    .venv\\Scripts\\python.exe -I scripts\\score.py [--model models/guardian-v1] [--out runs/score_v1.json]
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from blue_guardian.detect import HeuristicDetector, ModelDetector  # noqa: E402
from blue_guardian.evaluate import evaluate, load  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", action="append", default=[], help="model folder; repeat to compare several (omit for the heuristic only)")
    ap.add_argument("--data", default=str(ROOT / "data" / "test.jsonl"))
    ap.add_argument("--out")
    a = ap.parse_args()
    rows = load(a.data)
    detectors = [HeuristicDetector()]
    for m in a.model:
        d = ModelDetector(m, device=0)
        d.name = Path(m).name                                      # report each model under its folder name
        detectors.append(d)
    report = {}
    for det in detectors:
        r = evaluate(det, rows)
        r["by_source"] = {}
        for src in sorted({x["source"] for x in rows}):
            sub = evaluate(det, [x for x in rows if x["source"] == src])
            r["by_source"][src] = {k: sub[k] for k in ("attacks", "normal", "catch_rate", "false_alarm_rate")}
        r.pop("missed"); r.pop("false_alarms")                # keep attack text out of logs
        report[r["detector"]] = r
    print(json.dumps(report, indent=2))
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
