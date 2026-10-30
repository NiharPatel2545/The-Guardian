"""Builds data/train.jsonl, data/tune.jsonl and data/test.jsonl from the files in data/raw (see PASS_MARKS.md for which
source goes where). Test sources never appear in training. Run with the project venv:
    .venv\\Scripts\\python.exe -I scripts\\prepare_data.py
"""
import csv
import json
import random
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
RAW, OUT = ROOT / "data" / "raw", ROOT / "data"
csv.field_size_limit(10**8)
rng = random.Random(7)


def row(text, label, source, category=""):
    t = " ".join(str(text).split())
    return {"text": t[:4000], "label": int(label), "source": source, "category": category} if len(t) >= 3 else None


def spml():
    with open(RAW / "spml.csv", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            yield row(r["User Prompt"], int(float(r["Prompt injection"] or 0)), "spml", "direct")


def jailbreak(split):
    with open(RAW / f"jb_{split}.csv", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            yield row(r["prompt"], r["type"].strip().lower() == "jailbreak", "jailbreak-classification", "jailbreak")


def llmail_emails(cap=2500):
    """Attack emails and the emails the challenge's judges marked as not attacks, in equal numbers, so that "it is an
    email" carries no label signal (v1 learned email = attack). 'Unclear' ones are left out."""
    d = json.load(open(RAW / "llmail_phase2.json", encoding="utf-8"))
    att = [row(k, 1, "llmail-phase2", "email-injection") for k, v in d.items() if str(v.get("attack_attempt")).lower() == "true"]
    ok = [row(k, 0, "llmail-phase2", "email-normal") for k, v in d.items() if str(v.get("attack_attempt")).lower() == "false"]
    rng.shuffle(att); rng.shuffle(ok)
    return att[:cap] + ok[:cap]


def dolly(n_instr=5000, n_ctx=3000):
    items = [json.loads(line) for line in open(RAW / "dolly.jsonl", encoding="utf-8")]
    rng.shuffle(items)
    out = [row(i["instruction"], 0, "dolly", "instruction") for i in items[:n_instr]]
    out += [row(i["context"], 0, "dolly", "document") for i in items if i["context"].strip()][:n_ctx]
    return out


def test_rows():
    for f in ("deepset_train.parquet", "deepset_test.parquet"):
        for t, l in pd.read_parquet(RAW / f)[["text", "label"]].itertuples(index=False):
            yield row(t, l, "deepset", "mixed")
    for f in ("gandalf_train.parquet", "gandalf_validation.parquet", "gandalf_test.parquet"):
        for t in pd.read_parquet(RAW / f)["text"]:
            yield row(t, 1, "gandalf", "override")
    for t in json.load(open(RAW / "llmail_fp_emails.json", encoding="utf-8")):
        yield row(t, 0, "llmail-fp-emails", "email-normal")


def write(name, rows):
    rows = [r for r in rows if r]
    seen, uniq = set(), []
    for r in rows:
        if r["text"] not in seen:
            seen.add(r["text"]); uniq.append(r)
    rng.shuffle(uniq)
    with open(OUT / f"{name}.jsonl", "w", encoding="utf-8") as f:
        for r in uniq:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    pos = sum(r["label"] for r in uniq)
    print(f"{name}: {len(uniq)} rows, {pos} attacks, {len(uniq) - pos} normal, sources {sorted({r['source'] for r in uniq})}")
    return uniq


if __name__ == "__main__":
    test = write("test", test_rows())
    test_texts = {r["text"] for r in test}
    tune = write("tune", (r for r in jailbreak("test") if r and r["text"] not in test_texts))
    held = test_texts | {r["text"] for r in tune}
    write("train", (r for r in [*spml(), *jailbreak("train"), *llmail_emails(), *dolly()] if r and r["text"] not in held))
