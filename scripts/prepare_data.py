"""Builds data/train.jsonl, data/tune.jsonl and data/test.jsonl from the files in data/raw (see PASS_MARKS.md for which
source goes where). Test sources never appear in training. Run with the project venv:
    .venv\\Scripts\\python.exe -I scripts\\prepare_data.py
"""
import csv
import json
import random
from collections import defaultdict
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


SHIELD_KEEP = ("alespalla/", "safeguard/", "harelix/", "trustailab/", "injecagent/", "jailbreakbench/")


def fresh_rows():
    """v3's fresh test: ShieldLM rows from sources we never train on, plus the S-Labs test split."""
    d = pd.read_parquet(RAW / "shieldlm_test.parquet")
    for t, l, src, cat in d[["text", "label_binary", "source", "label_category"]].itertuples(index=False):
        if str(src).startswith(SHIELD_KEEP):
            yield row(t, l, "shieldlm:" + str(src).split("/")[0], str(cat))
    for t, l in pd.read_csv(RAW / "slabs_test.csv")[["text", "label"]].itertuples(index=False):
        yield row(t, l, "s-labs", "mixed")


def v3_additions():
    for t in pd.read_csv(RAW / "yanis.csv")["prompt_injections"]:
        yield row(t, 1, "yanismiraoui", "multilingual")
    for split in ("train", "validation", "test"):
        for t, l in pd.read_parquet(RAW / f"neural_core_{split}.parquet")[["text", "label"]].itertuples(index=False):
            yield row(t, l, "neuralchemy", "mixed")


def v4_additions(cap_chat=15000, cap_orbench=15000, cap_mosscap=6000):
    """v4: more varied normal text (chat prompts in many languages, harmless requests that sound risky) and attacks from
    Lakera's password games, including attacks hidden in text to summarise."""
    oa = pd.concat([pd.read_parquet(RAW / f) for f in ("oasst2_train.parquet", "oasst2_val.parquet")])
    oa = oa[(oa.role == "prompter") & ~oa.deleted & (oa.review_result == True)]  # noqa: E712
    out = [row(t, 0, "oasst2", "chat") for t in oa.text.sample(frac=1, random_state=7)[:cap_chat]]
    ob = pd.read_csv(RAW / "orbench_80k.csv").sample(frac=1, random_state=7)[:cap_orbench]
    out += [row(t, 0, "or-bench", "harmless-sounds-risky") for t in ob.prompt]
    xs = pd.read_parquet(RAW / "xstest_prompts.parquet")
    out += [row(t, 0, "xstest", "harmless-sounds-risky") for t, ty in zip(xs.prompt, xs.type) if not str(ty).startswith("contrast")]
    ms = pd.concat([pd.read_parquet(RAW / f"mosscap_{s}.parquet") for s in ("train", "val", "test")])
    out += [row(t, 1, "mosscap", "password-game") for t in ms.prompt.drop_duplicates().sample(frac=1, random_state=7)[:cap_mosscap]]
    for s in ("train", "validation", "test"):
        out += [row(t, 1, "gandalf-summarization", "hidden-in-document") for t in pd.read_parquet(RAW / f"gsum_{s}.parquet").text]
    return [r for r in out if r]


def split_tune(rows, frac=0.1):
    """Holds out a share of each source for the tune set (threshold and epoch choice), the rest goes to training."""
    by_src = defaultdict(list)
    for r in rows:
        by_src[r["source"]].append(r)
    tune, train = [], []
    for rs in by_src.values():
        rng.shuffle(rs)
        k = int(frac * len(rs))
        tune += rs[:k]; train += rs[k:]
    return tune, train


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
    fresh = write("fresh_test", (r for r in fresh_rows() if r and r["text"] not in test_texts))
    fresh_texts = {r["text"] for r in fresh}
    v4_tune, v4_train = split_tune([r for r in v4_additions() if r["text"] not in test_texts | fresh_texts])
    tune = write("tune", (r for r in [*jailbreak("test"), *v4_tune] if r and r["text"] not in test_texts | fresh_texts))
    held = test_texts | fresh_texts | {r["text"] for r in tune}
    write("train", (r for r in [*spml(), *jailbreak("train"), *llmail_emails(), *dolly(), *v3_additions(), *v4_train]
                    if r and r["text"] not in held))
