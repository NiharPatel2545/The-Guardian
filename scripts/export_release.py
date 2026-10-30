"""Writes a release copy of a trained model: weights in bfloat16 (half the size, same answers to 2 decimals), tokenizer,
config, the tuned threshold and the model card. Then checks the copy scores the tune set like the original.
    .venv\Scripts\python.exe -I scripts\export_release.py models/guardian-v4 release/guardian-v4
"""
import json
import shutil
import sys
from pathlib import Path

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from guardian.detect import ModelDetector  # noqa: E402

src, dst = Path(sys.argv[1]), Path(sys.argv[2])
dst.mkdir(parents=True, exist_ok=True)
AutoModelForSequenceClassification.from_pretrained(src, dtype=torch.bfloat16).save_pretrained(dst)
AutoTokenizer.from_pretrained(src).save_pretrained(dst)
shutil.copy(src / "guardian.json", dst / "guardian.json")
card = ROOT / "release" / "MODEL_CARD.md"
if card.exists():
    shutil.copy(card, dst / "README.md")

rows = [json.loads(line) for line in open(ROOT / "data" / "tune.jsonl", encoding="utf-8")][:600]
a, b = ModelDetector(str(src)), ModelDetector(str(dst))
diff = max(abs(a.score(r["text"]).score - b.score(r["text"]).score) for r in rows)
flips = sum(a.score(r["text"]).flagged != b.score(r["text"]).flagged for r in rows)
print(f"release copy: {sum(f.stat().st_size for f in dst.iterdir()) / 1e6:.0f} MB, max score change {diff:.3f}, decisions changed {flips} of {len(rows)}")
