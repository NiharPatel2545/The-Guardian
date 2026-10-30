"""The detector half of the Guardian: reads untrusted text (web pages, emails, documents, tool output) before an agent does,
and scores how likely it is to be a prompt injection.

HeuristicDetector is the starting point: readable rules, no download, microseconds per message. It is the baseline the
trained model (ModelDetector, see PASS_MARKS.md) must beat on held-out data before it ships.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field


@dataclass
class Detection:
    score: float                               # 0 = looks normal, 1 = almost certainly an attack
    flagged: bool
    reasons: list[str] = field(default_factory=list)


# (name, weight, pattern). Weights combine as independent signals: score = 1 - prod(1 - w).
RULES = [
    ("override", 0.75, r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(all |any |the |your |my )?(previous|prior|above|earlier|preceding|original|system)\b[^.\n]{0,25}\b(instructions?|rules|prompts?|directions|guidelines|messages?)"),
    ("new-rules", 0.55, r"\b(new|updated|real|actual) (instructions|rules|task|orders)\b\s*[:\-]"),
    ("role-hijack", 0.6, r"\b(you are now|from now on,? you are|pretend (to be|you are)|act as)\b[^.\n]{0,40}\b(DAN|developer mode|unfiltered|jailbr\w*|no (rules|restrictions|limits)|evil|uncensored)"),
    ("dev-mode", 0.5, r"\b(developer|god|admin|debug|maintenance) mode\b[^.\n]{0,20}\b(enabled|activated|on)\b"),
    ("prompt-leak", 0.6, r"\b(reveal|print|show|repeat|output|dump|leak|tell me)\b[^.\n]{0,40}\b(system prompt|hidden (instructions|prompt)|your (instructions|rules|prompt)|initial prompt|developer message)"),
    ("fake-authority", 0.55, r"(\[|<|\b)(SYSTEM|ADMIN|ADMINISTRATOR|ROOT|ANTHROPIC|OPENAI|DEVELOPER)(\]|>|\s*(:|MESSAGE|OVERRIDE|NOTICE|INSTRUCTION))"),
    ("chat-markup", 0.6, r"<\|?(im_start|im_end|system|endoftext)\|?>|\[/?INST\]|<</?SYS>>"),
    ("secret-grab", 0.7, r"\b(send|email|post|upload|forward|paste|exfiltrate|transmit|share)\b[^.\n]{0,60}\b(passwords?|api[ _-]?keys?|tokens?|secrets?|credentials|\.env|ssh keys?|private keys?|cookies)"),
    ("exfil-link", 0.65, r"!\[[^\]]*\]\(https?://[^)\s]*\?[^)\s]*=[^)\s]*\)"),
    ("hide-from-user", 0.6, r"\b(do not|don'?t|never)\b[^.\n]{0,15}\b(tell|inform|mention|show|alert|notify)\b[^.\n]{0,20}\b(the )?(user|human|owner|operator)"),
    ("tool-order", 0.4, r"\b(run|execute|call)\b[^.\n]{0,20}\b(this|the following)\b[^.\n]{0,20}\b(command|code|script|tool)\b"),
    ("base64-blob", 0.25, r"[A-Za-z0-9+/]{160,}={0,2}"),
]
_CASE_SENSITIVE = {"fake-authority"}                      # shouting SYSTEM: is a signal, the word "system" is not
_COMPILED = [(n, w, re.compile(p, 0 if n in _CASE_SENSITIVE else re.I)) for n, w, p in RULES]

INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤﻿\U000e0000-\U000e007f]")


class HeuristicDetector:
    name = "heuristic-v0"

    def __init__(self, threshold: float = 0.5):
        self.threshold = threshold

    def score(self, text: str) -> Detection:
        reasons, keep = [], 1.0
        hidden = INVISIBLE.findall(text)
        if len(hidden) >= 3:
            reasons.append(f"hidden-characters ({len(hidden)})")
            keep *= 1 - 0.6
        clean = unicodedata.normalize("NFKC", INVISIBLE.sub("", text))
        for name, weight, rx in _COMPILED:
            if rx.search(clean):
                reasons.append(name)
                keep *= 1 - weight
        s = round(1 - keep, 3)
        return Detection(s, s >= self.threshold, reasons)


class ModelDetector:
    """A fine-tuned classifier (see PASS_MARKS.md). Needs `pip install torch transformers` and a trained model folder."""
    name = "model"

    def __init__(self, model_dir: str, threshold: float = 0.5, device: str | None = None):
        try:
            from transformers import pipeline
        except ImportError as e:
            raise RuntimeError("ModelDetector needs torch and transformers: pip install torch transformers") from e
        self.threshold = threshold
        extra = {}
        if device not in (None, "cpu", -1):
            import torch
            extra["dtype"] = torch.bfloat16                 # half precision on the GPU: about 2x faster, same answers to 2 decimals
        self._clf = pipeline("text-classification", model=model_dir, device=device, truncation=True, max_length=512, **extra)

    def score(self, text: str) -> Detection:
        out = self._clf(text)[0]
        s = out["score"] if out["label"].lower() in ("injection", "attack", "1", "label_1") else 1 - out["score"]
        return Detection(round(s, 3), s >= self.threshold, [f"model:{out['label']}"])
