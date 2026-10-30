# Pass marks

Written before any model is trained. A detector ships only if it meets every mark on data it never saw during training
or tuning. Misses are published along with the wins.

## Test data rules

- Train, tune and test sets come from **different sources** (different datasets or collections), not a random split of one
  set, so the score reflects attacks the model has not seen.
- Normal text includes hard cases: everyday messages that mention "ignore", "instructions", "system" or "password" in a
  harmless way, security discussions, and code. A guard that flags these interrupts real users.
- The test set is used once per candidate. Anything used to choose a threshold or a model is a tuning set, not a test set.

## Data for v1 (fixed before download, 30 Oct 2026)

| Set | Sources (licence) | Used for |
|---|---|---|
| Train | SPML Chatbot Prompt Injection (MIT); jailbreak-classification train split (Apache-2.0); LLMail-Inject phase-2 labelled submissions, attacks hidden in emails (MIT); Dolly-15k instructions and context passages as normal text (CC BY-SA 3.0) | fitting the model |
| Tune | jailbreak-classification test split (Apache-2.0) | choosing epochs and the threshold only |
| Test (held out, sources never seen in training) | deepset prompt-injections, all splits (Apache-2.0); Lakera Gandalf ignore-instructions (MIT, attacks only); LLMail-Inject emails for false-positive tests (MIT, normal emails) | the marks below, once per candidate |

Prompt Guard 2 is scored on the same test set when access to it is granted (Mark 1 waits for that).

## Marks for the first trained detector (v1)

| # | Mark | Why |
|---|---|---|
| 1 | At no more than 2% false alarms on normal text, catches at least 5 points more attacks than Meta's Prompt Guard 2 (86M) on the same held-out test set | The point of the project: fewer interruptions for the same or better protection |
| 2 | Beats the rules-only `HeuristicDetector` by at least 15 points of catch rate at the same false-alarm rate | Otherwise the model is not worth its weight |
| 3 | No more than 3% false alarms on the hard-normal set | Real users must not be blocked for normal sentences |
| 4 | Under 20 ms per message on the RTX 5070 Ti laptop GPU, under 150 ms on a laptop CPU | It sits in front of every message an agent reads |
| 5 | Results reported per source and per attack type, including every type where it is worse than the baseline | Honest claims only |

## Results

**Baseline, heuristic-v0 (test set):** catches 31.0% of attacks, 0 of 559 normal texts flagged. deepset 5.7%, Gandalf 37.7%.

**v1, ModernBERT-base, 3 epochs (test set, 30 Oct 2026): FAILED marks 1-4.** Catches 71.2% of attacks (deepset 52.1%,
Gandalf 76.2%) but false alarms are 34.3%: all 160 normal emails flagged, 8% of deepset's normal texts. Catch rate at 2%
false alarms: 0. 26 ms per text on the GPU. Cause: every email in the training data was an attack, so the model learned
"email = attack". Tune set (same family as training) looked perfect (99% caught, 1.6% false alarms), which is why the
held-out test matters.

**v2 change (written before v2 ran):** add the 2,500 LLMail-Inject phase-2 emails its judges marked as not attacks to the
training set as normal text, and cap attack emails at 2,500 so emails carry no label signal on their own. Everything else
unchanged. Same test set, scored once.

**v2 result (test set, 30 Oct 2026):** catches 67.2% of attacks with 3.6% false alarms (0 of 160 normal emails, 5.0% of
deepset's normal texts). At 2% false alarms it catches 61.6%, against 31.3% for the heuristic. 24 ms per text on the GPU.
- Mark 1 (vs Prompt Guard 2): not yet scored, needs access to the model.
- Mark 2 (beat the heuristic by 15+ points at the same false-alarm rate): **passed**, +30.3 points.
- Mark 3 (no more than 3% false alarms on hard normal text): **failed narrowly**, 3.6% overall, 5.0% on deepset.
- Mark 4 (under 20 ms per message on the GPU): **failed narrowly**, 24 ms.
- Weakest spot: deepset (44% caught). Part of it is German, and ModernBERT-base is English-only.

The test set has now been used for two candidates. Before v3, add a fresh held-out source so later choices are not tuned to it.

## Marks for the rules half (policy and gateway)

Met by `tests/test_guardian.py` (6 tests): unknown tools blocked, paths cannot escape allowed folders, only listed websites,
forbidden command patterns blocked, approval for "ask" tools, rate and spending caps, kill switch, taint after a suspected
injection, and a full audit log.
