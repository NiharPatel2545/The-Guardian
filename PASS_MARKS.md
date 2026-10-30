# Pass marks

Written before any model is trained. A detector ships only if it meets every mark on data it never saw during training
or tuning. Misses are published along with the wins.

## Test data rules

- Train, tune and test sets come from **different sources** (different datasets or collections), not a random split of one
  set, so the score reflects attacks the model has not seen.
- Normal text includes hard cases: everyday messages that mention "ignore", "instructions", "system" or "password" in a
  harmless way, security discussions, and code. A guard that flags these interrupts real users.
- The test set is used once per candidate. Anything used to choose a threshold or a model is a tuning set, not a test set.

## Marks for the first trained detector (v1)

| # | Mark | Why |
|---|---|---|
| 1 | At no more than 2% false alarms on normal text, catches at least 5 points more attacks than Meta's Prompt Guard 2 (86M) on the same held-out test set | The point of the project: fewer interruptions for the same or better protection |
| 2 | Beats the rules-only `HeuristicDetector` by at least 15 points of catch rate at the same false-alarm rate | Otherwise the model is not worth its weight |
| 3 | No more than 3% false alarms on the hard-normal set | Real users must not be blocked for normal sentences |
| 4 | Under 20 ms per message on the RTX 5070 Ti laptop GPU, under 150 ms on a laptop CPU | It sits in front of every message an agent reads |
| 5 | Results reported per source and per attack type, including every type where it is worse than the baseline | Honest claims only |

## Marks for the rules half (policy and gateway)

Met by `tests/test_guardian.py` (6 tests): unknown tools blocked, paths cannot escape allowed folders, only listed websites,
forbidden command patterns blocked, approval for "ask" tools, rate and spending caps, kill switch, taint after a suspected
injection, and a full audit log.
