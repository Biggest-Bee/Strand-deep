# Exploration Log

Format:
```
## YYYY-MM-DD: <question>
- Hypothesis:
- Experiment:
- Result:
- Decision:
- Follow-ups:
```

## 2026-11-21: Spike #1 (partial) - name-based call resolution rate
- Hypothesis: cheap name-based resolution reaches >=60% of calls on real Python repos.
- Experiment: built function-level call graph (import bindings + same-module defs + self/cls methods + builtin exclusion), ran on pallets/click (91 files, ~30k LOC).
- Result: 63.1% of analyzable calls resolved (7160 calls; import 3564, local 278, method 162; unknown_object 2042 dominates the rest).
- Decision: PASS - above kill threshold. unknown_object (obj.method() needing types) is the wall; that's points-to/CHA territory, not name resolution.
- Follow-ups: run on requests/flask/httpx for corpus numbers; measure per-file resolution; unknown_object breakdown (instance vs module vs class attr).
