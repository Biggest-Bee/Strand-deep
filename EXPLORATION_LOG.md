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

## 2025-11-21: IPA engine v1 + corpus spike
- Hypothesis: summary-based taint/null/leak over SCC call graph reaches useful precision on real repos
- Built: facts.rs dataflow, solver.rs SCC fixpoint, TOML models, module-globals seeding, null narrowing (is/is not/==/!=/isinstance/and/or/not/assert), per-index container tracking, resource lifecycle (acquire/release/yield/escape)
- Critical bug found+fixed: if/elif/else bodies were never statement-walked (grammar uses direct children, not if_clause wrappers) - all branch bodies silently skipped
- Precision fixes: overload stubs, break/continue terminal, or-result nullness, for-target elements, module try/except guards
- Corpus (analyzable-call resolution / findings / solve ms):
  - click: 63.1% / 16 / ~180ms (1956 funcs)
  - requests: 55.7% / 14 / ~64ms (728 funcs)
  - flask: 45.0% / 14 / ~94ms (1514 funcs) - below 60% kill line, unknown_object dominates
  - httpx: 52.5% / 63 / ~98ms (1182 funcs) - FP-heavy: optional-import module derefs, except-clause exception-type evals, cross-method self.attr
- Decision: name-based resolution viable for click/requests/httpx, marginal for flask; unknown_object (2042 calls on click) is the wall - needs CHA/type hints next
- Follow-ups: --min-confidence, SARIF, incremental invalidation, per-file stats, precision sampling on findings
