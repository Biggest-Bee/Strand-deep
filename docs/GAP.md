# Day 0: Gap Research

Date: 2026-11-21. Sources: GitHub issues on codeql-action / codeql /
infer, HN threads, vendor comparisons.

## Closest tools

| Tool | Build needed? | Cost/licence | Speed reputation | Interprocedural | Offline |
|---|---|---|---|---|---|
| CodeQL | Yes (extractor DB; "buildless" modes exist w/ caveats) | Free for OSS only; CLI forbidden on non-OSS without paid GHAS | 3-8x a normal build; reports of mins->hours regressions | Strong (dataflow/taint via CodeQL) | Yes but licence-gated |
| Infer | Yes - requires build system / compilation DB; "Infer's analysis requires a build system integration because it takes the AST from the compiler" | Apache-2.0 | Moderate; Java/C-family focus | Strong (separation logic) | Yes |
| Semgrep | No (pattern matching; taint mode is intra-procedural-ish) | LGPL engine / commercial rules | Seconds-minutes | Weakest of the three - "interprocedural reasoning depth can vary" | Yes |
| Language linters/IDE | No | Free | Fast | Mostly intra-procedural | Yes |

## Recurring complaints (from issues/HN)

1. CodeQL: "autobuild analysis takes 4 hours vs 20-30min build" - analysis cost dwarfs the build it depends on.
2. CodeQL false positives erode trust: "useless parameter / unread variable" noise reported as broken.
3. CodeQL licence: CLI not allowed on non-open-source code without paid GitHub Advanced Security.
4. Infer: requires a working build; even valid Makefiles fail; no analysis without compiler integration.
5. HN consensus: automated security scanning FP fatigue - "the vast majority of vulnerabilities I've seen are actually noise/not applicable."
6. Semgrep: fast but interprocedural depth varies by rule; complex cross-function flows are its known weakness.
7. >10min PR scans are "a nonstarter" for large legacy apps (codeql-action #1367).

## Thesis candidate (to validate)

> Teams cannot get **explainable cross-function taint findings** in
> **polyglot repos** **offline, with no build step, in seconds, with
> incremental re-analysis** - CodeQL needs a build + paid licence,
> Infer needs a build, Semgrep can't go deep interprocedurally.

Structural edge: no-build tree-sitter frontend + summary-based IPA +
Strand's incremental graph = the "seconds, offline, explainable" cell
nobody occupies. Precision/honesty (blind-spot report) is the trust
mechanism against FP fatigue.

## Open decisions (need owner input)

- Bug class for v1: taint (env/argv -> sinks) vs null/None vs resource leak
- Language for v1: Python (matches existing strand-deep code + weakest
  incumbent coverage) vs Rust/JS
- Corpus: which 10 real repos
