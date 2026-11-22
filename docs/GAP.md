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

## Decisions (owner, 2026-11-21)

- Bug classes: ALL, in order - taint -> null/None -> resource leaks.
  Engine must be bug-class-agnostic; sources/sinks/sanitizers are
  declarative (TOML models), not hardcoded.
- Languages: ALL - Python, Rust, JS/TS. First proving slice is
  taint-on-Python (existing code + weakest incumbent coverage), then
  expand in order.
- Corpus: picked by agent (below).

## Test corpus (10 repos)

Python (4):
- psf/requests - HTTP lib, clean structure, moderate size
- pallets/flask - web framework, request->response flows
- encode/httpx - modern HTTP client, async + sync paths
- pallets/click - CLI framework, argv taint sources everywhere

Rust (3):
- sharkdp/bat - CLI tool, good size, real-world
- clap-rs/clap - argument parser, heavy macro + derive patterns
- rayon-rs/rayon - parallel iterators, closure-heavy call graphs

JS/TS (3):
- axios/axios - HTTP client, promise chains, interceptors
- expressjs/express - web framework, middleware = natural taint flows
- preactjs/preact - VDOM lib, hooks/closures stress call resolution

Rationale: all free to clone/analyze, no build required for our
frontend, varied sizes (10k-100k LOC), cover CLI/web/lib shapes and
stress different call-resolution patterns (callbacks, decorators,
macros, promises).
