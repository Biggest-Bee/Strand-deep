# Offline Interprocedural Analysis: Fastest Path to a Real Gap

A plan for building an offline interprocedural analysis (IPA) tool as fast as possible, finding the gap it should fill, and exploring territory nobody has mapped yet.

---

## 1. The Thesis (write this first, one sentence)

> "[Developers/teams] cannot get **[cross-function answer]** across **[languages]** without **[build setup / cloud / licence / expertise]**, and nothing good exists."

If you can't fill in the brackets, you don't have a gap yet. Everything below serves to fill them in quickly and prove or kill the thesis.

**Candidate thesis (to test, not to assume):**
> Teams cannot get explainable cross-function taint/null/leak findings across polyglot repos, offline, with no build step, in seconds, and with incremental re-analysis.

---

## 2. Principles for Going Fast

1. **Reuse, don't rebuild.** Use the existing call graph and CSR engine. Use tree-sitter for bodies. Write no new parsers.
2. **Summaries over inlining.** Analyze each function once, store a summary, apply it at call sites.
3. **Vertical slice first.** One language, one bug class, one finding with a full path trace, end to end, before anything broad.
4. **Precision beats coverage.** Ten findings people trust beat a thousand they ignore.
5. **Timebox everything unknown.** Every unknown gets a spike with a deadline and a kill criterion.
6. **Ship ugly, measure real.** Run on real repos from day 3, not day 30.
7. **Be honest about blind spots.** Report what you skipped. This is a feature (see section 6).

---

## 3. Finding the Gap Fast (Day 0, max 4 hours)

| Step | Action | Output |
|---|---|---|
| 1 | List the 5 closest tools (CodeQL, Infer, Semgrep, language linters, IDE inspections) | Comparison table |
| 2 | Read their GitHub issues sorted by most-reacted, and search for "slow", "needs build", "doesn't support", "cross-file", "false positive" | 10 recurring complaints |
| 3 | Search Hacker News and Reddit for "static analysis" complaints | Pain quotes |
| 4 | Talk to or read posts from 3 to 5 people who run these tools in CI | Real constraint list |
| 5 | Pick the complaint that your architecture solves *structurally*, not by effort | The thesis |

**Gap signals worth chasing:**
- "Requires a successful build" (you don't)
- "Takes 40 minutes in CI" (you incrementally re-analyze in seconds)
- "Can't follow data across Python to JS to Rust" (you're polyglot)
- "Can't run in our air-gapped environment" (you're offline)
- "Findings with no explanation" (you show the path)
- "Licence not allowed at our company" (you're Apache-2.0)

---

## 4. Exploring Unknown Territory

Interprocedural analysis has open questions nobody has answered for your setup. Treat exploration as a process, not a mood.

### 4.1 The Spike Protocol
For each unknown:
1. Write the question as a testable yes/no ("Can name-based call resolution reach 80% of real calls in Python repos?")
2. Set a timebox (2 to 6 hours)
3. Write the kill criterion up front ("If under 50%, switch to CHA")
4. Run it on 3 real repos
5. Log the result, whether it was a win or a failure

### 4.2 Unknowns to Spike (in priority order)

| # | Question | Timebox | Kill criterion |
|---|---|---|---|
| 1 | What % of call sites can cheap name-based resolution resolve per language? | 3h | <60% means add CHA or type hints |
| 2 | How many findings on a 100k-LOC repo, and what % are true positives? | 4h | <30% TP means narrow the rule |
| 3 | How big do summaries get per function? Do they stay under ~1 KB? | 2h | Blow-up means cap and widen to "unknown" |
| 4 | How long does a cold full analysis take vs. an incremental one after a 1-file change? | 3h | Incremental not 10x faster means revisit invalidation |
| 5 | Does SCC fixpoint converge quickly on real recursive code? | 2h | >10 iterations means add widening |
| 6 | Can taint be tracked across one language boundary (HTTP route, FFI, subprocess)? | 6h | Not feasible means drop the feature, keep the idea in the log |
| 7 | How much of the "unknown call" mass is callbacks, dynamic dispatch, `eval`, reflection? | 2h | Informs what to model next |

### 4.3 Ground Truth Without Labels
You will not have labeled data, so manufacture it:
- **Fix-commit mining:** take real CVE or bug-fix commits, check out the *parent* commit, and see whether the tool flags the bug. Each hit is a verified true positive. Each miss is a roadmap item.
- **Differential testing:** run the same repo through Semgrep, CodeQL, or Infer where possible. Disagreements are where the interesting findings (and your bugs) live.
- **Seeded bugs:** inject 20 known flows into a repo and measure recall.
- **Benchmark suites:** OWASP Benchmark, Juliet, and similar suites give cheap recall numbers, but don't trust them for precision on real code.

### 4.4 The Exploration Log
Keep a single `EXPLORATION_LOG.md`:
```
## YYYY-MM-DD: <question>
- Hypothesis:
- Experiment:
- Result:
- Decision:
- Follow-ups:
```
Failures are as valuable as wins. Your log becomes the documentation and the credibility.

---

## 5. Core Architecture (minimum viable)

```
source files
   |  tree-sitter
   v
function bodies + call sites ---> per-function CFG
   |                                   |
   v                                   v
call graph (Strand CSR) <------ function summaries (stored per node)
   |
   v
bottom-up SCC pass (callees first, fixpoint inside cycles)
   |
   v
findings + path traces ---> CLI / GUI / SARIF
```

**Summary contents (v1, keep tiny):**
- param-to-return flow set
- param-to-sink flow set
- returns-source flag (e.g. returns tainted data)
- may-return-null / may-throw flag
- "touches unknown call" flag with the reason

**Analysis settings (v1):** context-insensitive, flow-sensitive within function, unresolved calls conservatively marked unknown, no points-to analysis yet.

---

## 6. Features That Fill Additional Gaps

Each of these is a gap in current tools. They are ordered by (value / effort), so build from the top.

### Tier 1: Cheap, high differentiation
1. **Blind-spot report.** After every run, print what was *not* analyzed (unresolved calls, dynamic dispatch, skipped files, widened summaries) with counts and locations. Most tools silently hide their unsoundness. Yours shows it, so trust goes up.
2. **Explainable path traces.** Every finding shows the full source-to-sink chain across functions and files, reusing the `why` machinery. Output as readable text and SARIF `codeFlows`.
3. **Confidence score per finding.** Based on number of unknown hops, resolution quality, and path length. Let users filter by `--min-confidence`.
4. **Declarative models in TOML, not a query language.** Sources, sinks, sanitizers, and propagators described as data files that users can edit and share. This lowers the barrier compared to learning QL-style languages.
5. **Baseline and suppression file.** `--baseline` records current findings so teams adopt it on legacy code and only fail on *new* ones.

### Tier 2: Strand's structural advantages
6. **Incremental analysis through impact.** On a change, use impact analysis to find the transitive callers whose summaries could change, and re-analyze only those. Cold run in minutes, incremental run in seconds. This is the clearest structural edge you have.
7. **PR mode.** Given a git diff, report (a) new findings, (b) which function summaries changed, (c) what downstream functions are now affected. "Behavioral blast radius" of a PR is a gap almost nobody fills.
8. **Summary diff between versions.** Show "this function used to sanitize its input, now it doesn't." Security-relevant regressions caught as semantic changes rather than text diffs.
9. **Anytime mode with a time budget.** `--budget 10s` returns the best findings so far, highest-confidence first. Good for editors and pre-commit hooks.
10. **Deterministic, reproducible output.** Stable ordering and stable finding IDs, so results can be diffed and cached.

### Tier 3: Territory few tools cover
11. **Library summary packs.** Precomputed, shippable summaries for popular dependencies, so analysis works *offline* without analyzing node_modules or site-packages every time. A community-contributed registry of summaries could become a moat.
12. **Cross-language boundary tracking.** Model HTTP routes, subprocess calls, FFI, and message queues as edges between functions, so taint flowing Python to JS to Rust is traceable.
13. **Dead and unreachable code via call graph.** Given declared entry points, report functions that are never reachable. This is cheap given what you already have.
14. **Config and environment flow.** Treat env vars, config files, and CLI args as sources, and trace them to dangerous operations.
15. **Resource lifecycle checks.** Cross-function leaks (opened but never closed, locked but never unlocked) through summaries like "acquires arg 0, doesn't release."
16. **Entry-point discovery.** Auto-detect likely entry points (route handlers, `main`, exported APIs, CLI commands) to drive reachability and taint sources automatically.
17. **Policy checks over the graph.** Rules like "UI layer must not call DB layer," where architecture rules are expressed over the same call graph.

### Tier 4: Speculative (explore, don't commit)
18. Summary-based "what-if" queries: "if I change this function's contract, what breaks?"
19. Cross-repo analysis by merging graphs from multiple projects.
20. Learned ranking of findings from user accept/reject feedback, stored locally.

---

## 7. Five-Day Build Plan

| Day | Goal | Done when |
|---|---|---|
| 0 | Gap research, thesis, spike list | Thesis written, 7 spikes queued |
| 1 | Expose bodies and call sites from `scan`; CFG for one language | CFGs render for a real repo |
| 2 | Worklist solver, summary format, store summaries per node | One intra-function analysis works with summaries saved |
| 3 | Bottom-up SCC pass; apply summaries at call sites | First cross-function finding on a real repo |
| 4 | Path traces, blind-spot report, SARIF, confidence | Findings are readable and honest |
| 5 | Run on 10 real repos, mine 5 fix commits, tune false positives, release | Public release with a measured precision number |

**Week 2+:** incremental mode (feature 6), PR mode (7), TOML models (4), second language.

---

## 8. Metrics (decide what "working" means)

- **Precision** on a sampled set of findings (target: >50% true positive for the first release, then >70%)
- **Recall** on mined fix commits (any non-zero hit rate is useful at first)
- **Cold analysis time** per 100k LOC
- **Incremental analysis time** after a one-file change
- **Call resolution rate** per language
- **Unknown-call ratio** (the number your blind-spot report is built around)
- **Adoption signals:** stars, crate downloads, issues from strangers, someone running it in CI

---

## 9. Risks and How to Dodge Them

| Risk | Mitigation |
|---|---|
| False positives kill trust | Narrow rule, confidence scores, baseline mode, ship precision numbers |
| Summaries blow up in size | Hard cap, widen to "unknown" when exceeded, and log it |
| Dynamic languages resist resolution | Start with the best-resolved language, report unknowns honestly |
| Scope creep from the feature list | Only Tier 1 before first release; every other feature needs a spike result first |
| Perfectionism about soundness | Document that it's a bug-finder, not a verifier |
| No users | Release early, show it on a famous open-source repo, write up findings responsibly |
| Responsible disclosure | If you find real vulnerabilities in public projects, report privately before posting |

---

## 10. Decision Checklist Before You Start

- [ ] Thesis sentence written and specific
- [ ] One language chosen
- [ ] One bug class chosen (taint, null, or resource leak)
- [ ] Spike list with timeboxes and kill criteria
- [ ] 10 real repos picked as test corpus
- [ ] 5 fix commits identified as ground truth
- [ ] Exploration log created
- [ ] Release date set (a deadline forces scope cuts)

---

## 11. The One-Paragraph Version

Find a structural gap (offline, no build, polyglot, incremental, explainable). Reuse the existing call graph and tree-sitter. Build summary-based analysis bottom-up over SCCs for one language and one bug class. Prove it on real repos with mined fix commits. Make honesty (blind-spot reports) and speed (incremental via impact) your differentiators. Expand only when a timeboxed spike says the next feature is worth it.
