# strand-deep

Offline interprocedural analysis for Python - a research companion
to [Strand](https://github.com/Biggest-Bee/Strand).

## What it does

Builds a function-level call graph, computes interprocedural
summaries via SCC-ordered fixpoint, and reports findings for three
bug classes:

- **Taint** - untrusted sources (env vars, request data, CLI args)
  flowing to dangerous sinks (shell exec, SQL, eval, ...)
- **Null/None** - values that may be `None` reaching dereferences,
  with guard-clause and narrowing awareness
- **Resource leaks** - acquired resources (files, sockets, locks)
  that may escape without release

It also resolves dynamic imports interprocedurally: `import_module`
arguments propagated backward from literal call sites become
`Heuristic`-confidence edges.

Sources, sinks, sanitizers and propagators are data, not code -
TOML model files per language (`models/python.toml` by default,
`--models <dir>` to extend/override).

Every finding carries a call path and confidence; calls that can't
be resolved are counted in a blind-spot report, never guessed.

## Usage

```
strand-deep <project-root> [-o out.strand]
    [--ipa-only] [--analyze] [--models <dir>]
    [--dump-callgraph]
```

- default: Strand static scan (all languages) + IPA edges merged
  into a `.strand` graph (or stdout summary)
- `--analyze`: run taint/null/leak analysis, print findings +
  blind-spot report
- `--models <dir>`: directory of `*.toml` model files
- `--dump-callgraph`: print resolved `module.func -> module.func`
  edges

## Scope / non-goals

- IPA bug classes: taint, null/None, resource leaks (Python only;
  JS/Rust IPA is future work)
- Sources/sinks/sanitizers/propagators are TOML-modeled per
  language (`models/python.toml`, `--models <dir>`)
- Interprocedural via SCC-ordered summary fixpoint over the
  function-level call graph; may-analysis with honest blind-spot
  reporting (unresolved calls, budget exhaustion)
- File-level dependency graph covers Python, JS/TS, Rust plus
  manifests and lockfiles for major ecosystems (delegated to
  `strand-import`)
- Not a replacement for build-integrated analyzers (CodeQL,
  Infer): no type information, so `obj.method()` calls on unknown
  receivers stay unresolved by design

## Status

Research project. Not yet integrated into Strand - integration path
is `EdgeList`-compatible `Heuristic` edges via `strand scan --import`.
