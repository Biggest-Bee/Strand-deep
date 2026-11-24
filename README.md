# strand-deep

> **Moved.** This repository is archived. The engine now lives in the
> [Strand](https://github.com/Biggest-Bee/Strand) workspace as
> [`crates/strand-deep`](https://github.com/Biggest-Bee/Strand/tree/main/crates/strand-deep)
> and is published on crates.io as
> [`strand-deep`](https://crates.io/crates/strand-deep).

## Where it went

- **CLI**: `cargo install strand-cli` (binary `strand`), then
  `strand deep <dir> [--analyze] [--dump-callgraph] [--ipa-only]
  [--models <dir>]` - the same pipeline this repo's binary provided,
  now with JS/TS, Go, and Rust solvers in addition to Python.
- **GUI**: `cargo install strand-gui` - the "Deep scan..." button
  runs the same `analyze_project` pipeline on any directory.
- **Library**: `strand_deep::analyze::analyze_project(root)` is the
  one-call API (scan + parse + all language solvers + findings).

## What it does

Offline interprocedural analysis across Python, JS/TS, Go, and Rust:

- **Taint** - untrusted sources (env vars, request data, CLI args,
  `include_str!`, file reads) flowing to dangerous sinks (shell
  exec, SQL, eval, ...) across function boundaries
- **Null/None** - `None`/`null`/`nil`/`Option` values reaching
  dereferences, unwraps, or uses, with guard-clause narrowing
- **Resource leaks** - acquired resources escaping without release
  (defer/RAII aware per language)

Plus dynamic-import resolution: `import_module`/`require(expr)`/
`import(expr)` arguments propagated from literal call sites become
`Heuristic`-confidence graph edges.

Sources, sinks, sanitizers and propagators are data, not code -
TOML model files per language (`python.toml`, `js.toml`, `go.toml`,
`rust.toml`; `--models <dir>` to extend/override).

Every finding carries a call path and confidence; calls that can't
be resolved are counted in a blind-spot report, never guessed.

## Status

Frozen at the Python-only research stage. All further development
happens in the Strand monorepo.
