# strand-deep

Demand-driven interprocedural analysis for Python dynamic imports -
a research companion to [Strand](https://github.com/Biggest-Bee/Strand).

## What it does

Strand's scanner resolves `import_module("literal")` and same-file
constants, but reports `import_module(name)` inside a function as an
unresolved dynamic site. strand-deep goes one level deeper: it finds
call sites of that function **across the whole project** - through
`from m import f`, `import m`, aliases, and `m.f()` attribute calls -
and propagates literal arguments backward through the import.

```
loader.py:  def load(name): import_module("plugins." + name)
app.py:     from loader import load
            load("ldap")          # -> edge loader.py -> plugins/ldap.py
```

Every inferred edge is tagged `Heuristic` (lowest confidence) because
the value chain crosses function boundaries. Sites that can't be
resolved are reported, never guessed.

## Usage

```
strand-deep <project-root> [-o out.strand] [--ipa-only]
```

Runs Strand's static scan, layers IPA edges on top, writes a merged
`.strand` graph. `--ipa-only` prints inferred edges as text.

## v0 scope / non-goals

- Single-parameter specifiers: `lit* + param + lit*` shapes only
- Literal/const call-site arguments (no nested call returns yet)
- No recursion beyond depth 1 (function -> its callers)
- Caps: 64 call sites, 64 candidate strings; overflow -> unresolved
- Python only; JS/Rust IPA is future work

## Status

Research project. Not yet integrated into Strand - integration path
is `EdgeList`-compatible `Heuristic` edges via `strand scan --import`.
