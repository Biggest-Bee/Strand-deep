//! Demand-driven interprocedural analysis for Python dynamic imports.
//!
//! Strand's scanner resolves `import_module(name)` when `name` is a
//! literal or a same-file constant. This crate goes one level deeper:
//! when the specifier is a *parameter* of the enclosing function, it
//! finds call sites of that function across the whole project -
//! through `from m import f`, `import m`, aliases, and attribute
//! calls - and propagates literal arguments back through the import.
//!
//! Honesty contract: every inferred edge is emitted as
//! [`strand_core::EdgeKind::Heuristic`] (lowest confidence) because
//! the value chain crosses function boundaries. Sites that can't be
//! resolved stay unresolved and are reported, never guessed.
//!
//! v0 scope: single-parameter specifiers only, literal/const call-site
//! arguments, max depth/caps degrade to "unresolved".

use std::collections::{BTreeMap, BTreeSet, HashMap};

use strand_core::EdgeKind;
use rayon::prelude::*;
use tree_sitter::{Node, Tree};

/// Hard caps - the analyzer degrades to "unresolved" rather than
/// running away on pathological call graphs.
const MAX_CALL_SITES: usize = 64;
const MAX_STRINGS: usize = 64;

/// One Python file's parsed view.
struct PyFile {
    /// Project-root-relative path, `/`-separated, `.py` suffix.
    rel: String,
    /// Dotted module name (`pkg.loader`; `__init__` stripped).
    module: String,
    tree: Tree,
    text: String,
    /// Local name -> (module key, member). `member=None` means the
    /// local name refers to the module itself (`import m [as x]`).
    /// `member=Some(f)` means `from m import f [as x]` - `f` may be a
    /// function OR a submodule (resolved by usage context).
    /// Module keys may start with `.` for relative imports.
    bindings: HashMap<String, (String, Option<String>)>,
    /// Module-level `NAME = "literal"` constants.
    consts: HashMap<String, String>,
    /// `def` name -> ordered parameter names.
    funcs: HashMap<String, Vec<String>>,
}

/// A dynamic-import site whose specifier is `prefix + param + suffix`
/// inside function `func` of module `module`.
struct DynSite {
    file_rel: String,
    module: String,
    func: String,
    /// Parameter position of the specifier's variable part.
    param: String,
    /// Literal text around the parameter in the specifier expression.
    prefix: String,
    suffix: String,
}

/// Result of the analysis.
pub struct IpaOutput {
    /// `(src_file_rel, dst_file_rel)` inferred edges.
    pub edges: Vec<(String, String, EdgeKind)>,
    /// Human-readable descriptions of unresolved sites.
    pub unresolved: Vec<String>,
    /// Count of sites resolved through call-site propagation.
    pub resolved: usize,
}

/// Module name for a `.py` rel path: `pkg/loader.py` -> `pkg.loader`,
/// `pkg/__init__.py` -> `pkg`, `app.py` -> `app`.
pub fn module_of(rel: &str) -> String {
    let noext = rel.strip_suffix(".py").unwrap_or(rel);
    let noinit = noext.strip_suffix("/__init__").unwrap_or(noext);
    noinit.replace('/', ".")
}

/// File rel path for a dotted module, or `None` if not in `files`.
fn file_of_module(module: &str, files: &BTreeSet<String>) -> Option<String> {
    let base = module.replace('.', "/");
    for cand in [format!("{base}.py"), format!("{base}/__init__.py")] {
        if files.contains(&cand) {
            return Some(cand);
        }
    }
    None
}

fn parse_ts(text: &str) -> Option<Tree> {
    let mut p = tree_sitter::Parser::new();
    p.set_language(&tree_sitter_python::LANGUAGE.into()).ok()?;
    p.parse(text, None)
}

/// String literal content of a node, or `None` for non-literals,
/// f-strings, and strings containing format braces.
fn string_literal(node: Node, text: &str) -> Option<String> {
    if node.kind() != "string" {
        return None;
    }
    let raw = node.utf8_text(text.as_bytes()).ok()?;
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len()
        && matches!(
            bytes[i],
            b'r' | b'R' | b'b' | b'B' | b'f' | b'F' | b'u' | b'U'
        )
    {
        i += 1;
    }
    let rest = &raw[i..];
    let qlen = if rest.starts_with("'''") || rest.starts_with("\"\"\"") {
        3
    } else if rest.starts_with('\'') || rest.starts_with('"') {
        1
    } else {
        return None;
    };
    let inner = rest.get(qlen..rest.len().checked_sub(qlen)?)?;
    if inner.contains('{') {
        return None;
    }
    Some(inner.to_string())
}

/// Evaluate a node to a set of constant strings: literal, module-level
/// const name, or `+` concatenation of evaluable parts.
fn eval_strset(node: Node, text: &str, f: &PyFile, depth: usize) -> Option<BTreeSet<String>> {
    if depth > 8 {
        return None;
    }
    if let Some(s) = string_literal(node, text) {
        return Some(BTreeSet::from([s]));
    }
    if node.kind() == "identifier" {
        let name = node.utf8_text(text.as_bytes()).ok()?;
        return f.consts.get(name).map(|s| BTreeSet::from([s.clone()]));
    }
    if node.kind() == "binary_operator" {
        let op = node
            .child_by_field_name("operator")
            .and_then(|o| o.utf8_text(text.as_bytes()).ok())
            .unwrap_or("");
        if op == "+" {
            let l = node.child_by_field_name("left")?;
            let r = node.child_by_field_name("right")?;
            let lv = eval_strset(l, text, f, depth + 1)?;
            let rv = eval_strset(r, text, f, depth + 1)?;
            let mut out = BTreeSet::new();
            for a in &lv {
                for b in &rv {
                    out.insert(format!("{a}{b}"));
                    if out.len() > MAX_STRINGS {
                        return None;
                    }
                }
            }
            return Some(out);
        }
    }
    None
}

/// Build ordered "parts" of an expression: literal strings and
/// identifiers, for `+`-concatenations. Returns `None` for any other
/// shape (calls, attributes, subscripts, ...).
fn expr_parts(node: Node, text: &str, f: &PyFile, depth: usize) -> Option<Vec<Part>> {
    if depth > 8 {
        return None;
    }
    if let Some(s) = string_literal(node, text) {
        return Some(vec![Part::Lit(s)]);
    }
    if node.kind() == "identifier" {
        let name = node.utf8_text(text.as_bytes()).ok()?;
        if let Some(v) = f.consts.get(name) {
            return Some(vec![Part::Lit(v.clone())]);
        }
        return Some(vec![Part::Name(name.to_string())]);
    }
    if node.kind() == "binary_operator" {
        let op = node
            .child_by_field_name("operator")
            .and_then(|o| o.utf8_text(text.as_bytes()).ok())
            .unwrap_or("");
        if op == "+" {
            let l = expr_parts(node.child_by_field_name("left")?, text, f, depth + 1)?;
            let r = expr_parts(node.child_by_field_name("right")?, text, f, depth + 1)?;
            let mut out = l;
            out.extend(r);
            return Some(out);
        }
    }
    None
}

enum Part {
    Lit(String),
    /// Identifier that is NOT a module const - could be a parameter.
    Name(String),
}

/// Analyze a dynamic-import argument into `(param, prefix, suffix)`
/// when it has the shape `lit* + param + lit*` with exactly one
/// non-const identifier.
fn specifier_template(
    arg: Node,
    text: &str,
    f: &PyFile,
    params: &[String],
) -> Option<(String, String, String)> {
    let parts = expr_parts(arg, text, f, 0)?;
    let names: Vec<&Part> = parts
        .iter()
        .filter(|p| matches!(p, Part::Name(_)))
        .collect();
    if names.len() != 1 {
        return None;
    }
    let Part::Name(pname) = names[0] else {
        return None;
    };
    if !params.iter().any(|p| p == pname) {
        return None;
    }
    // Rebuild prefix/suffix around the single Name part.
    let mut prefix = String::new();
    let mut suffix = String::new();
    let mut seen_name = false;
    for p in &parts {
        match p {
            Part::Lit(s) => {
                if seen_name {
                    suffix.push_str(s);
                } else {
                    prefix.push_str(s);
                }
            }
            Part::Name(_) => seen_name = true,
        }
    }
    Some((pname.clone(), prefix, suffix))
}

fn analyze_file(rel: &str, text: &str) -> Option<PyFile> {
    let tree = parse_ts(text)?;
    let mut f = PyFile {
        rel: rel.to_string(),
        module: module_of(rel),
        tree,
        text: text.to_string(),
        bindings: HashMap::new(),
        consts: HashMap::new(),
        funcs: HashMap::new(),
    };
    let root = f.tree.root_node();
    let text = f.text.clone();
    let (mut bindings, mut consts, mut funcs) =
        (HashMap::new(), HashMap::new(), HashMap::new());
    collect_facts(root, &text, &mut bindings, &mut consts, &mut funcs);
    f.bindings = bindings;
    f.consts = consts;
    f.funcs = funcs;
    Some(f)
}

fn collect_facts(
    root: Node,
    text: &str,
    bindings: &mut HashMap<String, (String, Option<String>)>,
    consts: &mut HashMap<String, String>,
    funcs: &mut HashMap<String, Vec<String>>,
) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "import_statement" => {
                // `import a.b.c` binds `a` -> module "a" (top package;
                // a.b.c resolves through attribute chains).
                // `import a.b.c as x` binds x -> "a.b.c".
                let mut c = node.walk();
                for name in node.children_by_field_name("name", &mut c) {
                    if name.kind() == "aliased_import" {
                        let m = name
                            .child_by_field_name("name")
                            .and_then(|n| n.utf8_text(text.as_bytes()).ok())
                            .unwrap_or("")
                            .replace(' ', "");
                        if let Some(alias) = name.child_by_field_name("alias") {
                            if let Ok(a) = alias.utf8_text(text.as_bytes()) {
                                bindings.insert(a.to_string(), (m, None));
                            }
                        }
                    } else if let Ok(t) = name.utf8_text(text.as_bytes()) {
                        let dotted = t.trim().replace(' ', "");
                        if let Some(first) = dotted.split('.').next() {
                            // Only the top package is bound; store it
                            // once (multiple `import a.x` lines agree).
                            bindings
                                .entry(first.to_string())
                                .or_insert_with(|| (first.to_string(), None));
                        }
                    }
                }
            }
            "import_from_statement" => {
                // `from a.b import c [as d]` -> d -> ("a.b", Some("c"))
                // Relative levels: count leading `import_prefix` dots.
                let module = node
                    .child_by_field_name("module_name")
                    .and_then(|m| m.utf8_text(text.as_bytes()).ok())
                    .unwrap_or("")
                    .replace(' ', "");
                let level = node
                    .children(&mut node.walk())
                    .take_while(|c| c.kind() == "import_prefix")
                    .count();
                let mod_key = format!("{}{}", ".".repeat(level), module);
                let mut c = node.walk();
                for name in node.children_by_field_name("name", &mut c) {
                    if name.kind() == "wildcard_import" {
                        continue;
                    }
                    let (orig, local) = if name.kind() == "aliased_import" {
                        let o = name
                            .child_by_field_name("name")
                            .and_then(|n| n.utf8_text(text.as_bytes()).ok())
                            .unwrap_or("")
                            .to_string();
                        let l = name
                            .child_by_field_name("alias")
                            .and_then(|n| n.utf8_text(text.as_bytes()).ok())
                            .unwrap_or("")
                            .to_string();
                        (o, l)
                    } else {
                        let t = name
                            .utf8_text(text.as_bytes())
                            .unwrap_or("")
                            .trim()
                            .to_string();
                        (t.clone(), t)
                    };
                    if !local.is_empty() {
                        bindings.insert(local, (mod_key.clone(), Some(orig)));
                    }
                }
            }
            "assignment" => {
                if let (Some(l), Some(r)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    if l.kind() == "identifier" {
                        if let (Ok(name), Some(val)) =
                            (l.utf8_text(text.as_bytes()), string_literal(r, text))
                        {
                            consts.insert(name.to_string(), val);
                        }
                    }
                }
            }
            "function_definition" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(text.as_bytes()) {
                        let mut params = Vec::new();
                        if let Some(pn) = node.child_by_field_name("parameters") {
                            let mut pc = pn.walk();
                            for p in pn.children(&mut pc) {
                                match p.kind() {
                                    "identifier" => {
                                        if let Ok(t) = p.utf8_text(text.as_bytes()) {
                                            params.push(t.to_string());
                                        }
                                    }
                                    "default_parameter" | "typed_parameter" => {
                                        let mut sc = p.walk();
                                        for d in p.children(&mut sc) {
                                            if d.kind() == "identifier" {
                                                if let Ok(t) =
                                                    d.utf8_text(text.as_bytes())
                                                {
                                                    params.push(t.to_string());
                                                }
                                                break;
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        funcs.insert(name.to_string(), params);
                    }
                }
            }
            _ => {}
        }
        let mut c = node.walk();
        stack.extend(node.children(&mut c));
    }
}

fn is_dyn_import_call(call: Node, text: &str) -> bool {
    let Some(func) = call.child_by_field_name("function") else {
        return false;
    };
    let Ok(ft) = func.utf8_text(text.as_bytes()) else {
        return false;
    };
    ft == "__import__" || ft == "import_module" || ft.ends_with(".import_module")
}

fn first_arg(call: Node) -> Option<Node> {
    let args = call.child_by_field_name("arguments")?;
    let mut c = args.walk();
    let found = args
        .children(&mut c)
        .find(|c| !matches!(c.kind(), "(" | ")" | ","));
    found
}

/// Enclosing `def` of a node -> (name, ordered params).
fn enclosing_func<'t>(node: Node<'t>, f: &PyFile) -> Option<(String, Vec<String>)> {
    let mut anc = node.parent();
    while let Some(n) = anc {
        if n.kind() == "function_definition" {
            let name = n
                .child_by_field_name("name")
                .and_then(|x| x.utf8_text(f.text.as_bytes()).ok())?
                .to_string();
            return f.funcs.get(&name).map(|p| (name, p.clone()));
        }
        anc = n.parent();
    }
    None
}

/// Find dynamic-import sites in `f` shaped `lit* + param + lit*`.
fn dyn_sites(f: &PyFile) -> Vec<DynSite> {
    let mut out = Vec::new();
    let mut stack = vec![f.tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "call" && is_dyn_import_call(node, &f.text) {
            if let Some(arg) = first_arg(node) {
                if arg.kind() != "string" {
                    if let Some((func, params)) = enclosing_func(node, f) {
                        if let Some((param, prefix, suffix)) =
                            specifier_template(arg, &f.text, f, &params)
                        {
                            out.push(DynSite {
                                file_rel: f.rel.clone(),
                                module: f.module.clone(),
                                func,
                                param,
                                prefix,
                                suffix,
                            });
                        }
                    }
                }
            }
        }
        let mut c = node.walk();
        stack.extend(node.children(&mut c));
    }
    out
}

/// Resolve a possibly-relative module key against the importer's
/// module. `from . import x` in `pkg.loader` -> base `pkg`;
/// `from ..a import b` -> parent of pkg.
fn resolve_module_key(key: &str, importer_module: &str) -> Option<String> {
    if !key.starts_with('.') {
        return Some(key.to_string());
    }
    let level = key.chars().take_while(|c| *c == '.').count();
    let rest = key[level..].trim_matches('.');
    let mut parts: Vec<&str> = importer_module.split('.').collect();
    // `.` refers to the importer's *package* (strip the module name).
    for _ in 0..level {
        parts.pop();
    }
    if !rest.is_empty() {
        parts.extend(rest.split('.').filter(|s| !s.is_empty()));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("."))
    }
}

/// Resolved import bindings for one file: local name ->
/// (absolutized module, member). Computed once per file so call
/// resolution doesn't redo relative-import math per call site.
type RBindings = HashMap<String, (String, Option<String>)>;

fn resolve_bindings(f: &PyFile) -> RBindings {
    f.bindings
        .iter()
        .filter_map(|(local, (mk, member))| {
            resolve_module_key(mk, &f.module)
                .map(|m| (local.clone(), (m, member.clone())))
        })
        .collect()
}

/// Module an attribute-call object expression refers to, if statically
/// known. `m.f()` where m is `import m [as x]` / `from p import m`,
/// and dotted chains `a.b.c.f()` from `import a.b.c`.
fn object_module(obj: Node, rbind: &RBindings, text: &str) -> Option<String> {
    match obj.kind() {
        "identifier" => {
            let name = obj.utf8_text(text.as_bytes()).ok()?;
            match rbind.get(name) {
                // `import m as x` -> x IS module m.
                Some((m, None)) => Some(m.clone()),
                // `from p import m` -> refers to p.m as a module.
                Some((m, Some(mem))) => Some(format!("{m}.{mem}")),
                None => None,
            }
        }
        "attribute" => {
            // Dotted chain a.b.c - reconstruct, resolve head binding.
            let mut parts = Vec::new();
            let mut cur = obj;
            loop {
                match cur.kind() {
                    "attribute" => {
                        if let Some(a) = cur.child_by_field_name("attribute") {
                            if let Ok(t) = a.utf8_text(text.as_bytes()) {
                                parts.push(t.to_string());
                            }
                        }
                        match cur.child_by_field_name("object") {
                            Some(o) => cur = o,
                            None => return None,
                        }
                    }
                    "identifier" => {
                        if let Ok(t) = cur.utf8_text(text.as_bytes()) {
                            parts.push(t.to_string());
                        }
                        break;
                    }
                    _ => return None,
                }
            }
            parts.reverse();
            let dotted = parts.join(".");
            let first = dotted.split('.').next()?;
            let (base, rest) = match rbind.get(first) {
                Some((m, None)) => (m.clone(), &dotted[first.len()..]),
                Some((m, Some(mem))) => (format!("{m}.{mem}"), &dotted[first.len()..]),
                None => return None,
            };
            let rest = rest.trim_start_matches('.');
            Some(if rest.is_empty() {
                base
            } else {
                format!("{base}.{rest}")
            })
        }
        _ => None,
    }
}

/// (module, func) candidates a call's callee may invoke. Usually 0 or
/// 1; a name bound by `from m import f` yields (m, f).
fn call_targets(func_node: Node, rbind: &RBindings, text: &str) -> Vec<(String, String)> {
    match func_node.kind() {
        "identifier" => {
            let Ok(name) = func_node.utf8_text(text.as_bytes()) else {
                return Vec::new();
            };
            match rbind.get(name) {
                // `from m import f [as g]` -> g(...) invokes m.f.
                Some((m, Some(member))) => vec![(m.clone(), member.clone())],
                // Module objects aren't function calls.
                _ => Vec::new(),
            }
        }
        "attribute" => {
            let Some(attr) = func_node.child_by_field_name("attribute") else {
                return Vec::new();
            };
            let Some(obj) = func_node.child_by_field_name("object") else {
                return Vec::new();
            };
            let Ok(fname) = attr.utf8_text(text.as_bytes()) else {
                return Vec::new();
            };
            object_module(obj, rbind, text)
                .map(|m| vec![(m, fname.to_string())])
                .unwrap_or_default()
        }
        _ => Vec::new(),
    }
}

/// A recorded call site: which file, and the byte range of the `call`
/// node (recovered on demand via `descendant_for_byte_range`).
struct CallRec {
    file: usize,
    start: usize,
    end: usize,
}

/// Collect the value nodes for `param` from a matched call site:
/// keyword arg by name, else positional at the param's index.
fn callsite_param_arg<'t>(
    call: Node<'t>,
    caller: &PyFile,
    func_params: &[String],
    param: &str,
) -> Option<Node<'t>> {
    let idx = func_params.iter().position(|p| p == param)?;
    let args = call.child_by_field_name("arguments")?;
    let mut positional: Vec<Node> = Vec::new();
    let mut keyword: Option<Node> = None;
    let mut c = args.walk();
    for ch in args.children(&mut c) {
        match ch.kind() {
            "keyword_argument" => {
                let name_ok = ch
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(caller.text.as_bytes()).ok())
                    == Some(param);
                if name_ok {
                    keyword = ch.child_by_field_name("value");
                }
            }
            "(" | ")" | "," => {}
            _ => positional.push(ch),
        }
    }
    keyword.or_else(|| positional.get(idx).copied())
}

/// Main entry: analyze `files` (rel -> text) for cross-file dynamic
/// import resolution. `file_set` is the set of known rel paths.
pub fn analyze(files: &BTreeMap<String, String>) -> IpaOutput {
    let file_set: BTreeSet<String> = files.keys().cloned().collect();

    // Phase 1: parse every file in parallel. The Vec keeps input
    // order (indexed par_iter), so output stays deterministic.
    let file_vec: Vec<(&String, &String)> = files.iter().collect();
    let parsed: Vec<PyFile> = file_vec
        .par_iter()
        .map(|(rel, text)| analyze_file(rel, text))
        .collect::<Vec<_>>()
        .into_iter()
        .flatten()
        .collect();

    // Phase 2: find dynamic sites shaped lit* + param + lit*,
    // in parallel per file (order preserved).
    let sites: Vec<DynSite> = parsed
        .par_iter()
        .flat_map_iter(dyn_sites)
        .collect();

    // Phase 3: build the call index once - every call node resolved
    // to its (module, func) targets, inverted for O(1) site lookup.
    // Each file contributes (target, call-range) pairs; merged in
    // file order so rec_ids ordering stays deterministic.
    let per_file: Vec<Vec<((String, String), usize, usize)>> = parsed
        .par_iter()
        .enumerate()
        .map(|(fi, f)| {
            let rbind = resolve_bindings(f);
            let mut out = Vec::new();
            let mut stack = vec![f.tree.root_node()];
            while let Some(node) = stack.pop() {
                if node.kind() == "call" {
                    if let Some(func_node) = node.child_by_field_name("function") {
                        for target in call_targets(func_node, &rbind, &f.text) {
                            out.push((
                                target,
                                node.start_byte(),
                                node.end_byte(),
                            ));
                        }
                    }
                }
                let mut c = node.walk();
                stack.extend(node.children(&mut c));
            }
            let _ = fi;
            out
        })
        .collect();
    let mut calls: Vec<CallRec> = Vec::new();
    let mut index: HashMap<(String, String), Vec<usize>> = HashMap::new();
    for (fi, recs) in per_file.into_iter().enumerate() {
        for (target, start, end) in recs {
            let ci = calls.len();
            calls.push(CallRec { file: fi, start, end });
            index.entry(target).or_default().push(ci);
        }
    }

    // Phase 4: resolve each site through its indexed call sites.
    let mut edges: Vec<(String, String, EdgeKind)> = Vec::new();
    let mut unresolved: Vec<String> = Vec::new();
    let mut resolved = 0usize;
    let mut seen_edges: BTreeSet<(String, String)> = BTreeSet::new();

    for site in &sites {
        let site_file = parsed
            .iter()
            .find(|f| f.rel == site.file_rel)
            .expect("site file was parsed");
        let Some(func_params) = site_file.funcs.get(&site.func) else {
            unresolved.push(format!("{}:{} (no signature)", site.file_rel, site.func));
            continue;
        };

        let key = (site.module.clone(), site.func.clone());
        let Some(rec_ids) = index.get(&key) else {
            unresolved.push(format!("{}:{} (no call sites)", site.file_rel, site.func));
            continue;
        };

        // Collect candidate specifier strings from every call site.
        let mut candidates: BTreeSet<String> = BTreeSet::new();
        let mut n_calls = 0usize;
        let mut call_failed = false;

        for &ci in rec_ids {
            n_calls += 1;
            if n_calls > MAX_CALL_SITES {
                call_failed = true;
                break;
            }
            let rec = &calls[ci];
            let caller = &parsed[rec.file];
            let Some(call_node) = caller
                .tree
                .root_node()
                .descendant_for_byte_range(rec.start, rec.end)
            else {
                continue;
            };
            if call_node.kind() != "call" {
                continue;
            }
            match callsite_param_arg(call_node, caller, func_params, &site.param) {
                Some(arg_node) => match eval_strset(arg_node, &caller.text, caller, 0) {
                    Some(vals) => {
                        for v in vals {
                            candidates.insert(format!(
                                "{}{}{}",
                                site.prefix, v, site.suffix
                            ));
                            if candidates.len() > MAX_STRINGS {
                                call_failed = true;
                                break;
                            }
                        }
                    }
                    None => call_failed = true,
                },
                // Call site doesn't pass this param (default or
                // *args) - can't prove coverage; mark unresolved.
                None => call_failed = true,
            }
            if call_failed {
                break;
            }
        }

        if candidates.is_empty() {
            unresolved.push(format!(
                "{}:{} ({})",
                site.file_rel,
                site.func,
                if call_failed { "unresolved call sites" } else { "no call sites" }
            ));
            continue;
        }

        let mut any = false;
        for cand in candidates {
            if let Some(dst) = file_of_module(&cand, &file_set) {
                if dst != site.file_rel
                    && seen_edges.insert((site.file_rel.clone(), dst.clone()))
                {
                    edges.push((site.file_rel.clone(), dst, EdgeKind::Heuristic));
                    any = true;
                }
            }
        }
        if any {
            resolved += 1;
        } else {
            unresolved.push(format!("{}:{} (no matching module)", site.file_rel, site.func));
        }
    }

    IpaOutput {
        edges,
        unresolved,
        resolved,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn from_import_positional_and_keyword() {
        let f = files(&[
            ("loader.py", "from importlib import import_module\ndef load(name):\n    return import_module(\"plugins.\" + name)\n"),
            ("app.py", "from loader import load\nload(\"ldap\")\nload(name=\"sql\")\n"),
            ("plugins/__init__.py", ""),
            ("plugins/ldap.py", ""),
            ("plugins/sql.py", ""),
        ]);
        let out = analyze(&f);
        assert_eq!(out.edges.len(), 2);
        assert!(out.edges.iter().all(|(_, _, k)| *k == EdgeKind::Heuristic));
        assert!(out.edges.contains(&("loader.py".into(), "plugins/ldap.py".into(), EdgeKind::Heuristic)));
        assert!(out.edges.contains(&("loader.py".into(), "plugins/sql.py".into(), EdgeKind::Heuristic)));
        assert_eq!(out.unresolved.len(), 0);
    }

    #[test]
    fn aliased_from_import() {
        let f = files(&[
            ("loader.py", "from importlib import import_module\ndef load(name):\n    import_module(name)\n"),
            ("app.py", "from loader import load as l\nl(\"ldap\")\n"),
            ("ldap.py", ""),
        ]);
        let out = analyze(&f);
        assert_eq!(out.edges, vec![("loader.py".into(), "ldap.py".into(), EdgeKind::Heuristic)]);
    }

    #[test]
    fn module_attr_call() {
        let f = files(&[
            ("pkg/loader.py", "from importlib import import_module\ndef load(name):\n    import_module(\"plugins.\" + name)\n"),
            ("app.py", "import pkg.loader\npkg.loader.load(\"ldap\")\n"),
            ("plugins/__init__.py", ""),
            ("plugins/ldap.py", ""),
        ]);
        let out = analyze(&f);
        assert_eq!(out.edges.len(), 1);
        assert_eq!(out.edges[0].1, "plugins/ldap.py");
    }

    #[test]
    fn relative_from_import() {
        let f = files(&[
            ("pkg/loader.py", "from importlib import import_module\ndef load(name):\n    import_module(\"plugins.\" + name)\n"),
            ("pkg/app.py", "from .loader import load\nload(\"ldap\")\n"),
            ("pkg/plugins/__init__.py", ""),
            ("pkg/plugins/ldap.py", ""),
        ]);
        // "plugins.ldap" resolves against CWD root, not pkg/ - the
        // literal prefix is absolute. This test documents that
        // behavior: candidate "plugins.ldap" has no file -> unresolved.
        let out = analyze(&f);
        assert!(out.edges.is_empty());
        assert_eq!(out.unresolved.len(), 1);
    }

    #[test]
    fn unresolved_variable_callsite() {
        let f = files(&[
            ("loader.py", "from importlib import import_module\ndef load(name):\n    import_module(name)\n"),
            ("app.py", "from loader import load\nimport sys\nload(sys.argv[1])\n"),
            ("ldap.py", ""),
        ]);
        let out = analyze(&f);
        assert!(out.edges.is_empty());
        assert_eq!(out.unresolved.len(), 1);
        assert!(out.unresolved[0].contains("unresolved call sites"));
    }

    #[test]
    fn no_call_sites() {
        let f = files(&[
            ("loader.py", "from importlib import import_module\ndef load(name):\n    import_module(name)\n"),
            ("ldap.py", ""),
        ]);
        let out = analyze(&f);
        assert!(out.edges.is_empty());
        assert!(out.unresolved[0].contains("no call sites"));
    }

    #[test]
    fn const_arg_at_callsite() {
        let f = files(&[
            ("loader.py", "from importlib import import_module\ndef load(name):\n    import_module(name)\n"),
            ("app.py", "from loader import load\nWHICH = \"ldap\"\nload(WHICH)\n"),
            ("ldap.py", ""),
        ]);
        let out = analyze(&f);
        assert_eq!(out.edges.len(), 1);
    }

    #[test]
    fn concat_prefix_and_suffix() {
        let f = files(&[
            ("loader.py", "from importlib import import_module\ndef load(name):\n    import_module(\"pre.\" + name + \".post\")\n"),
            ("app.py", "from loader import load\nload(\"mid\")\n"),
            ("pre/__init__.py", ""),
            ("pre/mid/__init__.py", ""),
            ("pre/mid/post.py", ""),
        ]);
        let out = analyze(&f);
        assert_eq!(out.edges.len(), 1);
        assert_eq!(out.edges[0].1, "pre/mid/post.py");
    }

    #[test]
    fn literal_sites_ignored() {
        // import_module("literal") inside a function is Strand's job,
        // not IPA's - no DynSite should be produced.
        let f = files(&[
            ("m.py", "from importlib import import_module\ndef f():\n    import_module(\"ldap\")\n"),
            ("ldap.py", ""),
        ]);
        let out = analyze(&f);
        assert!(out.edges.is_empty());
        assert!(out.unresolved.is_empty());
    }
}
