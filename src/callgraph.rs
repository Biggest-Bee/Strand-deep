//! Function-level call graph for Python sources.
//!
//! Resolves every `call` node's callee to `(module, qualname)` where
//! possible:
//! - `from m import f` / `import m` + `m.f()` -> imported functions
//! - bare `f()` where `f` is a module-level `def` in the same file
//! - `self.f()` / `cls.f()` inside a class -> `Class.f` methods
//!
//! Everything else is counted in [`CallStats`] by reason - this is
//! the measurement instrument for spike #1 (call resolution rate).

use std::collections::HashSet;

use rayon::prelude::*;
use tree_sitter::Node;

use crate::ipa::{resolve_bindings, resolve_module_key, PyFile, RBindings};

/// A resolved call edge: caller `(module, qualname)` -> callee
/// `(module, qualname)`.
pub type CallEdge = ((String, String), (String, String));

#[derive(Default, Debug)]
pub struct CallStats {
    /// Every `call` node seen.
    pub total: usize,
    /// Callee resolved through import bindings.
    pub resolved_import: usize,
    /// Bare call to a same-module function.
    pub resolved_local: usize,
    /// `self.`/`cls.` call resolved to a class method.
    pub resolved_method: usize,
    /// Bare name with no binding and no local def (builtins,
    /// star-imports, unresolved).
    pub unknown_name: usize,
    /// `obj.attr()` where `obj` isn't a statically known module.
    pub unknown_object: usize,
    /// `self.`/`cls.` call with no matching method found.
    pub unknown_method: usize,
    /// Callee expression isn't identifier/attribute (subscript,
    /// call result, lambda, ...).
    pub complex_callee: usize,
    /// Calls to Python builtins (len, print, str, ...).
    pub builtin: usize,
}

impl CallStats {
    pub fn resolved(&self) -> usize {
        self.resolved_import + self.resolved_local + self.resolved_method
    }
    /// Fraction of calls resolved, 0.0-1.0.
    pub fn resolution_rate(&self) -> f64 {
        // Builtins aren't analyzable project calls - exclude them
        // from the denominator.
        let analyzable = self.total.saturating_sub(self.builtin);
        if analyzable == 0 {
            0.0
        } else {
            self.resolved() as f64 / analyzable as f64
        }
    }
}

pub struct CallGraph {
    pub edges: Vec<CallEdge>,
    pub stats: CallStats,
}

/// Python builtins - not project calls, excluded from resolution
/// stats so the rate reflects analyzable code.
fn is_builtin(name: &str) -> bool {
    matches!(name,
        "abs"|"all"|"any"|"ascii"|"bin"|"bool"|"breakpoint"|"bytearray"|
        "bytes"|"callable"|"chr"|"classmethod"|"compile"|"complex"|"delattr"|
        "dict"|"dir"|"divmod"|"enumerate"|"eval"|"exec"|"filter"|"float"|
        "format"|"frozenset"|"getattr"|"globals"|"hasattr"|"hash"|"help"|
        "hex"|"id"|"input"|"int"|"isinstance"|"issubclass"|"iter"|"len"|
        "list"|"locals"|"map"|"max"|"memoryview"|"min"|"next"|"object"|
        "oct"|"open"|"ord"|"pow"|"print"|"property"|"range"|"repr"|
        "reversed"|"round"|"set"|"setattr"|"slice"|"sorted"|"staticmethod"|
        "str"|"sum"|"super"|"tuple"|"type"|"vars"|"zip"|"__import__"|
        "Exception"|"ValueError"|"TypeError"|"KeyError"|"IndexError"|
        "AttributeError"|"RuntimeError"|"StopIteration"|"NotImplementedError"|
        "ImportError"|"OSError"|"IOError"|"FileNotFoundError"|"True"|
        "False"|"None"|"NotImplemented"|"Ellipsis"|"ArithmeticError"|
        "AssertionError"|"LookupError"|"NameError"|"UnboundLocalError"|
        "ZeroDivisionError"|"OverflowError"|"MemoryError"|"RecursionError"|
        "Warning"|"UserWarning"|"DeprecationWarning"
    )
}

/// Enclosing function's `(module, qualname)` for a call node.
fn enclosing_func_id(node: Node, f: &PyFile) -> Option<(String, String)> {
    let mut anc = node.parent();
    while let Some(n) = anc {
        if n.kind() == "function_definition" {
            let name = n
                .child_by_field_name("name")
                .and_then(|x| x.utf8_text(f.text.as_bytes()).ok())?;
            // Find matching FuncInfo for qualname.
            if let Some(infos) = f.funcs.get(name) {
                if let Some(info) = infos.first() {
                    return Some((f.module.clone(), info.qualname.clone()));
                }
            }
            return Some((f.module.clone(), name.to_string()));
        }
        anc = n.parent();
    }
    // Module-level call site: attribute to a synthetic "<module>".
    Some((f.module.clone(), "<module>".to_string()))
}

/// Enclosing class name for a call node (for self/cls resolution).
fn enclosing_class(node: Node, f: &PyFile) -> Option<String> {
    let mut anc = node.parent();
    while let Some(n) = anc {
        if n.kind() == "class_definition" {
            return n
                .child_by_field_name("name")
                .and_then(|x| x.utf8_text(f.text.as_bytes()).ok())
                .map(|s| s.to_string());
        }
        anc = n.parent();
    }
    None
}

/// All `(module, qualname)` callees a call node may invoke.
/// Returns (targets, stat_category_if_none).
fn resolve_call(
    call: Node,
    f: &PyFile,
    rbind: &RBindings,
    methods: &HashSet<(String, String)>, // (module, "Class.method")
    stats: &mut CallStats,
) -> Vec<((String, String), (String, String))> {
    let Some(func_node) = call.child_by_field_name("function") else {
        stats.complex_callee += 1;
        return Vec::new();
    };
    let text = f.text.as_str();
    let caller = enclosing_func_id(call, f);

    match func_node.kind() {
        "identifier" => {
            let Ok(name) = func_node.utf8_text(text.as_bytes()) else {
                stats.unknown_name += 1;
                return Vec::new();
            };
            // Import-bound: `from m import f [as g]`.
            if let Some((mk, Some(member))) = rbind.get(name) {
                if let Some(m) = resolve_module_key(mk, &f.module) {
                    stats.resolved_import += 1;
                    return caller
                        .map(|c| vec![(c, (m, member.clone()))])
                        .unwrap_or_default();
                }
            }
            // Python builtins aren't project calls.
            if is_builtin(name) {
                stats.builtin += 1;
                return Vec::new();
            }
            // Same-module function (non-method defs only - bare names
            // inside a class body don't see methods).
            if let Some(infos) = f.funcs.get(name) {
                if let Some(info) = infos
                    .iter()
                    .rev()
                    .find(|i| !i.is_method && !i.is_stub)
                    .or_else(|| infos.iter().rev().find(|i| !i.is_method))
                {
                    stats.resolved_local += 1;
                    return caller
                        .map(|c| vec![(c, (f.module.clone(), info.qualname.clone()))])
                        .unwrap_or_default();
                }
            }
            stats.unknown_name += 1;
            Vec::new()
        }
        "attribute" => {
            let Some(attr) = func_node.child_by_field_name("attribute") else {
                stats.complex_callee += 1;
                return Vec::new();
            };
            let Ok(fname) = attr.utf8_text(text.as_bytes()) else {
                stats.complex_callee += 1;
                return Vec::new();
            };
            let Some(obj) = func_node.child_by_field_name("object") else {
                stats.unknown_object += 1;
                return Vec::new();
            };
            // self.f() / cls.f() -> Class.f method.
            if obj.kind() == "identifier" {
                if let Ok(oname) = obj.utf8_text(text.as_bytes()) {
                    if oname == "self" || oname == "cls" {
                        if let Some(class) = enclosing_class(call, f) {
                            let qual = format!("{class}.{fname}");
                            if methods.contains(&(f.module.clone(), qual.clone())) {
                                stats.resolved_method += 1;
                                return caller
                                    .map(|c| {
                                        vec![(c, (f.module.clone(), qual))]
                                    })
                                    .unwrap_or_default();
                            }
                        }
                        stats.unknown_method += 1;
                        return Vec::new();
                    }
                }
            }
            // obj.attr() where obj is a known module.
            match crate::ipa::object_module(obj, rbind, text) {
                Some(m) => {
                    stats.resolved_import += 1;
                    caller
                        .map(|c| vec![(c, (m, fname.to_string()))])
                        .unwrap_or_default()
                }
                None => {
                    stats.unknown_object += 1;
                    Vec::new()
                }
            }
        }
        _ => {
            stats.complex_callee += 1;
            Vec::new()
        }
    }
}

/// Build the call graph over pre-parsed files.
pub fn build(parsed: &[PyFile]) -> CallGraph {
    // Global method index: (module, "Class.method") -> exists.
    let methods: HashSet<(String, String)> = parsed
        .par_iter()
        .flat_map(|f| {
            f.funcs
                .values()
                .flat_map(|v| v.iter())
                .filter(|i| i.is_method)
                .map(|i| (f.module.clone(), i.qualname.clone()))
                .collect::<Vec<_>>()
        })
        .collect();

    // Per-file: resolve bindings once, then walk calls. Each file
    // contributes edges + local stats; merged in order.
    let per_file: Vec<(Vec<CallEdge>, CallStats)> = parsed
        .par_iter()
        .map(|f| {
            let rbind = resolve_bindings(f);
            let mut stats = CallStats::default();
            let mut edges = Vec::new();
            for node in crate::ipa::call_nodes(f) {
                stats.total += 1;
                for (caller, callee) in resolve_call(node, f, &rbind, &methods, &mut stats) {
                    edges.push((caller, callee));
                }
            }
            (edges, stats)
        })
        .collect();

    let mut edges = Vec::new();
    let mut stats = CallStats::default();
    let mut seen: HashSet<CallEdge> = HashSet::new();
    for (fe, fs) in per_file {
        stats.total += fs.total;
        stats.resolved_import += fs.resolved_import;
        stats.resolved_local += fs.resolved_local;
        stats.resolved_method += fs.resolved_method;
        stats.unknown_name += fs.unknown_name;
        stats.unknown_object += fs.unknown_object;
        stats.unknown_method += fs.unknown_method;
        stats.complex_callee += fs.complex_callee;
        stats.builtin += fs.builtin;
        for e in fe {
            if seen.insert(e.clone()) {
                edges.push(e);
            }
        }
    }
    edges.sort();
    CallGraph { edges, stats }
}
