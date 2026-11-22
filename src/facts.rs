//! Per-function dataflow facts: taint, nullness, and resource
//! tracking in a single tree walk, plus interprocedural summary
//! application through already-computed callee summaries.
//!
//! Value domains (all may-analyses, join = union):
//! - taint: Option<label> - provenance ("src:os.environ", "param:0",
//!   "call:eval", ...)
//! - is_none: bool - value may be None
//! - resource: Option<kind> - open handle ("file", "lock", "conn")
//!
//! Environment keys are dotted paths for attribute chains
//! (`self.count`); subscripts collapse to the base (`d["k"]` -> `d`).
//! Documented approximations: no fixpoint inside loops (single pass),
//! no cross-function globals, no instance-field sensitivity.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use tree_sitter::Node;

use crate::ipa::{object_module, resolve_bindings, resolve_module_key, PyFile, RBindings};
use crate::models::{Model, SinkKind};

/// A concrete finding: untrusted/None/resource-violating value reached
/// a sink inside one function.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub class: SinkKind,
    /// Provenance label, or "none" / "resource:<kind>".
    pub source: String,
    /// Sink description: dotted call name or operation.
    pub sink: String,
    pub file: String,
    pub line: u32,
    /// Qualified function containing the sink.
    pub func: String,
    /// Interprocedural path of `module.func` from entry to sink.
    pub via: Vec<String>,
    /// 1.0 concrete; lower when param-propagated or via unknown calls.
    pub confidence: f32,
}

/// Sink reached through a parameter - re-instantiated at call sites.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PendingSink {
    pub class: SinkKind,
    pub file: String,
    pub line: u32,
    /// Qualified name of the function containing the sink call.
    pub func: String,
    pub sink: String,
    /// Callee chain inside the function.
    pub through: Vec<String>,
}

/// Function summary - the unit of interprocedural reuse.
#[derive(Debug, Clone, Default)]
pub struct Summary {
    /// param index -> sinks reachable when that param is tainted.
    pub param_sinks: BTreeMap<usize, Vec<PendingSink>>,
    /// param index -> value flows into the return.
    pub param_to_return: BTreeSet<usize>,
    /// Returns tainted data not derived from params.
    pub returns_tainted: bool,
    /// May return None.
    pub may_return_none: bool,
    /// Returns an open resource handle (kind string).
    pub returns_unclosed: Option<String>,
    /// Called something unresolvable.
    pub touches_unknown: bool,
    /// Concrete local findings.
    pub findings: Vec<Finding>,
}

impl Summary {
    /// Fixpoint comparison: flow fields only (findings accumulate).
    pub(crate) fn flows_equal(&self, other: &Summary) -> bool {
        self.param_sinks == other.param_sinks
            && self.param_to_return == other.param_to_return
            && self.returns_tainted == other.returns_tainted
            && self.may_return_none == other.may_return_none
            && self.returns_unclosed == other.returns_unclosed
            && self.touches_unknown == other.touches_unknown
    }
}

/// Per-variable state.
#[derive(Debug, Clone, Default)]
pub(crate) struct VarState {
    taint: Option<String>,
    is_none: bool,
    resource: Option<String>,
}

impl VarState {
    fn join(&mut self, other: &VarState) {
        if self.taint.is_none() {
            self.taint = other.taint.clone();
        }
        self.is_none |= other.is_none;
        if self.resource.is_none() {
            self.resource = other.resource.clone();
        }
    }
    fn merge_labels(&mut self, other: &VarState) {
        // For sequential (non-branch) combination: union taint
        // possibilities by keeping existing or taking other's.
        self.join(other);
    }
}

#[derive(Debug, Clone, Default)]
struct ExprVal {
    state: VarState,
    /// Set when the expr itself is a model source.
    source_label: Option<String>,
}

/// Shared context for one function's walk. `env` is passed separately
/// so branch bodies can run on cloned environments.
pub struct Ctx<'a> {
    f: &'a PyFile,
    rbind: RBindings,
    model: &'a Model,
    summaries: &'a HashMap<(String, String), Summary>,
    params: &'a [String],
    qualname: &'a str,
    acquired: Vec<(String, String, u32)>,
    released: HashSet<String>,
    /// Resource-holding vars passed to calls - ownership may
    /// transfer to the callee; suppresses local leak findings.
    escaped: HashSet<String>,
    ret: VarState,
    saw_return: bool,
    nodes_left: usize,
    pub findings: Vec<Finding>,
    pub param_sinks: BTreeMap<usize, Vec<PendingSink>>,
    pub touches_unknown: bool,
    /// Dedup key for findings (same expr evaluated twice via
    /// per-index container tracking).
    reported: HashSet<(SinkKind, u32, String, String)>,
    /// Set by apply_summary; consumed by eval_call.
    pending_result: Option<ExprVal>,
}

const NODE_BUDGET: usize = 100_000;

pub struct FuncAnalysis {
    pub summary: Summary,
    /// Final environment - used for `<module>` nodes to seed
    /// function scopes with module globals.
    pub env: HashMap<String, VarState>,
}

/// Analyze a function body. `func_node` = function_definition or
/// module; `params` = ordered param names; `qualname` = "mod.func".
pub fn analyze_function(
    f: &PyFile,
    func_node: Node,
    params: &[String],
    qualname: &str,
    model: &Model,
    summaries: &HashMap<(String, String), Summary>,
    globals: Option<&HashMap<String, VarState>>,
) -> FuncAnalysis {
    let mut ctx = Ctx {
        f,
        rbind: resolve_bindings(f),
        model,
        summaries,
        params,
        qualname,
        acquired: Vec::new(),
        released: HashSet::new(),
        escaped: HashSet::new(),
        ret: VarState::default(),
        saw_return: false,
        nodes_left: NODE_BUDGET,
        findings: Vec::new(),
        param_sinks: BTreeMap::new(),
        touches_unknown: false,
        reported: HashSet::new(),
        pending_result: None,
    };
    // Seed with module globals (Python: functions read module scope);
    // params/locals shadow via insert.
    let mut env: HashMap<String, VarState> =
        globals.cloned().unwrap_or_default();
    for (i, p) in params.iter().enumerate() {
        env.insert(
            p.clone(),
            VarState {
                taint: Some(format!("param:{i}")),
                is_none: false,
                resource: None,
            },
        );
    }
    walk_suite(func_node, &mut ctx, &mut env);

    // Resource leaks: acquired, never released, not returned.
    for (var, kind, line) in &ctx.acquired {
        if ctx.released.contains(var) || ctx.escaped.contains(var) {
            continue;
        }
        let still_held = env.get(var).is_some_and(|st| st.resource.is_some());
        let was_returned = ctx.ret.resource.is_some();
        if still_held && !was_returned {
            ctx.findings.push(Finding {
                class: SinkKind::Leak,
                source: format!("resource:{kind}"),
                sink: format!("acquire {var}"),
                file: ctx.f.rel.clone(),
                line: *line,
                func: qualname.to_string(),
                via: vec![format!("{}.{}", ctx.f.module, qualname)],
                confidence: 0.8,
            });
        }
    }

    let mut summary = Summary {
        may_return_none: ctx.ret.is_none || may_fall_off(func_node),
        returns_tainted: ctx
            .ret
            .taint
            .as_ref()
            .is_some_and(|l| !l.starts_with("param:")),
        returns_unclosed: first_unclosed(&ctx),
        touches_unknown: ctx.touches_unknown,
        findings: std::mem::take(&mut ctx.findings),
        param_sinks: std::mem::take(&mut ctx.param_sinks),
        ..Default::default()
    };
    if let Some(label) = &ctx.ret.taint {
        if let Some(idx) = label.strip_prefix("param:").and_then(|r| r.parse().ok()) {
            summary.param_to_return.insert(idx);
        }
    }
    FuncAnalysis { summary, env }
}

fn first_unclosed(ctx: &Ctx) -> Option<String> {
    for (var, kind, _) in &ctx.acquired {
        if !ctx.released.contains(var) {
            return Some(kind.clone());
        }
    }
    ctx.ret.resource.clone()
}

/// Conservative check: can control reach the end of this node?
/// `return`/`raise` are terminal; compound statements fall through if any
/// branch can.
fn may_fall_off(node: Node) -> bool {
    match node.kind() {
        // return/raise exit the function; break/continue exit the
        // current suite iteration - none fall through to the next
        // statement in the same block.
        "return_statement" | "raise_statement" | "break_statement"
        | "continue_statement" => false,
        "block" | "suite" | "module" => {
            let mut c = node.walk();
            match node.children(&mut c).last() {
                Some(last) => may_fall_off(last),
                None => true,
            }
        }
        "function_definition" => node
            .child_by_field_name("body")
            .map(may_fall_off)
            .unwrap_or(true),
        "lambda" => true,
        "if_statement" => {
            // Fallback clause is the `else`/`elif` chain; without one the
            // if can be skipped entirely.
            let mut c = node.walk();
            let children: Vec<Node> = node.children(&mut c).collect();
            let mut has_else = false;
            let mut any_branch_falls = false;
            let mut i = 0;
            while i < children.len() {
                let ch = children[i];
                match ch.kind() {
                    "elif_clause" | "else_clause" => {
                        if ch.kind() == "else_clause" {
                            has_else = true;
                        }
                        let mut cc = ch.walk();
                        let inner: Vec<Node> = ch.children(&mut cc).collect();
                        // last child is the suite
                        if let Some(suite) = inner.last() {
                            any_branch_falls |= may_fall_off(*suite);
                        }
                    }
                    "block" => {
                        any_branch_falls |= may_fall_off(ch);
                    }
                    _ => {}
                }
                i += 1;
            }
            !has_else || any_branch_falls
        }
        "try_statement" => {
            let mut c = node.walk();
            let children: Vec<Node> = node.children(&mut c).collect();
            let mut body_falls = true;
            let mut handler_falls = false;
            let mut else_falls = false;
            let mut finally_falls = false;
            let mut has_finally = false;
            for ch in children {
                match ch.kind() {
                    "block" if body_falls && !handler_falls && !else_falls => {
                        body_falls = may_fall_off(ch);
                    }
                    "except_clause" | "else_clause" | "finally_clause" => {
                        let mut cc = ch.walk();
                        let inner: Vec<Node> = ch.children(&mut cc).collect();
                        if let Some(suite) = inner.last() {
                            match ch.kind() {
                                "except_clause" => handler_falls |= may_fall_off(*suite),
                                "else_clause" => else_falls = may_fall_off(*suite),
                                "finally_clause" => {
                                    has_finally = true;
                                    finally_falls = may_fall_off(*suite);
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
            // Falls through if any completing path falls through; a finally
            // that itself returns/raises makes the whole statement terminal.
            let paths_fall = body_falls || handler_falls || else_falls;
            if has_finally {
                paths_fall && finally_falls
            } else {
                paths_fall
            }
        }
        "with_statement" => {
            // Body always runs once; fall-off = body fall-off.
            let mut c = node.walk();
            let body = node.children(&mut c).find(|n| n.kind() == "block");
            match body {
                Some(b) => may_fall_off(b),
                None => true,
            }
        }
        // Loops may execute zero times (or break); conservatively fall off.
        "for_statement" | "while_statement" => true,
        "match_statement" => true, // conservative: cases/defaults may fall through
        _ => true,
    }
}

fn line_of(node: Node) -> u32 {
    node.start_position().row as u32 + 1
}

fn budget(ctx: &mut Ctx) -> bool {
    if ctx.nodes_left == 0 {
        return true;
    }
    ctx.nodes_left -= 1;
    false
}

fn walk_suite(node: Node, ctx: &mut Ctx, env: &mut HashMap<String, VarState>) {
    let suite = if node.kind() == "function_definition" {
        node.child_by_field_name("body").unwrap_or(node)
    } else {
        node
    };
    let mut c = suite.walk();
    let stmts: Vec<Node> = suite.children(&mut c).collect();
    for st in stmts {
        if budget(ctx) {
            return;
        }
        walk_stmt(st, ctx, env);
    }
}

/// Branch bodies run on a cloned env, then join back (may-analysis).
fn walk_branch(node: Node, ctx: &mut Ctx, env: &mut HashMap<String, VarState>) {
    walk_branch_narrow(node, ctx, env, &[]);
}

/// Walk a branch on a cloned env; `narrow` applies null-check
/// refinements (env_key, is_none) inside the branch only - the
/// post-branch join restores the may-state.
fn walk_branch_narrow(
    node: Node,
    ctx: &mut Ctx,
    env: &mut HashMap<String, VarState>,
    narrow: &[(String, bool)],
) {
    let mut env2 = env.clone();
    for (key, is_none) in narrow {
        if let Some(st) = env2.get_mut(key.as_str()) {
            st.is_none = *is_none;
        }
    }
    walk_suite(node, ctx, &mut env2);
    for (k, v) in env2 {
        env.entry(k).or_default().join(&v);
    }
}

/// Null-related condition analysis. Returns
/// `(narrow_if_true, narrow_if_false)`: (env_key, is_none)
/// refinements that hold when the condition evaluates true/false.
/// Recurses through `and` / `or` / `not`; leaf checks are
/// `x is None`-style comparisons and `isinstance(x, T)`.
type Narrows = (Vec<(String, bool)>, Vec<(String, bool)>);

fn null_checks(cond: Node, ctx: &Ctx, env: &HashMap<String, VarState>) -> Narrows {
    let text = ctx.f.text.as_str();
    match cond.kind() {
        "parenthesized_expression" => {
            let inner = {
                let mut c = cond.walk();
                let found = cond.children(&mut c).find(|k| k.is_named());
                found
            };
            match inner {
                Some(n) => null_checks(n, ctx, env),
                None => (vec![], vec![]),
            }
        }
        "unary_operator" => {
            let t = cond.utf8_text(text.as_bytes()).unwrap_or("").trim();
            if t == "not" {
                let inner = {
                    let mut c = cond.walk();
                    let found = cond.children(&mut c).find(|k| k.is_named());
                    found
                };
                if let Some(n) = inner {
                    let (a, b) = null_checks(n, ctx, env);
                    return (b, a);
                }
            }
            (vec![], vec![])
        }
        "boolean_operator" => {
            let mut c = cond.walk();
            let kids: Vec<Node> = cond.children(&mut c).collect();
            let optext = kids
                .iter()
                .filter(|k| !k.is_named())
                .filter_map(|k| k.utf8_text(text.as_bytes()).ok())
                .collect::<String>();
            let operands: Vec<Node> =
                kids.iter().copied().filter(|k| k.is_named()).collect();
            if operands.len() == 2 {
                let (lt, lf) = null_checks(operands[0], ctx, env);
                let (rt, rf) = null_checks(operands[1], ctx, env);
                if optext.trim() == "and" {
                    // True: both hold. False: either may have failed.
                    let mut t = lt;
                    t.extend(rt);
                    (t, vec![])
                } else {
                    // `or`: True -> either may hold; False: both false.
                    let mut f = lf;
                    f.extend(rf);
                    (vec![], f)
                }
            } else {
                (vec![], vec![])
            }
        }
        _ => leaf_null_check(cond, ctx, env),
    }
}

/// Leaf null checks: `x is None` / `x == None` / `isinstance(x, T)`.
fn leaf_null_check(cond: Node, ctx: &Ctx, env: &HashMap<String, VarState>) -> Narrows {
    let text = ctx.f.text.as_str();
    // `isinstance(x, T)`: an instance is never None when true.
    if cond.kind() == "call" {
        let is_isinstance = cond
            .child_by_field_name("function")
            .map(|f| {
                f.kind() == "identifier"
                    && f.utf8_text(text.as_bytes()).unwrap_or("") == "isinstance"
            })
            .unwrap_or(false);
        if is_isinstance {
            let first = cond.child_by_field_name("arguments").and_then(|a| {
                let mut ac = a.walk();
                let found = a.children(&mut ac).find(|k| k.is_named());
                found
            });
            if let Some(arg0) = first {
                if let Some(key) = expr_key(arg0, ctx, env) {
                    return (vec![(key, false)], vec![]);
                }
            }
        }
        return (vec![], vec![]);
    }
    if cond.kind() != "comparison_operator" {
        return (vec![], vec![]);
    }
    let mut c = cond.walk();
    let kids: Vec<Node> = cond.children(&mut c).collect();
    let named: Vec<Node> = kids.iter().copied().filter(|k| k.is_named()).collect();
    if named.len() != 2 {
        return (vec![], vec![]);
    }
    let optext = kids
        .iter()
        .filter(|k| !k.is_named())
        .filter_map(|k| k.utf8_text(text.as_bytes()).ok())
        .collect::<Vec<_>>()
        .join(" ");
    let optext = optext.split_whitespace().collect::<Vec<_>>().join(" ");
    let (left, right) = (named[0], named[1]);
    let target = if right.kind() == "none" {
        left
    } else if left.kind() == "none" {
        right
    } else {
        return (vec![], vec![]);
    };
    let is_none_true = match optext.trim() {
        "is" | "==" => true,
        "is not" | "!=" => false,
        _ => return (vec![], vec![]),
    };
    match expr_key(target, ctx, env) {
        Some(key) => (
            vec![(key.clone(), is_none_true)],
            vec![(key, !is_none_true)],
        ),
        None => (vec![], vec![]),
    }
}

fn walk_stmt(node: Node, ctx: &mut Ctx, env: &mut HashMap<String, VarState>) {
    if std::env::var("SD_DEBUG").is_ok() && ctx.qualname == "main" {
        eprintln!("[dbg] stmt kind={} text={:?}", node.kind(), &ctx.f.text[node.start_byte()..node.end_byte().min(node.start_byte()+40)]);
    }
    match node.kind() {
        "expression_statement" => {
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if !ch.is_named() {
                    continue;
                }
                // This grammar wraps assignments in
                // expression_statement - dispatch them properly.
                match ch.kind() {
                    "assignment" | "augmented_assignment" => {
                        walk_assign(ch, ctx, env)
                    }
                    _ => {
                        eval_expr(ch, ctx, env);
                    }
                }
            }
        }
        "assignment" | "augmented_assignment" => walk_assign(node, ctx, env),
        "if_statement" => {
            // Grammar shape: `if` cond `:` block (elif_clause |
            // else_clause)* - the leading condition and its block are
            // DIRECT children; only elif/else get clause wrappers.
            // Collect (narrows, suite, is_else) per clause.
            let mut clauses: Vec<(Narrows, Node, bool)> = Vec::new();
            {
                let mut c = node.walk();
                let kids: Vec<Node> = node.children(&mut c).collect();
                let mut idx = 0;
                // Leading `if` clause: named cond exprs then first block.
                let mut conds: Vec<Node> = Vec::new();
                let mut suite = None;
                while idx < kids.len() {
                    let k = kids[idx];
                    if k.kind() == "block" {
                        suite = Some(k);
                        idx += 1;
                        break;
                    }
                    if k.is_named() {
                        conds.push(k);
                    }
                    idx += 1;
                }
                for cn in &conds {
                    eval_expr(*cn, ctx, env);
                }
                if let Some(s) = suite {
                    let check = if conds.len() == 1 {
                        null_checks(conds[0], ctx, env)
                    } else {
                        (vec![], vec![])
                    };
                    clauses.push((check, s, false));
                }
                // elif_clause / else_clause children.
                for k in kids[idx..].iter() {
                    match k.kind() {
                        "elif_clause" | "else_clause" => {
                            let is_else = k.kind() == "else_clause";
                            let mut cc = k.walk();
                            let mut econds: Vec<Node> = Vec::new();
                            let mut esuite = None;
                            for kk in k.children(&mut cc) {
                                if kk.kind() == "block" {
                                    esuite = Some(kk);
                                } else if kk.is_named() {
                                    econds.push(kk);
                                }
                            }
                            for cn in &econds {
                                eval_expr(*cn, ctx, env);
                            }
                            if let Some(s) = esuite {
                                let check = if !is_else && econds.len() == 1 {
                                    null_checks(econds[0], ctx, env)
                                } else {
                                    (vec![], vec![])
                                };
                                clauses.push((check, s, is_else));
                            }
                        }
                        _ => {
                            eval_expr(*k, ctx, env);
                        }
                    }
                }
            }
            // The else branch means EVERY condition was false: union of
            // each clause's when_false narrows.
            let else_narrow: Vec<(String, bool)> = clauses
                .iter()
                .filter(|c| !c.2)
                .flat_map(|(narrows, _, _)| narrows.1.iter().cloned())
                .collect();
            for (narrows, suite, is_else) in &clauses {
                let narrow: &[(String, bool)] = if *is_else {
                    &else_narrow
                } else {
                    &narrows.0
                };
                walk_branch_narrow(*suite, ctx, env, narrow);
            }
            // Guard-clause narrowing past the if: a terminal then-branch
            // means its condition was false on every path that reaches
            // past it (provided all earlier branches were terminal too,
            // else post-if could come from an earlier branch). A
            // terminal else of a uniquely-falling-through if means its
            // condition held true.
            let n = clauses.len();
            let terms: Vec<bool> = clauses.iter().map(|(_, s, _)| !may_fall_off(*s)).collect();
            let mut prev_all_term = true;
            let mut first_fall: Option<usize> = None;
            for i in 0..n {
                if clauses[i].2 {
                    continue;
                }
                if terms[i] {
                    if prev_all_term {
                        // Terminal then-branch: condition false past
                        // the if -> apply its when_false narrows.
                        for (key, v) in &clauses[i].0 .1 {
                            if std::env::var("SD_DEBUG").is_ok() {
                                eprintln!("[dbg]   guard-narrow {key} -> {v}");
                            }
                            if let Some(st) = env.get_mut(key.as_str()) {
                                st.is_none = *v;
                            }
                        }
                    }
                } else if first_fall.is_none() {
                    first_fall = Some(i);
                }
                prev_all_term &= terms[i];
            }
            if n > 0 && clauses[n - 1].2 && terms[n - 1] {
                if let Some(fi) = first_fall {
                    let unique = (0..n - 1).all(|i| terms[i] || i == fi);
                    if unique {
                        // Post-if reachable only through fi's branch
                        // with its condition true -> when_true narrows.
                        for (key, v) in &clauses[fi].0 .0 {
                            if let Some(st) = env.get_mut(key.as_str()) {
                                st.is_none = *v;
                            }
                        }
                    }
                }
            }
        }
        "while_statement" => {
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.kind() == "block" {
                    walk_branch(ch, ctx, env); // single pass
                } else {
                    eval_expr(ch, ctx, env);
                }
            }
        }
        "for_statement" => {
            // for target in iter: body
            let mut c = node.walk();
            let kids: Vec<Node> = node.children(&mut c).collect();
            let in_pos = kids.iter().position(|k| k.kind() == "in");
            if let Some(ip) = in_pos {
                let target = kids[..ip]
                    .iter()
                    .rev()
                    .find(|k| k.is_named() && !matches!(k.kind(), "for"))
                    .copied();
                let iter = kids.get(ip + 1).copied();
                let body = kids.iter().find(|k| k.kind() == "block").copied();
                if let (Some(t), Some(it), Some(b)) = (target, iter, body) {
                    let iv = eval_expr(it, ctx, env);
                    if let Some(tn) = expr_key(t, ctx, env) {
                        // Iterated elements are not the iterable's
                        // return value: a maybe-None iterable crashes
                        // before the body runs, and elements don't
                        // inherit the collection's resource.
                        let mut st = VarState::default();
                        st.taint = iv.state.taint.clone();
                        env.insert(tn, st);
                    }
                    walk_branch(b, ctx, env);
                }
            }
        }
        "with_statement" => {
            let mut c = node.walk();
            let mut released_here = Vec::new();
            for ch in node.children(&mut c) {
                match ch.kind() {
                    "with_clause" => {
                        let mut ic = ch.walk();
                        for wi in ch.children(&mut ic) {
                            if wi.kind() == "with_item" {
                                handle_with_item(wi, ctx, env, &mut released_here);
                            }
                        }
                    }
                    "block" => walk_branch(ch, ctx, env),
                    _ => { eval_expr(ch, ctx, env); },
                }
            }
            for v in released_here {
                ctx.released.insert(v.clone());
                if let Some(st) = env.get_mut(&v) {
                    st.resource = None;
                }
            }
        }
        "try_statement" => {
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                match ch.kind() {
                    "block" | "except_clause" | "else_clause" | "finally_clause" => {
                        // except/else/finally contain blocks; walk
                        // the clause node directly (walk_suite finds
                        // nested blocks via walk_stmt on children? no -
                        // walk_branch expects a suite; use walk_stmt on
                        // each child block instead).
                        if ch.kind() == "block" {
                            walk_branch(ch, ctx, env);
                        } else {
                            // clause: eval header exprs + walk its block
                            let mut cc = ch.walk();
                            let mut header_done = false;
                            for k in ch.children(&mut cc) {
                                if k.kind() == "block" {
                                    header_done = true;
                                    walk_branch(k, ctx, env);
                                } else if !header_done {
                                    eval_expr(k, ctx, env);
                                }
                            }
                        }
                    }
                    _ => { eval_expr(ch, ctx, env); },
                }
            }
        }
        "match_statement" => {
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.kind() == "case_clause" {
                    let mut cc = ch.walk();
                    for k in ch.children(&mut cc) {
                        if k.kind() == "block" {
                            walk_branch(k, ctx, env);
                        } else {
                            eval_expr(k, ctx, env);
                        }
                    }
                } else {
                    eval_expr(ch, ctx, env);
                }
            }
        }
        "assert_statement" => {
            // `assert cond` raises on false - past it, cond's
            // when_true narrows hold permanently.
            let mut c = node.walk();
            let cond = {
                let found = node.children(&mut c).find(|k| k.is_named());
                found
            };
            if let Some(cond) = cond {
                eval_expr(cond, ctx, env);
                let (t, _) = null_checks(cond, ctx, env);
                for (k, v) in t {
                    if let Some(st) = env.get_mut(&k) {
                        st.is_none = v;
                    }
                }
            }
        }
        "return_statement" => {
            ctx.saw_return = true;
            let mut c = node.walk();
            let mut has_expr = false;
            for ch in node.children(&mut c) {
                if ch.is_named() {
                    has_expr = true;
                    let v = eval_expr(ch, ctx, env);
                    ctx.ret.join(&v.state);
                    if ctx.ret.taint.is_none() {
                        ctx.ret.taint = v.state.taint.clone();
                    }
                }
            }
            if !has_expr {
                ctx.ret.is_none = true;
            }
        }
        "function_definition" | "class_definition" | "lambda" => {}
        "global_statement" | "nonlocal_statement" | "pass" | "break"
        | "continue" | "delete_statement" => {}
        _ => {
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.is_named() {
                    eval_expr(ch, ctx, env);
                }
            }
        }
    }
}

fn handle_with_item(
    wi: Node,
    ctx: &mut Ctx,
    env: &mut HashMap<String, VarState>,
    released: &mut Vec<String>,
) {
    // with_item: `expr as var` or `expr`
    let mut c = wi.walk();
    let kids: Vec<Node> = wi.children(&mut c).collect();
    let value = kids.iter().find(|k| k.is_named()).copied();
    let alias = kids.last().copied().filter(|k| {
        k.is_named() && Some(*k) != value
    });
    let Some(val) = value else { return };
    let vv = eval_expr(val, ctx, env);
    if let Some(a) = alias {
        if let Some(key) = expr_key(a, ctx, env) {
            let mut st = vv.state.clone();
            // with-managed resources are released at block end -
            // keep resource flag during body, release after.
            if st.resource.is_some() {
                released.push(key.clone());
            }
            env.insert(key, st);
        }
    }
}

fn walk_assign(node: Node, ctx: &mut Ctx, env: &mut HashMap<String, VarState>) {
    let rhs = node.child_by_field_name("right").or_else(|| {
        // augmented_assignment: `x += y` -> right is `y`? tree-sitter
        // uses left/right fields too.
        node.child_by_field_name("right")
    });
    let lhs = node.child_by_field_name("left");
    let (Some(l), Some(r)) = (lhs, rhs) else { return };
    let rv = eval_expr(r, ctx, env);
    assign_target(l, rv.state, rv.source_label, ctx, env, node);
}

/// True if evaluating this expr cannot produce findings or mutate
/// analysis state (no calls, walrus, lambdas, nested assignments).
fn expr_is_side_effect_free(node: Node) -> bool {
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        if matches!(
            n.kind(),
            "call" | "named_expression" | "lambda" | "assignment" | "augmented_assignment"
        ) {
            return false;
        }
        let mut c = n.walk();
        for ch in n.children(&mut c) {
            if ch.is_named() {
                stack.push(ch);
            }
        }
    }
    true
}

/// Assign evaluated state to a target (identifier, tuple, attribute,
/// subscript, starred).
fn assign_target(
    target: Node,
    state: VarState,
    source_label: Option<String>,
    ctx: &mut Ctx,
    env: &mut HashMap<String, VarState>,
    assign_node: Node,
) {
    match target.kind() {
        "identifier" => {
            let Ok(name) = target.utf8_text(ctx.f.text.as_bytes()) else { return };
            let mut st = state.clone();
            if st.taint.is_none() {
                st.taint = source_label;
            }
            // Resource acquisition tracking.
            if let Some(kind) = resource_kind_of(assign_node, ctx) {
                st.resource = Some(kind.clone());
                ctx.acquired.push((name.to_string(), kind, line_of(assign_node)));
            }
            // Explicit release calls handled in eval; nothing here.
            if std::env::var("SD_DEBUG").is_ok() {
                eprintln!("[dbg] assign {} taint={:?}", name, st.taint);
            }
            env.insert(name.to_string(), st);
            // Record per-index element states for `x = (a, b)` /
            // `x = [a, b]` so `x[0]`/`x[1]` subscripts resolve
            // precisely. Only side-effect-free elements: the RHS was
            // already evaluated once and re-evaluating calls would
            // double-report findings.
            if let Some(rhs) = assign_node.child_by_field_name("right") {
                if matches!(rhs.kind(), "tuple" | "list") {
                    let mut rc = rhs.walk();
                    let elems: Vec<Node> = rhs
                        .children(&mut rc)
                        .filter(|k| k.is_named())
                        .collect();
                    if !elems.is_empty()
                        && elems.iter().all(|e| expr_is_side_effect_free(*e))
                    {
                        for (i, e) in elems.iter().enumerate() {
                            let v = eval_expr(*e, ctx, env);
                            let mut est = v.state.clone();
                            if est.taint.is_none() {
                                est.taint = v.source_label.clone();
                            }
                            if std::env::var("SD_DEBUG").is_ok() {
                                eprintln!("[dbg]   idx {name}[{i}] none={}", est.is_none);
                            }
                            env.insert(format!("{name}[{i}]"), est);
                        }
                    }
                }
            }
        }
        "tuple" | "list" | "pattern_list" => {
            // `a, b = expr` - if RHS is a literal of matching arity
            // with side-effect-free elements, distribute per-element
            // states; else all targets get the joined state.
            let mut c = target.walk();
            let elems: Vec<Node> = target
                .children(&mut c)
                .filter(|k| k.is_named())
                .collect();
            if let Some(rhs) = assign_node.child_by_field_name("right") {
                if matches!(rhs.kind(), "tuple" | "list") {
                    let mut rc = rhs.walk();
                    let relems: Vec<Node> = rhs
                        .children(&mut rc)
                        .filter(|k| k.is_named())
                        .collect();
                    if relems.len() == elems.len()
                        && relems.iter().all(|e| expr_is_side_effect_free(*e))
                    {
                        for (t, r) in elems.iter().zip(relems.iter()) {
                            let v = eval_expr(*r, ctx, env);
                            assign_target(
                                *t,
                                v.state.clone(),
                                v.source_label.clone(),
                                ctx,
                                env,
                                assign_node,
                            );
                        }
                        return;
                    }
                }
            }
            for e in elems {
                assign_target(e, state.clone(), source_label.clone(), ctx, env, assign_node);
            }
        }
        "attribute" | "subscript" => {
            if let Some(key) = expr_key(target, ctx, env) {
                let mut st = state.clone();
                if st.taint.is_none() {
                    st.taint = source_label;
                }
                if let Some(kind) = resource_kind_of(assign_node, ctx) {
                    st.resource = Some(kind.clone());
                    ctx.acquired.push((key.clone(), kind, line_of(assign_node)));
                }
                env.insert(key, st);
            }
        }
        _ => {}
    }
}

/// If this assignment's RHS is a resource-acquiring call, return kind.
fn resource_kind_of(assign_node: Node, ctx: &Ctx) -> Option<String> {
    let r = assign_node.child_by_field_name("right")?;
    if r.kind() != "call" {
        return None;
    }
    let dotted = dotted_callee(r, ctx)?;
    let last = dotted.rsplit('.').next().unwrap_or(&dotted);
    if matches!(last, "open" | "acquire" | "connect" | "socket" | "urlopen") {
        return Some(if last == "open" || last == "urlopen" {
            "file".into()
        } else if last == "acquire" {
            "lock".into()
        } else {
            "conn".into()
        });
    }
    None
}

/// Dotted name of a call's callee expression, import-resolved.
fn dotted_callee(call: Node, ctx: &Ctx) -> Option<String> {
    let func = call.child_by_field_name("function")?;
    dotted_expr(func, ctx)
}

/// Dotted name for identifier/attribute chains, resolving the head
/// through import bindings (`import os` + `os.environ` -> "os.environ";
/// `from os import environ` + `environ` -> "os.environ").
fn dotted_expr(node: Node, ctx: &Ctx) -> Option<String> {
    let text = ctx.f.text.as_str();
    match node.kind() {
        "identifier" => {
            let name = node.utf8_text(text.as_bytes()).ok()?;
            match ctx.rbind.get(name) {
                Some((mk, Some(mem))) => {
                    let m = resolve_module_key(mk, &ctx.f.module)?;
                    Some(format!("{m}.{mem}"))
                }
                Some((mk, None)) => resolve_module_key(mk, &ctx.f.module),
                None => Some(name.to_string()),
            }
        }
        "attribute" => {
            let attr = node.child_by_field_name("attribute")?;
            let obj = node.child_by_field_name("object")?;
            let base = dotted_expr(obj, ctx)?;
            let a = attr.utf8_text(text.as_bytes()).ok()?;
            Some(format!("{base}.{a}"))
        }
        "subscript" => {
            let v = node.child_by_field_name("value")?;
            dotted_expr(v, ctx)
        }
        _ => None,
    }
}

/// Environment key for an lvalue-ish expression: identifiers and
/// attribute chains; subscripts collapse to base.
fn expr_key(node: Node, ctx: &Ctx, env: &HashMap<String, VarState>) -> Option<String> {
    let text = ctx.f.text.as_str();
    match node.kind() {
        "identifier" => node.utf8_text(text.as_bytes()).ok().map(|s| s.to_string()),
        "attribute" => {
            let obj = node.child_by_field_name("object")?;
            let base = expr_key(obj, ctx, env)?;
            let attr = node.child_by_field_name("attribute")?;
            let a = attr.utf8_text(text.as_bytes()).ok()?;
            Some(format!("{base}.{a}"))
        }
        "subscript" => {
            let v = node.child_by_field_name("value")?;
            let base = expr_key(v, ctx, env)?;
            // Integer literal index on a tracked container -> `base[i]`.
            if let Some(idx) = node.child_by_field_name("subscript") {
                if idx.kind() == "integer" {
                    if let Ok(i) = idx.utf8_text(text.as_bytes()) {
                        if let Ok(n) = i.trim().parse::<i64>() {
                            return Some(format!("{base}[{n}]"));
                        }
                    }
                }
            }
            Some(base)
        }
        _ => None,
    }
}

/// Evaluate an expression to a VarState + optional source label.
fn eval_expr(node: Node, ctx: &mut Ctx, env: &mut HashMap<String, VarState>) -> ExprVal {
    if budget(ctx) {
        return ExprVal::default();
    }
    let text = ctx.f.text.as_str();
    match node.kind() {
        "string" | "integer" | "float" | "true" | "false" | "none" => {
            let mut st = VarState::default();
            if node.kind() == "none" {
                st.is_none = true;
            }
            ExprVal { state: st, source_label: None }
        }
        "identifier" => {
            let name = node.utf8_text(text.as_bytes()).unwrap_or("");
            // Import-bound names used as values: `os` alone is clean.
            ExprVal {
                state: env.get(name).cloned().unwrap_or_default(),
                source_label: None,
            }
        }
        "attribute" | "subscript" => {
            // Check for source shape first: os.environ["X"],
            // sys.argv[1], pathlib.Path("f").read_text().
            if let Some(label) = source_label_of(node, ctx) {
                return ExprVal {
                    state: VarState {
                        taint: Some(label.clone()),
                        is_none: false,
                        resource: None,
                    },
                    source_label: Some(label),
                };
            }
            // Otherwise propagate base object's state.
            let base = if node.kind() == "attribute" {
                node.child_by_field_name("object")
            } else {
                node.child_by_field_name("value")
            };
            let mut st = VarState::default();
            if let Some(b) = base {
                let bv = eval_expr(b, ctx, env);
                st = bv.state;
                if std::env::var("SD_DEBUG").is_ok() {
                    eprintln!("[dbg]   attr/sub {} none={}", node.utf8_text(text.as_bytes()).unwrap_or("?"), st.is_none);
                }
                // Attribute access on possibly-None -> NullDeref.
                if st.is_none {
                    push_finding_at(
                        ctx,
                        SinkKind::NullDeref,
                        "none",
                        "attribute access",
                        node,
                        0.8,
                    );
                    st.is_none = false;
                }
            }
            // env key lookup for previously assigned attr/subscript.
            // `x[i]` falls back to the container state `x` when no
            // per-index entry exists.
            if let Some(key) = expr_key(node, ctx, env) {
                let prev = env.get(&key).or_else(|| {
                    key.split_once('[')
                        .and_then(|(b, _)| env.get(b))
                });
                if std::env::var("SD_DEBUG").is_ok() {
                    eprintln!("[dbg]   key={key} prev_none={:?}", prev.map(|p| p.is_none));
                }
                if let Some(prev) = prev {
                    if prev.taint.is_some() || prev.is_none || prev.resource.is_some() {
                        // merge: stored state wins for taint/resource
                        let mut merged = st.clone();
                        if prev.taint.is_some() {
                            merged.taint = prev.taint.clone();
                        }
                        merged.is_none |= prev.is_none;
                        if prev.resource.is_some() {
                            merged.resource = prev.resource.clone();
                        }
                        st = merged;
                    }
                }
            }
            ExprVal { state: st, source_label: None }
        }
        "call" => eval_call(node, ctx, env),
        "binary_operator" => {
            // + - * etc: join operand states.
            let mut st = VarState::default();
            let mut label = None;
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.is_named() && !matches!(ch.kind(), "operator") {
                    let v = eval_expr(ch, ctx, env);
                    st.join(&v.state);
                    if label.is_none() {
                        label = v.source_label;
                    }
                }
            }
            ExprVal { state: st, source_label: label }
        }
        "comparison_operator" => {
            let mut st = VarState::default();
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.is_named() {
                    let v = eval_expr(ch, ctx, env);
                    st.join(&v.state);
                }
            }
            ExprVal { state: st, source_label: None }
        }
        "boolean_operator" => {
            // `a and b` / `a or b`: the right operand only evaluates
            // under the left's outcome - apply short-circuit narrows
            // while evaluating it, then restore.
            let text2 = ctx.f.text.as_str();
            let mut c = node.walk();
            let kids: Vec<Node> = node.children(&mut c).collect();
            let operands: Vec<Node> =
                kids.iter().copied().filter(|k| k.is_named()).collect();
            let optext = kids
                .iter()
                .filter(|k| !k.is_named())
                .filter_map(|k| k.utf8_text(text2.as_bytes()).ok())
                .collect::<Vec<_>>()
                .join(" ");
            if operands.len() == 2 && matches!(optext.trim(), "and" | "or") {
                let lv = eval_expr(operands[0], ctx, env);
                // Right sees left-true for `and`, left-false for `or`.
                let (lt, lf) = null_checks(operands[0], ctx, env);
                let narrow = if optext.trim() == "and" { lt } else { lf };
                let mut saved: Vec<(String, bool)> = Vec::new();
                for (k, v) in &narrow {
                    if let Some(st) = env.get_mut(k.as_str()) {
                        saved.push((k.clone(), st.is_none));
                        st.is_none = *v;
                    }
                }
                let rv = eval_expr(operands[1], ctx, env);
                for (k, old) in saved {
                    if let Some(st) = env.get_mut(&k) {
                        st.is_none = old;
                    }
                }
                let mut st = lv.state;
                st.join(&rv.state);
                // `A or B`: if A is None it is falsy, so the result is
                // B - nullness comes from the right side only.
                // `A and B`: A being None short-circuits to A, so
                // either side can produce None.
                if optext.trim() == "or" {
                    st.is_none = rv.state.is_none;
                }
                return ExprVal { state: st, source_label: None };
            }
            // Fallback: join all operand states.
            let mut st = VarState::default();
            let mut c2 = node.walk();
            for ch in node.children(&mut c2) {
                if ch.is_named() {
                    let v = eval_expr(ch, ctx, env);
                    st.join(&v.state);
                }
            }
            ExprVal { state: st, source_label: None }
        }
        "conditional_expression" => {
            let mut st = VarState::default();
            let mut label = None;
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.is_named() {
                    let v = eval_expr(ch, ctx, env);
                    st.join(&v.state);
                    if label.is_none() {
                        label = v.source_label;
                    }
                }
            }
            ExprVal { state: st, source_label: label }
        }
        "list" | "tuple" | "set" | "dictionary" | "concatenated_string" => {
            let mut st = VarState::default();
            let mut label = None;
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.is_named() {
                    let v = eval_expr(ch, ctx, env);
                    st.join(&v.state);
                    if label.is_none() {
                        label = v.source_label;
                    }
                }
            }
            // A container is never None itself; element nullness is
            // tracked per-index via `name[i]` env keys instead.
            st.is_none = false;
            ExprVal { state: st, source_label: label }
        }
        "parenthesized_expression" | "await" => {
            let inner = {
                let mut c = node.walk();
                let found = node.children(&mut c).find(|k| k.is_named());
                found
            };
            inner.map(|k| eval_expr(k, ctx, env)).unwrap_or_default()
        }
        "lambda" => ExprVal::default(),
        "yield" => {
            // `yield x` hands x's ownership to the consumer - treat a
            // held resource like a returned one.
            let mut st = VarState::default();
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.is_named() {
                    let v = eval_expr(ch, ctx, env);
                    if v.state.resource.is_some() && ctx.ret.resource.is_none() {
                        ctx.ret.resource = v.state.resource.clone();
                    }
                    st.join(&v.state);
                }
            }
            ExprVal { state: st, source_label: None }
        }
        "named_expression" => {
            // walrus: eval value, assign to target.
            let mut c = node.walk();
            let kids: Vec<Node> = node.children(&mut c).collect();
            let val = kids.last().copied();
            let target = kids.first().copied();
            if let (Some(v), Some(t)) = (val, target) {
                let vv = eval_expr(v, ctx, env);
                assign_target(t, vv.state.clone(), vv.source_label.clone(), ctx, env, node);
                return vv;
            }
            ExprVal::default()
        }
        _ => {
            // Fallback: join named children states (side effects
            // still processed for calls inside).
            let mut st = VarState::default();
            let mut label = None;
            let mut c = node.walk();
            for ch in node.children(&mut c) {
                if ch.is_named() {
                    let v = eval_expr(ch, ctx, env);
                    st.join(&v.state);
                    if label.is_none() {
                        label = v.source_label;
                    }
                }
            }
            ExprVal { state: st, source_label: label }
        }
    }
}

/// Is this expression a model source? Returns provenance label.
fn source_label_of(node: Node, ctx: &Ctx) -> Option<String> {
    let dotted = dotted_expr(node, ctx)?;
    if std::env::var("SD_DEBUG").is_ok() {
        eprintln!("[dbg] source? {} -> kind {:?}", dotted, ctx.model.source_kind(&dotted));
    }
    let kind = ctx.model.source_kind(&dotted)?;
    Some(format!("src:{:?}", kind))
}

/// Process a call: sinks, sources, sanitizers, resolved callees,
/// unknown-call taint propagation.
fn eval_call(node: Node, ctx: &mut Ctx, env: &mut HashMap<String, VarState>) -> ExprVal {
    // Evaluate the callee expression itself: `x.m()` / `x[i]()` on a
    // maybe-None receiver is a NullDeref sink, and attribute state
    // (taint/resource) on the callee object still matters.
    if let Some(func) = node.child_by_field_name("function") {
        if matches!(func.kind(), "attribute" | "subscript") {
            eval_expr(func, ctx, env);
        }
    }
    let Some(dotted) = dotted_callee(node, ctx) else {
        // Unresolvable callee expr (subscript result, etc).
        ctx.touches_unknown = true;
        return ExprVal::default();
    };

    // Collect arg states first (findings inside args still emit).
    let args = call_args(node, ctx, env);

    // Resource args may transfer ownership to the callee.
    if let Some(arglist) = node.child_by_field_name("arguments") {
        let mut ac = arglist.walk();
        let arg_nodes: Vec<Node> = arglist
            .children(&mut ac)
            .filter(|k| k.is_named())
            .collect();
        for an in arg_nodes {
            // unwrap keyword_argument / starred to the value expr
            let val = if an.kind() == "keyword_argument" {
                let mut vc = an.walk();
                an.children(&mut vc)
                    .filter(|k| k.is_named())
                    .last()
            } else {
                Some(an)
            };
            if let Some(v) = val {
                if let Some(key) = expr_key(v, ctx, env) {
                    if env.get(&key).is_some_and(|st| st.resource.is_some()) {
                        ctx.escaped.insert(key);
                    }
                }
            }
        }
    }

    // Explicit resource release: `x.close()`, `x.release()`,
    // `lock.unlock()`, `conn.disconnect()` etc. Marks the env key
    // released so end-of-function leak checks skip it.
    if let Some(func) = node.child_by_field_name("function") {
        if func.kind() == "attribute" {
            let attr_name = func
                .child_by_field_name("attribute")
                .and_then(|a| a.utf8_text(ctx.f.text.as_bytes()).ok())
                .unwrap_or("");
            if matches!(
                attr_name,
                "close" | "release" | "unlock" | "disconnect" | "dispose" | "__exit__"
            ) {
                if let Some(obj) = func.child_by_field_name("object") {
                    if let Some(key) = expr_key(obj, ctx, env) {
                        ctx.released.insert(key.clone());
                        if let Some(st) = env.get_mut(&key) {
                            st.resource = None;
                        }
                    }
                }
            }
        }
    }

    // 1. Sink check by dotted name.
    let mut sink_hit: Vec<(SinkKind, usize)> = Vec::new();
    for rule in ctx.model.sinks_for(&dotted) {
        match rule.arg {
            Some(i) => {
                if i < args.len() {
                    sink_hit.push((rule.class.clone(), i));
                }
            }
            None => {
                for i in 0..args.len() {
                    sink_hit.push((rule.class.clone(), i));
                }
            }
        }
    }
    // Null-deref sinks: method calls on possibly-None receivers are
    // handled at attribute eval; call args checked for taint below.

    // 2. Source check: the call itself may produce tainted data
    //    (e.g. input(), os.getenv via dotted name, requests.get().text
    //    handled by attribute source rules).
    let mut result = ExprVal::default();
    if let Some(kind) = ctx.model.source_kind(&dotted) {
        result.source_label = Some(format!("src:{kind:?}"));
        result.state.taint = result.source_label.clone();
    }

    // 3. Sanitizer: cleans tainted args for sink purposes AND result.
    let is_sanitizer = ctx
        .model
        .sanitizer_names()
        .contains(dotted.rsplit('.').next().unwrap_or(&dotted));

    // 4. Apply sink rules to arg states.
    if !is_sanitizer {
        for (class, idx) in &sink_hit {
            let Some(av) = args.get(*idx) else { continue };
            if let Some(label) = &av.state.taint {
                handle_sink_taint(ctx, class.clone(), label.clone(), &dotted, node);
            }
            // Leak sinks: arg holding unclosed resource passed onward?
            // v1: resource findings emitted at function end instead.
        }
    }

    // 5. Callee resolution + summary application.
    if let Some((cm, cf)) = resolve_callee(node, ctx) {
        let key = (cm.clone(), cf.clone());
        if std::env::var("SD_DEBUG").is_ok() {
            eprintln!("[dbg] {}:{} call -> {:?} summary={}", ctx.f.rel, ctx.qualname, key, ctx.summaries.contains_key(&key));
        }
        if let Some(sum) = ctx.summaries.get(&key) {
            if std::env::var("SD_DEBUG").is_ok() {
                eprintln!("[dbg]   sum {:?} may_none={} ret_taint={:?}", key, sum.may_return_none, sum.returns_tainted);
            }
            apply_summary(node, ctx, env, &args, sum, &format!("{cm}.{cf}"));
        } else {
            // Same-project function not yet summarized (SCC
            // in-progress or module-level): conservative.
            unknown_call_result(&args, &mut result, ctx, &dotted);
        }
    } else {
        // Builtin / external / unresolvable.
        unknown_call_result(&args, &mut result, ctx, &dotted);
        // Builtins that return resources (open) still tracked via
        // resource_kind_of at assignment.
    }

    // Merge summary-produced result state.
    if let Some(pr) = ctx.pending_result.take() {
        if result.state.taint.is_none() {
            result.state.taint = pr.state.taint;
        }
        result.state.is_none |= pr.state.is_none;
        if result.state.resource.is_none() {
            result.state.resource = pr.state.resource;
        }
    }

    // Sanitizer cleans result taint.
    if is_sanitizer {
        result.state.taint = None;
        result.source_label = None;
    }
    result
}

/// Tainted arg reached a sink: concrete finding or param flow.
fn handle_sink_taint(
    ctx: &mut Ctx,
    class: SinkKind,
    label: String,
    sink_name: &str,
    node: Node,
) {
    if let Some(param_part) = label.strip_prefix("param:") {
        if let Ok(idx) = param_part.parse::<usize>() {
            let ps = PendingSink {
                class,
                file: ctx.f.rel.clone(),
                line: line_of(node),
                func: ctx.qualname.to_string(),
                sink: sink_name.to_string(),
                through: vec![format!("{}.{}", ctx.f.module, ctx.qualname)],
            };
            ctx.param_sinks.entry(idx).or_default().push(ps);
            return;
        }
    }
    push_finding_at(ctx, class, &label, sink_name, node, 1.0);
}

fn push_finding_at(
    ctx: &mut Ctx,
    class: SinkKind,
    source: &str,
    sink: &str,
    node: Node,
    conf: f32,
) {
    let key = (
        class.clone(),
        line_of(node),
        source.to_string(),
        sink.to_string(),
    );
    if !ctx.reported.insert(key) {
        return;
    }
    ctx.findings.push(Finding {
        class,
        source: source.to_string(),
        sink: sink.to_string(),
        file: ctx.f.rel.clone(),
        line: line_of(node),
        func: ctx.qualname.to_string(),
        via: vec![format!("{}.{}", ctx.f.module, ctx.qualname)],
        confidence: conf,
    });
}

/// All argument value states of a call, in order.
fn call_args(node: Node, ctx: &mut Ctx, env: &mut HashMap<String, VarState>) -> Vec<ExprVal> {
    let mut out = Vec::new();
    let Some(args) = node.child_by_field_name("arguments") else {
        return out;
    };
    let mut c = args.walk();
    for ch in args.children(&mut c) {
        match ch.kind() {
            "keyword_argument" => {
                if let Some(v) = ch.child_by_field_name("value") {
                    out.push(eval_expr(v, ctx, env));
                }
            }
            "(" | ")" | "," => {}
            _ => out.push(eval_expr(ch, ctx, env)),
        }
    }
    out
}

/// Resolve this call's callee to (module, qualname) using the same
/// rules as the call graph: import bindings, same-module defs,
/// self/cls methods.
fn resolve_callee(node: Node, ctx: &Ctx) -> Option<(String, String)> {
    let func_node = node.child_by_field_name("function")?;
    let text = ctx.f.text.as_str();
    match func_node.kind() {
        "identifier" => {
            let name = func_node.utf8_text(text.as_bytes()).ok()?;
            // from m import f [as g]
            if let Some((mk, Some(member))) = ctx.rbind.get(name) {
                let m = resolve_module_key(mk, &ctx.f.module)?;
                return Some((m, member.clone()));
            }
            // same-module function (non-method for bare names)
            if let Some(infos) = ctx.f.funcs.get(name) {
                if let Some(info) = infos
                    .iter()
                    .rev()
                    .find(|i| !i.is_method && !i.is_stub)
                    .or_else(|| infos.iter().rev().find(|i| !i.is_method))
                {
                    return Some((ctx.f.module.clone(), info.qualname.clone()));
                }
            }
            None
        }
        "attribute" => {
            let attr = func_node.child_by_field_name("attribute")?;
            let fname = attr.utf8_text(text.as_bytes()).ok()?;
            let obj = func_node.child_by_field_name("object")?;
            // self.f() / cls.f() inside a class -> Class.f
            if obj.kind() == "identifier" {
                if let Ok(on) = obj.utf8_text(text.as_bytes()) {
                    if on == "self" || on == "cls" {
                        if let Some(class) = enclosing_class(node, ctx.f) {
                            let qual = format!("{class}.{fname}");
                            if ctx
                                .f
                                .funcs
                                .get(fname)
                                .is_some_and(|v| v.iter().any(|i| i.qualname == qual))
                            {
                                return Some((ctx.f.module.clone(), qual));
                            }
                        }
                        return None;
                    }
                }
            }
            let m = object_module(obj, &ctx.rbind, text)?;
            Some((m, fname.to_string()))
        }
        _ => None,
    }
}

/// Nearest enclosing class name of a node.
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

/// Apply a resolved callee's summary to this call: param flows,
/// return taint, none-ness, unclosed resources, and re-emitted
/// findings for tainted params reaching callee sinks.
fn apply_summary(
    node: Node,
    ctx: &mut Ctx,
    env: &mut HashMap<String, VarState>,
    args: &[ExprVal],
    sum: &Summary,
    callee_label: &str,
) {
    let _ = env;
    let caller_qual = format!("{}.{}", ctx.f.module, ctx.qualname);
    let mut result_taint: Option<String> = None;
    let mut result_none = false;
    let result_resource = sum.returns_unclosed.clone();

    for (i, av) in args.iter().enumerate() {
        if let Some(label) = &av.state.taint {
            if let Some(pending_list) = sum.param_sinks.get(&i) {
                for ps in pending_list {
                    // Param-propagated label: defer upward as a
                    // PendingSink under the caller's param index.
                    if let Some(pi) = label
                        .strip_prefix("param:")
                        .and_then(|r| r.parse::<usize>().ok())
                    {
                        let mut through = vec![caller_qual.clone()];
                        through.extend(ps.through.iter().cloned());
                        ctx.param_sinks.entry(pi).or_default().push(PendingSink {
                            class: ps.class.clone(),
                            file: ps.file.clone(),
                            line: ps.line,
                            func: ps.func.clone(),
                            sink: ps.sink.clone(),
                            through,
                        });
                    } else {
                        // Concrete source: instantiate the finding
                        // with path caller -> ... -> sink func.
                        let mut via = vec![caller_qual.clone()];
                        via.extend(ps.through.iter().cloned());
                        ctx.findings.push(Finding {
                            class: ps.class.clone(),
                            source: label.clone(),
                            sink: ps.sink.clone(),
                            file: ps.file.clone(),
                            line: ps.line,
                            func: ps.func.clone(),
                            via,
                            confidence: 0.9,
                        });
                    }
                }
            }
        }
        if sum.param_to_return.contains(&i) && result_taint.is_none() {
            result_taint = av.state.taint.clone();
        }
    }
    // Callee-level facts apply regardless of arg count.
    if sum.returns_tainted && result_taint.is_none() {
        result_taint = Some(format!("ret:{callee_label}"));
    }
    result_none = sum.may_return_none;

    ctx.pending_result = Some(ExprVal {
        state: VarState {
            taint: result_taint,
            is_none: result_none,
            resource: result_resource,
        },
        source_label: None,
    });
}

fn extend_via(through: &[String], callee: &str, ctx: &Ctx) -> Vec<String> {
    let mut v: Vec<String> = through.to_vec();
    v.push(format!("{}.{}", ctx.f.module, ctx.qualname));
    v.push(callee.to_string());
    v
}

/// Unresolvable/unknown callee: taint propagates arg->result
/// conservatively; flag touches_unknown.
fn unknown_call_result(
    args: &[ExprVal],
    result: &mut ExprVal,
    ctx: &mut Ctx,
    dotted: &str,
) {
    ctx.touches_unknown = true;
    for av in args {
        if av.state.taint.is_some() {
            result.state.taint = Some(format!("call:{dotted}"));
            break;
        }
        // Note: arg None-ness does NOT make the result None.
        if av.state.resource.is_some() && result.state.resource.is_none() {
            result.state.resource = av.state.resource.clone();
        }
    }
}
