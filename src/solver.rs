//! Bottom-up SCC solver: computes function summaries callees-first,
//! iterates within cycles to a fixpoint, collects findings.
//!
//! Order: Tarjan SCC over the function call graph, components
//! processed in reverse topological order (callees before callers).
//! Single-node acyclic functions analyze once; cyclic SCCs iterate
//! until summaries stabilize (max 5 passes - then widen to current
//! state, findings stay conservative).

use rayon::prelude::*;
use std::collections::{HashMap, HashSet};

use tree_sitter::Node;

use crate::callgraph;
use crate::facts::{analyze_function, Finding, Summary, VarState};
use crate::ipa::PyFile;
use crate::models::{Model, SinkKind};

/// Node id: (module, qualname). "<module>" = top-level code.
pub type NodeId = (String, String);

pub struct SolveStats {
    pub functions: usize,
    pub sccs: usize,
    pub cyclic_sccs: usize,
    pub fixpoint_iters: usize,
    pub findings: usize,
    pub budget_exceeded: usize,
}

pub struct SolveOutput {
    pub summaries: HashMap<NodeId, Summary>,
    pub findings: Vec<Finding>,
    pub stats: SolveStats,
}

/// A function to analyze: where its body node lives.
struct FuncRef {
    file_idx: usize,
    /// Byte range of the function_definition (None = module root).
    range: Option<(usize, usize)>,
    params: Vec<String>,
    qualname: String,
}

/// Collect all analyzable functions: every def + each file's
/// top-level "<module>".
fn collect_funcs(parsed: &[PyFile]) -> HashMap<NodeId, FuncRef> {
    let mut out = HashMap::new();
    for (fi, f) in parsed.iter().enumerate() {
        out.insert(
            (f.module.clone(), "<module>".to_string()),
            FuncRef {
                file_idx: fi,
                range: None,
                params: Vec::new(),
                qualname: "<module>".to_string(),
            },
        );
        // Group by qualname; prefer the last non-stub definition
        // (Python semantics: later def shadows earlier; overload
        // stubs are `...` bodies).
        let mut by_qual: HashMap<String, &crate::ipa::FuncInfo> = HashMap::new();
        for infos in f.funcs.values() {
            for info in infos {
                let e = by_qual.entry(info.qualname.clone()).or_insert(info);
                if info.is_stub {
                    // keep existing unless nothing yet
                    if e.is_stub {
                        *e = info;
                    }
                } else {
                    *e = info; // non-stub always wins; last wins
                }
            }
        }
        for (qual, info) in by_qual {
            out.insert(
                (f.module.clone(), qual.clone()),
                FuncRef {
                    file_idx: fi,
                    range: Some((info.start, info.end)),
                    params: info.params.clone(),
                    qualname: qual,
                },
            );
        }
    }
    out
}

/// Recover the function_definition node for a FuncRef.
fn func_node<'t>(f: &'t PyFile, r: &FuncRef) -> Option<Node<'t>> {
    match r.range {
        None => Some(f.tree.root_node()),
        Some((s, e)) => {
            let n = f.tree.root_node().descendant_for_byte_range(s, e)?;
            if n.kind() == "function_definition" {
                Some(n)
            } else {
                // Range may have landed on a child; walk up.
                let mut cur = n;
                loop {
                    if cur.kind() == "function_definition" {
                        return Some(cur);
                    }
                    cur = cur.parent()?;
                }
            }
        }
    }
}

/// Iterative Tarjan SCC. Returns components in reverse topological
/// order already? No - returns in Tarjan order; we sort by finish.
fn tarjan_scc(nodes: &HashSet<NodeId>, adj: &HashMap<NodeId, Vec<NodeId>>) -> Vec<Vec<NodeId>> {
    // Iterative Tarjan.
    struct Frame {
        node: NodeId,
        child_idx: usize,
    }
    let mut index_of: HashMap<NodeId, usize> = HashMap::new();
    let mut low: HashMap<NodeId, usize> = HashMap::new();
    let mut on_stack: HashSet<NodeId> = HashSet::new();
    let mut stack: Vec<NodeId> = Vec::new();
    let mut sccs: Vec<Vec<NodeId>> = Vec::new();
    let mut next_index = 0usize;

    for start in nodes {
        if index_of.contains_key(start) {
            continue;
        }
        let mut work: Vec<Frame> = vec![Frame {
            node: start.clone(),
            child_idx: 0,
        }];
        index_of.insert(start.clone(), next_index);
        low.insert(start.clone(), next_index);
        next_index += 1;
        stack.push(start.clone());
        on_stack.insert(start.clone());

        while let Some(frame) = work.last_mut() {
            let node = frame.node.clone();
            let children = adj.get(&node).cloned().unwrap_or_default();
            if frame.child_idx < children.len() {
                let child = children[frame.child_idx].clone();
                frame.child_idx += 1;
                if !nodes.contains(&child) {
                    continue;
                }
                if !index_of.contains_key(&child) {
                    index_of.insert(child.clone(), next_index);
                    low.insert(child.clone(), next_index);
                    next_index += 1;
                    stack.push(child.clone());
                    on_stack.insert(child.clone());
                    work.push(Frame {
                        node: child,
                        child_idx: 0,
                    });
                } else if on_stack.contains(&child) {
                    let li = low[&node].min(low[&child]);
                    low.insert(node.clone(), li);
                }
            } else {
                // Done with node: propagate lowlink to parent.
                work.pop();
                if let Some(parent) = work.last() {
                    let pl = low[&parent.node].min(low[&node]);
                    low.insert(parent.node.clone(), pl);
                }
                if low[&node] == index_of[&node] {
                    let mut scc = Vec::new();
                    loop {
                        let w = stack.pop().unwrap();
                        on_stack.remove(&w);
                        scc.push(w.clone());
                        if w == node {
                            break;
                        }
                    }
                    sccs.push(scc);
                }
            }
        }
    }
    sccs
}

/// Topological order of SCCs: Tarjan emits components in reverse
/// topo order already (sinks first) for this formulation - but we
/// verify by sorting on a computed finish order. Safer: build cond
/// graph and Kahn it.
fn order_sccs(
    sccs: Vec<Vec<NodeId>>,
    adj: &HashMap<NodeId, Vec<NodeId>>,
) -> Vec<Vec<NodeId>> {
    // Map node -> scc index.
    let mut comp_of: HashMap<NodeId, usize> = HashMap::new();
    for (i, scc) in sccs.iter().enumerate() {
        for n in scc {
            comp_of.insert(n.clone(), i);
        }
    }
    // Condensation edges: caller comp -> callee comp.
    let mut callees: Vec<HashSet<usize>> = vec![HashSet::new(); sccs.len()];
    let mut callers_count = vec![0usize; sccs.len()];
    for (n, targets) in adj {
        let Some(&a) = comp_of.get(n) else { continue };
        for t in targets {
            if let Some(&b) = comp_of.get(t) {
                if a != b && callees[a].insert(b) {
                    callers_count[b] += 1;
                }
            }
        }
    }
    // We want callees first: process comps with no unresolved
    // callees. callers_count[b] = number of comps b calls? We built
    // callees[a] = comps a calls. Process in order: a comp is ready
    // when all comps it calls are done -> track remaining callee deps.
    let mut remaining: Vec<usize> = callees.iter().map(|s| s.len()).collect();
    let mut done = vec![false; sccs.len()];
    let mut order = Vec::new();
    // Simple O(n^2) ready scan - comp counts are modest.
    loop {
        let mut progressed = false;
        for i in 0..sccs.len() {
            if !done[i] && remaining[i] == 0 {
                done[i] = true;
                order.push(i);
                progressed = true;
                // i is done; decrement remaining for comps that call i
                for (a, callee_set) in callees.iter().enumerate() {
                    if !done[a] && callee_set.contains(&i) {
                        remaining[a] -= 1;
                    }
                }
            }
        }
        if !progressed {
            // Cycle in condensation (shouldn't happen post-SCC) or
            // remaining>0 comps - append leftovers.
            for i in 0..sccs.len() {
                if !done[i] {
                    order.push(i);
                }
            }
            break;
        }
        if order.len() == sccs.len() {
            break;
        }
    }
    order.into_iter().map(|i| sccs[i].clone()).collect()
}

/// Run the full analysis.
pub fn solve(parsed: &[PyFile], model: &Model) -> SolveOutput {
    let funcs = collect_funcs(parsed);
    let node_set: HashSet<NodeId> = funcs.keys().cloned().collect();

    // Call graph edges -> adjacency restricted to known functions.
    let cg = callgraph::build(parsed);
    let mut adj: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
    for ((cm, cf), (tm, tf)) in &cg.edges {
        let from = (cm.clone(), cf.clone());
        let to = (tm.clone(), tf.clone());
        if node_set.contains(&from) && node_set.contains(&to) {
            adj.entry(from).or_default().push(to);
        }
    }

    let sccs = tarjan_scc(&node_set, &adj);
    let ordered = order_sccs(sccs, &adj);

    // Phase 0: module-level environments. Python functions read their
    // module's globals, so each file's `<module>` body is analyzed once
    // up front (empty summaries - calls degrade to unknown_call_result)
    // and the resulting env seeds every function in that file.
    let empty_sums: HashMap<NodeId, Summary> = HashMap::new();
    let module_envs: Vec<(usize, HashMap<String, VarState>)> = funcs
        .values()
        .filter(|r| r.qualname == "<module>")
        .collect::<Vec<_>>()
        .par_iter()
        .filter_map(|r| {
            let f = &parsed[r.file_idx];
            let analysis = analyze_function(
                f,
                f.tree.root_node(),
                &[],
                "<module>",
                model,
                &empty_sums,
                None,
            );
            Some((r.file_idx, analysis.env))
        })
        .collect();
    let file_globals: HashMap<usize, HashMap<String, VarState>> =
        module_envs.into_iter().collect();

    let mut summaries: HashMap<NodeId, Summary> = HashMap::new();
    let mut findings_dedup: HashMap<(SinkKindKey, String, u32, String, String), Finding> =
        HashMap::new();
    let mut stats = SolveStats {
        functions: funcs.len(),
        sccs: ordered.len(),
        cyclic_sccs: 0,
        fixpoint_iters: 0,
        findings: 0,
        budget_exceeded: 0,
    };

    for scc in &ordered {
        let cyclic = scc.len() > 1
            || scc.iter().any(|n| {
                adj.get(n).is_some_and(|v| v.contains(n))
            });
        if cyclic {
            stats.cyclic_sccs += 1;
        }
        let max_iters = if cyclic { 5 } else { 1 };
        let mut prev: HashMap<NodeId, Summary> = HashMap::new();
        for iter in 0..max_iters {
            let mut changed = false;
            for node in scc {
                let Some(fref) = funcs.get(node) else { continue };
                let f = &parsed[fref.file_idx];
                let Some(fnode) = func_node(f, fref) else { continue };
                let globals = if fref.qualname == "<module>" {
                    None
                } else {
                    file_globals.get(&fref.file_idx)
                };
                let analysis = analyze_function(
                    f,
                    fnode,
                    &fref.params,
                    &fref.qualname,
                    model,
                    &summaries,
                    globals,
                );
                if analysis.budget_hit {
                    stats.budget_exceeded += 1;
                }
                // Collect findings every pass (dedup later).
                for finding in &analysis.summary.findings {
                    let key = (
                        SinkKindKey(finding.class.clone()),
                        finding.file.clone(),
                        finding.line,
                        finding.sink.clone(),
                        finding.source.clone(),
                    );
                    findings_dedup.entry(key).or_insert_with(|| finding.clone());
                }
                let sum = analysis.summary;
                let old = summaries.get(node);
                if old.is_none_or(|o| !o.flows_equal(&sum)) {
                    changed = true;
                }
                summaries.insert(node.clone(), sum);
                prev.insert(node.clone(), Summary::default());
            }
            stats.fixpoint_iters += 1;
            if !changed || iter + 1 == max_iters {
                break;
            }
        }
        let _ = prev;
    }

    let mut findings: Vec<Finding> = findings_dedup.into_values().collect();
    findings.sort_by(|a, b| {
        (&a.file, a.line, format!("{:?}", a.class), &a.sink)
            .cmp(&(&b.file, b.line, format!("{:?}", b.class), &b.sink))
    });
    stats.findings = findings.len();

    SolveOutput {
        summaries,
        findings,
        stats,
    }
}

/// Wrapper for Ord on SinkKind in the dedup key.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Debug)]
struct SinkKindKey(SinkKind);

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn run(files: &[(&str, &str)]) -> SolveOutput {
        let map: BTreeMap<String, String> = files
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let parsed = crate::ipa::parse_all(&map);
        let model = crate::models::python_default().unwrap();
        solve(&parsed, &model)
    }

    #[test]
    fn taint_env_to_subprocess_cross_function() {
        let out = run(&[(
            "app.py",
            r#"
import os, subprocess

def run(name):
    subprocess.call(name)

def main():
    name = os.environ["X"]
    run(name)
"#,
        )]);
        assert!(
            out.findings.iter().any(|f| f.class == SinkKind::Shell
                && f.source.contains("Env")
                && f.via.len() >= 2),
            "expected interprocedural shell finding, got {:?}",
            out.findings
        );
    }

    #[test]
    fn taint_argv_to_eval() {
        let out = run(&[(
            "app.py",
            "import sys\ndef main():\n    eval(sys.argv[1])\n",
        )]);
        assert!(out.findings.iter().any(|f| f.class == SinkKind::CodeExec));
    }

    #[test]
    fn null_guard_no_finding_unguarded_finding() {
        let guarded = run(&[(
            "t.py",
            "def maybe():\n    return None\n\ndef f():\n    x = maybe()\n    if x is None:\n        return\n    x.bit_length()\n",
        )]);
        assert!(
            !guarded.findings.iter().any(|f| f.class == SinkKind::NullDeref),
            "guarded deref should not flag: {:?}",
            guarded.findings
        );
        let unguarded = run(&[(
            "t.py",
            "def maybe():\n    return None\n\ndef f():\n    x = maybe()\n    x.bit_length()\n",
        )]);
        assert!(unguarded.findings.iter().any(|f| f.class == SinkKind::NullDeref));
    }

    #[test]
    fn null_isinstance_and_assert_narrowing() {
        let out = run(&[(
            "t.py",
            r#"
def get():
    return None

def f():
    x = get()
    assert x is not None
    x.bit_length()

def g():
    y = get()
    if isinstance(y, int):
        y.bit_length()
"#,
        )]);
        assert!(
            !out.findings.iter().any(|f| f.class == SinkKind::NullDeref),
            "assert/isinstance narrowing should suppress: {:?}",
            out.findings
        );
    }

    #[test]
    fn tuple_index_nullness() {
        let out = run(&[(
            "t.py",
            r#"
T = (None, {"a": 1})

def f():
    y = T[1]
    y.keys()
    z = T[0]
    z.bit_length()
"#,
        )]);
        let nd: Vec<_> = out
            .findings
            .iter()
            .filter(|f| f.class == SinkKind::NullDeref)
            .collect();
        assert_eq!(nd.len(), 1, "only T[0] should flag: {:?}", out.findings);
        assert_eq!(nd[0].line, 8);
    }

    #[test]
    fn leak_open_close_and_yield() {
        let out = run(&[(
            "t.py",
            r#"
def leaker():
    f = open("x")

def closer():
    f = open("x")
    f.close()

def gen():
    f = open("x")
    yield f
"#,
        )]);
        let leaks: Vec<_> = out
            .findings
            .iter()
            .filter(|f| f.class == SinkKind::Leak)
            .collect();
        assert_eq!(leaks.len(), 1, "only leaker should flag: {:?}", out.findings);
        assert!(leaks[0].func.contains("leaker"));
    }

    #[test]
    fn recursive_scc_converges() {
        // Mutual recursion with taint flowing through params.
        let out = run(&[(
            "t.py",
            r#"
import os, subprocess

def a(x):
    if x:
        return b(x)
    subprocess.call(x)

def b(x):
    return a(x)

def main():
    a(os.environ["X"])
"#,
        )]);
        assert!(
            out.findings.iter().any(|f| f.class == SinkKind::Shell),
            "taint should propagate through recursive cycle: {:?}",
            out.findings
        );
        assert!(out.stats.cyclic_sccs >= 1, "expected a cyclic SCC");
    }

    #[test]
    fn sanitizer_stops_taint() {
        let out = run(&[(
            "t.py",
            "import sys\ndef main():\n    x = int(sys.argv[1])\n    eval(x)\n",
        )]);
        assert!(
            !out.findings.iter().any(|f| f.class == SinkKind::CodeExec),
            "int() sanitizer should stop argv taint: {:?}",
            out.findings
        );
    }

    #[test]
    fn module_globals_visible_in_functions() {
        let out = run(&[(
            "t.py",
            "X = None\n\ndef f():\n    X.bit_length()\n",
        )]);
        assert!(out.findings.iter().any(|f| f.class == SinkKind::NullDeref));
    }
}
