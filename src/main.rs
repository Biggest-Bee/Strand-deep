//! strand-deep: demand-driven interprocedural analysis for Python
//! dynamic imports. Scaffolds on strand-import's static scan, then
//! resolves `import_module(param)`-style sites by propagating literal
//! call-site arguments across function and module boundaries.

mod callgraph;
mod facts;
mod ipa;
mod models;
mod solver;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use clap::Parser;
use strand_core::GraphBuilder;
use strand_import::scan::{scan_project, Lang};

#[derive(Parser)]
#[command(name = "strand-deep", version, about = "Interprocedural dynamic-import analysis")]
struct Cli {
    /// Project root to scan.
    #[arg(default_value = ".")]
    root: PathBuf,

    /// Output .strand graph (default: stdout JSON summary).
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Only run IPA; skip writing the graph.
    #[arg(long)]
    ipa_only: bool,

    /// Dump resolved call edges as `module.func -> module.func`.
    #[arg(long)]
    dump_callgraph: bool,

    /// Run taint/null/leak analysis and print findings.
    #[arg(long)]
    analyze: bool,

    /// Model directory (default: embedded python.toml).
    #[arg(long)]
    models: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let root = cli.root.canonicalize()?;

    // Phase 0: Strand's static scan - nodes, static edges, warnings.
    let scan = scan_project(
        &root,
        &[Lang::Python, Lang::Js, Lang::Rust],
    )?;
    eprintln!(
        "scan: {} nodes, {} edges, {} warnings",
        scan.nodes.len(),
        scan.edges.len(),
        scan.warnings.len()
    );
    for w in &scan.warnings {
        eprintln!("  warn: {w}");
    }

    // Collect .py file texts.
    let mut files: BTreeMap<String, String> = BTreeMap::new();
    for node in &scan.nodes {
        if node.ends_with(".py") {
            let p = root.join(node);
            if let Ok(text) = std::fs::read_to_string(&p) {
                files.insert(node.clone(), text);
            }
        }
    }

    // Parse once; both IPA and the call graph share the trees.
    let t0 = std::time::Instant::now();
    let parsed = ipa::parse_all(&files);
    let file_set: std::collections::BTreeSet<String> =
        files.keys().cloned().collect();

    // Call graph + resolution stats (spike #1 instrumentation).
    let cg = callgraph::build(&parsed);
    eprintln!(
        "callgraph: {} edges, {} calls - {:.1}% resolved          (import {} local {} method {}; unknown: name {} object {} method {} complex {}; builtin {})",
        cg.edges.len(),
        cg.stats.total,
        cg.stats.resolution_rate() * 100.0,
        cg.stats.resolved_import,
        cg.stats.resolved_local,
        cg.stats.resolved_method,
        cg.stats.unknown_name,
        cg.stats.unknown_object,
        cg.stats.unknown_method,
        cg.stats.complex_callee,
        cg.stats.builtin,
    );
    if cli.dump_callgraph {
        for ((cm, cf), (tm, tf)) in &cg.edges {
            println!("{cm}.{cf} -> {tm}.{tf}");
        }
    }

    // Bug-class analysis (taint/null/leak) via summary solver.
    if cli.analyze {
        let model = match &cli.models {
            Some(dir) => {
                let models = models::load_dir(dir)?;
                models.get("python").cloned().unwrap_or_else(|| {
                    models::python_default().expect("embedded model")
                })
            }
            None => models::python_default().expect("embedded model"),
        };
        let t1 = std::time::Instant::now();
        let sol = solver::solve(&parsed, &model);
        eprintln!(
            "solve: {} functions, {} SCCs ({} cyclic), {} fixpoint iters, {} findings ({:?})",
            sol.stats.functions,
            sol.stats.sccs,
            sol.stats.cyclic_sccs,
            sol.stats.fixpoint_iters,
            sol.stats.findings,
            t1.elapsed()
        );
        // Blind-spot report: what the analysis could NOT see.
        let unknown_funcs = sol
            .summaries
            .values()
            .filter(|s| s.touches_unknown)
            .count();
        eprintln!(
            "blind spots: {} functions touched unresolvable calls;              {} param-flow sinks pending instantiation",
            unknown_funcs,
            sol.summaries
                .values()
                .map(|s| s.param_sinks.values().map(|v| v.len()).sum::<usize>())
                .sum::<usize>()
        );
        for f in &sol.findings {
            println!(
                "[{:?}] {}:{} {} - {} (via {}) [{:.0}%]",
                f.class,
                f.file,
                f.line,
                f.sink,
                f.source,
                f.via.join(" -> "),
                f.confidence * 100.0
            );
        }
    }

    // Phase 1: interprocedural resolution.
    let out = ipa::analyze_parsed(&parsed, &file_set);
    eprintln!(
        "ipa: {} edges inferred, {} sites resolved, {} unresolved ({:?})",
        out.edges.len(),
        out.resolved,
        out.unresolved.len(),
        t0.elapsed()
    );
    for u in out.unresolved.iter().take(20) {
        eprintln!("  unresolved: {u}");
    }

    if cli.ipa_only {
        for (s, d, k) in &out.edges {
            println!("{s} -> {d} [{k:?}]");
        }
        return Ok(());
    }

    // Phase 2: emit merged .strand.
    let mut builder = GraphBuilder::new();
    for n in &scan.nodes {
        builder.add_node(n);
    }
    for (s, d, w, k) in &scan.edges {
        builder.add_edge_weighted_kind(s, d, w.unwrap_or(1.0), *k);
    }
    for (s, d, k) in &out.edges {
        builder.add_edge_weighted_kind(s, d, 1.0, *k);
    }
    let dest = cli
        .output
        .unwrap_or_else(|| Path::new("strand-deep.strand").to_path_buf());
    let stats = builder.build(&dest)?;
    eprintln!(
        "wrote {} ({} nodes, {} edges)",
        dest.display(),
        stats.n_nodes,
        stats.n_edges
    );
    Ok(())
}
