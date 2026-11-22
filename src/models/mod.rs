//! Declarative source/sink/sanitizer models (TOML), per PLAN.md
//! Tier-1 #4. Bug classes share one engine; models are data.

use std::collections::BTreeMap;

/// How an expression introduces tainted data.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// `os.environ[...]` / `os.getenv(...)` style: subscript or call
    /// on a named root, matched by dotted suffix.
    Env,
    /// `sys.argv`, `sys.stdin`.
    Argv,
    /// `input(...)`, `sys.stdin.read()`.
    Stdin,
    /// `open(...).read()`, `pathlib.Path.read_text()` - file content.
    File,
    /// `requests.get(...).text/json()` and similar - network input.
    Net,
}

/// What makes a call a sink for a given bug class.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Hash)]
pub enum SinkKind {
    /// eval / exec / compile.
    CodeExec,
    /// subprocess.*, os.system, os.popen.
    Shell,
    /// pickle/marshal/yaml.load - deserialization.
    Deser,
    /// cursor.execute / engine.execute - SQL.
    Sql,
    /// html/template rendering with raw value (reserved).
    Render,
    /// Attribute access or call on possibly-None value.
    NullDeref,
    /// Resource acquired but never released on some path.
    Leak,
}

/// A sink rule: call whose dotted name ends with `name`, in arg
/// position `arg` (None = any arg), for bug class `class`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SinkRule {
    /// Dotted suffix match, e.g. "subprocess.call", "eval".
    pub name: String,
    pub class: SinkKind,
    /// 0-based arg index to check for taint; `None` = any argument.
    #[serde(default)]
    pub arg: Option<usize>,
    /// Arg index whose taint matters for null-deref sinks.
    /// Reserved for future sink kinds; unused in v1.
    #[allow(dead_code)]
    #[serde(default)]
    pub deref_arg: Option<usize>,
}

/// A source rule: expression shape producing taint.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SourceRule {
    pub kind: SourceKind,
    /// Dotted name suffixes that count, e.g. ["os.environ", "os.getenv"].
    pub names: Vec<String>,
}

/// Sanitizer: function names that clean their argument for all sinks.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SanitizerRule {
    pub names: Vec<String>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct Model {
    #[serde(default)]
    pub sources: Vec<SourceRule>,
    #[serde(default)]
    pub sinks: Vec<SinkRule>,
    #[serde(default)]
    pub sanitizers: Vec<SanitizerRule>,
    /// Extra propagators: dotted call names that pass taint
    /// arg->return even when the callee is unknown.
    #[serde(default)]
    pub propagators: Vec<String>,
}

impl Model {
    /// All sanitizer names flattened.
    pub fn sanitizer_names(&self) -> HashSet<&str> {
        self.sanitizers
            .iter()
            .flat_map(|s| s.names.iter().map(|n| n.as_str()))
            .collect()
    }

    /// Sink rules matching a dotted call name.
    pub fn sinks_for<'a>(&'a self, dotted: &str) -> Vec<&'a SinkRule> {
        self.sinks
            .iter()
            .filter(|r| dotted == r.name || dotted.ends_with(&format!(".{}", r.name)) || r.name == "*")
            .collect()
    }

    /// Source kind for an expression, if it is a source.
    /// `dotted` = resolved dotted name of the expression's root
    /// (e.g. "os.environ" for `os.environ["X"]`, "sys.argv" for
    /// `sys.argv[1]`).
    pub fn source_kind(&self, dotted: &str) -> Option<SourceKind> {
        for rule in &self.sources {
            if rule.names.iter().any(|n| dotted == *n || dotted.starts_with(&format!("{n}.")) || n == "*") {
                return Some(rule.kind.clone());
            }
        }
        None
    }
}

use std::collections::HashSet;

pub type Models = BTreeMap<String, Model>;

/// Load all `*.toml` model files from a directory; missing dir = empty.
pub fn load_dir(dir: &std::path::Path) -> Result<Models, String> {
    let mut out = Models::new();
    let rd = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return Ok(out),
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        let text = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        let model: Model = toml::from_str(&text).map_err(|e| format!("{}: {e}", p.display()))?;
        let lang = p.file_stem().and_then(|s| s.to_str()).unwrap_or("model").to_string();
        out.insert(lang, model);
    }
    Ok(out)
}

/// Parse the embedded Python default model.
pub fn python_default() -> Result<Model, String> {
    toml::from_str(include_str!("../../models/python.toml"))
        .map_err(|e| format!("embedded python.toml: {e}"))
}
