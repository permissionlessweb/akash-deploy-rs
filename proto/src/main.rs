//! Proto compiler for akash-deploy-rs.
//!
//! Auto-discovers every .proto file under proto/ (excluding vendor/,
//! rust-vendored/, src/, and target/), compiles them with prost/tonic,
//! then regenerates src/gen/mod.rs from the resulting output files.
//!
//! Run via: `just gen-proto`

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::fs;

const SERDE_JSON: &str = "#[derive(serde::Serialize, serde::Deserialize)]";

/// Directories inside proto/ that are skipped during compilation.
/// - vendor / rust-vendored: include paths only, not compiled directly.
/// - console: Zod-generated API schemas, compiled separately via `just console-api-proto`.
/// - src / target: proto compiler's own Rust source and build artifacts.
const EXCLUDE_DIRS: &[&str] = &["vendor", "rust-vendored", "console", "src", "target"];

fn main() -> anyhow::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    println!("proto root: {}", root.display());

    // Output goes to the parent crate's src/gen/
    let target_dir = root.join("..").join("src").join("gen");
    fs::create_dir_all(&target_dir)?;
    let target_dir = target_dir.canonicalize()?;
    println!("target_dir:  {}", target_dir.display());

    // ------------------------------------------------------------------
    // Auto-discover all .proto files to compile.
    // Everything under proto/ is included except the vendor/include dirs.
    // ------------------------------------------------------------------
    let proto_files: Vec<PathBuf> = walkdir::WalkDir::new(&root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let path = e.path();
            path.extension().map_or(false, |ext| ext == "proto")
                && !path.components().any(|c| {
                    EXCLUDE_DIRS.iter().any(|excl| c.as_os_str() == *excl)
                })
        })
        .map(|e| e.path().to_path_buf())
        .collect();

    if proto_files.is_empty() {
        anyhow::bail!("No .proto files found under {}", root.display());
    }
    println!("Compiling {} proto file(s):", proto_files.len());
    for f in &proto_files {
        println!("  {}", f.display());
    }

    // Include paths: proto root first, then any vendor dirs that exist.
    let mut include_paths = vec![root.clone()];
    for vendor in EXCLUDE_DIRS {
        let p = root.join(vendor);
        if p.exists() {
            include_paths.push(p);
        }
    }

    // ------------------------------------------------------------------
    // Compile
    // ------------------------------------------------------------------
    let mut config = prost_build::Config::new();

    config.extern_path(".google.protobuf", "::pbjson_types");
    config.compile_well_known_types();
    config.type_attribute(".", SERDE_JSON);
    config.out_dir(&target_dir).enable_type_names();

    let rpc_doc_attr = r#"#[cfg(feature = "rpc")]"#;

    tonic_prost_build::configure()
        .out_dir(&target_dir)
        .emit_rerun_if_changed(false)
        .server_mod_attribute(".", rpc_doc_attr)
        .client_mod_attribute(".", rpc_doc_attr)
        .compile_with_config(config, &proto_files, &include_paths)?;

    // ------------------------------------------------------------------
    // pbjson Serialize/Deserialize impls (descriptor-set path commented
    // out upstream; kept as-is until descriptor generation is wired in)
    // ------------------------------------------------------------------
    pbjson_build::Builder::new()
        .ignore_unknown_fields()
        .out_dir(&target_dir)
        .build(&["."])?;

    // ------------------------------------------------------------------
    // Post-process: strip conflicting serde / Hash derives from generated files
    // ------------------------------------------------------------------
    let types_to_remove_serde_from_mixed_derives = [
        "QueryCertificatesRequest",
        "QueryCertificatesResponse",
        "QueryDeploymentsResponse",
        "QueryDeploymentsRequest",
        "Params",
        "ResourceUnit",
        "MsgCreateDeployment",
        "MsgDepositDeployment",
        "GroupSpec",
        "Account",
        "FractionalPayment",
        "Order",
        "MsgCreateBid",
        "Bid",
        "Lease",
        "QueryOrdersRequest",
        "QueryOrdersResponse",
        "QueryBidsRequest",
        "QueryBidsResponse",
        "QueryLeasesRequest",
        "QueryLeasesResponse",
    ];

    let types_to_remove_separate_serde_derive = ["SctFrontierResponse"];

    for entry in walkdir::WalkDir::new(&target_dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.path().extension().is_some_and(|ext| ext == "rs") {
            let content = fs::read_to_string(entry.path())?;
            let lines: Vec<&str> = content.lines().collect();
            let mut new_lines: Vec<String> = Vec::new();
            let mut i = 0;

            while i < lines.len() {
                let line = lines[i];

                let mut is_mixed_derive_type = false;
                for type_name in &types_to_remove_serde_from_mixed_derives {
                    if line.contains(&format!("struct {}", type_name))
                        || line.contains(&format!("enum {}", type_name))
                    {
                        is_mixed_derive_type = true;
                        break;
                    }
                }

                let mut is_separate_derive_type = false;
                for type_name in &types_to_remove_separate_serde_derive {
                    if line.contains(&format!("struct {}", type_name))
                        || line.contains(&format!("enum {}", type_name))
                    {
                        is_separate_derive_type = true;
                        break;
                    }
                }

                if is_mixed_derive_type && i > 0 {
                    let prev_line = lines[i - 1];
                    if prev_line.contains("#[derive(") && prev_line.contains("serde::Serialize") {
                        let new_derive = prev_line
                            .replace(", serde::Serialize", "")
                            .replace("serde::Serialize, ", "")
                            .replace(", serde::Deserialize", "")
                            .replace("serde::Deserialize, ", "")
                            .replace("serde::Serialize", "")
                            .replace("serde::Deserialize", "");

                        if new_derive.contains("#[derive()]") || new_derive == "#[derive" {
                            new_lines.pop();
                        } else {
                            new_lines.pop();
                            new_lines.push(new_derive);
                        }
                    }
                }

                if is_separate_derive_type && i > 1 {
                    let prev_line = lines[i - 1];
                    let prev_prev_line = lines[i - 2];

                    if prev_prev_line.contains("#[derive(")
                        && (prev_prev_line.contains("serde::Serialize")
                            || prev_prev_line.contains("serde::Deserialize"))
                        && prev_line.contains("#[derive(")
                        && !prev_line.contains("serde::")
                    {
                        if new_lines.len() >= 2 {
                            let last = new_lines.pop().unwrap();
                            new_lines.pop();
                            new_lines.push(last);
                        }
                    }
                }

                if line.contains("#[derive(") && line.contains("Hash") && i < lines.len() - 1 {
                    let mut j = i + 1;
                    let mut found_struct = false;
                    let mut struct_start = 0;
                    let mut struct_end = 0;

                    while j < lines.len() {
                        let next_line = lines[j];
                        if next_line.contains("struct ") || next_line.contains("enum ") {
                            found_struct = true;
                            struct_start = j;
                            break;
                        }
                        j += 1;
                    }

                    if found_struct {
                        let mut brace_count = 0;
                        let mut k = struct_start;
                        while k < lines.len() {
                            let struct_line = lines[k];
                            if struct_line.contains("{") {
                                brace_count += struct_line.matches("{").count();
                            }
                            if struct_line.contains("}") {
                                brace_count -= struct_line.matches("}").count();
                            }
                            if brace_count == 0 && k > struct_start {
                                struct_end = k;
                                break;
                            }
                            k += 1;
                        }

                        let mut has_problematic_type = false;
                        for l in struct_start..=struct_end {
                            if lines[l].contains("ibc_proto::cosmos::base::v1beta1::Coin")
                                || lines[l].contains("ibc_proto::cosmos::base::v1beta1::DecCoin")
                                || lines[l]
                                    .contains("ibc_proto::ibc::core::commitment::v1::MerkleProof")
                                || lines[l].contains(
                                    "ibc_proto::cosmos::base::query::v1beta1::PageRequest",
                                )
                                || lines[l].contains(
                                    "ibc_proto::cosmos::base::query::v1beta1::PageResponse",
                                )
                            {
                                has_problematic_type = true;
                                break;
                            }
                        }

                        if has_problematic_type && line.contains("Hash") {
                            let new_derive = line
                                .replace(", Hash", "")
                                .replace("Hash, ", "")
                                .replace(" Eq,", "")
                                .replace("Hash", "");

                            new_lines.push(new_derive);
                            i += 1;
                            continue;
                        }
                    }
                }

                new_lines.push(line.to_string());
                i += 1;
            }

            let new_content = new_lines.join("\n");
            if new_content != content {
                fs::write(entry.path(), new_content)?;
            }
        }
    }

    // ------------------------------------------------------------------
    // Auto-generate src/gen/mod.rs from the compiled output files
    // ------------------------------------------------------------------
    generate_mod_rs(&target_dir)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Module tree — converts dotted filenames into nested pub mod blocks.
//
// e.g.  akash.cert.v1.rs  →  pub mod akash { pub mod cert { pub mod v1 {
//                                  include!("akash.cert.v1.rs");
//                             }}}
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ModNode {
    /// If this node is a leaf (or combined leaf+branch), the file to include.
    file: Option<String>,
    children: BTreeMap<String, ModNode>,
}

impl ModNode {
    fn insert(&mut self, parts: &[&str], filename: String) {
        match parts {
            [] => {}
            [only] => {
                self.children
                    .entry((*only).to_string())
                    .or_default()
                    .file = Some(filename);
            }
            [head, rest @ ..] => {
                self.children
                    .entry((*head).to_string())
                    .or_default()
                    .insert(rest, filename);
            }
        }
    }

    fn render(&self, indent: usize) -> String {
        let mut out = String::new();
        let pad = "    ".repeat(indent);
        for (name, node) in &self.children {
            out.push_str(&format!("{}pub mod {} {{\n", pad, name));
            if let Some(file) = &node.file {
                out.push_str(&format!("{}    include!(\"{}\");\n", pad, file));
            }
            out.push_str(&node.render(indent + 1));
            out.push_str(&format!("{}}}\n", pad));
        }
        out
    }
}

/// Regenerate src/gen/mod.rs by scanning the files that were just compiled.
///
/// Any content below the `PRESERVE_SENTINEL` line (or the first `pub mod prelude`
/// block if no sentinel exists yet) is kept verbatim so hand-written re-exports
/// survive regeneration.
fn generate_mod_rs(gen_dir: &Path) -> anyhow::Result<()> {
    const SENTINEL: &str = "// ==== hand-written section — do not remove this line ====";

    let mod_path = gen_dir.join("mod.rs");

    // Preserve anything after the sentinel (or the prelude block).
    let preserved: Option<String> = if mod_path.exists() {
        let existing = fs::read_to_string(&mod_path)?;
        if let Some(pos) = existing.find(SENTINEL) {
            Some(existing[pos..].to_string())
        } else if let Some(pos) = existing.find("pub mod prelude") {
            Some(format!("{SENTINEL}\n{}", &existing[pos..]))
        } else {
            None
        }
    } else {
        None
    };

    // Collect all generated .rs files, sorted, excluding mod.rs itself.
    let mut rs_files: Vec<String> = walkdir::WalkDir::new(gen_dir)
        .max_depth(1)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let path = e.path();
            path.is_file()
                && path.extension().map_or(false, |ext| ext == "rs")
                && path.file_name().map_or(false, |n| n != "mod.rs")
        })
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    rs_files.sort();

    // Partition: single-part stems (no dots) → top-level include.
    //            multi-part stems             → nested pub mod tree.
    let mut top_level: Vec<String> = Vec::new();
    let mut tree = ModNode::default();

    for filename in rs_files {
        let stem = filename.strip_suffix(".rs").unwrap_or(&filename).to_string();
        if !stem.contains('.') {
            top_level.push(filename);
        } else {
            let parts: Vec<&str> = stem.split('.').collect();
            tree.insert(&parts, filename);
        }
    }

    // Build file content.
    let mut content = String::from(
        "//! Generated protobuf types.\n\
         //! Auto-generated by proto-gen — do NOT edit the module hierarchy.\n\
         //! Run `just gen-proto` to regenerate.\n\n\
         #![cfg_attr(test, allow(rustdoc::invalid_rust_codeblocks))]\n\n",
    );

    for f in &top_level {
        content.push_str(&format!("include!(\"{f}\");\n"));
    }
    if !top_level.is_empty() {
        content.push('\n');
    }

    content.push_str(&tree.render(0));

    if let Some(preserved) = preserved {
        content.push('\n');
        content.push_str(&preserved);
    }

    fs::write(&mod_path, &content)?;
    println!("Generated {}", mod_path.display());
    Ok(())
}
