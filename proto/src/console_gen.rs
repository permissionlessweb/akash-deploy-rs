//! Proto compiler for Akash Console API schemas.
//!
//! Compiles proto/console/*.proto into Rust types with tonic gRPC clients.
//! Run via: `just gen-console`

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::fs;

const SERDE_JSON: &str = "#[derive(serde::Serialize, serde::Deserialize)]";

fn main() -> anyhow::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let console_dir = root.join("console");

    if !console_dir.exists() {
        anyhow::bail!("proto/console/ not found. Run `just console-api-proto` first.");
    }

    // Output alongside the other gen files
    let target_dir = root.join("..").join("src").join("gen");
    fs::create_dir_all(&target_dir)?;
    let target_dir = target_dir.canonicalize()?;

    // Find all console proto files
    let proto_files: Vec<PathBuf> = walkdir::WalkDir::new(&console_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "proto"))
        .map(|e| e.path().to_path_buf())
        .collect();

    if proto_files.is_empty() {
        anyhow::bail!("No .proto files found in {}", console_dir.display());
    }

    println!("Compiling {} console proto file(s):", proto_files.len());
    for f in &proto_files {
        println!("  {}", f.display());
    }

    // Include path is the proto root (parent of console/)
    let include_paths = vec![root.clone()];

    let mut config = prost_build::Config::new();
    config.type_attribute(".", SERDE_JSON);
    config.out_dir(&target_dir).enable_type_names();

    let rpc_doc_attr = r#"#[cfg(feature = "rpc")]"#;

    tonic_prost_build::configure()
        .out_dir(&target_dir)
        .emit_rerun_if_changed(false)
        .server_mod_attribute(".", rpc_doc_attr)
        .client_mod_attribute(".", rpc_doc_attr)
        .compile_with_config(config, &proto_files, &include_paths)?;

    println!("Console proto compilation complete.");

    // Now update mod.rs to include the console modules
    update_mod_rs(&target_dir)?;

    Ok(())
}

/// Append console module entries to the existing mod.rs if not already present.
fn update_mod_rs(gen_dir: &Path) -> anyhow::Result<()> {
    let mod_path = gen_dir.join("mod.rs");
    let existing = fs::read_to_string(&mod_path)?;

    // Check if console modules already exist
    if existing.contains("pub mod console") {
        println!("Console modules already in mod.rs, updating...");
        // Remove old console block and re-add
        let lines: Vec<&str> = existing.lines().collect();
        let mut new_lines = Vec::new();
        let mut skip = false;
        for line in &lines {
            if line.contains("pub mod console {") {
                skip = true;
                continue;
            }
            if skip {
                // Count braces to find end of console block
                if line.trim() == "}" {
                    skip = false;
                    continue;
                }
                continue;
            }
            // Skip the comment line too
            if line.contains("// ── Console API") {
                continue;
            }
            new_lines.push(*line);
        }
        let content = new_lines.join("\n");
        fs::write(&mod_path, &content)?;
    }

    // Find all console.*.rs files
    let mut console_files: Vec<String> = walkdir::WalkDir::new(gen_dir)
        .max_depth(1)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .file_name()
                .map_or(false, |n| {
                    let s = n.to_string_lossy();
                    s.starts_with("console.") && s.ends_with(".rs")
                })
        })
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    console_files.sort();

    if console_files.is_empty() {
        println!("Warning: no console.*.rs files found");
        return Ok(());
    }

    println!("Found {} console module files:", console_files.len());
    for f in &console_files {
        println!("  {}", f);
    }

    // Build console module tree
    let mut content = fs::read_to_string(&mod_path)?;
    content.push_str("\n// ── Console API (auto-generated from Zod schemas) ──\n");
    content.push_str("pub mod console {\n");
    for filename in &console_files {
        let stem = filename.strip_suffix(".rs").unwrap();
        // console.deployment.rs -> deployment
        let module_name = stem.strip_prefix("console.").unwrap();
        content.push_str(&format!("    pub mod {} {{\n", module_name));
        content.push_str(&format!("        include!(\"{}\");\n", filename));
        content.push_str("    }\n");
    }
    content.push_str("}\n");

    fs::write(&mod_path, &content)?;
    println!("Updated {}", mod_path.display());

    Ok(())
}
