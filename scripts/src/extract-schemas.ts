/**
 * Extract all exported Zod schemas from the Akash Console API source
 * and generate the additions needed for console-api-schemas.ts and generate-proto.ts.
 *
 * Run from: ~/abstract/bme/akash-deploy-rs/scripts/
 * Usage: npx tsx /tmp/extract-console-schemas.ts
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const CONSOLE_API_SRC = "/home/returniflost/abstract/bme/console/apps/api/src";
const EXISTING_SCHEMAS_PATH = join(import.meta.dirname ?? ".", "src/console-api-schemas.ts");

// ── 1. Find all schema files ────────────────────────────────────────────────

function walkDir(dir: string, pattern: RegExp): string[] {
  const results: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      results.push(...walkDir(full, pattern));
    } else if (pattern.test(entry) && !entry.includes(".spec.")) {
      results.push(full);
    }
  }
  return results;
}

const schemaFiles = walkDir(CONSOLE_API_SRC, /\.schema\.ts$/);

// ── 2. Extract exported schema names from each file ─────────────────────────

interface SchemaExport {
  name: string;
  file: string;
  relPath: string;
  hasRefine: boolean;
  hasTransform: boolean;
}

const allExports: SchemaExport[] = [];

for (const file of schemaFiles) {
  const content = readFileSync(file, "utf8");
  const relPath = relative(CONSOLE_API_SRC, file);

  // Match: export const FooSchema = z.object(...)
  const exportRegex = /export\s+const\s+(\w+Schema)\s*=/g;
  let match;
  while ((match = exportRegex.exec(content)) !== null) {
    allExports.push({
      name: match[1],
      file,
      relPath,
      hasRefine: content.includes(".refine("),
      hasTransform: content.includes(".transform("),
    });
  }
}

// ── 3. Load existing registry to find what's already there ──────────────────

let existingNames: Set<string>;
try {
  const existing = readFileSync(EXISTING_SCHEMAS_PATH, "utf8");
  const nameRegex = /export\s+const\s+(\w+Schema)\s*=/g;
  existingNames = new Set<string>();
  let m;
  while ((m = nameRegex.exec(existing)) !== null) {
    existingNames.add(m[1]);
  }
} catch {
  existingNames = new Set();
}

// ── 4. Report ───────────────────────────────────────────────────────────────

const missing = allExports.filter(e => !existingNames.has(e.name));
const byDomain = new Map<string, SchemaExport[]>();

for (const exp of missing) {
  const domain = exp.relPath.split("/")[0]; // billing, user, dashboard, etc.
  if (!byDomain.has(domain)) byDomain.set(domain, []);
  byDomain.get(domain)!.push(exp);
}

console.log("=== Console API Schema Gap Report ===\n");
console.log(`Total schema files scanned: ${schemaFiles.length}`);
console.log(`Total exported schemas found: ${allExports.length}`);
console.log(`Already in registry: ${existingNames.size}`);
console.log(`Missing from registry: ${missing.length}\n`);

for (const [domain, exports] of byDomain) {
  console.log(`--- ${domain} (${exports.length} missing) ---`);
  for (const exp of exports) {
    const flags = [];
    if (exp.hasRefine) flags.push("REFINE");
    if (exp.hasTransform) flags.push("TRANSFORM");
    const flagStr = flags.length > 0 ? ` [${flags.join(",")}]` : "";
    console.log(`  ${exp.name}${flagStr}`);
    console.log(`    → ${exp.relPath}`);
  }
  console.log();
}

// ── 5. Output importable paths for each domain ─────────────────────────────

console.log("=== Import paths for generate-proto.ts ===\n");
const filesByDomain = new Map<string, Set<string>>();
for (const exp of missing) {
  const domain = exp.relPath.split("/")[0];
  if (!filesByDomain.has(domain)) filesByDomain.set(domain, new Set());
  filesByDomain.get(domain)!.add(exp.relPath);
}

for (const [domain, files] of filesByDomain) {
  console.log(`// ${domain}`);
  for (const f of files) {
    const names = missing.filter(e => e.relPath === f).map(e => e.name);
    console.log(`// import { ${names.join(", ")} } from "${CONSOLE_API_SRC}/${f}";`);
  }
  console.log();
}
