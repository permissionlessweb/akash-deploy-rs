#!/usr/bin/env bash
# prost-to-pyo3.sh — Parse prost-generated .rs files and emit:
#   1. proto/src/py_gen.rs   — Rust encode/decode registry (match on type_url)
#   2. proto/python/akash_deploy/<module>.py — Python dataclasses per proto package
#
# Usage: ./scripts/gen/prost-to-pyo3.sh [--modules terp,osmosis,ibc,cosmos] [--out-dir proto/python/akash_deploy]
#
# Prost field patterns handled:
#   string                → str         (default: "")
#   bool                  → bool        (default: False)
#   uint64/int64/sint64   → str         (bigint-as-string, Cosmos convention)
#   uint32/int32/sint32   → int         (default: 0)
#   float/double          → float       (default: 0.0)
#   bytes = "vec"         → str         (base64, default: "")
#   message, optional     → Optional[T] (default: None)
#   message, repeated     → List[T]     (default_factory=list)
#   string, repeated      → List[str]   (default_factory=list)
#   enumeration(...)      → int         (default: 0)
set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GEN_DIR="$ROOT/src/gen"
PY_OUT_DIR="${PY_OUT_DIR:-$ROOT/python/akash_deploy}"
RS_OUT="$ROOT/src/py_gen.rs"
MODULES="${MODULES:-console,akash}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --modules)  MODULES="$2"; shift 2 ;;
    --out-dir)  PY_OUT_DIR="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 [--modules terp,osmosis,ibc,cosmos] [--out-dir proto/python/akash_deploy]"
      exit 0 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

mkdir -p "$PY_OUT_DIR"

# ── Prost type → Python type mapping ─────────────────────────────────

prost_to_py_type() {
  local ptype="$1"
  case "$ptype" in
    string)                  echo "str" ;;
    bool)                    echo "bool" ;;
    uint64|int64|sint64|fixed64|sfixed64)
                             echo "str" ;;   # Cosmos: bigints as string
    uint32|int32|sint32|fixed32|sfixed32)
                             echo "int" ;;
    float|double)            echo "float" ;;
    'bytes = "vec"')         echo "str" ;;   # base64
    *)                       echo "Any" ;;
  esac
}

prost_to_py_default() {
  local ptype="$1"
  case "$ptype" in
    string)                  echo '""' ;;
    bool)                    echo "False" ;;
    uint64|int64|sint64|fixed64|sfixed64)
                             echo '"0"' ;;
    uint32|int32|sint32|fixed32|sfixed32)
                             echo "0" ;;
    float|double)            echo "0.0" ;;
    'bytes = "vec"')         echo '""' ;;
    *)                       echo "None" ;;
  esac
}

# ── Derive Rust module path from filename ─────────────────────────────
# terp.clock.v1 → crate::terp::clock::v1
filename_to_rust_path() {
  local basename="$1"
  # cosmos_proto is a special case (underscore, not dot)
  if [[ "$basename" == "cosmos_proto" ]]; then
    echo "crate::gen::cosmos_proto"
    return
  fi
  echo "crate::gen::$(echo "$basename" | sed 's/\./::/'g)"
}

# terp.clock.v1 → terp_clock_v1  (Python module name)
filename_to_py_module() {
  local basename="$1"
  echo "${basename//./_}"
}

# ── Extract struct+package info from a .rs file ───────────────────────
# Outputs lines: PACKAGE|TYPE_URL|STRUCT_NAME
extract_types() {
  local rs_file="$1"
  local current_struct=""
  local in_name_impl=0

  while IFS= read -r line; do
    # Detect struct definition
    if [[ "$line" =~ ^pub[[:space:]]+struct[[:space:]]+([A-Za-z0-9_]+) ]]; then
      current_struct="${BASH_REMATCH[1]}"
    fi

    # Detect impl ::prost::Name for StructName
    if [[ "$line" =~ ^impl[[:space:]].*prost::Name[[:space:]]+for[[:space:]]+([A-Za-z0-9_]+) ]]; then
      current_struct="${BASH_REMATCH[1]}"
      in_name_impl=1
    fi

    if [[ $in_name_impl -eq 1 ]]; then
      if [[ "$line" =~ const[[:space:]]NAME.*\"([^\"]+)\" ]]; then
        local name="${BASH_REMATCH[1]}"
        # Hold until we get PACKAGE
        local held_name="$name"
      fi
      if [[ "$line" =~ const[[:space:]]PACKAGE.*\"([^\"]+)\" ]]; then
        local pkg="${BASH_REMATCH[1]}"
        local type_url="/${pkg}.${held_name}"
        echo "${pkg}|${type_url}|${current_struct}"
      fi
      if [[ "$line" =~ ^\} ]]; then
        in_name_impl=0
      fi
    fi
  done < "$rs_file"
}

# ── Parse a .rs file → Python dataclass file ─────────────────────────

parse_file_py() {
  local rs_file="$1"
  local basename
  basename="$(basename "$rs_file" .rs)"
  local py_module
  py_module="$(filename_to_py_module "$basename")"
  local py_file="$PY_OUT_DIR/${py_module}.py"

  local package
  package=$(grep -m1 'const PACKAGE' "$rs_file" | sed 's/.*"\(.*\)".*/\1/' || echo "$basename")

  local all_structs
  all_structs=$(grep -E '^pub struct [A-Z]\w*' "$rs_file" | sed 's/pub struct \([A-Za-z0-9_]*\).*/\1/')

  {
    echo "# Auto-generated from $basename — do not edit."
    echo "# Source: terp-rs/proto/src/gen/$basename.rs"
    echo "# Package: $package"
    echo "# Run \`just py-gen\` to regenerate."
    echo "from __future__ import annotations"
    echo ""
    echo "import json"
    echo "from dataclasses import dataclass, field, asdict"
    echo "from typing import Any, List, Optional"
    echo ""
    echo "PACKAGE = \"$package\""
    echo ""

    # State machine
    local current_struct=""
    local in_struct=0
    local fields_py=""  # accumulated field lines
    local struct_doc=""
    local current_doc=""
    local type_url=""

    # We need the type_url per struct — pre-extract them
    declare -A struct_type_urls
    while IFS='|' read -r pkg turl sname; do
      struct_type_urls["$sname"]="$turl"
    done < <(extract_types "$rs_file")

    while IFS= read -r line; do
      # Accumulate doc comments
      if [[ "$line" =~ ^[[:space:]]*///[[:space:]]*(.*) ]]; then
        local doc="${BASH_REMATCH[1]}"
        if [[ -n "$current_doc" ]]; then
          current_doc="$current_doc $doc"
        else
          current_doc="$doc"
        fi
        continue
      fi

      # Struct start
      if [[ "$line" =~ ^pub[[:space:]]+struct[[:space:]]+([A-Za-z0-9_]+)[[:space:]]* ]]; then
        current_struct="${BASH_REMATCH[1]}"
        struct_doc="$current_doc"
        current_doc=""
        fields_py=""
        type_url="${struct_type_urls[$current_struct]:-}"
        in_struct=1

        # Empty struct
        if [[ "$line" =~ \{\} ]]; then
          echo "@dataclass"
          echo "class ${current_struct}:"
          if [[ -n "$struct_doc" ]]; then
            echo "    \"\"\"${struct_doc}\"\"\""
          fi
          if [[ -n "$type_url" ]]; then
            echo "    TYPE_URL: str = field(default=\"${type_url}\", init=False, repr=False)"
          fi
          emit_methods "$current_struct" "$type_url"
          echo ""
          in_struct=0
          current_struct=""
          struct_doc=""
          type_url=""
        fi
        continue
      fi

      if [[ $in_struct -eq 1 ]]; then
        # End of struct
        if [[ "$line" =~ ^\} ]]; then
          echo "@dataclass"
          echo "class ${current_struct}:"
          if [[ -n "$struct_doc" ]]; then
            echo "    \"\"\"${struct_doc}\"\"\""
          fi
          # Emit fields (or pass if none)
          if [[ -n "$fields_py" ]]; then
            echo -e "$fields_py"
          fi
          if [[ -n "$type_url" ]]; then
            echo "    TYPE_URL: str = field(default=\"${type_url}\", init=False, repr=False)"
          fi
          emit_methods "$current_struct" "$type_url"
          echo ""
          in_struct=0
          current_struct=""
          struct_doc=""
          fields_py=""
          type_url=""
          continue
        fi

        # Field doc
        if [[ "$line" =~ ^[[:space:]]*///[[:space:]]*(.*) ]]; then
          current_doc="${BASH_REMATCH[1]}"
          continue
        fi

        # Parse prost attribute + field
        local prost_re='#\[prost\(([^)]+)\)\]'
        if [[ "$line" =~ $prost_re ]]; then
          local prost_attr="${BASH_REMATCH[1]}"
          IFS= read -r field_line
          if [[ "$field_line" =~ pub[[:space:]]+([a-z_][a-z0-9_]*): ]]; then
            local fname="${BASH_REMATCH[1]}"
            local py_type=""
            local py_default=""
            local is_optional=0
            local is_repeated=0
            local is_message=0
            local is_enum=0

            if [[ "$prost_attr" == *"optional"* ]]; then is_optional=1; fi
            if [[ "$prost_attr" == *"repeated"* ]]; then is_repeated=1; fi
            if [[ "$prost_attr" == *"message"* ]]; then is_message=1; fi
            if [[ "$prost_attr" == *"enumeration"* ]]; then is_enum=1; fi

            if [[ $is_enum -eq 1 ]]; then
              py_type="int"
              py_default="0"
            elif [[ $is_message -eq 1 ]]; then
              local ref_type=""
              if [[ "$field_line" =~ Option\<([A-Za-z0-9_:]+)\> ]]; then
                ref_type="${BASH_REMATCH[1]##*::}"
              elif [[ "$field_line" =~ Vec\<[[:space:]]*([A-Za-z0-9_:]+) ]]; then
                ref_type="${BASH_REMATCH[1]##*::}"
              fi
              if [[ -z "$ref_type" ]]; then ref_type="Any"; fi
              # Check if local or cross-module
              if echo "$all_structs" | grep -qx "$ref_type" 2>/dev/null; then
                py_type="$ref_type"
              else
                py_type="Any  # ${ref_type}"
              fi
              if [[ $is_repeated -eq 1 ]]; then
                py_type="List[${ref_type}]"
                py_default="field(default_factory=list)"
              else
                py_type="Optional[${py_type}]"
                py_default="None"
              fi
            else
              local prost_type
              if [[ "$prost_attr" == *'bytes = "vec"'* ]]; then
                prost_type='bytes = "vec"'
              else
                prost_type=$(echo "$prost_attr" | sed 's/,.*//' | tr -d ' ')
              fi
              py_type="$(prost_to_py_type "$prost_type")"
              if [[ $is_repeated -eq 1 ]]; then
                py_type="List[${py_type}]"
                py_default="field(default_factory=list)"
              else
                py_default="$(prost_to_py_default "$prost_type")"
              fi
            fi

            local field_entry="    ${fname}: ${py_type} = ${py_default}"
            if [[ -n "$current_doc" ]]; then
              field_entry="    # ${current_doc}\n${field_entry}"
            fi
            if [[ -n "$fields_py" ]]; then
              fields_py="${fields_py}\n${field_entry}"
            else
              fields_py="${field_entry}"
            fi
            current_doc=""
          fi
        fi
      fi

      if [[ ! "$line" =~ ^[[:space:]]*(///|#\[|pub[[:space:]]) ]]; then
        current_doc=""
      fi
    done < "$rs_file"

  } > "$py_file"

  echo "  $(printf '%-44s' "$basename") → ${py_module}.py"
}

# Emit encode/decode/to_dict/to_json methods for a dataclass
emit_methods() {
  local struct_name="$1"
  local type_url="$2"

  if [[ -z "$type_url" ]]; then
    return
  fi

  echo ""
  echo "    def encode(self) -> bytes:"
  echo "        \"\"\"Encode to protobuf binary (requires native extension).\"\"\""
  echo "        from akash_deploy._native import encode_message  # type: ignore[import]"
  echo "        return encode_message(self.TYPE_URL, json.dumps(asdict(self)).encode())"
  echo ""
  echo "    @classmethod"
  echo "    def decode(cls, data: bytes) -> \"${struct_name}\":"
  echo "        \"\"\"Decode from protobuf binary (requires native extension).\"\"\""
  echo "        from akash_deploy._native import decode_message  # type: ignore[import]"
  echo "        return cls(**json.loads(decode_message(cls.TYPE_URL, data)))"
  echo ""
  echo "    def to_dict(self) -> dict:"
  echo "        return asdict(self)"
  echo ""
  echo "    def to_json(self) -> str:"
  echo "        return json.dumps(asdict(self))"
}

# ── Generate Rust py_gen.rs ───────────────────────────────────────────

generate_rust_registry() {
  local files=("$@")

  {
    echo "// Auto-generated by scripts/gen/prost-to-pyo3.sh — do not edit."
    echo "// Run \`just py-gen\` to regenerate when proto types change."
    echo ""
    echo "type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;"
    echo "use prost::Message;"
    echo ""

    # Collect all type info
    local all_type_urls=()
    declare -A type_to_rust  # type_url → rust_path::StructName

    for rs_file in "${files[@]}"; do
      local basename
      basename="$(basename "$rs_file" .rs)"
      local rust_mod
      rust_mod="$(filename_to_rust_path "$basename")"

      while IFS='|' read -r pkg turl sname; do
        all_type_urls+=("$turl")
        type_to_rust["$turl"]="${rust_mod}::${sname}"
      done < <(extract_types "$rs_file")
    done

    # TYPE_URLS const
    echo "pub const TYPE_URLS: &[&str] = &["
    for turl in "${all_type_urls[@]}"; do
      echo "    \"${turl}\","
    done
    echo "];"
    echo ""

    # encode() fn
    echo "pub fn encode(type_url: &str, json_data: &[u8]) -> Result<Vec<u8>> {"
    echo "    match type_url {"
    for turl in "${all_type_urls[@]}"; do
      local rust_type="${type_to_rust[$turl]}"
      echo "        \"${turl}\" => {"
      echo "            let msg: ${rust_type} = serde_json::from_slice(json_data)?;"
      echo "            Ok(msg.encode_to_vec())"
      echo "        }"
    done
    echo "        _ => return Err(format!(\"Unknown type URL: {}\", type_url).into()),"
    echo "    }"
    echo "}"
    echo ""

    # decode() fn
    echo "pub fn decode(type_url: &str, proto_data: &[u8]) -> Result<Vec<u8>> {"
    echo "    match type_url {"
    for turl in "${all_type_urls[@]}"; do
      local rust_type="${type_to_rust[$turl]}"
      echo "        \"${turl}\" => {"
      echo "            let msg = ${rust_type}::decode(proto_data)?;"
      echo "            Ok(serde_json::to_vec(&msg)?)"
      echo "        }"
    done
    echo "        _ => return Err(format!(\"Unknown type URL: {}\", type_url).into()),"
    echo "    }"
    echo "}"
  } > "$RS_OUT"

  echo "  → $RS_OUT ($(wc -l < "$RS_OUT") lines)"
}

# ── Main ──────────────────────────────────────────────────────────────

echo "prost-to-pyo3: generating Python dataclasses + Rust registry"
echo "  gen dir:   $GEN_DIR"
echo "  py out:    $PY_OUT_DIR"
echo "  rs out:    $RS_OUT"
echo "  modules:   $MODULES"
echo ""

IFS=',' read -ra MODULE_LIST <<< "$MODULES"

# Collect matching files
matching_files=()
for rs_file in "$GEN_DIR"/*.rs; do
  basename="$(basename "$rs_file" .rs)"
  match=0
  for mod in "${MODULE_LIST[@]}"; do
    if [[ "$basename" == "$mod"* ]]; then match=1; break; fi
  done
  [[ $match -eq 0 ]] && continue
  matching_files+=("$rs_file")
done

echo "Python dataclasses:"
for rs_file in "${matching_files[@]}"; do
  parse_file_py "$rs_file"
done

echo ""
echo "Rust registry:"
generate_rust_registry "${matching_files[@]}"

echo ""
echo "Done — ${#matching_files[@]} modules processed"
echo "  Python: $PY_OUT_DIR/"
echo "  Rust:   $RS_OUT"
echo ""
echo "Next steps:"
echo "  just py-dev    # install in editable mode (requires maturin)"
echo "  just py-build  # build a wheel"
