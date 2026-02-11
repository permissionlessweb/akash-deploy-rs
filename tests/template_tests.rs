#![cfg(feature = "sdl-templates")]

use akash_deploy_rs::sdl::template::{
    apply_template, extract_variables, validate_template, SdlTemplate, TemplateDefaults,
    TemplateVariables,
};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════════
// EXTRACTION TESTS
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_extract_variables_simple() {
    let template = "image: ${IMAGE}";
    let vars = extract_variables(template).unwrap();
    assert_eq!(vars, vec!["IMAGE"]);
}

#[test]
fn test_extract_variables_multiple() {
    let template = "image: ${IMAGE}:${VERSION}\nport: ${PORT}";
    let vars = extract_variables(template).unwrap();
    assert_eq!(vars, vec!["IMAGE", "VERSION", "PORT"]);
}

#[test]
fn test_extract_variables_duplicate() {
    let template = r#"
a: ${VAR}
b: ${VAR}
c: ${OTHER}
d: ${VAR}
"#;
    let vars = extract_variables(template).unwrap();
    // Should be deduplicated
    assert_eq!(vars, vec!["VAR", "OTHER"]);
}

#[test]
fn test_extract_variables_unclosed() {
    let template = "image: ${IMAGE";
    let result = extract_variables(template);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Unclosed") || err_msg.contains("missing"));
}

#[test]
fn test_extract_variables_invalid_char() {
    let template = "image: ${IMAGE-TAG}";
    let result = extract_variables(template);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Invalid character") || err_msg.contains("alphanumeric"));
}

#[test]
fn test_extract_variables_empty() {
    let template = "image: ${}";
    let result = extract_variables(template);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Empty variable"));
}

#[test]
fn test_extract_variables_with_underscores() {
    let template = "value: ${MY_VARIABLE_123}";
    let vars = extract_variables(template).unwrap();
    assert_eq!(vars, vec!["MY_VARIABLE_123"]);
}

#[test]
fn test_extract_variables_no_placeholders() {
    let template = "image: nginx:1.25\nport: 80";
    let vars = extract_variables(template).unwrap();
    assert!(vars.is_empty());
}

#[test]
fn test_extract_variables_dollar_without_brace() {
    let template = "price: $100";
    let vars = extract_variables(template).unwrap();
    assert!(vars.is_empty()); // $ without { should be ignored
}

// ═══════════════════════════════════════════════════════════════════
// APPLICATION TESTS
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_apply_template_simple() {
    let template = "image: ${IMAGE}";
    let mut defaults = HashMap::new();
    defaults.insert("IMAGE".to_string(), "nginx".to_string());

    let result = apply_template(template, &HashMap::new(), &defaults).unwrap();
    assert!(result.contains("nginx"));
}

#[test]
fn test_apply_template_priority() {
    let template = "image: ${IMAGE}";
    let mut defaults = HashMap::new();
    defaults.insert("IMAGE".to_string(), "nginx".to_string());

    let mut variables = HashMap::new();
    variables.insert("IMAGE".to_string(), "apache".to_string());

    let result = apply_template(template, &variables, &defaults).unwrap();
    assert!(result.contains("apache"));
    assert!(!result.contains("nginx"));
}

#[test]
fn test_apply_template_nested() {
    let template = r#"
version: "2.0"
services:
  web:
    image: ${IMAGE}:${VERSION}
    port: ${PORT}
"#;
    let mut defaults = HashMap::new();
    defaults.insert("IMAGE".to_string(), "nginx".to_string());
    defaults.insert("VERSION".to_string(), "1.25".to_string());
    defaults.insert("PORT".to_string(), "80".to_string());

    let result = apply_template(template, &HashMap::new(), &defaults).unwrap();
    assert!(result.contains("nginx:1.25"));
    assert!(result.contains("80"));
    assert!(result.contains("version:"));
    assert!(result.contains("services:"));
}

#[test]
fn test_apply_template_multiple_occurrences() {
    let template = r#"
service1:
  image: ${IMAGE}:${VERSION}
service2:
  image: ${IMAGE}:${VERSION}
"#;
    let mut defaults = HashMap::new();
    defaults.insert("IMAGE".to_string(), "nginx".to_string());
    defaults.insert("VERSION".to_string(), "latest".to_string());

    let result = apply_template(template, &HashMap::new(), &defaults).unwrap();
    // Both occurrences should be replaced
    let nginx_count = result.matches("nginx:latest").count();
    assert_eq!(nginx_count, 2);
}

#[test]
fn test_apply_template_preserves_structure() {
    let template = r#"
list:
  - ${ITEM1}
  - ${ITEM2}
map:
  key: ${VALUE}
"#;
    let mut defaults = HashMap::new();
    defaults.insert("ITEM1".to_string(), "first".to_string());
    defaults.insert("ITEM2".to_string(), "second".to_string());
    defaults.insert("VALUE".to_string(), "result".to_string());

    let result = apply_template(template, &HashMap::new(), &defaults).unwrap();
    assert!(result.contains("first"));
    assert!(result.contains("second"));
    assert!(result.contains("result"));
}

#[test]
fn test_apply_template_missing_variable() {
    let template = "image: ${IMAGE}";
    let defaults = HashMap::new(); // Missing IMAGE

    let result = apply_template(template, &HashMap::new(), &defaults);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("IMAGE") && err_msg.contains("no value"));
}

#[test]
fn test_apply_template_invalid_yaml() {
    let template = "${IMAGE}:\n  invalid: {";
    let mut defaults = HashMap::new();
    defaults.insert("IMAGE".to_string(), "test".to_string());

    let result = apply_template(template, &HashMap::new(), &defaults);
    // Should fail during YAML parsing
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════════
// VALIDATION TESTS
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_validate_template_missing_default() {
    let template = "image: ${IMAGE}\nport: ${PORT}";
    let mut defaults = HashMap::new();
    defaults.insert("IMAGE".to_string(), "nginx".to_string());
    // Missing PORT

    let result = validate_template(template, &defaults);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Variables missing defaults") && err_msg.contains("PORT"));
}

#[test]
fn test_validate_template_valid() {
    let template = "image: ${IMAGE}";
    let mut defaults = HashMap::new();
    defaults.insert("IMAGE".to_string(), "nginx".to_string());

    let result = validate_template(template, &defaults);
    assert!(result.is_ok());
}

#[test]
fn test_validate_template_no_variables() {
    let template = "image: nginx\nport: 80";
    let defaults = HashMap::new();

    let result = validate_template(template, &defaults);
    assert!(result.is_ok());
}

#[test]
fn test_validate_template_all_defaults_present() {
    let template = r#"
image: ${IMAGE}:${VERSION}
cpu: ${CPU}
memory: ${MEMORY}
"#;
    let mut defaults = HashMap::new();
    defaults.insert("IMAGE".to_string(), "nginx".to_string());
    defaults.insert("VERSION".to_string(), "1.25".to_string());
    defaults.insert("CPU".to_string(), "100m".to_string());
    defaults.insert("MEMORY".to_string(), "128Mi".to_string());

    let result = validate_template(template, &defaults);
    assert!(result.is_ok());
}

#[test]
fn test_validate_template_produces_invalid_yaml() {
    let template = "${IMAGE}:\n  {invalid";
    let mut defaults = HashMap::new();
    defaults.insert("IMAGE".to_string(), "test".to_string());

    let result = validate_template(template, &defaults);
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════════
// SDL TEMPLATE STRUCT TESTS
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_sdl_template_new() {
    let template = SdlTemplate::new("image: ${IMAGE}").unwrap();
    assert_eq!(template.variables, vec!["IMAGE"]);
    assert_eq!(template.content, "image: ${IMAGE}");
}

#[test]
fn test_sdl_template_new_invalid() {
    let result = SdlTemplate::new("image: ${IMAGE");
    assert!(result.is_err());
}

#[test]
fn test_sdl_template_validate() {
    let template = SdlTemplate::new("image: ${IMAGE}").unwrap();

    let mut defaults = HashMap::new();
    defaults.insert("IMAGE".to_string(), "nginx".to_string());

    assert!(template.validate(&defaults).is_ok());

    let empty_defaults = HashMap::new();
    assert!(template.validate(&empty_defaults).is_err());
}

#[test]
fn test_sdl_template_apply() {
    let template = SdlTemplate::new("image: ${IMAGE}:${VERSION}").unwrap();

    let mut defaults = HashMap::new();
    defaults.insert("IMAGE".to_string(), "nginx".to_string());
    defaults.insert("VERSION".to_string(), "1.25".to_string());

    let mut variables = HashMap::new();
    variables.insert("VERSION".to_string(), "1.26".to_string());

    let result = template.apply(&variables, &defaults).unwrap();
    assert!(result.contains("nginx:1.26"));
}

#[test]
fn test_sdl_template_process() {
    let template = SdlTemplate::new("image: ${IMAGE}").unwrap();

    let mut defaults = HashMap::new();
    defaults.insert("IMAGE".to_string(), "nginx".to_string());

    // Should validate + apply
    let result = template.process(&HashMap::new(), &defaults).unwrap();
    assert!(result.contains("nginx"));
}

#[test]
fn test_sdl_template_process_missing_default() {
    let template = SdlTemplate::new("image: ${IMAGE}").unwrap();
    let defaults = HashMap::new();

    // Should fail validation
    let result = template.process(&HashMap::new(), &defaults);
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════════
// COMPREHENSIVE INTEGRATION TESTS
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_full_sdl_template() {
    let template_content = r#"
version: "2.0"
services:
  web:
    image: ${IMAGE}:${VERSION}
    expose:
      - port: ${PORT}
        as: ${PORT}
        to:
          - global: true
profiles:
  compute:
    web:
      resources:
        cpu:
          units: ${CPU_UNITS}
        memory:
          size: ${MEMORY_SIZE}
        storage:
          size: ${STORAGE_SIZE}
  placement:
    dcloud:
      pricing:
        web:
          denom: uakt
          amount: ${PRICE}
deployment:
  web:
    dcloud:
      profile: web
      count: ${COUNT}
"#;

    let template = SdlTemplate::new(template_content).unwrap();

    // Check extracted variables
    assert!(template.variables.contains(&"IMAGE".to_string()));
    assert!(template.variables.contains(&"VERSION".to_string()));
    assert!(template.variables.contains(&"PORT".to_string()));
    assert!(template.variables.contains(&"CPU_UNITS".to_string()));
    assert!(template.variables.contains(&"MEMORY_SIZE".to_string()));
    assert!(template.variables.contains(&"STORAGE_SIZE".to_string()));
    assert!(template.variables.contains(&"PRICE".to_string()));
    assert!(template.variables.contains(&"COUNT".to_string()));

    let mut defaults = TemplateDefaults::new();
    defaults.insert("IMAGE".to_string(), "nginx".to_string());
    defaults.insert("VERSION".to_string(), "1.25".to_string());
    defaults.insert("PORT".to_string(), "80".to_string());
    defaults.insert("CPU_UNITS".to_string(), "100m".to_string());
    defaults.insert("MEMORY_SIZE".to_string(), "128Mi".to_string());
    defaults.insert("STORAGE_SIZE".to_string(), "1Gi".to_string());
    defaults.insert("PRICE".to_string(), "100".to_string());
    defaults.insert("COUNT".to_string(), "1".to_string());

    // Validate
    assert!(template.validate(&defaults).is_ok());

    // Override VERSION
    let mut variables = TemplateVariables::new();
    variables.insert("VERSION".to_string(), "1.26".to_string());

    // Process
    let result = template.process(&variables, &defaults).unwrap();

    // Verify substitutions
    assert!(result.contains("nginx:1.26"));
    assert!(result.contains("80"));
    assert!(result.contains("100m"));
    assert!(result.contains("128Mi"));
    assert!(result.contains("1Gi"));
    assert!(result.contains("100"));
    assert!(result.contains("version:"));
    assert!(result.contains("services:"));
    assert!(result.contains("profiles:"));
    assert!(result.contains("deployment:"));
}

#[test]
fn test_template_with_partial_defaults() {
    let template = SdlTemplate::new("a: ${A}\nb: ${B}\nc: ${C}").unwrap();

    let mut defaults = HashMap::new();
    defaults.insert("A".to_string(), "1".to_string());
    defaults.insert("B".to_string(), "2".to_string());
    // Missing C

    let result = template.process(&HashMap::new(), &defaults);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("C"));
}

#[test]
fn test_template_type_aliases() {
    // Just verify the type aliases work
    let _vars: TemplateVariables = HashMap::new();
    let _defaults: TemplateDefaults = HashMap::new();
}

#[test]
fn test_template_empty_content() {
    let result = SdlTemplate::new("");
    assert!(result.is_ok());
    let template = result.unwrap();
    assert!(template.variables.is_empty());
}

#[test]
fn test_template_numeric_values() {
    let template = r#"
port: ${PORT}
count: ${COUNT}
price: ${PRICE}
"#;
    let mut defaults = HashMap::new();
    defaults.insert("PORT".to_string(), "8080".to_string());
    defaults.insert("COUNT".to_string(), "3".to_string());
    defaults.insert("PRICE".to_string(), "1000".to_string());

    let result = apply_template(template, &HashMap::new(), &defaults).unwrap();
    assert!(result.contains("8080"));
    assert!(result.contains("3"));
    assert!(result.contains("1000"));
}

#[test]
fn test_template_boolean_values() {
    let template = r#"
enabled: ${ENABLED}
debug: ${DEBUG}
"#;
    let mut defaults = HashMap::new();
    defaults.insert("ENABLED".to_string(), "true".to_string());
    defaults.insert("DEBUG".to_string(), "false".to_string());

    let result = apply_template(template, &HashMap::new(), &defaults).unwrap();
    assert!(result.contains("true"));
    assert!(result.contains("false"));
}

#[test]
fn test_template_with_special_characters_in_values() {
    let template = "url: ${URL}";
    let mut defaults = HashMap::new();
    defaults.insert(
        "URL".to_string(),
        "https://example.com:8080/path".to_string(),
    );

    let result = apply_template(template, &HashMap::new(), &defaults).unwrap();
    assert!(result.contains("https://example.com:8080/path"));
}

#[test]
fn test_template_whitespace_preservation() {
    let template = r#"
services:
  web:
    image: ${IMAGE}
"#;
    let mut defaults = HashMap::new();
    defaults.insert("IMAGE".to_string(), "nginx".to_string());

    let result = apply_template(template, &HashMap::new(), &defaults).unwrap();
    // YAML structure should be preserved (though exact formatting may vary)
    assert!(result.contains("services"));
    assert!(result.contains("web"));
    assert!(result.contains("nginx"));
}

// ═══════════════════════════════════════════════════════════════════
// INTEGRATION TESTS WITH MANIFEST BUILDER
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_template_to_manifest_pipeline() {
    use akash_deploy_rs::ManifestBuilder;

    let template_content = include_str!("template_testdata/template_simple.yaml");
    let template = SdlTemplate::new(template_content).unwrap();

    let mut defaults = HashMap::new();
    defaults.insert("IMAGE".to_string(), "nginx".to_string());
    defaults.insert("VERSION".to_string(), "1.25".to_string());
    defaults.insert("PORT".to_string(), "80".to_string());
    defaults.insert("CPU_UNITS".to_string(), "100m".to_string());
    defaults.insert("MEMORY_SIZE".to_string(), "128Mi".to_string());
    defaults.insert("STORAGE_SIZE".to_string(), "1Gi".to_string());
    defaults.insert("PRICE".to_string(), "100".to_string());
    defaults.insert("COUNT".to_string(), "1".to_string());

    // Process template
    let result = template.process(&HashMap::new(), &defaults).unwrap();

    // Build manifest from processed SDL
    let builder = ManifestBuilder::new("akash1test", 123);
    let manifest = builder.build_from_sdl(&result).unwrap();

    // Verify manifest structure
    assert!(!manifest.is_empty());
    assert_eq!(manifest[0].name, "dcloud");
    assert_eq!(manifest[0].services.len(), 1);
    assert_eq!(manifest[0].services[0].image, "nginx:1.25");
}

#[test]
fn test_template_fixture_with_overrides() {
    use akash_deploy_rs::ManifestBuilder;

    let template_content = include_str!("template_testdata/template_simple.yaml");
    let template = SdlTemplate::new(template_content).unwrap();

    let mut defaults = HashMap::new();
    defaults.insert("IMAGE".to_string(), "nginx".to_string());
    defaults.insert("VERSION".to_string(), "1.25".to_string());
    defaults.insert("PORT".to_string(), "80".to_string());
    defaults.insert("CPU_UNITS".to_string(), "100m".to_string());
    defaults.insert("MEMORY_SIZE".to_string(), "128Mi".to_string());
    defaults.insert("STORAGE_SIZE".to_string(), "1Gi".to_string());
    defaults.insert("PRICE".to_string(), "100".to_string());
    defaults.insert("COUNT".to_string(), "1".to_string());

    // Override VERSION and PORT
    let mut variables = HashMap::new();
    variables.insert("VERSION".to_string(), "1.26".to_string());
    variables.insert("PORT".to_string(), "8080".to_string());

    // Process template
    let result = template.process(&variables, &defaults).unwrap();

    // Build manifest
    let builder = ManifestBuilder::new("akash1test", 123);
    let manifest = builder.build_from_sdl(&result).unwrap();

    // Verify overrides applied
    assert_eq!(manifest[0].services[0].image, "nginx:1.26");
    // Verify the port override was applied in the processed SDL
    // The template has both port and as fields set to ${PORT}
    assert!(result.contains("8080"));
}

#[test]
fn test_template_state_integration() {
    use akash_deploy_rs::DeploymentState;

    let mut state = DeploymentState::new("session-1", "akash1owner");

    let template_content = "version: \"2.0\"\nservices:\n  web:\n    image: ${IMAGE}";

    let mut defaults = HashMap::new();
    defaults.insert("IMAGE".to_string(), "nginx".to_string());

    let mut variables = HashMap::new();
    variables.insert("IMAGE".to_string(), "apache".to_string());

    // Use builder pattern
    state = state
        .with_sdl(template_content)
        .with_template(defaults)
        .with_variables(variables);

    // Verify state
    assert!(state.is_template);
    assert!(state.template_defaults.is_some());
    assert!(state.template_variables.is_some());

    // Verify defaults
    let stored_defaults = state.template_defaults.as_ref().unwrap();
    assert_eq!(stored_defaults.get("IMAGE").unwrap(), "nginx");

    // Verify variables
    let stored_vars = state.template_variables.as_ref().unwrap();
    assert_eq!(stored_vars.get("IMAGE").unwrap(), "apache");
}

#[test]
fn test_template_state_serialization() {
    use akash_deploy_rs::DeploymentState;

    let mut state = DeploymentState::new("session-1", "akash1owner");

    let mut defaults = HashMap::new();
    defaults.insert("IMAGE".to_string(), "nginx".to_string());

    state = state.with_sdl("version: \"2.0\"").with_template(defaults);

    // Serialize to JSON
    let json = serde_json::to_string(&state).unwrap();

    // Deserialize back
    let restored: DeploymentState = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.is_template, state.is_template);
    assert_eq!(
        restored
            .template_defaults
            .as_ref()
            .unwrap()
            .get("IMAGE")
            .unwrap(),
        "nginx"
    );
}

#[test]
fn test_backwards_compatibility_no_template_fields() {
    use akash_deploy_rs::DeploymentState;

    // Create state without template fields
    let state = DeploymentState::new("session-1", "akash1owner").with_sdl("version: \"2.0\"");

    // Should not be a template
    assert!(!state.is_template);
    assert!(state.template_defaults.is_none());
    assert!(state.template_variables.is_none());

    // Should serialize without template fields
    let json = serde_json::to_string(&state).unwrap();
    assert!(!json.contains("template_defaults"));
    assert!(!json.contains("template_variables"));
}

#[test]
fn test_manifest_hash_consistency() {
    use akash_deploy_rs::{to_canonical_json, ManifestBuilder};

    let template_content = r#"
version: "2.0"
services:
  web:
    image: ${IMAGE}
    expose:
      - port: 80
        as: 80
        to:
          - global: true
profiles:
  compute:
    web:
      resources:
        cpu:
          units: 100m
        memory:
          size: 128Mi
        storage:
          size: 1Gi
  placement:
    dc:
      pricing:
        web:
          denom: uakt
          amount: 100
deployment:
  web:
    dc:
      profile: web
      count: 1
"#;

    let mut defaults = HashMap::new();
    defaults.insert("IMAGE".to_string(), "nginx".to_string());

    let template = SdlTemplate::new(template_content).unwrap();
    let processed = template.process(&HashMap::new(), &defaults).unwrap();

    // Build manifest twice
    let builder1 = ManifestBuilder::new("akash1test", 123);
    let manifest1 = builder1.build_from_sdl(&processed).unwrap();

    let builder2 = ManifestBuilder::new("akash1test", 123);
    let manifest2 = builder2.build_from_sdl(&processed).unwrap();

    // Serialize to canonical JSON
    let json1 = to_canonical_json(&manifest1).unwrap();
    let json2 = to_canonical_json(&manifest2).unwrap();

    // Hashes should be identical
    assert_eq!(json1, json2);
}

// ═══════════════════════════════════════════════════════════════════
// ERROR HANDLING TESTS
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_template_error_unclosed_placeholder() {
    let result = SdlTemplate::new("image: ${IMAGE");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("template error"));
}

#[test]
fn test_template_error_invalid_variable_name() {
    let result = SdlTemplate::new("image: ${IMAGE-TAG}");
    assert!(result.is_err());
}

#[test]
fn test_template_error_missing_defaults() {
    let template = SdlTemplate::new("image: ${IMAGE}").unwrap();
    let result = template.validate(&HashMap::new());
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("missing defaults"));
}

#[test]
fn test_template_error_not_recoverable() {
    use akash_deploy_rs::DeployError;

    let err = DeployError::Template("test error".to_string());
    assert!(!err.is_recoverable());
}

#[test]
fn test_apply_template_unclosed_in_string() {
    // This tests the unclosed placeholder error in substitute_string
    let template = "key: ${UNCLOSED";
    let mut defaults = HashMap::new();
    defaults.insert("UNCLOSED".to_string(), "value".to_string());

    let result = apply_template(template, &HashMap::new(), &defaults);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Unclosed placeholder"));
}

#[test]
fn test_extract_variables_comprehensive() {
    // Test multiple edge cases in one go
    let template = r#"
# Variables at different positions
start: ${VAR1}
middle: prefix_${VAR2}_suffix
end: ${VAR3}
multiline: |
  ${VAR4}
nested:
  deep:
    value: ${VAR5}
"#;
    let vars = extract_variables(template).unwrap();
    assert_eq!(vars.len(), 5);
    assert!(vars.contains(&"VAR1".to_string()));
    assert!(vars.contains(&"VAR2".to_string()));
    assert!(vars.contains(&"VAR3".to_string()));
    assert!(vars.contains(&"VAR4".to_string()));
    assert!(vars.contains(&"VAR5".to_string()));
}
