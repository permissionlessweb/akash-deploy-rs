//! SDL template substitution with variable placeholders.
//!
//! This module provides template processing for SDL files using `${VAR}` syntax.
//! Templates allow reusable deployment configurations where infrastructure parameters
//! can be configured without modifying the SDL structure.
//!
//! # Features
//!
//! - Extract variable placeholders from templates
//! - Apply variable substitution with defaults and overrides
//! - Strict validation (all variables must have defaults)
//! - YAML-aware substitution that preserves structure
//!
//! # Example
//!
//! ```ignore
//! use akash_deploy_rs::template::{SdlTemplate, TemplateVariables, TemplateDefaults};
//! use std::collections::HashMap;
//!
//! let template_content = r#"
//! version: "2.0"
//! services:
//!   web:
//!     image: ${IMAGE}:${VERSION}
//! "#;
//!
//! let template = SdlTemplate::new(template_content)?;
//!
//! let mut defaults = TemplateDefaults::new();
//! defaults.insert("IMAGE".to_string(), "nginx".to_string());
//! defaults.insert("VERSION".to_string(), "1.25".to_string());
//!
//! let mut variables = TemplateVariables::new();
//! variables.insert("VERSION".to_string(), "1.26".to_string());
//!
//! let result = template.process(&variables, &defaults)?;
//! // Result contains: image: nginx:1.26
//! ```

use crate::error::DeployError;
use std::collections::HashMap;

/// Type alias for user-provided variable overrides.
pub type TemplateVariables = HashMap<String, String>;

/// Type alias for default variable values.
pub type TemplateDefaults = HashMap<String, String>;

/// SDL template with variable placeholders.
///
/// A template contains raw SDL content with `${VAR}` placeholders that get
/// substituted with actual values during processing.
#[derive(Debug, Clone)]
pub struct SdlTemplate {
    /// Raw template content with ${VAR} placeholders
    pub content: String,
    /// Extracted variable names from the template
    pub variables: Vec<String>,
}

impl SdlTemplate {
    /// Create a new template from SDL content.
    ///
    /// This extracts all variable placeholders from the template.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Template contains unclosed placeholders
    /// - Variable names contain invalid characters
    pub fn new(content: impl Into<String>) -> Result<Self, DeployError> {
        let content = content.into();
        let variables = extract_variables(&content)?;

        Ok(Self { content, variables })
    }

    /// Validate that all variables have defaults.
    ///
    /// # Errors
    ///
    /// Returns an error if any variables are missing defaults.
    pub fn validate(&self, defaults: &TemplateDefaults) -> Result<(), DeployError> {
        validate_template(&self.content, defaults)
    }

    /// Apply variable substitution to the template.
    ///
    /// Variables override defaults. This does not validate - use `process()` for
    /// validation + application.
    ///
    /// # Errors
    ///
    /// Returns an error if template processing fails.
    pub fn apply(
        &self,
        variables: &TemplateVariables,
        defaults: &TemplateDefaults,
    ) -> Result<String, DeployError> {
        apply_template(&self.content, variables, defaults)
    }

    /// Process the template with validation.
    ///
    /// This validates that all variables have defaults, then applies substitution.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails or template processing fails.
    pub fn process(
        &self,
        variables: &TemplateVariables,
        defaults: &TemplateDefaults,
    ) -> Result<String, DeployError> {
        self.validate(defaults)?;
        self.apply(variables, defaults)
    }
}

/// Extract variable names from a template.
///
/// This uses a character-by-character parser to find `${VAR}` placeholders.
/// Variable names must be alphanumeric or underscore.
///
/// # Errors
///
/// Returns an error if:
/// - Template contains unclosed placeholders (`${VAR` without `}`)
/// - Variable names contain invalid characters
///
/// # Example
///
/// ```ignore
/// let vars = extract_variables("image: ${IMAGE}:${VERSION}")?;
/// assert_eq!(vars, vec!["IMAGE", "VERSION"]);
/// ```
pub fn extract_variables(template: &str) -> Result<Vec<String>, DeployError> {
    let mut variables = Vec::new();
    let chars: Vec<char> = template.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        // Look for ${
        if chars[i] == '$' && i + 1 < chars.len() && chars[i + 1] == '{' {
            i += 2; // Skip ${

            // Extract variable name
            let start = i;
            while i < chars.len() && chars[i] != '}' {
                let c = chars[i];
                if !c.is_alphanumeric() && c != '_' {
                    return Err(DeployError::Template(format!(
                        "Invalid character '{}' in variable name. Variable names must be alphanumeric or underscore.",
                        c
                    )));
                }
                i += 1;
            }

            if i >= chars.len() {
                return Err(DeployError::Template(
                    "Unclosed placeholder: missing '}'".to_string(),
                ));
            }

            let var_name: String = chars[start..i].iter().collect();
            if var_name.is_empty() {
                return Err(DeployError::Template(
                    "Empty variable name in placeholder".to_string(),
                ));
            }

            if !variables.contains(&var_name) {
                variables.push(var_name);
            }

            i += 1; // Skip }
        } else {
            i += 1;
        }
    }

    Ok(variables)
}

/// Apply template substitution with variables and defaults.
///
/// Variables override defaults. The substitution is YAML-aware and preserves
/// the document structure by parsing and recursively processing values.
///
/// # Errors
///
/// Returns an error if:
/// - Template is not valid YAML
/// - Substitution produces invalid YAML
///
/// # Example
///
/// ```ignore
/// let template = "image: ${IMAGE}:${VERSION}";
/// let mut vars = HashMap::new();
/// vars.insert("VERSION".to_string(), "1.26".to_string());
/// let mut defaults = HashMap::new();
/// defaults.insert("IMAGE".to_string(), "nginx".to_string());
/// defaults.insert("VERSION".to_string(), "1.25".to_string());
///
/// let result = apply_template(template, &vars, &defaults)?;
/// // result: "image: nginx:1.26"
/// ```
pub fn apply_template(
    template: &str,
    variables: &TemplateVariables,
    defaults: &TemplateDefaults,
) -> Result<String, DeployError> {
    // Merge variables and defaults (variables override defaults)
    let mut values = defaults.clone();
    values.extend(variables.clone());

    // Parse as YAML to preserve structure
    let yaml_value: serde_yaml::Value = serde_yaml::from_str(template)
        .map_err(|e| DeployError::Template(format!("Template is not valid YAML: {}", e)))?;

    // Recursively substitute in the YAML structure
    let substituted = substitute_yaml_value(&yaml_value, &values)?;

    // Serialize back to YAML
    serde_yaml::to_string(&substituted)
        .map_err(|e| DeployError::Template(format!("Failed to serialize result: {}", e)))
}

/// Recursively substitute variables in a YAML value.
fn substitute_yaml_value(
    value: &serde_yaml::Value,
    values: &HashMap<String, String>,
) -> Result<serde_yaml::Value, DeployError> {
    match value {
        serde_yaml::Value::String(s) => {
            let substituted = substitute_string(s, values)?;
            Ok(serde_yaml::Value::String(substituted))
        }
        serde_yaml::Value::Mapping(map) => {
            let mut new_map = serde_yaml::Mapping::new();
            for (k, v) in map {
                let new_value = substitute_yaml_value(v, values)?;
                new_map.insert(k.clone(), new_value);
            }
            Ok(serde_yaml::Value::Mapping(new_map))
        }
        serde_yaml::Value::Sequence(seq) => {
            let new_seq: Result<Vec<_>, _> = seq
                .iter()
                .map(|v| substitute_yaml_value(v, values))
                .collect();
            Ok(serde_yaml::Value::Sequence(new_seq?))
        }
        // Numbers, bools, null - no substitution needed
        other => Ok(other.clone()),
    }
}

/// Substitute variables in a string value.
fn substitute_string(s: &str, values: &HashMap<String, String>) -> Result<String, DeployError> {
    let mut result = String::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] == '$' && i + 1 < chars.len() && chars[i + 1] == '{' {
            i += 2; // Skip ${

            // Extract variable name
            let start = i;
            while i < chars.len() && chars[i] != '}' {
                i += 1;
            }

            if i >= chars.len() {
                return Err(DeployError::Template(
                    "Unclosed placeholder in string".to_string(),
                ));
            }

            let var_name: String = chars[start..i].iter().collect();

            // Look up value
            let value = values.get(&var_name).ok_or_else(|| {
                DeployError::Template(format!("Variable '{}' has no value", var_name))
            })?;

            result.push_str(value);
            i += 1; // Skip }
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }

    Ok(result)
}

/// Validate that a template can be processed.
///
/// Checks that:
/// - All variables have defaults
/// - Template with defaults produces valid YAML
///
/// # Errors
///
/// Returns an error if:
/// - Any variables are missing defaults
/// - Template with defaults is not valid YAML
///
/// # Example
///
/// ```ignore
/// let template = "image: ${IMAGE}";
/// let mut defaults = HashMap::new();
/// defaults.insert("IMAGE".to_string(), "nginx".to_string());
///
/// validate_template(template, &defaults)?; // OK
///
/// let bad_defaults = HashMap::new();
/// validate_template(template, &bad_defaults)?; // Error: IMAGE missing
/// ```
pub fn validate_template(template: &str, defaults: &TemplateDefaults) -> Result<(), DeployError> {
    // Extract variables
    let variables = extract_variables(template)?;

    // Check all have defaults
    let missing: Vec<_> = variables
        .iter()
        .filter(|v| !defaults.contains_key(*v))
        .collect();

    if !missing.is_empty() {
        let missing_names: Vec<String> = missing.iter().map(|s| s.to_string()).collect();
        return Err(DeployError::Template(format!(
            "Variables missing defaults: {}",
            missing_names.join(", ")
        )));
    }

    // Try to render with defaults to ensure it produces valid output
    let rendered = apply_template(template, &HashMap::new(), defaults)?;

    // Validate it's valid YAML
    serde_yaml::from_str::<serde_yaml::Value>(&rendered)
        .map_err(|e| DeployError::Template(format!("Template produces invalid YAML: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_variables_simple() {
        let template = "image: ${IMAGE}";
        let vars = extract_variables(template).unwrap();
        assert_eq!(vars, vec!["IMAGE"]);
    }

    #[test]
    fn test_extract_variables_multiple() {
        let template = "image: ${IMAGE}:${VERSION}";
        let vars = extract_variables(template).unwrap();
        assert_eq!(vars, vec!["IMAGE", "VERSION"]);
    }

    #[test]
    fn test_extract_variables_duplicate() {
        let template = "a: ${VAR}\nb: ${VAR}";
        let vars = extract_variables(template).unwrap();
        assert_eq!(vars, vec!["VAR"]); // Deduplicated
    }

    #[test]
    fn test_extract_variables_unclosed() {
        let template = "image: ${IMAGE";
        let result = extract_variables(template);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unclosed"));
    }

    #[test]
    fn test_extract_variables_invalid_char() {
        let template = "image: ${IMAGE-TAG}";
        let result = extract_variables(template);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid character"));
    }

    #[test]
    fn test_extract_variables_empty() {
        let template = "image: ${}";
        let result = extract_variables(template);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Empty variable"));
    }

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
    }

    #[test]
    fn test_apply_template_nested() {
        let template = r#"
version: "2.0"
services:
  web:
    image: ${IMAGE}:${VERSION}
"#;
        let mut defaults = HashMap::new();
        defaults.insert("IMAGE".to_string(), "nginx".to_string());
        defaults.insert("VERSION".to_string(), "1.25".to_string());

        let result = apply_template(template, &HashMap::new(), &defaults).unwrap();
        assert!(result.contains("nginx:1.25"));
        assert!(result.contains("version:"));
        assert!(result.contains("services:"));
    }

    #[test]
    fn test_validate_template_missing_default() {
        let template = "image: ${IMAGE}";
        let defaults = HashMap::new();

        let result = validate_template(template, &defaults);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Variables missing defaults"));
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
    fn test_sdl_template_new() {
        let template = SdlTemplate::new("image: ${IMAGE}").unwrap();
        assert_eq!(template.variables, vec!["IMAGE"]);
    }

    #[test]
    fn test_sdl_template_process() {
        let template = SdlTemplate::new("image: ${IMAGE}").unwrap();

        let mut defaults = HashMap::new();
        defaults.insert("IMAGE".to_string(), "nginx".to_string());

        let result = template.process(&HashMap::new(), &defaults).unwrap();
        assert!(result.contains("nginx"));
    }

    #[test]
    fn test_sdl_template_process_missing_default() {
        let template = SdlTemplate::new("image: ${IMAGE}").unwrap();
        let defaults = HashMap::new();

        let result = template.process(&HashMap::new(), &defaults);
        assert!(result.is_err());
    }
}
