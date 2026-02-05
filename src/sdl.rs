//! SDL (Stack Definition Language) utilities.
//!
//! Minimal validation and parsing for Akash SDL files.
//! This is NOT a full SDL parser — just enough to validate
//! and extract what the workflow needs.

use crate::error::DeployError;

/// Validate that SDL content is well-formed.
///
/// This does basic structure validation, not full semantic validation.
/// The chain will reject truly invalid SDL anyway.
pub fn validate_sdl(content: &str) -> Result<(), DeployError> {
    if content.trim().is_empty() {
        return Err(DeployError::Sdl("empty SDL".into()));
    }

    // Must be valid YAML
    let _: serde_yaml::Value = serde_yaml::from_str(content)
        .map_err(|e| DeployError::Sdl(format!("invalid YAML: {}", e)))?;

    // Check for required top-level keys
    let doc: serde_yaml::Value = serde_yaml::from_str(content)
        .map_err(|e| DeployError::Sdl(format!("parse error: {}", e)))?;

    let map = doc
        .as_mapping()
        .ok_or_else(|| DeployError::Sdl("SDL must be a YAML mapping".into()))?;

    // version is required
    if !map.contains_key(serde_yaml::Value::String("version".into())) {
        return Err(DeployError::Sdl("missing 'version' field".into()));
    }

    // services is required
    if !map.contains_key(serde_yaml::Value::String("services".into())) {
        return Err(DeployError::Sdl("missing 'services' field".into()));
    }

    // profiles is required
    if !map.contains_key(serde_yaml::Value::String("profiles".into())) {
        return Err(DeployError::Sdl("missing 'profiles' field".into()));
    }

    // deployment is required
    if !map.contains_key(serde_yaml::Value::String("deployment".into())) {
        return Err(DeployError::Sdl("missing 'deployment' field".into()));
    }

    Ok(())
}

/// Extract service names from SDL.
pub fn extract_service_names(content: &str) -> Result<Vec<String>, DeployError> {
    let doc: serde_yaml::Value = serde_yaml::from_str(content)
        .map_err(|e| DeployError::Sdl(format!("parse error: {}", e)))?;

    let services = doc
        .get("services")
        .and_then(|s| s.as_mapping())
        .ok_or_else(|| DeployError::Sdl("services must be a mapping".into()))?;

    let names: Vec<String> = services
        .keys()
        .filter_map(|k| k.as_str().map(|s| s.to_string()))
        .collect();

    if names.is_empty() {
        return Err(DeployError::Sdl("no services defined".into()));
    }

    Ok(names)
}

/// Get the SDL version.
pub fn get_version(content: &str) -> Result<String, DeployError> {
    let doc: serde_yaml::Value = serde_yaml::from_str(content)
        .map_err(|e| DeployError::Sdl(format!("parse error: {}", e)))?;

    let version = doc
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DeployError::Sdl("version must be a string".into()))?;

    Ok(version.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_SDL: &str = r#"
version: "2.0"
services:
  web:
    image: nginx
    expose:
      - port: 80
        to:
          - global: true
profiles:
  compute:
    web:
      resources:
        cpu:
          units: 0.5
        memory:
          size: 512Mi
        storage:
          size: 1Gi
  placement:
    dcloud:
      pricing:
        web:
          denom: uakt
          amount: 1000
deployment:
  web:
    dcloud:
      profile: web
      count: 1
"#;

    #[test]
    fn test_validate_valid_sdl() {
        assert!(validate_sdl(VALID_SDL).is_ok());
    }

    #[test]
    fn test_validate_empty_sdl() {
        assert!(validate_sdl("").is_err());
        assert!(validate_sdl("   ").is_err());
    }

    #[test]
    fn test_validate_missing_version() {
        let sdl = "services: {}\nprofiles: {}\ndeployment: {}";
        let err = validate_sdl(sdl).unwrap_err();
        assert!(err.to_string().contains("version"));
    }

    #[test]
    fn test_extract_service_names() {
        let names = extract_service_names(VALID_SDL).unwrap();
        assert_eq!(names, vec!["web"]);
    }

    #[test]
    fn test_get_version() {
        let version = get_version(VALID_SDL).unwrap();
        assert_eq!(version, "2.0");
    }
}
