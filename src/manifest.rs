//! Manifest construction from SDL.
//!
//! The manifest is what gets sent to providers via their REST API.
//! It's derived from the SDL but serialized in the exact format the provider expects.
//!
//! ## Critical Serialization Requirements
//!
//! Provider JSON API requires:
//! - CPU units as STRING millicores ("1000", not float 1.0 or bytes)
//! - Memory/storage sizes as STRING bytes ("536870912", not int or bytes)
//! - Empty command/args/env as `null`, not `[]`
//! - Field names in camelCase (externalPort, httpOptions, readOnly)
//! - GPU attributes as composite keys (vendor/nvidia/model/h100/ram/80Gi)
//! - Storage attributes sorted by key
//! - Services sorted by name
//!
//! These types mirror akash.manifest.v2beta3 protos but serialize for JSON API, not protobuf.

use crate::error::DeployError;
use serde::{Deserialize, Serialize};

// ============================================================================
// Manifest Types (JSON API format, NOT protobuf)
// ============================================================================

/// Full manifest structure (mirrors akash.manifest.v2beta3.Manifest).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub groups: Vec<ManifestGroup>,
}

/// Manifest group (mirrors akash.manifest.v2beta3.Group).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestGroup {
    pub name: String,
    pub services: Vec<ManifestService>,
}

/// Service definition (mirrors akash.manifest.v2beta3.Service).
///
/// CRITICAL: Empty Vec fields MUST serialize as `null`, not `[]`.
/// Provider validation fails if command/args/env are present as empty arrays.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestService {
    pub name: String,
    pub image: String,
    pub command: Option<Vec<String>>,
    pub args: Option<Vec<String>>,
    /// Env vars as "KEY=VALUE" strings, NOT Vec<(K,V)>
    pub env: Option<Vec<String>>,
    pub resources: ManifestResources,
    pub count: u32,
    pub expose: Vec<ManifestServiceExpose>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<ManifestServiceParams>,
    pub credentials: Option<ManifestCredentials>,
}

/// Service expose (mirrors akash.manifest.v2beta3.ServiceExpose).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestServiceExpose {
    pub port: u32,
    /// CRITICAL: camelCase field name (not snake_case)
    #[serde(rename = "externalPort")]
    pub external_port: u32,
    pub proto: String,
    #[serde(default)]
    pub service: String,
    pub global: bool,
    /// `null` when missing, `[]` when present-but-empty
    pub hosts: Option<Vec<String>>,
    /// CRITICAL: camelCase field name
    #[serde(rename = "httpOptions")]
    pub http_options: ManifestHttpOptions,
    #[serde(default)]
    pub ip: String,
    #[serde(rename = "endpointSequenceNumber", default)]
    pub endpoint_sequence_number: u32,
}

/// HTTP options for service expose (mirrors provider defaults).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestHttpOptions {
    #[serde(rename = "maxBodySize")]
    pub max_body_size: u32,
    #[serde(rename = "readTimeout")]
    pub read_timeout: u32,
    #[serde(rename = "sendTimeout")]
    pub send_timeout: u32,
    #[serde(rename = "nextTries")]
    pub next_tries: u32,
    #[serde(rename = "nextTimeout")]
    pub next_timeout: u32,
    #[serde(rename = "nextCases")]
    pub next_cases: Vec<String>,
}

impl Default for ManifestHttpOptions {
    fn default() -> Self {
        Self {
            max_body_size: 1_048_576,   // 1MB
            read_timeout: 60_000,        // 60s
            send_timeout: 60_000,        // 60s
            next_tries: 3,
            next_timeout: 0,
            next_cases: vec!["error".to_string(), "timeout".to_string()],
        }
    }
}

/// Resources (mirrors akash.base.resources.v1beta4.Resources).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestResources {
    pub id: u32,
    pub cpu: ManifestCpu,
    pub memory: ManifestMemory,
    pub storage: Vec<ManifestStorage>,
    pub gpu: ManifestGpu,
    #[serde(default)]
    pub endpoints: Vec<serde_json::Value>,
}

/// CPU resource (mirrors akash.base.resources.v1beta4.CPU).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestCpu {
    pub units: ManifestResourceValue,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attributes: Vec<serde_json::Value>,
}

/// Memory resource (mirrors akash.base.resources.v1beta4.Memory).
///
/// CRITICAL: Field is "size" (Go JSON), not "quantity" (proto).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestMemory {
    pub size: ManifestResourceValue,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attributes: Vec<serde_json::Value>,
}

/// Storage resource (mirrors akash.base.resources.v1beta4.Storage).
///
/// CRITICAL: Field is "size" (Go JSON), not "quantity" (proto).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestStorage {
    pub name: String,
    pub size: ManifestResourceValue,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attributes: Vec<serde_json::Value>,
}

/// GPU resource (mirrors akash.base.resources.v1beta4.GPU).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestGpu {
    pub units: ManifestResourceValue,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attributes: Vec<serde_json::Value>,
}

/// Resource value - STRING representation of numeric value.
///
/// CRITICAL: Proto uses bytes, but JSON API expects string.
/// "1000" for CPU millicores, "536870912" for memory bytes, etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestResourceValue {
    pub val: String,
}

/// Service params (mirrors akash.manifest.v2beta3.ServiceParams).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestServiceParams {
    #[serde(default)]
    pub storage: Vec<ManifestStorageParams>,
}

/// Storage params for volume mounts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestStorageParams {
    pub name: String,
    pub mount: String,
    #[serde(rename = "readOnly", default)]
    pub read_only: bool,
}

/// Image pull credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestCredentials {
    pub host: String,
    pub email: String,
    pub username: String,
    pub password: String,
}

// ============================================================================
// Manifest Builder
// ============================================================================

/// Build manifest from SDL YAML.
///
/// Handles:
/// - CPU parsing: "100m" (millicores), "1" (cores), 1.5 (float cores)
/// - Memory/storage size parsing: Gi, Mi, Ki suffixes
/// - GPU attributes: Composite keys (vendor/nvidia/model/h100/ram/80Gi)
/// - Storage attributes: persistent, class (sorted by key)
/// - Service sorting: Provider requires alphabetical by name
pub struct ManifestBuilder {
    #[allow(dead_code)]
    owner: String,
    #[allow(dead_code)]
    dseq: u64,
}

impl ManifestBuilder {
    /// Create a new manifest builder.
    pub fn new(owner: &str, dseq: u64) -> Self {
        Self {
            owner: owner.to_string(),
            dseq,
        }
    }

    /// Build manifest from SDL YAML content.
    ///
    /// Returns Vec<ManifestGroup> ready for canonical JSON serialization.
    pub fn build_from_sdl(&self, sdl_yaml: &str) -> Result<Vec<ManifestGroup>, DeployError> {
        let yaml: serde_yaml::Value = serde_yaml::from_str(sdl_yaml)
            .map_err(|e| DeployError::Sdl(format!("parse error: {}", e)))?;

        self.parse_manifest_groups(&yaml)
    }

    /// Parse manifest groups from SDL.
    ///
    /// The manifest group name must match the deployment group name (placement name in SDL).
    fn parse_manifest_groups(&self, yaml: &serde_yaml::Value) -> Result<Vec<ManifestGroup>, DeployError> {
        let mut groups = Vec::new();

        let services_section = yaml
            .get("services")
            .ok_or_else(|| DeployError::Sdl("Missing 'services' section".into()))?;

        let deployment_section = yaml
            .get("deployment")
            .ok_or_else(|| DeployError::Sdl("Missing 'deployment' section".into()))?;

        let profiles_section = yaml.get("profiles");

        // Extract group name from deployment section (the placement name)
        // SDL structure: deployment: { <service>: { <placement>: { ... } } }
        let group_name = self.extract_group_name(deployment_section)?;

        let mut services = self.parse_services(services_section, deployment_section, profiles_section)?;

        // CRITICAL: Provider requires services sorted by name
        services.sort_by(|a, b| a.name.cmp(&b.name));

        if !services.is_empty() {
            groups.push(ManifestGroup {
                name: group_name,
                services,
            });
        }

        Ok(groups)
    }

    /// Extract group name (placement name) from deployment section.
    fn extract_group_name(&self, deployment: &serde_yaml::Value) -> Result<String, DeployError> {
        let deployment_map = deployment
            .as_mapping()
            .ok_or_else(|| DeployError::Sdl("'deployment' must be a mapping".into()))?;

        // Get first service's first placement name as the group name
        for (_service_name, service_config) in deployment_map {
            if let Some(config_map) = service_config.as_mapping() {
                for (placement_name, _) in config_map {
                    if let Some(name) = placement_name.as_str() {
                        return Ok(name.to_string());
                    }
                }
            }
        }

        // Fallback to "dcloud" which is common default
        Ok("dcloud".to_string())
    }

    /// Parse services from SDL.
    fn parse_services(
        &self,
        services_section: &serde_yaml::Value,
        deployment_section: &serde_yaml::Value,
        profiles_section: Option<&serde_yaml::Value>,
    ) -> Result<Vec<ManifestService>, DeployError> {
        let mut services = Vec::new();

        let services_map = services_section
            .as_mapping()
            .ok_or_else(|| DeployError::Sdl("'services' must be a mapping".into()))?;

        for (name, config) in services_map {
            let service_name = name
                .as_str()
                .ok_or_else(|| DeployError::Sdl("Service name must be string".into()))?;

            let service = self.parse_service(
                service_name,
                config,
                deployment_section,
                profiles_section,
            )?;
            services.push(service);
        }

        Ok(services)
    }

    /// Parse a single service.
    fn parse_service(
        &self,
        name: &str,
        config: &serde_yaml::Value,
        deployment_section: &serde_yaml::Value,
        profiles_section: Option<&serde_yaml::Value>,
    ) -> Result<ManifestService, DeployError> {
        let image = config
            .get("image")
            .and_then(|i| i.as_str())
            .ok_or_else(|| DeployError::Sdl(format!("Service '{}' missing image", name)))?
            .to_string();

        let count = self.get_service_count(name, deployment_section);
        let (command, args) = self.parse_command_args(config);
        let env = self.parse_env(config);
        let expose = self.parse_expose(config)?;
        let resources = self.parse_service_resources(name, profiles_section)?;

        // CRITICAL: Convert empty vecs to None (Go serializes missing fields as null, not [])
        let command = if command.is_empty() { None } else { Some(command) };
        let args = if args.is_empty() { None } else { Some(args) };
        let env = if env.is_empty() { None } else { Some(env) };

        // Parse storage params (mount points)
        let params = self.parse_storage_params(config);

        Ok(ManifestService {
            name: name.to_string(),
            image,
            command,
            args,
            env,
            expose,
            count,
            resources,
            params,
            credentials: None,
        })
    }

    fn get_service_count(&self, service_name: &str, deployment: &serde_yaml::Value) -> u32 {
        deployment
            .get(service_name)
            .and_then(|d| d.as_mapping())
            .and_then(|m| {
                m.values().next().and_then(|v| {
                    v.get("count").and_then(|c| c.as_u64())
                })
            })
            .unwrap_or(1) as u32
    }

    fn parse_command_args(&self, config: &serde_yaml::Value) -> (Vec<String>, Vec<String>) {
        let command = config
            .get("command")
            .and_then(|c| {
                if c.is_sequence() {
                    c.as_sequence()
                        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                } else {
                    c.as_str().map(|s| vec![s.to_string()])
                }
            })
            .unwrap_or_default();

        let args = config
            .get("args")
            .and_then(|a| {
                a.as_sequence()
                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            })
            .unwrap_or_default();

        (command, args)
    }

    fn parse_env(&self, config: &serde_yaml::Value) -> Vec<String> {
        config
            .get("env")
            .and_then(|e| {
                e.as_sequence().map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
            })
            .unwrap_or_default()
    }

    fn parse_storage_params(&self, config: &serde_yaml::Value) -> Option<ManifestServiceParams> {
        let params_section = config.get("params")?.get("storage")?;
        let params_map = params_section.as_mapping()?;

        let mut storage_params = Vec::new();
        for (name, value) in params_map {
            let name = name.as_str()?;
            let mount = value.get("mount")?.as_str()?;
            let read_only = value
                .get("readOnly")
                .and_then(|r| r.as_bool())
                .unwrap_or(false);
            storage_params.push(ManifestStorageParams {
                name: name.to_string(),
                mount: mount.to_string(),
                read_only,
            });
        }

        if storage_params.is_empty() {
            None
        } else {
            Some(ManifestServiceParams {
                storage: storage_params,
            })
        }
    }

    fn parse_expose(&self, config: &serde_yaml::Value) -> Result<Vec<ManifestServiceExpose>, DeployError> {
        let mut exposes = Vec::new();

        let expose_section = match config.get("expose") {
            Some(e) => e,
            None => return Ok(exposes),
        };

        let expose_arr = expose_section
            .as_sequence()
            .ok_or_else(|| DeployError::Sdl("'expose' must be an array".into()))?;

        for expose_config in expose_arr {
            let port = expose_config
                .get("port")
                .and_then(|p| p.as_u64())
                .unwrap_or(80) as u32;

            // external_port: 0 when not explicitly set (matches Go provider behavior)
            let external_port = expose_config
                .get("as")
                .and_then(|p| p.as_u64())
                .unwrap_or(0) as u32;

            let proto = expose_config
                .get("proto")
                .and_then(|p| p.as_str())
                .unwrap_or("TCP")
                .to_uppercase();

            let global = expose_config
                .get("to")
                .and_then(|t| t.as_sequence())
                .map(|arr| {
                    arr.iter().any(|item| {
                        item.get("global")
                            .and_then(|g| g.as_bool())
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false);

            // Parse accept hosts
            let hosts = expose_config
                .get("accept")
                .and_then(|a| a.as_sequence())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect::<Vec<_>>()
                });
            // CRITICAL: Go serializes missing hosts as null, present-but-empty as []
            let hosts = hosts.filter(|h| !h.is_empty());

            exposes.push(ManifestServiceExpose {
                port,
                external_port,
                proto,
                service: String::new(),
                global,
                hosts,
                http_options: ManifestHttpOptions::default(),
                ip: String::new(),
                endpoint_sequence_number: 0,
            });
        }

        Ok(exposes)
    }

    fn parse_service_resources(
        &self,
        service_name: &str,
        profiles: Option<&serde_yaml::Value>,
    ) -> Result<ManifestResources, DeployError> {
        let profiles = profiles.ok_or_else(|| DeployError::Sdl("Missing profiles section".into()))?;

        let compute = profiles
            .get("compute")
            .ok_or_else(|| DeployError::Sdl("Missing compute profiles".into()))?;

        let profile = compute
            .get(service_name)
            .ok_or_else(|| DeployError::Sdl(format!("Missing compute profile for '{}'", service_name)))?;

        let resources = profile
            .get("resources")
            .ok_or_else(|| DeployError::Sdl("Missing resources in profile".into()))?;

        // CPU: parse units - SDL uses millicores notation (e.g. "100m" = 100 millicores)
        // Provider expects millicores as the value (100m → "100")
        let cpu_millicpus = resources
            .get("cpu")
            .and_then(|c| c.get("units"))
            .and_then(|u| {
                if u.is_number() {
                    // Numeric value: treat as whole CPUs → convert to millicores
                    u.as_f64().map(|f| (f * 1000.0) as u64)
                } else {
                    u.as_str().map(|s| {
                        if let Some(millis) = s.strip_suffix('m') {
                            // Already in millicores (e.g. "100m" → 100)
                            millis.parse::<u64>().unwrap_or(1000)
                        } else {
                            // Whole CPUs as string (e.g. "1" → 1000)
                            s.parse::<f64>()
                                .map(|f| (f * 1000.0) as u64)
                                .unwrap_or(1000)
                        }
                    })
                }
            })
            .unwrap_or(1000);

        let cpu = ManifestCpu {
            units: ManifestResourceValue { val: cpu_millicpus.to_string() },
            attributes: Vec::new(),
        };

        // Memory: parse size string to bytes
        let memory_bytes = resources
            .get("memory")
            .and_then(|m| m.get("size"))
            .and_then(|s| s.as_str())
            .map(|s| self.parse_size(s))
            .transpose()?
            .unwrap_or(536_870_912); // 512Mi default

        let memory = ManifestMemory {
            size: ManifestResourceValue { val: memory_bytes.to_string() },
            attributes: Vec::new(),
        };

        let storage = self.parse_storage_resources(resources)?;

        // GPU: always include (provider requires it, default to 0 units)
        let gpu_units = resources
            .get("gpu")
            .and_then(|g| g.get("units"))
            .and_then(|u| u.as_u64())
            .unwrap_or(0);

        let mut gpu_attributes: Vec<serde_json::Value> = Vec::new();

        // Parse GPU attributes (vendor/model/ram composite keys)
        // CRITICAL: Must match provider's expected format
        if gpu_units > 0 {
            if let Some(gpu_section) = resources.get("gpu") {
                if let Some(attrs) = gpu_section.get("attributes") {
                    if let Some(vendor_section) = attrs.get("vendor") {
                        if let Some(vendor_map) = vendor_section.as_mapping() {
                            for (vendor_name, vendor_config) in vendor_map {
                                let vendor = vendor_name.as_str().unwrap_or("nvidia");
                                if let Some(models) = vendor_config.as_sequence() {
                                    for model_entry in models {
                                        if let Some(model_map) = model_entry.as_mapping() {
                                            let model_name = model_map
                                                .get(serde_yaml::Value::String("model".to_string()))
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("");

                                            let ram = model_map
                                                .get(serde_yaml::Value::String("ram".to_string()))
                                                .and_then(|v| v.as_str());

                                            let iface = model_map
                                                .get(serde_yaml::Value::String("interface".to_string()))
                                                .and_then(|v| v.as_str());

                                            if !model_name.is_empty() {
                                                // Composite key: vendor/nvidia/model/h100/ram/80Gi
                                                let mut key = format!("vendor/{}/model/{}", vendor, model_name);
                                                if let Some(ram_value) = ram {
                                                    key.push_str(&format!("/ram/{}", ram_value));
                                                }
                                                if let Some(iface_value) = iface {
                                                    key.push_str(&format!("/interface/{}", iface_value));
                                                }
                                                gpu_attributes.push(serde_json::json!({
                                                    "key": key,
                                                    "value": "true"
                                                }));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let gpu = ManifestGpu {
            units: ManifestResourceValue { val: gpu_units.to_string() },
            attributes: gpu_attributes,
        };

        Ok(ManifestResources {
            id: 1,
            cpu,
            memory,
            storage,
            gpu,
            endpoints: Vec::new(),
        })
    }

    fn parse_storage_resources(&self, resources: &serde_yaml::Value) -> Result<Vec<ManifestStorage>, DeployError> {
        let mut storage_list = Vec::new();

        let storage_section = match resources.get("storage") {
            Some(s) => s,
            None => {
                // Default 1Gi storage
                storage_list.push(ManifestStorage {
                    name: "default".to_string(),
                    size: ManifestResourceValue { val: "1073741824".to_string() },
                    attributes: Vec::new(),
                });
                return Ok(storage_list);
            }
        };

        let storage_arr = if storage_section.is_sequence() {
            storage_section.as_sequence().unwrap().clone()
        } else {
            vec![storage_section.clone()]
        };

        for storage in storage_arr {
            let name = storage
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("default")
                .to_string();

            let size_str = storage
                .get("size")
                .and_then(|s| s.as_str())
                .unwrap_or("1Gi");

            let size_bytes = self.parse_size(size_str)?;

            // Parse storage attributes (persistent, class)
            let mut storage_attrs: Vec<serde_json::Value> = Vec::new();
            if let Some(attrs) = storage.get("attributes") {
                if let Some(persistent) = attrs.get("persistent") {
                    let val = match persistent {
                        serde_yaml::Value::Bool(b) => b.to_string(),
                        serde_yaml::Value::String(s) => s.clone(),
                        _ => "false".to_string(),
                    };
                    storage_attrs.push(serde_json::json!({
                        "key": "persistent",
                        "value": val
                    }));
                }
                if let Some(class) = attrs.get("class") {
                    let val = class.as_str().unwrap_or("default");
                    storage_attrs.push(serde_json::json!({
                        "key": "class",
                        "value": val
                    }));
                }
                // CRITICAL: Sort attributes by key for consistency with Go
                storage_attrs.sort_by(|a, b| {
                    let ak = a.get("key").and_then(|k| k.as_str()).unwrap_or("");
                    let bk = b.get("key").and_then(|k| k.as_str()).unwrap_or("");
                    ak.cmp(bk)
                });
            }

            storage_list.push(ManifestStorage {
                name,
                size: ManifestResourceValue { val: size_bytes.to_string() },
                attributes: storage_attrs,
            });
        }

        Ok(storage_list)
    }

    /// Parse size string (Gi, Mi, Ki suffixes) to bytes.
    fn parse_size(&self, s: &str) -> Result<u64, DeployError> {
        let (num_str, multiplier) = if s.ends_with("Gi") {
            (&s[..s.len() - 2], 1024 * 1024 * 1024u64)
        } else if s.ends_with("Mi") {
            (&s[..s.len() - 2], 1024 * 1024u64)
        } else if s.ends_with("Ki") {
            (&s[..s.len() - 2], 1024u64)
        } else {
            (s, 1u64)
        };

        let num: u64 = num_str
            .parse()
            .map_err(|_| DeployError::Manifest(format!("Invalid size: {}", s)))?;

        Ok(num * multiplier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_size() {
        let builder = ManifestBuilder::new("akash1test", 1);
        assert_eq!(builder.parse_size("1Gi").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(builder.parse_size("512Mi").unwrap(), 512 * 1024 * 1024);
        assert_eq!(builder.parse_size("1024Ki").unwrap(), 1024 * 1024);
    }

    #[test]
    fn test_http_options_defaults() {
        let opts = ManifestHttpOptions::default();
        assert_eq!(opts.max_body_size, 1_048_576);
        assert_eq!(opts.read_timeout, 60_000);
        assert_eq!(opts.next_tries, 3);
        assert_eq!(opts.next_cases, vec!["error".to_string(), "timeout".to_string()]);
    }
}
