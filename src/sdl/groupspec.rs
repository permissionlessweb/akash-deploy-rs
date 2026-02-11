//! SDL to GroupSpec conversion for deployment transactions.
//!
//! This module converts SDL (Stack Definition Language) to Akash GroupSpec format
//! required for creating deployment transactions on-chain.

use crate::error::DeployError;
use std::collections::HashMap;

use crate::gen::akash::{
    base::{
        attributes::v1::{Attribute, PlacementRequirements, SignedBy},
        resources::v1beta4::{Cpu, Gpu, Memory, Resources, Storage},
    },
    deployment::v1beta4::{GroupSpec, ResourceUnit},
};
use crate::gen::cosmos::base::v1beta1::DecCoin;

/// Build GroupSpec list from SDL content.
///
/// This groups services by their placement group and creates one GroupSpec per unique placement.
/// Multiple services in the same placement group are represented as multiple ResourceUnits
/// within a single GroupSpec.
pub fn build_groupspecs_from_sdl(sdl_yaml: &str) -> Result<Vec<GroupSpec>, DeployError> {
    let yaml: serde_yaml::Value = serde_yaml::from_str(sdl_yaml)
        .map_err(|e| DeployError::Sdl(format!("parse error: {}", e)))?;

    let deployment_section = yaml
        .get("deployment")
        .ok_or_else(|| DeployError::Sdl("Missing 'deployment' section".into()))?;

    let profiles_section = yaml
        .get("profiles")
        .ok_or_else(|| DeployError::Sdl("Missing 'profiles' section".into()))?;

    let deployment_map = deployment_section
        .as_mapping()
        .ok_or_else(|| DeployError::Sdl("'deployment' must be a mapping".into()))?;

    // Service info: (service_name, profile_name, count, placement_group)
    let mut service_infos: Vec<(String, String, u32, String)> = Vec::new();

    for (service_name, service_deployment) in deployment_map {
        let service_str = service_name
            .as_str()
            .ok_or_else(|| DeployError::Sdl("Service name must be string".into()))?;

        if let Some(config_map) = service_deployment.as_mapping() {
            // Get the placement group name and config
            for (placement_name, placement_config) in config_map {
                if let Some(group_name) = placement_name.as_str() {
                    // Extract count and profile from placement config
                    let count = placement_config
                        .get("count")
                        .and_then(|c| c.as_u64())
                        .unwrap_or(1) as u32;

                    let profile = placement_config
                        .get("profile")
                        .and_then(|p| p.as_str())
                        .unwrap_or(service_str)
                        .to_string();

                    service_infos.push((
                        service_str.to_string(),
                        profile,
                        count,
                        group_name.to_string(),
                    ));
                    break;
                }
            }
        }
    }

    // Group services by placement group
    let mut groups_map: HashMap<String, Vec<(String, String, u32)>> = HashMap::new();
    for (service, profile, count, group) in service_infos {
        eprintln!(
            "DEBUG: Grouping service '{}' (profile: {}, count: {}) into group '{}'",
            service, profile, count, group
        );
        groups_map
            .entry(group)
            .or_default()
            .push((service, profile, count));
    }

    // Build GroupSpec for each placement group
    let mut groups: Vec<GroupSpec> = Vec::new();

    for (group_name, mut services) in groups_map {
        eprintln!(
            "DEBUG: Building GroupSpec for group '{}' with {} services",
            group_name,
            services.len()
        );

        // CRITICAL: Sort services by name to match manifest service order
        // The manifest builder sorts services alphabetically, so GroupSpec must too
        services.sort_by(|a, b| a.0.cmp(&b.0));

        // Parse placement requirements and pricing for this group
        let (requirements, pricing_map) = parse_placement_for_group(&yaml, &group_name, &services)?;

        // Create ResourceUnits for each service
        let mut resources: Vec<ResourceUnit> = Vec::new();

        for (service_name, profile_name, count) in services {
            eprintln!(
                "DEBUG:   Creating ResourceUnit for service '{}' (profile: {}, count: {})",
                service_name, profile_name, count
            );

            // Parse resources from profile
            let resource = parse_resources_from_profile(profiles_section, &profile_name)?;

            // Get price for this service
            let price = pricing_map.get(&service_name).cloned().ok_or_else(|| {
                DeployError::Sdl(format!("Missing price for service {}", service_name))
            })?;

            resources.push(ResourceUnit {
                resource: Some(resource),
                count,
                price: Some(price),
            });
        }

        eprintln!(
            "DEBUG: GroupSpec '{}' final has {} ResourceUnits",
            group_name,
            resources.len()
        );

        groups.push(GroupSpec {
            name: group_name.clone(),
            requirements: Some(requirements),
            resources,
        });
    }

    // Sort groups by name for deterministic output
    groups.sort_by(|a, b| a.name.cmp(&b.name));

    eprintln!("DEBUG: Final GroupSpec list has {} groups:", groups.len());
    for g in &groups {
        eprintln!(
            "DEBUG:   - Group '{}': {} ResourceUnits",
            g.name,
            g.resources.len()
        );
    }

    Ok(groups)
}

/// Parse placement requirements and pricing for a group.
fn parse_placement_for_group(
    yaml: &serde_yaml::Value,
    group_name: &str,
    services: &[(String, String, u32)],
) -> Result<(PlacementRequirements, HashMap<String, DecCoin>), DeployError> {
    let profiles = yaml
        .get("profiles")
        .ok_or_else(|| DeployError::Sdl("Missing profiles section".into()))?;

    let placement_section = profiles
        .get("placement")
        .ok_or_else(|| DeployError::Sdl("Missing profiles.placement section".into()))?;

    let group_placement = placement_section
        .get(group_name)
        .ok_or_else(|| DeployError::Sdl(format!("Missing placement for group {}", group_name)))?;

    // Parse attributes (if present)
    let mut attributes: Vec<Attribute> = Vec::new();
    if let Some(attrs) = group_placement.get("attributes") {
        if let Some(attr_map) = attrs.as_mapping() {
            for (key, value) in attr_map {
                if let (Some(k), Some(v)) = (key.as_str(), value.as_str()) {
                    attributes.push(Attribute {
                        key: k.to_string(),
                        value: v.to_string(),
                    });
                }
            }
        }
    }

    // Parse pricing for each service
    let pricing = group_placement
        .get("pricing")
        .ok_or_else(|| DeployError::Sdl(format!("Missing pricing for placement {}", group_name)))?;

    let mut pricing_map = HashMap::new();
    for (service_name, _, _) in services {
        let service_pricing = pricing.get(service_name).ok_or_else(|| {
            DeployError::Sdl(format!("Missing price for service {}", service_name))
        })?;

        let denom = service_pricing
            .get("denom")
            .and_then(|d| d.as_str())
            .unwrap_or("uakt")
            .to_string();

        let amount = service_pricing
            .get("amount")
            .and_then(|a| a.as_u64())
            .unwrap_or(100)
            .to_string();

        pricing_map.insert(service_name.clone(), DecCoin { denom, amount });
    }

    let requirements = PlacementRequirements {
        signed_by: Some(SignedBy {
            all_of: Vec::new(),
            any_of: Vec::new(),
        }),
        attributes,
    };

    Ok((requirements, pricing_map))
}

/// Parse resources from profile.
fn parse_resources_from_profile(
    profiles: &serde_yaml::Value,
    profile_name: &str,
) -> Result<Resources, DeployError> {
    let compute = profiles
        .get("compute")
        .ok_or_else(|| DeployError::Sdl("Missing profiles.compute section".into()))?;

    let profile = compute
        .get(profile_name)
        .ok_or_else(|| DeployError::Sdl(format!("Missing compute profile {}", profile_name)))?;

    let resources_section = profile.get("resources").ok_or_else(|| {
        DeployError::Sdl(format!("Missing resources in profile {}", profile_name))
    })?;

    // Parse CPU
    let cpu = parse_cpu(resources_section)?;

    // Parse Memory
    let memory = parse_memory(resources_section)?;

    // Parse Storage
    let storage = parse_storage(resources_section)?;

    // Parse GPU (optional)
    let gpu = parse_gpu(resources_section)?;

    Ok(Resources {
        id: 0, // Will be assigned by chain
        cpu: Some(cpu),
        memory: Some(memory),
        storage,
        gpu: Some(gpu),
        endpoints: Vec::new(),
    })
}

fn parse_cpu(resources: &serde_yaml::Value) -> Result<Cpu, DeployError> {
    let cpu_section = resources
        .get("cpu")
        .ok_or_else(|| DeployError::Sdl("Missing cpu in resources".into()))?;

    let units_val = cpu_section
        .get("units")
        .ok_or_else(|| DeployError::Sdl("Missing cpu.units".into()))?;

    // Convert float to millicores (0.5 -> 500m)
    let units = if let Some(f) = units_val.as_f64() {
        (f * 1000.0) as u32
    } else if let Some(i) = units_val.as_u64() {
        (i * 1000) as u32
    } else {
        return Err(DeployError::Sdl("Invalid cpu.units format".into()));
    };

    Ok(Cpu {
        units: Some(crate::gen::akash::base::resources::v1beta4::ResourceValue {
            val: units.to_string().into_bytes(),
        }),
        attributes: Vec::new(),
    })
}

fn parse_memory(resources: &serde_yaml::Value) -> Result<Memory, DeployError> {
    let mem_section = resources
        .get("memory")
        .ok_or_else(|| DeployError::Sdl("Missing memory in resources".into()))?;

    let size_str = mem_section
        .get("size")
        .and_then(|s| s.as_str())
        .ok_or_else(|| DeployError::Sdl("Missing memory.size".into()))?;

    let size_bytes = parse_size_to_bytes(size_str)?;

    Ok(Memory {
        quantity: Some(crate::gen::akash::base::resources::v1beta4::ResourceValue {
            val: size_bytes.to_string().into_bytes(),
        }),
        attributes: Vec::new(),
    })
}

fn parse_storage(resources: &serde_yaml::Value) -> Result<Vec<Storage>, DeployError> {
    let storage_section = resources.get("storage");

    let storage_vec = if let Some(s) = storage_section {
        if s.is_sequence() {
            s.as_sequence().unwrap().clone()
        } else {
            vec![s.clone()]
        }
    } else {
        // Default storage
        vec![serde_yaml::Value::Mapping(serde_yaml::Mapping::new())]
    };

    let mut storages = Vec::new();
    for (idx, storage) in storage_vec.iter().enumerate() {
        let name = storage
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or(if idx == 0 { "default" } else { "data" })
            .to_string();

        let size_str = storage
            .get("size")
            .and_then(|s| s.as_str())
            .unwrap_or("1Gi");

        let size_bytes = parse_size_to_bytes(size_str)?;

        storages.push(Storage {
            name,
            quantity: Some(crate::gen::akash::base::resources::v1beta4::ResourceValue {
                val: size_bytes.to_string().into_bytes(),
            }),
            attributes: Vec::new(),
        });
    }

    Ok(storages)
}

fn parse_gpu(resources: &serde_yaml::Value) -> Result<Gpu, DeployError> {
    let gpu_section = resources.get("gpu");

    let units = if let Some(gpu) = gpu_section {
        gpu.get("units").and_then(|u| u.as_u64()).unwrap_or(0) as u32
    } else {
        0
    };

    // Parse GPU attributes if present
    let mut attributes: Vec<Attribute> = Vec::new();
    if let Some(gpu) = gpu_section {
        if let Some(attrs) = gpu.get("attributes") {
            if let Some(vendor) = attrs.get("vendor") {
                if let Some(vendor_map) = vendor.as_mapping() {
                    for (vendor_name, models) in vendor_map {
                        if let (Some(v_name), Some(model_arr)) =
                            (vendor_name.as_str(), models.as_sequence())
                        {
                            for model in model_arr {
                                if let Some(model_map) = model.as_mapping() {
                                    let model_name = model_map
                                        .get(serde_yaml::Value::String("model".into()))
                                        .and_then(|m| m.as_str())
                                        .unwrap_or("");

                                    let ram = model_map
                                        .get(serde_yaml::Value::String("ram".into()))
                                        .and_then(|r| r.as_str());

                                    // Build composite key: vendor/nvidia/model/h100/ram/80Gi
                                    let mut key = format!("vendor/{}/model/{}", v_name, model_name);
                                    if let Some(ram_val) = ram {
                                        key.push_str(&format!("/ram/{}", ram_val));
                                    }

                                    attributes.push(Attribute {
                                        key,
                                        value: "true".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(Gpu {
        units: Some(crate::gen::akash::base::resources::v1beta4::ResourceValue {
            val: units.to_string().into_bytes(),
        }),
        attributes,
    })
}

fn parse_size_to_bytes(size: &str) -> Result<u64, DeployError> {
    let (num_str, multiplier) = if size.ends_with("Gi") {
        (&size[..size.len() - 2], 1024u64 * 1024 * 1024)
    } else if size.ends_with("Mi") {
        (&size[..size.len() - 2], 1024u64 * 1024)
    } else if size.ends_with("Ki") {
        (&size[..size.len() - 2], 1024u64)
    } else {
        (size, 1u64)
    };

    let num: u64 = num_str
        .parse()
        .map_err(|_| DeployError::Sdl(format!("Invalid size: {}", size)))?;

    Ok(num * multiplier)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_size_to_bytes ────────────────────────────────────────

    #[test]
    fn test_parse_size_gi() {
        assert_eq!(parse_size_to_bytes("1Gi").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size_to_bytes("4Gi").unwrap(), 4 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_parse_size_mi() {
        assert_eq!(parse_size_to_bytes("512Mi").unwrap(), 512 * 1024 * 1024);
    }

    #[test]
    fn test_parse_size_ki() {
        assert_eq!(parse_size_to_bytes("256Ki").unwrap(), 256 * 1024);
    }

    #[test]
    fn test_parse_size_bytes() {
        assert_eq!(parse_size_to_bytes("4096").unwrap(), 4096);
    }

    #[test]
    fn test_parse_size_invalid() {
        assert!(parse_size_to_bytes("badGi").is_err());
        assert!(parse_size_to_bytes("notanumber").is_err());
    }

    // ── Minimal SDL for helpers ────────────────────────────────────

    fn minimal_sdl() -> &'static str {
        r#"
version: "2.0"
services:
  web:
    image: nginx
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
          units: 0.5
        memory:
          size: 512Mi
        storage:
          size: 1Gi
  placement:
    dcloud:
      attributes:
        region: us-west
      pricing:
        web:
          denom: uakt
          amount: 1000
deployment:
  web:
    dcloud:
      profile: web
      count: 1
"#
    }

    // ── build_groupspecs_from_sdl ─────────────────────────────────

    #[test]
    fn test_basic_sdl_groupspec() {
        let groups = build_groupspecs_from_sdl(minimal_sdl()).unwrap();

        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].name, "dcloud");
        assert_eq!(groups[0].resources.len(), 1);

        let ru = &groups[0].resources[0];
        assert_eq!(ru.count, 1);
        assert!(ru.price.is_some());

        let price = ru.price.as_ref().unwrap();
        assert_eq!(price.denom, "uakt");
        assert_eq!(price.amount, "1000");

        // Check resource parsing
        let res = ru.resource.as_ref().unwrap();
        let cpu = res.cpu.as_ref().unwrap();
        let cpu_val = std::str::from_utf8(&cpu.units.as_ref().unwrap().val).unwrap();
        assert_eq!(cpu_val, "500"); // 0.5 * 1000

        let mem = res.memory.as_ref().unwrap();
        let mem_val = std::str::from_utf8(&mem.quantity.as_ref().unwrap().val).unwrap();
        assert_eq!(mem_val, (512u64 * 1024 * 1024).to_string());

        assert_eq!(res.storage.len(), 1);
        assert_eq!(res.storage[0].name, "default");
    }

    #[test]
    fn test_multi_service_sdl() {
        let sdl = r#"
version: "2.0"
services:
  web:
    image: nginx
  api:
    image: node
profiles:
  compute:
    web:
      resources:
        cpu:
          units: 1
        memory:
          size: 512Mi
        storage:
          size: 1Gi
    api:
      resources:
        cpu:
          units: 2
        memory:
          size: 1Gi
        storage:
          size: 2Gi
  placement:
    westcoast:
      pricing:
        web:
          denom: uakt
          amount: 500
        api:
          denom: uakt
          amount: 800
deployment:
  web:
    westcoast:
      profile: web
      count: 1
  api:
    westcoast:
      profile: api
      count: 2
"#;
        let groups = build_groupspecs_from_sdl(sdl).unwrap();

        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].name, "westcoast");
        // Two services in one group → two ResourceUnits
        assert_eq!(groups[0].resources.len(), 2);

        // Services are sorted alphabetically: api before web
        let api_ru = &groups[0].resources[0];
        assert_eq!(api_ru.count, 2);
        let api_price = api_ru.price.as_ref().unwrap();
        assert_eq!(api_price.amount, "800");

        let web_ru = &groups[0].resources[1];
        assert_eq!(web_ru.count, 1);
        let web_price = web_ru.price.as_ref().unwrap();
        assert_eq!(web_price.amount, "500");
    }

    #[test]
    fn test_cpu_integer_units() {
        let sdl = r#"
version: "2.0"
services:
  web:
    image: nginx
profiles:
  compute:
    web:
      resources:
        cpu:
          units: 2
        memory:
          size: 1Gi
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
        let groups = build_groupspecs_from_sdl(sdl).unwrap();
        let cpu = groups[0].resources[0]
            .resource
            .as_ref()
            .unwrap()
            .cpu
            .as_ref()
            .unwrap();
        let val = std::str::from_utf8(&cpu.units.as_ref().unwrap().val).unwrap();
        assert_eq!(val, "2000"); // 2 * 1000
    }

    #[test]
    fn test_gpu_with_attributes() {
        let sdl = r#"
version: "2.0"
services:
  ml:
    image: pytorch
profiles:
  compute:
    ml:
      resources:
        cpu:
          units: 4
        memory:
          size: 8Gi
        storage:
          size: 50Gi
        gpu:
          units: 1
          attributes:
            vendor:
              nvidia:
                - model: h100
                  ram: 80Gi
  placement:
    dc:
      pricing:
        ml:
          denom: uakt
          amount: 5000
deployment:
  ml:
    dc:
      profile: ml
      count: 1
"#;
        let groups = build_groupspecs_from_sdl(sdl).unwrap();
        let res = groups[0].resources[0].resource.as_ref().unwrap();
        let gpu = res.gpu.as_ref().unwrap();
        let gpu_val = std::str::from_utf8(&gpu.units.as_ref().unwrap().val).unwrap();
        assert_eq!(gpu_val, "1");
        assert_eq!(gpu.attributes.len(), 1);
        assert_eq!(gpu.attributes[0].key, "vendor/nvidia/model/h100/ram/80Gi");
        assert_eq!(gpu.attributes[0].value, "true");
    }

    #[test]
    fn test_no_gpu() {
        let groups = build_groupspecs_from_sdl(minimal_sdl()).unwrap();
        let res = groups[0].resources[0].resource.as_ref().unwrap();
        let gpu = res.gpu.as_ref().unwrap();
        let gpu_val = std::str::from_utf8(&gpu.units.as_ref().unwrap().val).unwrap();
        assert_eq!(gpu_val, "0");
        assert!(gpu.attributes.is_empty());
    }

    #[test]
    fn test_placement_attributes() {
        let groups = build_groupspecs_from_sdl(minimal_sdl()).unwrap();
        let req = groups[0].requirements.as_ref().unwrap();
        assert_eq!(req.attributes.len(), 1);
        assert_eq!(req.attributes[0].key, "region");
        assert_eq!(req.attributes[0].value, "us-west");
    }

    #[test]
    fn test_placement_no_attributes() {
        let sdl = r#"
version: "2.0"
services:
  web:
    image: nginx
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
        let groups = build_groupspecs_from_sdl(sdl).unwrap();
        let req = groups[0].requirements.as_ref().unwrap();
        assert!(req.attributes.is_empty());
    }

    #[test]
    fn test_multiple_storage_entries() {
        let sdl = r#"
version: "2.0"
services:
  web:
    image: nginx
profiles:
  compute:
    web:
      resources:
        cpu:
          units: 1
        memory:
          size: 1Gi
        storage:
          - name: default
            size: 1Gi
          - name: data
            size: 10Gi
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
        let groups = build_groupspecs_from_sdl(sdl).unwrap();
        let res = groups[0].resources[0].resource.as_ref().unwrap();
        assert_eq!(res.storage.len(), 2);
        assert_eq!(res.storage[0].name, "default");
        assert_eq!(res.storage[1].name, "data");
    }

    #[test]
    fn test_default_storage_when_missing() {
        let sdl = r#"
version: "2.0"
services:
  web:
    image: nginx
profiles:
  compute:
    web:
      resources:
        cpu:
          units: 1
        memory:
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
        let groups = build_groupspecs_from_sdl(sdl).unwrap();
        let res = groups[0].resources[0].resource.as_ref().unwrap();
        // Should get default storage
        assert_eq!(res.storage.len(), 1);
        assert_eq!(res.storage[0].name, "default");
    }

    #[test]
    fn test_default_pricing_values() {
        // When denom/amount are missing, defaults kick in
        let sdl = r#"
version: "2.0"
services:
  web:
    image: nginx
profiles:
  compute:
    web:
      resources:
        cpu:
          units: 1
        memory:
          size: 1Gi
        storage:
          size: 1Gi
  placement:
    dc:
      pricing:
        web: {}
deployment:
  web:
    dc:
      profile: web
      count: 1
"#;
        let groups = build_groupspecs_from_sdl(sdl).unwrap();
        let price = groups[0].resources[0].price.as_ref().unwrap();
        assert_eq!(price.denom, "uakt");
        assert_eq!(price.amount, "100");
    }

    // ── Error cases ───────────────────────────────────────────────

    #[test]
    fn test_invalid_yaml() {
        let result = build_groupspecs_from_sdl("{{invalid yaml");
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_deployment_section() {
        let sdl = "version: \"2.0\"\nprofiles: {}";
        let result = build_groupspecs_from_sdl(sdl);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("deployment"));
    }

    #[test]
    fn test_missing_profiles_section() {
        let sdl =
            "version: \"2.0\"\ndeployment:\n  web:\n    dc:\n      profile: web\n      count: 1";
        let result = build_groupspecs_from_sdl(sdl);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("profiles"));
    }

    #[test]
    fn test_missing_compute_profile() {
        let sdl = r#"
version: "2.0"
services:
  web:
    image: nginx
profiles:
  compute: {}
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
        let result = build_groupspecs_from_sdl(sdl);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("compute profile"));
    }

    #[test]
    fn test_missing_pricing_section() {
        let sdl = r#"
version: "2.0"
services:
  web:
    image: nginx
profiles:
  compute:
    web:
      resources:
        cpu:
          units: 1
        memory:
          size: 1Gi
        storage:
          size: 1Gi
  placement:
    dc: {}
deployment:
  web:
    dc:
      profile: web
      count: 1
"#;
        let result = build_groupspecs_from_sdl(sdl);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("pricing"));
    }

    #[test]
    fn test_missing_service_in_pricing() {
        let sdl = r#"
version: "2.0"
services:
  web:
    image: nginx
profiles:
  compute:
    web:
      resources:
        cpu:
          units: 1
        memory:
          size: 1Gi
        storage:
          size: 1Gi
  placement:
    dc:
      pricing:
        other_service:
          denom: uakt
          amount: 100
deployment:
  web:
    dc:
      profile: web
      count: 1
"#;
        let result = build_groupspecs_from_sdl(sdl);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("price"));
    }

    #[test]
    fn test_missing_cpu_in_resources() {
        let sdl = r#"
version: "2.0"
services:
  web:
    image: nginx
profiles:
  compute:
    web:
      resources:
        memory:
          size: 1Gi
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
        let result = build_groupspecs_from_sdl(sdl);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cpu"));
    }

    #[test]
    fn test_missing_memory_in_resources() {
        let sdl = r#"
version: "2.0"
services:
  web:
    image: nginx
profiles:
  compute:
    web:
      resources:
        cpu:
          units: 1
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
        let result = build_groupspecs_from_sdl(sdl);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("memory"));
    }

    #[test]
    fn test_gpu_model_without_ram() {
        let sdl = r#"
version: "2.0"
services:
  ml:
    image: pytorch
profiles:
  compute:
    ml:
      resources:
        cpu:
          units: 4
        memory:
          size: 8Gi
        storage:
          size: 50Gi
        gpu:
          units: 1
          attributes:
            vendor:
              nvidia:
                - model: a100
  placement:
    dc:
      pricing:
        ml:
          denom: uakt
          amount: 5000
deployment:
  ml:
    dc:
      profile: ml
      count: 1
"#;
        let groups = build_groupspecs_from_sdl(sdl).unwrap();
        let gpu = groups[0].resources[0]
            .resource
            .as_ref()
            .unwrap()
            .gpu
            .as_ref()
            .unwrap();
        assert_eq!(gpu.attributes.len(), 1);
        // No ram suffix
        assert_eq!(gpu.attributes[0].key, "vendor/nvidia/model/a100");
    }

    #[test]
    fn test_groups_sorted_by_name() {
        let sdl = r#"
version: "2.0"
services:
  web:
    image: nginx
  api:
    image: node
profiles:
  compute:
    web:
      resources:
        cpu:
          units: 1
        memory:
          size: 512Mi
        storage:
          size: 1Gi
    api:
      resources:
        cpu:
          units: 1
        memory:
          size: 512Mi
        storage:
          size: 1Gi
  placement:
    zgroup:
      pricing:
        web:
          denom: uakt
          amount: 100
    agroup:
      pricing:
        api:
          denom: uakt
          amount: 200
deployment:
  web:
    zgroup:
      profile: web
      count: 1
  api:
    agroup:
      profile: api
      count: 1
"#;
        let groups = build_groupspecs_from_sdl(sdl).unwrap();
        assert_eq!(groups.len(), 2);
        // Sorted alphabetically
        assert_eq!(groups[0].name, "agroup");
        assert_eq!(groups[1].name, "zgroup");
    }
}
