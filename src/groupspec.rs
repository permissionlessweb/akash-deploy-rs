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
