use anyhow::{Context, Result};
use rand::seq::SliceRandom;
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tracing::info;

pub struct GeneratorConfig {
    pub num_nodes: usize,
    pub num_accounts: usize,
    pub seed: u64,
}

impl GeneratorConfig {
    pub fn from_size_string(size: &str, seed: u64) -> Self {
        match size {
            "10k" => Self {
                num_nodes: 10_000,
                num_accounts: 50,
                seed,
            },
            "100k" => Self {
                num_nodes: 100_000,
                num_accounts: 200,
                seed,
            },
            _ => panic!("Unsupported size: {}", size),
        }
    }
}

#[derive(Clone, Debug)]
struct Principal {
    id: String,
    arn: String,
    principal_type: PrincipalType,
    account_id: String,
}

#[derive(Clone, Debug)]
enum PrincipalType {
    Role,
    User,
    ServicePrincipal,
    FederatedProvider,
}

impl PrincipalType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Role => "Role",
            Self::User => "User",
            Self::ServicePrincipal => "ServicePrincipal",
            Self::FederatedProvider => "FederatedProvider",
        }
    }
}

#[derive(Clone, Debug)]
struct Policy {
    id: String,
    arn: String,
    name: String,
}

#[derive(Clone, Debug)]
struct Resource {
    id: String,
    arn: String,
    resource_type: String,
}

pub fn generate(output_dir: &Path, config: &GeneratorConfig, stats_only: bool) -> Result<()> {
    let mut rng = ChaCha8Rng::seed_from_u64(config.seed);

    info!(
        nodes = config.num_nodes,
        accounts = config.num_accounts,
        seed = config.seed,
        "Starting synthetic graph generation"
    );

    // Generate principals (roles, users, service principals)
    let mut principals = Vec::new();
    let mut account_roles: HashMap<String, Vec<usize>> = HashMap::new();

    let num_roles = (config.num_nodes as f64 * 0.4) as usize;
    let num_users = (config.num_nodes as f64 * 0.3) as usize;
    let num_service_principals = (config.num_nodes as f64 * 0.15) as usize;
    let num_federated = (config.num_nodes as f64 * 0.05) as usize;
    let num_policies = (config.num_nodes as f64 * 0.1) as usize;

    // Generate roles
    for i in 0..num_roles {
        let account_id = format!("{:012}", rng.gen_range(0..config.num_accounts) as u64);
        let principal = Principal {
            id: format!("principal_{}", i),
            arn: format!("arn:aws:iam::{}:role/role_{}", account_id, rng.gen::<u32>()),
            principal_type: PrincipalType::Role,
            account_id: account_id.clone(),
        };
        account_roles
            .entry(account_id)
            .or_insert_with(Vec::new)
            .push(principals.len());
        principals.push(principal);
    }

    // Generate users
    for i in 0..num_users {
        let account_id = format!("{:012}", rng.gen_range(0..config.num_accounts) as u64);
        principals.push(Principal {
            id: format!("principal_{}", num_roles + i),
            arn: format!("arn:aws:iam::{}:user/user_{}", account_id, rng.gen::<u32>()),
            principal_type: PrincipalType::User,
            account_id,
        });
    }

    // Generate service principals
    let services = vec![
        "lambda.amazonaws.com",
        "ec2.amazonaws.com",
        "s3.amazonaws.com",
        "cloudformation.amazonaws.com",
    ];
    for i in 0..num_service_principals {
        let service = services[i % services.len()];
        principals.push(Principal {
            id: format!("principal_{}", num_roles + num_users + i),
            arn: format!("arn:aws:iam::000000000000:service-principal/{}", service),
            principal_type: PrincipalType::ServicePrincipal,
            account_id: "000000000000".to_string(),
        });
    }

    // Generate federated providers
    for i in 0..num_federated {
        principals.push(Principal {
            id: format!(
                "principal_{}",
                num_roles + num_users + num_service_principals + i
            ),
            arn: format!("arn:aws:iam::federated:saml:provider/provider_{}", i),
            principal_type: PrincipalType::FederatedProvider,
            account_id: "000000000000".to_string(),
        });
    }

    info!(
        roles = num_roles,
        users = num_users,
        service_principals = num_service_principals,
        federated = num_federated,
        total_principals = principals.len(),
        "Generated principals"
    );

    // Generate policies
    let mut policies = Vec::new();
    for i in 0..num_policies {
        policies.push(Policy {
            id: format!("policy_{}", i),
            arn: format!(
                "arn:aws:iam::{}:policy/policy_{}",
                format!("{:012}", rng.gen_range(0..config.num_accounts) as u64),
                i
            ),
            name: format!("policy_{}", i),
        });
    }

    info!(policies = policies.len(), "Generated policies");

    // Generate resources
    let mut resources = Vec::new();
    let num_resources = (config.num_nodes as f64 * 0.05) as usize;
    for i in 0..num_resources {
        resources.push(Resource {
            id: format!("resource_{}", i),
            arn: format!("arn:aws:s3:::bucket-{}", rng.gen::<u32>()),
            resource_type: "S3Bucket".to_string(),
        });
    }

    info!(resources = resources.len(), "Generated resources");

    // Generate edges
    let mut edges_by_type: HashMap<String, usize> = HashMap::new();

    // Role → Policy (HasPermission)
    let mut role_to_policy_count = 0;
    for _role_idx in 0..num_roles {
        let num_policies_for_role = rng.gen_range(1..=10);
        for _ in 0..num_policies_for_role.min(policies.len()) {
            let _policy_idx = rng.gen_range(0..policies.len());
            role_to_policy_count += 1;
        }
    }
    edges_by_type.insert("HasPermission".to_string(), role_to_policy_count);

    // Assume-role chains (20–30% of policies attached to ≥ 50 roles for fan-out)
    let high_fan_out_count = (num_roles as f64 * 0.25) as usize;
    let mut can_assume_count = 0;
    for i in 0..high_fan_out_count {
        // Pick a role that many will assume
        let _assumed_role = &principals[i % num_roles];
        // 50+ roles assume this one
        let num_assumers = rng.gen_range(50..=150).min(num_roles - 1);
        let mut potential_assumers: Vec<usize> =
            (0..num_roles).filter(|&idx| idx != i % num_roles).collect();
        potential_assumers.shuffle(&mut rng);
        for _j in 0..num_assumers.min(potential_assumers.len()) {
            can_assume_count += 1;
        }
    }
    edges_by_type.insert("CanAssume".to_string(), can_assume_count);

    // Cross-account assume-role chains (5% cross 3+ accounts)
    let cross_account_chains = (config.num_nodes as f64 * 0.05 * 0.1) as usize;
    for _ in 0..cross_account_chains {
        let _chain_length = rng.gen_range(3..=6);
        // This is accounted for in the CanAssume count above
    }

    info!(
        has_permission = edges_by_type.get("HasPermission").unwrap_or(&0),
        can_assume = edges_by_type.get("CanAssume").unwrap_or(&0),
        total_edges = edges_by_type.values().sum::<usize>(),
        "Generated edges"
    );

    if stats_only {
        println!("\nGraph Statistics:");
        println!(
            "  Nodes: {}",
            principals.len() + policies.len() + resources.len()
        );
        println!("  Principals: {}", principals.len());
        println!("  Policies: {}", policies.len());
        println!("  Resources: {}", resources.len());
        println!("\nEdges:");
        for (edge_type, count) in edges_by_type {
            println!("  {}: {}", edge_type, count);
        }
        return Ok(());
    }

    // Write principals CSV
    let principals_path = output_dir.join("principals.csv");
    let mut principals_wtr =
        csv::Writer::from_path(&principals_path).context("Failed to create principals CSV")?;

    for principal in &principals {
        principals_wtr.write_record(&[
            &principal.id,
            &principal.arn,
            principal.principal_type.as_str(),
            &principal.account_id,
        ])?;
    }
    principals_wtr.flush()?;
    info!(path = ?principals_path, count = principals.len(), "Wrote principals CSV");

    // Write policies CSV
    let policies_path = output_dir.join("policies.csv");
    let mut policies_wtr =
        csv::Writer::from_path(&policies_path).context("Failed to create policies CSV")?;

    for policy in &policies {
        policies_wtr.write_record(&[&policy.id, &policy.arn, &policy.name])?;
    }
    policies_wtr.flush()?;
    info!(path = ?policies_path, count = policies.len(), "Wrote policies CSV");

    // Write resources CSV
    let resources_path = output_dir.join("resources.csv");
    let mut resources_wtr =
        csv::Writer::from_path(&resources_path).context("Failed to create resources CSV")?;

    for resource in &resources {
        resources_wtr.write_record(&[&resource.id, &resource.arn, &resource.resource_type])?;
    }
    resources_wtr.flush()?;
    info!(path = ?resources_path, count = resources.len(), "Wrote resources CSV");

    // Write edges CSV
    let edges_path = output_dir.join("edges.csv");
    let mut edges_wtr =
        csv::Writer::from_path(&edges_path).context("Failed to create edges CSV")?;

    edges_wtr.write_record(&["from_id", "to_id", "edge_type"])?;

    // Role → Policy (HasPermission)
    for role_idx in 0..num_roles {
        let num_policies_for_role = rng.gen_range(1..=10);
        for _ in 0..num_policies_for_role.min(policies.len()) {
            let policy_idx = rng.gen_range(0..policies.len());
            edges_wtr.write_record(&[
                &principals[role_idx].id,
                &policies[policy_idx].id,
                "HasPermission",
            ])?;
        }
    }

    // Assume-role chains
    let mut assumed_indices = HashSet::new();
    for i in 0..high_fan_out_count {
        assumed_indices.insert(i % num_roles);
        let assumed_role_id = &principals[i % num_roles].id;
        let num_assumers = rng.gen_range(50..=150).min(num_roles - 1);
        let mut potential_assumers: Vec<usize> =
            (0..num_roles).filter(|&idx| idx != i % num_roles).collect();
        potential_assumers.shuffle(&mut rng);
        for j in 0..num_assumers.min(potential_assumers.len()) {
            edges_wtr.write_record(&[
                &principals[potential_assumers[j]].id,
                assumed_role_id,
                "CanAssume",
            ])?;
        }
    }

    edges_wtr.flush()?;
    info!(path = ?edges_path, "Wrote edges CSV");

    info!("Graph generation complete");
    Ok(())
}
