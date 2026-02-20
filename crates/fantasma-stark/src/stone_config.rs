//! Stone prover configuration templates
//!
//! Configuration for StarkWare's cpu_air_prover and cpu_air_verifier binaries.

use serde::{Deserialize, Serialize};

/// Stone prover configuration (passed as JSON to cpu_air_prover)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoneProverConfig {
    pub constraint_polynomial_task_size: u32,
    pub n_out_of_memory_merkle_layers: u32,
    pub table_prover_n_tasks_per_segment: u32,
}

impl Default for StoneProverConfig {
    fn default() -> Self {
        Self {
            constraint_polynomial_task_size: 256,
            n_out_of_memory_merkle_layers: 1,
            table_prover_n_tasks_per_segment: 32,
        }
    }
}

/// Stone prover parameters (FRI configuration)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoneProverParameters {
    pub field: String,
    pub stark: StarkParameters,
    pub fri: FriParameters,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarkParameters {
    pub fri: FriStarkParameters,
    pub log_n_cosets: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriStarkParameters {
    pub fri_step_list: Vec<u32>,
    pub last_layer_degree_bound: u32,
    pub n_queries: u32,
    pub proof_of_work_bits: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriParameters {
    pub fri_step_list: Vec<u32>,
    pub last_layer_degree_bound: u32,
    pub n_queries: u32,
    pub proof_of_work_bits: u32,
}

impl Default for StoneProverParameters {
    fn default() -> Self {
        Self {
            field: "PrimeField0".to_string(),
            stark: StarkParameters {
                fri: FriStarkParameters {
                    fri_step_list: vec![0, 4, 4, 3],
                    last_layer_degree_bound: 64,
                    n_queries: 18,
                    proof_of_work_bits: 24,
                },
                log_n_cosets: 2,
            },
            fri: FriParameters {
                fri_step_list: vec![0, 4, 4, 3],
                last_layer_degree_bound: 64,
                n_queries: 18,
                proof_of_work_bits: 24,
            },
        }
    }
}

impl StoneProverParameters {
    /// High-security parameters (128-bit security)
    pub fn high_security() -> Self {
        Self {
            field: "PrimeField0".to_string(),
            stark: StarkParameters {
                fri: FriStarkParameters {
                    fri_step_list: vec![0, 4, 4, 4, 3],
                    last_layer_degree_bound: 128,
                    n_queries: 30,
                    proof_of_work_bits: 30,
                },
                log_n_cosets: 4,
            },
            fri: FriParameters {
                fri_step_list: vec![0, 4, 4, 4, 3],
                last_layer_degree_bound: 128,
                n_queries: 30,
                proof_of_work_bits: 30,
            },
        }
    }
}
