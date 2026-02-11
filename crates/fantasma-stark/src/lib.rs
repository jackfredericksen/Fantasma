//! Fantasma STARK
//!
//! STARK prover/verifier integration for Fantasma.
//! This crate provides the interface between Rust and Cairo circuits.

pub mod cairo_runner;
pub mod circuit;
pub mod prover;
pub mod verifier;
pub mod witness;

pub use cairo_runner::{AgeVerificationCircuit, AgeVerificationProof, CairoError, CairoRunner};
pub use circuit::{Circuit, CircuitType};
pub use prover::{Prover, ProverError};
pub use verifier::{Verifier, VerifierError};
pub use witness::Witness;
