/**
 * API client for the Fantasma proof server.
 */

import type { WitnessResult, ProofStatus } from './types';
import { getSettings } from './storage';

// ─── Server Discovery ────────────────────────────────────────────────────────

interface ServerInfo {
  version: string;
  circuits: string[];
  healthy: boolean;
}

/**
 * Discover and health-check the Fantasma server.
 */
export async function discoverServer(
  serverUrl?: string
): Promise<ServerInfo> {
  const url = serverUrl ?? (await getSettings()).serverUrl;

  const response = await fetch(`${url}/health`, {
    method: 'GET',
    headers: { Accept: 'application/json' }
  });

  if (!response.ok) {
    throw new Error(`Server health check failed: ${response.status}`);
  }

  const body = (await response.json()) as Record<string, unknown>;

  return {
    version: (body.version as string) ?? 'unknown',
    circuits: (body.circuits as string[]) ?? [],
    healthy: true
  };
}

// ─── Witness Submission ──────────────────────────────────────────────────────

interface SubmitWitnessResponse {
  proof_id: string;
  status: string;
}

/**
 * Submit a witness (private + public inputs) to the server for proof
 * generation.
 */
export async function submitWitness(
  witness: WitnessResult,
  serverUrl?: string
): Promise<SubmitWitnessResponse> {
  const url = serverUrl ?? (await getSettings()).serverUrl;

  const response = await fetch(`${url}/api/v1/proofs/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      circuit_type: witness.circuit_type,
      private_inputs: witness.private_inputs,
      public_inputs: witness.public_inputs
    })
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Witness submission failed (${response.status}): ${errorBody}`);
  }

  return (await response.json()) as SubmitWitnessResponse;
}

// ─── Proof Status ────────────────────────────────────────────────────────────

/**
 * Poll the server for the status of a previously submitted proof.
 */
export async function getProofStatus(
  proofId: string,
  serverUrl?: string
): Promise<ProofStatus> {
  const url = serverUrl ?? (await getSettings()).serverUrl;

  const response = await fetch(`${url}/api/v1/proofs/${proofId}`, {
    method: 'GET',
    headers: { Accept: 'application/json' }
  });

  if (!response.ok) {
    throw new Error(`Proof status check failed: ${response.status}`);
  }

  return (await response.json()) as ProofStatus;
}

/**
 * Poll until the proof reaches a terminal state (complete or failed).
 */
export async function waitForProof(
  proofId: string,
  serverUrl?: string,
  pollIntervalMs = 2000,
  maxAttempts = 60
): Promise<ProofStatus> {
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const status = await getProofStatus(proofId, serverUrl);

    if (status.status === 'complete' || status.status === 'failed') {
      return status;
    }

    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
  }

  throw new Error('Proof generation timed out');
}
