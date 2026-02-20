// ─── Credential Types ────────────────────────────────────────────────────────

export interface StoredCredential {
  id: string;
  type: CredentialType;
  issuerName: string;
  issuedAt: string;
  expiresAt: string | null;
  encryptedData: string;       // base64-encoded AES-GCM ciphertext
  commitment: string;          // Pedersen commitment hex
}

export type CredentialType =
  | 'identity'
  | 'kyc'
  | 'degree'
  | 'license'
  | 'membership';

export interface DecryptedCredential {
  id: string;
  type: CredentialType;
  issuerName: string;
  issuedAt: string;
  expiresAt: string | null;
  commitment: string;
  attributes: Record<string, unknown>;
  birthdate?: string;
  signature?: string;
}

// ─── Witness / Proof Types ───────────────────────────────────────────────────

export interface WitnessResult {
  circuit_type: string;
  private_inputs: Record<string, string>;
  public_inputs: Record<string, string>;
}

export interface ProofStatus {
  proof_id: string;
  status: 'pending' | 'generating' | 'complete' | 'failed';
  proof_hash?: string;
  verified?: boolean;
  error?: string;
}

// ─── Auth Types ──────────────────────────────────────────────────────────────

export interface AuthRequest {
  origin: string;
  scopes: string[];
  nonce: string;
  callbackId: string;
}

export interface AuthApproval {
  approved: boolean;
  selectedCredentialIds: string[];
  authRequest: AuthRequest;
}

export interface AuthResult {
  proofs: Array<{
    scope: string;
    proof_id: string;
    proof_hash: string;
    zkid: string;
    verified: boolean;
  }>;
  nonce: string;
}

// ─── Wallet State ────────────────────────────────────────────────────────────

export interface WalletState {
  credentials: StoredCredential[];
  isLocked: boolean;
  serverUrl: string;
}

export interface WalletSettings {
  serverUrl: string;
  autoLockMinutes: number;
}

// ─── Message Types (background <-> popup <-> content) ────────────────────────

export type MessageType =
  // Wallet lifecycle
  | 'WALLET_IS_INITIALIZED'
  | 'WALLET_IS_UNLOCKED'
  | 'WALLET_INITIALIZE'
  | 'WALLET_UNLOCK'
  | 'WALLET_LOCK'
  // Credentials
  | 'CREDENTIALS_GET'
  | 'CREDENTIALS_SAVE'
  | 'CREDENTIALS_DELETE'
  | 'CREDENTIALS_IMPORT'
  // Auth flow
  | 'AUTH_REQUEST'
  | 'AUTH_APPROVE'
  | 'AUTH_DENY'
  | 'AUTH_RESULT'
  // Proof
  | 'PROOF_GENERATE'
  | 'PROOF_STATUS'
  // Settings
  | 'SETTINGS_GET'
  | 'SETTINGS_UPDATE'
  // Content script -> background
  | 'CONTENT_AUTH_REQUEST'
  | 'CONTENT_PROOF_RESULT';

export interface ExtensionMessage<T = unknown> {
  type: MessageType;
  payload: T;
}

export interface ExtensionResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
}

// ─── Content Script Page Communication ───────────────────────────────────────

export interface PageMessage {
  type: string;
  id: number;
  data?: unknown;
}

export interface PageResponse {
  type: string;
  id: number;
  success: boolean;
  data?: unknown;
  error?: string;
}

// ─── Credential Import ───────────────────────────────────────────────────────

export interface CredentialImportData {
  type: CredentialType;
  issuerName: string;
  expiresAt: string | null;
  attributes: Record<string, unknown>;
  birthdate?: string;
  commitment: string;
  signature?: string;
}
