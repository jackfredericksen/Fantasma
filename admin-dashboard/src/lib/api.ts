const API_BASE = '/admin';

let apiKey = '';

export function setApiKey(key: string) {
  apiKey = key;
}

export function getApiKey(): string {
  return apiKey;
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'X-Admin-Key': apiKey,
      ...options.headers
    }
  });

  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }

  if (res.status === 204) return undefined as T;
  return res.json();
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface AdminStats {
  clients: number;
  proofs: number;
  issuers: number;
  audit_entries: number;
  using_database: boolean;
}

export interface Client {
  id: string;
  client_id: string;
  client_name: string;
  redirect_uris: string[];
  allowed_scopes: string[];
  client_type: string;
  created_at: string;
}

export interface StoredProof {
  id: string;
  proof_id: string;
  circuit_type: string;
  verified: boolean;
  user_id: string | null;
  created_at: string;
  expires_at: string | null;
}

export interface Issuer {
  id: string;
  issuer_id: string;
  name: string;
  public_key_algorithm: string;
  verification_url: string | null;
  trusted: boolean;
  created_at: string;
}

export interface AuditLogEntry {
  id: string;
  event_type: string;
  user_id: string | null;
  client_id: string | null;
  details: any;
  ip_address: string | null;
  created_at: string;
}

export interface DetailedHealth {
  status: string;
  database: { connected: boolean; pool_size: number; pool_idle: number };
  uptime_seconds: number;
}

// Stats
export const getStats = () => request<AdminStats>('/stats');

// Clients
export const getClients = (limit = 20, offset = 0) =>
  request<PaginatedResponse<Client>>(`/clients?limit=${limit}&offset=${offset}`);
export const createClient = (data: { client_id: string; client_name: string; redirect_uris: string[]; allowed_scopes: string[]; client_type?: string }) =>
  request<void>('/clients', { method: 'POST', body: JSON.stringify(data) });
export const deleteClient = (clientId: string) =>
  request<void>(`/clients/${clientId}`, { method: 'DELETE' });

// Proofs
export const getProofs = (limit = 20, offset = 0, circuit_type?: string) => {
  let url = `/proofs?limit=${limit}&offset=${offset}`;
  if (circuit_type) url += `&circuit_type=${circuit_type}`;
  return request<PaginatedResponse<StoredProof>>(url);
};

// Issuers
export const getIssuers = () => request<Issuer[]>('/issuers');
export const createIssuer = (data: { issuer_id: string; name: string; public_key: string; public_key_algorithm: string; verification_url?: string; trusted?: boolean }) =>
  request<void>('/issuers', { method: 'POST', body: JSON.stringify(data) });
export const deleteIssuer = (issuerId: string) =>
  request<void>(`/issuers/${issuerId}`, { method: 'DELETE' });

// Audit
export const getAudit = (limit = 50, offset = 0) =>
  request<PaginatedResponse<AuditLogEntry>>(`/audit?limit=${limit}&offset=${offset}`);

// Health
export const getDetailedHealth = () => request<DetailedHealth>('/health/detailed');
