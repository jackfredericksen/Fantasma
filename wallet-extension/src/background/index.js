/**
 * Fantasma Wallet Background Service Worker
 * Handles wallet operations and communication with content scripts
 */

import { walletStorage } from '../utils/storage.js';
import { generatePseudonym, sha256, bytesToHex, generateNullifier } from '../utils/crypto.js';

// Auto-lock timer
let autoLockTimer = null;
const DEFAULT_AUTO_LOCK_MINUTES = 15;

/**
 * Message handlers
 */
const handlers = {
  // Wallet state
  async isInitialized() {
    return await walletStorage.isInitialized();
  },

  async isUnlocked() {
    return walletStorage.isUnlocked;
  },

  async initialize({ password }) {
    return await walletStorage.initialize(password);
  },

  async unlock({ password }) {
    const result = await walletStorage.unlock(password);
    if (result) {
      resetAutoLockTimer();
    }
    return result;
  },

  async lock() {
    walletStorage.lock();
    clearAutoLockTimer();
    return true;
  },

  // Credentials
  async getCredentials() {
    resetAutoLockTimer();
    return await walletStorage.getCredentials();
  },

  async storeCredential({ credential }) {
    resetAutoLockTimer();
    return await walletStorage.storeCredential(credential);
  },

  async deleteCredential({ credentialId }) {
    resetAutoLockTimer();
    return await walletStorage.deleteCredential(credentialId);
  },

  // Issuers
  async getIssuers() {
    return await walletStorage.getIssuers();
  },

  async addIssuer({ issuer }) {
    return await walletStorage.addIssuer(issuer);
  },

  // Settings
  async getSettings() {
    return await walletStorage.getSettings();
  },

  async updateSettings({ settings }) {
    await walletStorage.updateSettings(settings);
    resetAutoLockTimer();
    return true;
  },

  // ZK proof generation
  async generateProof({ credentialId, claimType, domain, serverProofEndpoint }) {
    resetAutoLockTimer();

    const credentials = await walletStorage.getCredentials();
    const credential = credentials.find(c => c.id === credentialId);

    if (!credential) {
      throw new Error('Credential not found');
    }

    // Generate pseudonymous user ID for this domain
    const masterSecret = walletStorage.getMasterSecret();
    const pseudonym = await generatePseudonym(masterSecret, domain);
    const zkid = `zkid:${bytesToHex(pseudonym).slice(0, 40)}`;

    // Generate nullifier for replay prevention
    const nullifier = generateNullifier();

    // Check if nullifier already used
    if (await walletStorage.isNullifierUsed(nullifier, domain)) {
      throw new Error('Proof already used for this domain');
    }

    // For now, use server-assisted proving (client-side STARK proving is expensive)
    // In production, this could be done via WASM
    const proofRequest = {
      credential_id: bytesToHex(new Uint8Array(credential.id)),
      claim_type: claimType,
      domain: domain,
      nullifier: bytesToHex(nullifier),
      zkid: zkid,
      birthdate: credential.birthdate,
      commitment: credential.commitment,
      signature_hash: credential.signature ? await sha256(credential.signature) : null
    };

    // Request proof from server
    const response = await fetch(`${serverProofEndpoint}/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(proofRequest)
    });

    if (!response.ok) {
      throw new Error('Failed to generate proof');
    }

    const proof = await response.json();

    // Record nullifier usage
    await walletStorage.recordNullifier(nullifier, domain);

    return {
      proof_id: proof.proof_id,
      proof_hash: proof.proof_hash,
      zkid: zkid,
      claim_type: claimType,
      verified: proof.verified
    };
  },

  // Authorization flow
  async handleAuthorization({ authRequest }) {
    resetAutoLockTimer();

    const {
      client_id,
      redirect_uri,
      scope,
      state,
      nonce,
      response_type
    } = authRequest;

    // Parse requested ZK scopes
    const zkScopes = scope.split(' ').filter(s => s.startsWith('zk:'));

    // Get credentials that can satisfy the scopes
    const credentials = await walletStorage.getCredentials();
    const matchingCredentials = credentials.filter(cred => {
      return zkScopes.some(scope => {
        if (scope.startsWith('zk:age:') && cred.type === 'identity') {
          return true;
        }
        if (scope.startsWith('zk:kyc:') && cred.type === 'kyc') {
          return true;
        }
        return false;
      });
    });

    return {
      client_id,
      redirect_uri,
      zkScopes,
      matchingCredentials,
      state,
      nonce
    };
  },

  // Complete authorization
  async completeAuthorization({ selectedCredentials, authRequest }) {
    resetAutoLockTimer();

    const domain = new URL(authRequest.redirect_uri).hostname;

    // Generate proofs for selected credentials
    const proofs = [];
    for (const credId of selectedCredentials) {
      for (const scope of authRequest.zkScopes) {
        const claimType = parseClaimType(scope);
        if (claimType) {
          const proof = await handlers.generateProof({
            credentialId: credId,
            claimType,
            domain,
            serverProofEndpoint: 'http://localhost:3000'
          });
          proofs.push({ scope, proof });
        }
      }
    }

    return {
      proofs,
      state: authRequest.state,
      nonce: authRequest.nonce
    };
  }
};

/**
 * Parse claim type from ZK scope
 */
function parseClaimType(scope) {
  if (scope.startsWith('zk:age:')) {
    const threshold = parseInt(scope.split(':')[2]);
    return { type: 'age_at_least', threshold };
  }
  if (scope.startsWith('zk:kyc:')) {
    const level = scope.split(':')[2];
    return { type: 'kyc_level', level };
  }
  return null;
}

/**
 * Reset auto-lock timer
 */
async function resetAutoLockTimer() {
  clearAutoLockTimer();

  const settings = await walletStorage.getSettings();
  const minutes = settings.autoLockMinutes || DEFAULT_AUTO_LOCK_MINUTES;

  autoLockTimer = setTimeout(() => {
    walletStorage.lock();
    console.log('Wallet auto-locked');
  }, minutes * 60 * 1000);
}

/**
 * Clear auto-lock timer
 */
function clearAutoLockTimer() {
  if (autoLockTimer) {
    clearTimeout(autoLockTimer);
    autoLockTimer = null;
  }
}

/**
 * Message listener
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const { type, payload } = message;

  if (handlers[type]) {
    handlers[type](payload || {})
      .then(result => sendResponse({ success: true, data: result }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true; // Keep channel open for async response
  }

  sendResponse({ success: false, error: 'Unknown message type' });
  return false;
});

/**
 * Extension installation handler
 */
chrome.runtime.onInstalled.addListener((details) => {
  console.log('Fantasma Wallet installed:', details.reason);

  // Set default issuers
  if (details.reason === 'install') {
    chrome.storage.local.set({
      issuers: [
        {
          id: 'gov.example',
          name: 'Example Government',
          verificationUrl: 'https://gov.example/.well-known/fantasma-issuer.json',
          trusted: true
        }
      ]
    });
  }
});

console.log('Fantasma Wallet background service worker started');
