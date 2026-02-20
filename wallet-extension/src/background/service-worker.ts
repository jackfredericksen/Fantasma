/**
 * Fantasma Wallet — Background Service Worker
 *
 * Responsibilities:
 *   - Listens for messages from popup and content scripts
 *   - Opens popup for user approval on auth requests
 *   - Coordinates witness generation and proof submission
 *   - Manages wallet lock state and auto-lock timer
 */

import browser from 'webextension-polyfill';
import * as storage from '$lib/storage';
import { submitWitness, waitForProof, discoverServer } from '$lib/api';
import { generatePseudonym, bytesToHex, generateNullifier, sha256 } from '$lib/crypto';
import type {
  ExtensionMessage,
  ExtensionResponse,
  AuthRequest,
  WitnessResult,
  WalletSettings,
  CredentialImportData
} from '$lib/types';

// ─── Auto-lock Timer ─────────────────────────────────────────────────────────

let autoLockTimer: ReturnType<typeof setTimeout> | null = null;

async function resetAutoLockTimer(): Promise<void> {
  clearAutoLockTimer();
  const settings = await storage.getSettings();
  const minutes = settings.autoLockMinutes || 15;
  autoLockTimer = setTimeout(() => {
    storage.lock();
    console.log('[Fantasma] Wallet auto-locked');
  }, minutes * 60 * 1000);
}

function clearAutoLockTimer(): void {
  if (autoLockTimer !== null) {
    clearTimeout(autoLockTimer);
    autoLockTimer = null;
  }
}

// ─── Pending Auth Requests ───────────────────────────────────────────────────

const pendingAuthRequests = new Map<
  string,
  { request: AuthRequest; tabId: number }
>();

// ─── Message Handlers ────────────────────────────────────────────────────────

type Handler = (payload: Record<string, unknown>) => Promise<unknown>;

const handlers: Record<string, Handler> = {
  // ── Wallet lifecycle ───────────────────────────────────────────────────

  async WALLET_IS_INITIALIZED(): Promise<boolean> {
    return storage.isInitialized();
  },

  async WALLET_IS_UNLOCKED(): Promise<boolean> {
    return !storage.isLocked();
  },

  async WALLET_INITIALIZE(payload): Promise<boolean> {
    await storage.initialize(payload.password as string);
    await resetAutoLockTimer();
    return true;
  },

  async WALLET_UNLOCK(payload): Promise<boolean> {
    await storage.unlock(payload.password as string);
    await resetAutoLockTimer();
    return true;
  },

  async WALLET_LOCK(): Promise<boolean> {
    storage.lock();
    clearAutoLockTimer();
    return true;
  },

  // ── Credentials ────────────────────────────────────────────────────────

  async CREDENTIALS_GET(): Promise<unknown> {
    await resetAutoLockTimer();
    return storage.getCredentials();
  },

  async CREDENTIALS_SAVE(payload): Promise<string> {
    await resetAutoLockTimer();
    return storage.saveCredential(payload.credential as CredentialImportData);
  },

  async CREDENTIALS_DELETE(payload): Promise<boolean> {
    await resetAutoLockTimer();
    await storage.deleteCredential(payload.credentialId as string);
    return true;
  },

  async CREDENTIALS_IMPORT(payload): Promise<string> {
    await resetAutoLockTimer();
    return storage.saveCredential(payload.credential as CredentialImportData);
  },

  // ── Settings ───────────────────────────────────────────────────────────

  async SETTINGS_GET(): Promise<WalletSettings> {
    return storage.getSettings();
  },

  async SETTINGS_UPDATE(payload): Promise<boolean> {
    await storage.updateSettings(payload.settings as Partial<WalletSettings>);
    await resetAutoLockTimer();
    return true;
  },

  // ── Auth flow (from content script) ────────────────────────────────────

  async CONTENT_AUTH_REQUEST(payload): Promise<boolean> {
    const authRequest = payload.authRequest as AuthRequest;
    const tabId = payload.tabId as number;

    // Store pending request so popup can retrieve it
    pendingAuthRequests.set(authRequest.callbackId, {
      request: authRequest,
      tabId
    });

    // Open the popup so the user can approve / deny
    // Chrome MV3 doesn't have a direct "open popup" API, so we use
    // action.openPopup() if available, otherwise fall back to creating a window.
    try {
      if (browser.action && typeof (browser.action as any).openPopup === 'function') {
        await (browser.action as any).openPopup();
      }
    } catch {
      // Fallback: the user will need to click the extension icon manually.
      // We could create a notification here.
      console.warn('[Fantasma] Could not programmatically open popup');
    }

    return true;
  },

  /**
   * Called by the popup when the user approves an auth request.
   */
  async AUTH_APPROVE(payload): Promise<unknown> {
    await resetAutoLockTimer();

    const callbackId = payload.callbackId as string;
    const selectedCredentialIds = payload.selectedCredentialIds as string[];
    const pending = pendingAuthRequests.get(callbackId);

    if (!pending) {
      throw new Error('No pending auth request found');
    }

    const authRequest = pending.request;
    pendingAuthRequests.delete(callbackId);

    const credentials = await storage.getCredentials();
    const settings = await storage.getSettings();

    const proofs: Array<{
      scope: string;
      proof_id: string;
      proof_hash: string;
      zkid: string;
      verified: boolean;
    }> = [];

    for (const credId of selectedCredentialIds) {
      const cred = credentials.find((c) => c.id === credId);
      if (!cred) continue;

      const ms = storage.getMasterSecret();
      const pseudonym = await generatePseudonym(ms, authRequest.origin);
      const zkid = `zkid:${bytesToHex(pseudonym).slice(0, 40)}`;
      const nullifier = generateNullifier();

      for (const scope of authRequest.scopes) {
        const witness: WitnessResult = {
          circuit_type: scope,
          private_inputs: {
            birthdate: cred.birthdate ?? '',
            commitment: cred.commitment,
            nullifier: bytesToHex(nullifier),
            master_secret: bytesToHex(ms),
            signature: cred.signature ?? ''
          },
          public_inputs: {
            zkid,
            domain: authRequest.origin,
            nonce: authRequest.nonce,
            scope
          }
        };

        const submission = await submitWitness(witness, settings.serverUrl);
        const result = await waitForProof(submission.proof_id, settings.serverUrl);

        proofs.push({
          scope,
          proof_id: result.proof_id,
          proof_hash: result.proof_hash ?? '',
          zkid,
          verified: result.verified ?? false
        });
      }
    }

    // Send result back to the content script's tab
    const resultMessage: ExtensionMessage = {
      type: 'AUTH_RESULT',
      payload: { proofs, nonce: authRequest.nonce, callbackId }
    };

    await browser.tabs.sendMessage(pending.tabId, resultMessage);

    return { proofs, nonce: authRequest.nonce };
  },

  /**
   * Called by the popup when the user denies an auth request.
   */
  async AUTH_DENY(payload): Promise<boolean> {
    const callbackId = payload.callbackId as string;
    const pending = pendingAuthRequests.get(callbackId);

    if (pending) {
      pendingAuthRequests.delete(callbackId);

      const resultMessage: ExtensionMessage = {
        type: 'AUTH_RESULT',
        payload: { error: 'User denied authorization', callbackId }
      };
      await browser.tabs.sendMessage(pending.tabId, resultMessage);
    }

    return true;
  },

  /**
   * Retrieve the current pending auth request (called by popup on open).
   */
  async AUTH_REQUEST(): Promise<unknown> {
    if (pendingAuthRequests.size === 0) return null;

    // Return the first pending request
    const [callbackId, entry] = pendingAuthRequests.entries().next().value!;
    return { callbackId, ...entry.request };
  },

  // ── Direct proof generation (no auth flow) ─────────────────────────────

  async PROOF_GENERATE(payload): Promise<unknown> {
    await resetAutoLockTimer();

    const witness = payload.witness as WitnessResult;
    const settings = await storage.getSettings();
    const submission = await submitWitness(witness, settings.serverUrl);
    return waitForProof(submission.proof_id, settings.serverUrl);
  },

  async PROOF_STATUS(payload): Promise<unknown> {
    const { default: api } = await import('$lib/api');
    const settings = await storage.getSettings();
    const { getProofStatus } = await import('$lib/api');
    return getProofStatus(payload.proofId as string, settings.serverUrl);
  },

  // ── Server health ──────────────────────────────────────────────────────

  async SERVER_DISCOVER(payload): Promise<unknown> {
    return discoverServer(payload.serverUrl as string | undefined);
  }
};

// ─── Message Listener ────────────────────────────────────────────────────────

browser.runtime.onMessage.addListener(
  (
    message: unknown,
    sender: browser.Runtime.MessageSender
  ): Promise<ExtensionResponse> | undefined => {
    const msg = message as ExtensionMessage;
    const handler = handlers[msg.type];

    if (!handler) {
      return Promise.resolve({
        success: false,
        error: `Unknown message type: ${msg.type}`
      });
    }

    const payload = (msg.payload ?? {}) as Record<string, unknown>;

    // Attach sender tab ID for content-script messages
    if (sender.tab?.id !== undefined) {
      payload.tabId = sender.tab.id;
    }

    return handler(payload)
      .then((data) => ({ success: true, data } as ExtensionResponse))
      .catch((err: Error) => ({ success: false, error: err.message } as ExtensionResponse));
  }
);

// ─── Installation Handler ────────────────────────────────────────────────────

browser.runtime.onInstalled.addListener((details) => {
  console.log('[Fantasma] Extension installed:', details.reason);
});

console.log('[Fantasma] Background service worker started');
