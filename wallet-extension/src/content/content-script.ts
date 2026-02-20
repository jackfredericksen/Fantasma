/**
 * Fantasma Wallet — Content Script
 *
 * Responsibilities:
 *   - Injects `window.fantasma` API into the page
 *   - Listens for `window.postMessage` with type "fantasma-auth-request"
 *   - Forwards auth requests to the background service worker
 *   - Receives proof results and posts them back to the page
 */

import browser from 'webextension-polyfill';
import type {
  ExtensionMessage,
  ExtensionResponse,
  AuthRequest,
  PageMessage,
  PageResponse
} from '$lib/types';

// ─── Inject Page Script ──────────────────────────────────────────────────────

function injectPageApi(): void {
  const script = document.createElement('script');
  script.textContent = `(${pageApiScript.toString()})();`;
  (document.head || document.documentElement).appendChild(script);
  script.remove();
}

/**
 * This function is serialised and injected into the page context.
 * It defines window.fantasma.
 */
function pageApiScript(): void {
  let requestId = 0;
  const pending = new Map<
    number,
    { resolve: (v: unknown) => void; reject: (e: Error) => void }
  >();

  function sendRequest(type: string, data: unknown = {}): Promise<unknown> {
    return new Promise((resolve, reject) => {
      const id = ++requestId;
      pending.set(id, { resolve, reject });

      window.postMessage(
        { type, id, data, source: 'fantasma-page' } as any,
        '*'
      );

      setTimeout(() => {
        if (pending.has(id)) {
          pending.delete(id);
          reject(new Error('Fantasma request timeout'));
        }
      }, 300_000);
    });
  }

  window.addEventListener('message', (event: MessageEvent) => {
    if (event.source !== window) return;
    const msg = event.data;
    if (!msg || msg.source !== 'fantasma-content') return;

    const entry = pending.get(msg.id);
    if (!entry) return;
    pending.delete(msg.id);

    if (msg.success) {
      entry.resolve(msg.data);
    } else {
      entry.reject(new Error(msg.error ?? 'Unknown error'));
    }
  });

  const fantasma = {
    isInstalled: true,
    version: '0.1.0',

    async connect() {
      return sendRequest('FANTASMA_CONNECT');
    },

    async getCredentials(options: { types?: string[] } = {}) {
      return sendRequest('FANTASMA_GET_CREDENTIALS', options);
    },

    async authorize(authRequest: {
      scopes: string[];
      nonce?: string;
    }) {
      return sendRequest('FANTASMA_AUTHORIZE', authRequest);
    },

    async generateProof(options: {
      credentialId: string;
      claimType: string;
    }) {
      return sendRequest('FANTASMA_GENERATE_PROOF', options);
    }
  };

  Object.defineProperty(window, 'fantasma', {
    value: Object.freeze(fantasma),
    writable: false,
    configurable: false
  });

  window.dispatchEvent(
    new CustomEvent('fantasma:ready', { detail: { version: '0.1.0' } })
  );
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

async function sendToBackground<T = unknown>(
  type: string,
  payload: Record<string, unknown> = {}
): Promise<T> {
  const message: ExtensionMessage = {
    type: type as any,
    payload
  };

  const response = (await browser.runtime.sendMessage(message)) as ExtensionResponse<T>;

  if (!response.success) {
    throw new Error(response.error ?? 'Background request failed');
  }

  return response.data as T;
}

// ─── Page Message Listener ───────────────────────────────────────────────────

window.addEventListener('message', async (event: MessageEvent) => {
  if (event.source !== window) return;

  const msg = event.data;
  if (!msg || msg.source !== 'fantasma-page') return;

  const { type, id, data } = msg as { type: string; id: number; data: unknown };

  try {
    let result: unknown;

    switch (type) {
      case 'FANTASMA_CONNECT': {
        const unlocked = await sendToBackground<boolean>('WALLET_IS_UNLOCKED');
        result = { connected: unlocked, version: '0.1.0' };
        break;
      }

      case 'FANTASMA_GET_CREDENTIALS': {
        const opts = (data ?? {}) as { types?: string[] };
        const credentials = await sendToBackground<
          Array<{
            id: string;
            type: string;
            issuerName: string;
            issuedAt: string;
            expiresAt: string | null;
          }>
        >('CREDENTIALS_GET');

        let filtered = credentials;
        if (opts.types && opts.types.length > 0) {
          filtered = credentials.filter((c) => opts.types!.includes(c.type));
        }

        // Return only public metadata
        result = filtered.map((c) => ({
          id: c.id,
          type: c.type,
          issuerName: c.issuerName,
          issuedAt: c.issuedAt,
          expiresAt: c.expiresAt
        }));
        break;
      }

      case 'FANTASMA_AUTHORIZE': {
        const authData = data as { scopes: string[]; nonce?: string };
        const callbackId = `auth-${Date.now()}-${Math.random().toString(36).slice(2)}`;
        const nonce = authData.nonce ?? crypto.randomUUID();

        const authRequest: AuthRequest = {
          origin: window.location.origin,
          scopes: authData.scopes,
          nonce,
          callbackId
        };

        // Forward to background — this will open the popup for user approval
        await sendToBackground('CONTENT_AUTH_REQUEST', { authRequest });

        // Wait for the background to send us the result via a direct message
        result = await new Promise<unknown>((resolve, reject) => {
          const timeout = setTimeout(() => {
            reject(new Error('Authorization timed out'));
            cleanup();
          }, 300_000);

          function onMessage(msg: unknown): void {
            const m = msg as ExtensionMessage;
            if (m.type !== 'AUTH_RESULT') return;

            const payload = m.payload as Record<string, unknown>;
            if (payload.callbackId !== callbackId) return;

            clearTimeout(timeout);
            cleanup();

            if (payload.error) {
              reject(new Error(payload.error as string));
            } else {
              resolve(payload);
            }
          }

          function cleanup(): void {
            browser.runtime.onMessage.removeListener(onMessage);
          }

          browser.runtime.onMessage.addListener(onMessage);
        });
        break;
      }

      case 'FANTASMA_GENERATE_PROOF': {
        const proofData = data as {
          credentialId: string;
          claimType: string;
        };
        result = await sendToBackground('PROOF_GENERATE', {
          witness: {
            circuit_type: proofData.claimType,
            private_inputs: { credential_id: proofData.credentialId },
            public_inputs: { domain: window.location.hostname }
          }
        });
        break;
      }

      default:
        throw new Error(`Unknown Fantasma request type: ${type}`);
    }

    // Send success response back to page
    window.postMessage(
      { id, success: true, data: result, source: 'fantasma-content' },
      '*'
    );
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    window.postMessage(
      { id, success: false, error, source: 'fantasma-content' },
      '*'
    );
  }
});

// ─── Listen for "fantasma-auth-request" from the page ────────────────────────

window.addEventListener('message', async (event: MessageEvent) => {
  if (event.source !== window) return;
  if (event.data?.type !== 'fantasma-auth-request') return;

  const { scopes, nonce } = event.data as {
    type: string;
    scopes: string[];
    nonce?: string;
  };

  const callbackId = `auth-${Date.now()}-${Math.random().toString(36).slice(2)}`;

  const authRequest: AuthRequest = {
    origin: window.location.origin,
    scopes: scopes ?? [],
    nonce: nonce ?? crypto.randomUUID(),
    callbackId
  };

  try {
    await sendToBackground('CONTENT_AUTH_REQUEST', { authRequest });
  } catch (err) {
    console.error('[Fantasma] Failed to forward auth request:', err);
  }
});

// ─── Boot ────────────────────────────────────────────────────────────────────

injectPageApi();
console.log('[Fantasma] Content script loaded');
