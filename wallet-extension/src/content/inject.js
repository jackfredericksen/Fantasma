/**
 * Fantasma Wallet Page API
 * Injected into web pages to provide window.fantasma API
 */

(function() {
  'use strict';

  // Request ID counter
  let requestId = 0;

  // Pending requests
  const pendingRequests = new Map();

  /**
   * Send request to content script
   */
  function sendRequest(type, data = {}) {
    return new Promise((resolve, reject) => {
      const id = ++requestId;

      pendingRequests.set(id, { resolve, reject });

      window.postMessage({
        type,
        id,
        data
      }, '*');

      // Timeout after 5 minutes (proof generation can be slow)
      setTimeout(() => {
        if (pendingRequests.has(id)) {
          pendingRequests.delete(id);
          reject(new Error('Request timeout'));
        }
      }, 300000);
    });
  }

  // Listen for responses
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;

    const { type, id, success, data, error } = event.data;

    if (!type || !type.endsWith('_RESPONSE')) return;

    const pending = pendingRequests.get(id);
    if (!pending) return;

    pendingRequests.delete(id);

    if (success) {
      pending.resolve(data);
    } else {
      pending.reject(new Error(error));
    }
  });

  /**
   * Fantasma Wallet API
   */
  const fantasma = {
    /**
     * Check if Fantasma Wallet is installed and available
     */
    isInstalled: true,

    /**
     * API version
     */
    version: '0.1.0',

    /**
     * Connect to the wallet
     * @returns {Promise<{connected: boolean, version?: string, reason?: string}>}
     */
    async connect() {
      return sendRequest('FANTASMA_CONNECT');
    },

    /**
     * Get available credentials
     * @param {Object} options - Filter options
     * @param {string[]} options.types - Credential types to filter by
     * @returns {Promise<Credential[]>}
     */
    async getCredentials(options = {}) {
      return sendRequest('FANTASMA_GET_CREDENTIALS', options);
    },

    /**
     * Request authorization (OIDC flow)
     * @param {Object} authRequest - Authorization request parameters
     * @returns {Promise<AuthorizationResult>}
     */
    async authorize(authRequest) {
      return sendRequest('FANTASMA_AUTHORIZE', authRequest);
    },

    /**
     * Generate a zero-knowledge proof
     * @param {Object} options - Proof options
     * @param {string} options.credentialId - ID of credential to prove
     * @param {Object} options.claimType - Type of claim to prove
     * @param {string} options.serverProofEndpoint - Proof generation server URL
     * @returns {Promise<Proof>}
     */
    async generateProof(options) {
      return sendRequest('FANTASMA_GENERATE_PROOF', options);
    },

    /**
     * Event handlers
     */
    _eventHandlers: {},

    /**
     * Subscribe to wallet events
     * @param {string} event - Event name
     * @param {Function} handler - Event handler
     */
    on(event, handler) {
      if (!this._eventHandlers[event]) {
        this._eventHandlers[event] = [];
      }
      this._eventHandlers[event].push(handler);
    },

    /**
     * Unsubscribe from wallet events
     * @param {string} event - Event name
     * @param {Function} handler - Event handler
     */
    off(event, handler) {
      if (!this._eventHandlers[event]) return;
      const index = this._eventHandlers[event].indexOf(handler);
      if (index > -1) {
        this._eventHandlers[event].splice(index, 1);
      }
    },

    /**
     * Emit an event
     * @param {string} event - Event name
     * @param {any} data - Event data
     */
    _emit(event, data) {
      if (!this._eventHandlers[event]) return;
      this._eventHandlers[event].forEach(handler => {
        try {
          handler(data);
        } catch (e) {
          console.error('Event handler error:', e);
        }
      });
    }
  };

  // Expose to window
  if (typeof window.fantasma !== 'undefined') {
    console.warn('Fantasma API already defined, overwriting');
  }

  Object.defineProperty(window, 'fantasma', {
    value: Object.freeze(fantasma),
    writable: false,
    configurable: false
  });

  // Dispatch ready event
  window.dispatchEvent(new CustomEvent('fantasma:ready', {
    detail: { version: fantasma.version }
  }));

  console.log('Fantasma Wallet API ready');
})();
