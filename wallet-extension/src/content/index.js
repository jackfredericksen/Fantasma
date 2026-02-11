/**
 * Fantasma Wallet Content Script
 * Bridges web pages with the wallet extension
 */

// Inject the page script
const script = document.createElement('script');
script.src = chrome.runtime.getURL('src/content/inject.js');
script.onload = () => script.remove();
(document.head || document.documentElement).appendChild(script);

// Listen for messages from the page
window.addEventListener('message', async (event) => {
  // Only accept messages from the same window
  if (event.source !== window) return;

  const { type, id, data } = event.data;

  // Only handle Fantasma requests
  if (!type || !type.startsWith('FANTASMA_')) return;

  try {
    let response;

    switch (type) {
      case 'FANTASMA_CONNECT':
        response = await handleConnect();
        break;

      case 'FANTASMA_GET_CREDENTIALS':
        response = await handleGetCredentials(data);
        break;

      case 'FANTASMA_AUTHORIZE':
        response = await handleAuthorize(data);
        break;

      case 'FANTASMA_GENERATE_PROOF':
        response = await handleGenerateProof(data);
        break;

      default:
        throw new Error(`Unknown request type: ${type}`);
    }

    // Send response back to page
    window.postMessage({
      type: `${type}_RESPONSE`,
      id,
      success: true,
      data: response
    }, '*');

  } catch (error) {
    window.postMessage({
      type: `${type}_RESPONSE`,
      id,
      success: false,
      error: error.message
    }, '*');
  }
});

/**
 * Handle connect request
 */
async function handleConnect() {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ type: 'isUnlocked' }, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }

      if (response.success && response.data) {
        resolve({
          connected: true,
          version: '0.1.0'
        });
      } else {
        resolve({
          connected: false,
          reason: 'Wallet is locked'
        });
      }
    });
  });
}

/**
 * Handle get credentials request
 */
async function handleGetCredentials(data) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(
      {
        type: 'getCredentials',
        payload: {}
      },
      (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }

        if (response.success) {
          // Filter by requested types if specified
          let credentials = response.data;

          if (data?.types) {
            credentials = credentials.filter(c => data.types.includes(c.type));
          }

          // Only return public metadata, not sensitive data
          resolve(credentials.map(c => ({
            id: c.id,
            type: c.type,
            issuer: c.issuer,
            schema: c.schema,
            issuedAt: c.issuedAt,
            expiresAt: c.expiresAt
          })));
        } else {
          reject(new Error(response.error));
        }
      }
    );
  });
}

/**
 * Handle authorization request (OIDC flow)
 */
async function handleAuthorize(authRequest) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(
      {
        type: 'handleAuthorization',
        payload: { authRequest }
      },
      (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }

        if (response.success) {
          // Show authorization popup
          showAuthorizationUI(response.data, (result) => {
            if (result.approved) {
              // Complete authorization
              chrome.runtime.sendMessage(
                {
                  type: 'completeAuthorization',
                  payload: {
                    selectedCredentials: result.selectedCredentials,
                    authRequest: response.data
                  }
                },
                (completeResponse) => {
                  if (completeResponse.success) {
                    resolve(completeResponse.data);
                  } else {
                    reject(new Error(completeResponse.error));
                  }
                }
              );
            } else {
              reject(new Error('User denied authorization'));
            }
          });
        } else {
          reject(new Error(response.error));
        }
      }
    );
  });
}

/**
 * Handle proof generation request
 */
async function handleGenerateProof(data) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(
      {
        type: 'generateProof',
        payload: {
          credentialId: data.credentialId,
          claimType: data.claimType,
          domain: window.location.hostname,
          serverProofEndpoint: data.serverProofEndpoint || 'http://localhost:3000'
        }
      },
      (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }

        if (response.success) {
          resolve(response.data);
        } else {
          reject(new Error(response.error));
        }
      }
    );
  });
}

/**
 * Show authorization UI overlay
 */
function showAuthorizationUI(authData, callback) {
  // Create overlay
  const overlay = document.createElement('div');
  overlay.id = 'fantasma-auth-overlay';
  overlay.innerHTML = `
    <style>
      #fantasma-auth-overlay {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0, 0, 0, 0.8);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 999999;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      }
      .fantasma-auth-modal {
        background: #1a1a3e;
        border-radius: 16px;
        padding: 24px;
        max-width: 400px;
        width: 90%;
        color: white;
        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
      }
      .fantasma-auth-header {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 20px;
      }
      .fantasma-auth-logo {
        width: 40px;
        height: 40px;
        background: linear-gradient(135deg, #8b5cf6, #3b82f6);
        border-radius: 10px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 20px;
        font-weight: bold;
      }
      .fantasma-auth-title {
        font-size: 18px;
        font-weight: 600;
      }
      .fantasma-auth-subtitle {
        font-size: 13px;
        color: #a0a0cc;
      }
      .fantasma-auth-scopes {
        background: #252550;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 20px;
      }
      .fantasma-auth-scope {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 8px 0;
        border-bottom: 1px solid #3b3b6d;
      }
      .fantasma-auth-scope:last-child {
        border-bottom: none;
      }
      .fantasma-auth-scope-badge {
        background: #8b5cf6;
        color: white;
        padding: 4px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 500;
      }
      .fantasma-auth-credentials {
        margin-bottom: 20px;
      }
      .fantasma-auth-credential {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 12px;
        background: #252550;
        border-radius: 8px;
        margin-bottom: 8px;
        cursor: pointer;
        border: 2px solid transparent;
        transition: border-color 0.2s;
      }
      .fantasma-auth-credential.selected {
        border-color: #8b5cf6;
      }
      .fantasma-auth-buttons {
        display: flex;
        gap: 12px;
      }
      .fantasma-auth-btn {
        flex: 1;
        padding: 12px;
        border: none;
        border-radius: 8px;
        font-size: 14px;
        font-weight: 500;
        cursor: pointer;
        transition: opacity 0.2s;
      }
      .fantasma-auth-btn:hover {
        opacity: 0.9;
      }
      .fantasma-auth-btn-primary {
        background: linear-gradient(135deg, #8b5cf6, #3b82f6);
        color: white;
      }
      .fantasma-auth-btn-secondary {
        background: #252550;
        color: white;
      }
    </style>
    <div class="fantasma-auth-modal">
      <div class="fantasma-auth-header">
        <div class="fantasma-auth-logo">F</div>
        <div>
          <div class="fantasma-auth-title">Authorization Request</div>
          <div class="fantasma-auth-subtitle">${authData.client_id}</div>
        </div>
      </div>

      <div class="fantasma-auth-scopes">
        <div style="font-size: 13px; color: #a0a0cc; margin-bottom: 8px;">Requested permissions:</div>
        ${authData.zkScopes.map(scope => `
          <div class="fantasma-auth-scope">
            <span class="fantasma-auth-scope-badge">ZK</span>
            <span>${formatScope(scope)}</span>
          </div>
        `).join('')}
      </div>

      <div class="fantasma-auth-credentials">
        <div style="font-size: 13px; color: #a0a0cc; margin-bottom: 8px;">Select credential:</div>
        ${authData.matchingCredentials.map(cred => `
          <div class="fantasma-auth-credential" data-id="${cred.id}">
            <input type="checkbox" checked>
            <div>
              <div style="font-size: 14px; font-weight: 500;">${getCredentialTitle(cred.type)}</div>
              <div style="font-size: 12px; color: #a0a0cc;">${cred.issuer}</div>
            </div>
          </div>
        `).join('')}
      </div>

      <div class="fantasma-auth-buttons">
        <button class="fantasma-auth-btn fantasma-auth-btn-secondary" id="fantasma-deny">Deny</button>
        <button class="fantasma-auth-btn fantasma-auth-btn-primary" id="fantasma-approve">Approve</button>
      </div>
    </div>
  `;

  document.body.appendChild(overlay);

  // Handle credential selection
  overlay.querySelectorAll('.fantasma-auth-credential').forEach(el => {
    el.addEventListener('click', () => {
      el.classList.toggle('selected');
      el.querySelector('input').checked = el.classList.contains('selected');
    });
    el.classList.add('selected');
  });

  // Handle buttons
  overlay.querySelector('#fantasma-deny').addEventListener('click', () => {
    overlay.remove();
    callback({ approved: false });
  });

  overlay.querySelector('#fantasma-approve').addEventListener('click', () => {
    const selected = Array.from(overlay.querySelectorAll('.fantasma-auth-credential.selected'))
      .map(el => el.dataset.id);
    overlay.remove();
    callback({ approved: true, selectedCredentials: selected });
  });
}

function formatScope(scope) {
  if (scope.startsWith('zk:age:')) {
    const age = scope.split(':')[2];
    return `Verify age is ${age} or older`;
  }
  if (scope.startsWith('zk:kyc:')) {
    const level = scope.split(':')[2];
    return `KYC verification (${level} level)`;
  }
  return scope;
}

function getCredentialTitle(type) {
  switch (type) {
    case 'identity': return 'Identity Credential';
    case 'kyc': return 'KYC Verification';
    case 'degree': return 'Academic Degree';
    case 'license': return 'Professional License';
    case 'membership': return 'Membership';
    default: return 'Credential';
  }
}

console.log('Fantasma Wallet content script loaded');
