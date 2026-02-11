/**
 * Demo Relying Party for Fantasma
 *
 * Shows the complete OAuth2/OIDC flow with ZK claims.
 * Run: npm install && npm start
 * Open: http://localhost:8080
 */

const express = require('express');
const crypto = require('crypto');
const https = require('https');
const http = require('http');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Configuration
const CONFIG = {
  clientId: 'demo-rp',
  clientSecret: 'demo-secret',
  redirectUri: 'http://localhost:8080/callback',
  fantasmaUrl: process.env.FANTASMA_URL || 'http://localhost:3000',
  port: 8080
};

// In-memory session store (use Redis in production)
const sessions = new Map();

// Generate random state for CSRF protection
function generateState() {
  return crypto.randomBytes(16).toString('hex');
}

// Generate nonce for replay protection
function generateNonce() {
  return crypto.randomBytes(16).toString('base64url');
}

// Simple HTTP fetch (no external deps)
function fetch(url, options = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const lib = parsed.protocol === 'https:' ? https : http;

    const req = lib.request(url, {
      method: options.method || 'GET',
      headers: options.headers || {}
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        resolve({
          ok: res.statusCode >= 200 && res.statusCode < 300,
          status: res.statusCode,
          json: () => Promise.resolve(JSON.parse(data)),
          text: () => Promise.resolve(data)
        });
      });
    });

    req.on('error', reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}

// Decode JWT without verification (for demo display)
function decodeJwt(token) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    return payload;
  } catch {
    return null;
  }
}

// Landing page
app.get('/', (req, res) => {
  const sessionId = req.query.session;
  const session = sessionId ? sessions.get(sessionId) : null;

  res.send(renderPage(session));
});

// Start OAuth flow
app.get('/login', (req, res) => {
  const state = generateState();
  const nonce = generateNonce();
  const scopes = req.query.scopes || 'openid zk:age:21+';

  // Store session
  const sessionId = crypto.randomBytes(8).toString('hex');
  sessions.set(sessionId, { state, nonce, scopes, status: 'pending' });

  // Build authorization URL
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CONFIG.clientId,
    redirect_uri: CONFIG.redirectUri,
    scope: scopes,
    state: `${sessionId}:${state}`,
    nonce: nonce
  });

  const authUrl = `${CONFIG.fantasmaUrl}/authorize?${params}`;
  res.redirect(authUrl);
});

// OAuth callback
app.get('/callback', async (req, res) => {
  const { code, state, error, error_description } = req.query;

  // Handle errors
  if (error) {
    return res.send(renderPage({
      status: 'error',
      error: error,
      errorDescription: error_description
    }));
  }

  // Validate state
  const [sessionId, expectedState] = (state || '').split(':');
  const session = sessions.get(sessionId);

  if (!session || session.state !== expectedState) {
    return res.send(renderPage({
      status: 'error',
      error: 'invalid_state',
      errorDescription: 'State mismatch - possible CSRF attack'
    }));
  }

  session.code = code;
  session.status = 'got_code';

  // Exchange code for tokens
  try {
    const tokenResponse = await fetch(`${CONFIG.fantasmaUrl}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: CONFIG.redirectUri,
        client_id: CONFIG.clientId,
        client_secret: CONFIG.clientSecret
      }).toString()
    });

    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      session.status = 'error';
      session.error = 'token_error';
      session.errorDescription = errorText;
      return res.redirect(`/?session=${sessionId}`);
    }

    const tokens = await tokenResponse.json();
    session.tokens = tokens;
    session.idTokenDecoded = decodeJwt(tokens.id_token);
    session.status = 'authenticated';

    // Extract ZK claims (they're flattened into the token)
    session.zkClaims = {
      age: session.idTokenDecoded?.zk_age_claim,
      kyc: session.idTokenDecoded?.zk_kyc_claim,
      credential: session.idTokenDecoded?.zk_credential_claim
    };

  } catch (err) {
    session.status = 'error';
    session.error = 'network_error';
    session.errorDescription = err.message;
  }

  res.redirect(`/?session=${sessionId}`);
});

// Clear session
app.get('/logout', (req, res) => {
  const sessionId = req.query.session;
  if (sessionId) sessions.delete(sessionId);
  res.redirect('/');
});

// Render the demo page
function renderPage(session) {
  const scopes = [
    { value: 'openid zk:age:18+', label: 'Age 18+' },
    { value: 'openid zk:age:21+', label: 'Age 21+' },
    { value: 'openid zk:kyc:basic', label: 'KYC Basic' },
    { value: 'openid zk:age:21+ zk:kyc:basic', label: 'Age 21+ & KYC' }
  ];

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Demo App - Fantasma Integration</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0a0a1a;
      color: #e0e0e0;
      min-height: 100vh;
      padding: 40px 20px;
    }

    .container {
      max-width: 800px;
      margin: 0 auto;
    }

    header {
      text-align: center;
      margin-bottom: 40px;
    }

    h1 {
      font-size: 28px;
      margin-bottom: 8px;
      color: #fff;
    }

    .subtitle {
      color: #888;
      font-size: 14px;
    }

    .card {
      background: #12122a;
      border: 1px solid #2a2a4a;
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 20px;
    }

    .card h2 {
      font-size: 14px;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: #888;
      margin-bottom: 16px;
    }

    .login-section {
      text-align: center;
      padding: 40px;
    }

    .scope-select {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      justify-content: center;
      margin-bottom: 24px;
    }

    .scope-btn {
      padding: 10px 16px;
      background: #1a1a3a;
      border: 1px solid #3a3a6a;
      border-radius: 8px;
      color: #aaa;
      cursor: pointer;
      font-size: 13px;
      transition: all 0.2s;
    }

    .scope-btn:hover, .scope-btn.selected {
      background: #2a2a5a;
      border-color: #8b5cf6;
      color: #fff;
    }

    .login-btn {
      display: inline-flex;
      align-items: center;
      gap: 12px;
      padding: 14px 32px;
      background: linear-gradient(135deg, #8b5cf6, #6366f1);
      border: none;
      border-radius: 10px;
      color: white;
      font-size: 16px;
      font-weight: 500;
      cursor: pointer;
      text-decoration: none;
      transition: transform 0.2s, box-shadow 0.2s;
    }

    .login-btn:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 20px rgba(139, 92, 246, 0.3);
    }

    .logo-icon {
      width: 24px;
      height: 24px;
      background: rgba(255,255,255,0.2);
      border-radius: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: bold;
    }

    .status-flow {
      display: flex;
      gap: 8px;
      margin-bottom: 24px;
      flex-wrap: wrap;
    }

    .status-step {
      padding: 8px 16px;
      background: #1a1a3a;
      border-radius: 20px;
      font-size: 12px;
      color: #666;
    }

    .status-step.active {
      background: #2a4a2a;
      color: #4ade80;
    }

    .status-step.error {
      background: #4a2a2a;
      color: #f87171;
    }

    .claims-grid {
      display: grid;
      gap: 12px;
    }

    .claim-item {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 16px;
      background: #1a1a3a;
      border-radius: 8px;
    }

    .claim-label {
      font-size: 14px;
      color: #aaa;
    }

    .claim-value {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .claim-badge {
      padding: 4px 12px;
      border-radius: 12px;
      font-size: 12px;
      font-weight: 500;
    }

    .badge-success {
      background: #166534;
      color: #4ade80;
    }

    .badge-info {
      background: #1e3a5f;
      color: #60a5fa;
    }

    .token-display {
      background: #0a0a1a;
      border: 1px solid #2a2a4a;
      border-radius: 8px;
      padding: 16px;
      font-family: 'Monaco', 'Consolas', monospace;
      font-size: 11px;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
      color: #888;
      max-height: 300px;
      overflow-y: auto;
    }

    .error-box {
      background: #2a1a1a;
      border: 1px solid #5a2a2a;
      border-radius: 8px;
      padding: 16px;
      color: #f87171;
    }

    .error-title {
      font-weight: 600;
      margin-bottom: 8px;
    }

    .logout-link {
      display: inline-block;
      margin-top: 20px;
      color: #888;
      text-decoration: none;
      font-size: 13px;
    }

    .logout-link:hover {
      color: #fff;
    }

    .flow-info {
      margin-top: 40px;
      padding-top: 20px;
      border-top: 1px solid #2a2a4a;
    }

    .flow-info h3 {
      font-size: 13px;
      color: #666;
      margin-bottom: 12px;
    }

    .flow-steps {
      font-size: 12px;
      color: #555;
      line-height: 1.8;
    }

    .flow-steps code {
      background: #1a1a3a;
      padding: 2px 6px;
      border-radius: 4px;
      color: #8b5cf6;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>Demo Relying Party</h1>
      <p class="subtitle">Testing Fantasma ZK Identity Integration</p>
    </header>

    ${session?.status === 'authenticated' ? `
      <div class="card">
        <h2>Authentication Status</h2>
        <div class="status-flow">
          <span class="status-step active">Authorized</span>
          <span class="status-step active">Code Exchanged</span>
          <span class="status-step active">Token Received</span>
          <span class="status-step active">Claims Verified</span>
        </div>
      </div>

      <div class="card">
        <h2>Verified ZK Claims</h2>
        <div class="claims-grid">
          ${session.zkClaims?.age ? `
            <div class="claim-item">
              <span class="claim-label">Age Verification</span>
              <div class="claim-value">
                <span class="claim-badge badge-success">≥ ${session.zkClaims.age.threshold}</span>
                <span class="claim-badge badge-info">${session.zkClaims.age.verified ? 'Verified' : 'Failed'}</span>
              </div>
            </div>
          ` : ''}
          ${session.zkClaims?.kyc ? `
            <div class="claim-item">
              <span class="claim-label">KYC Status</span>
              <div class="claim-value">
                <span class="claim-badge badge-success">${session.zkClaims.kyc.level}</span>
                <span class="claim-badge badge-info">${session.zkClaims.kyc.verified ? 'Verified' : 'Failed'}</span>
              </div>
            </div>
          ` : ''}
          ${session.zkClaims?.credential ? `
            <div class="claim-item">
              <span class="claim-label">Credential</span>
              <div class="claim-value">
                <span class="claim-badge badge-success">${session.zkClaims.credential.credential_type}</span>
                <span class="claim-badge badge-info">${session.zkClaims.credential.verified ? 'Verified' : 'Failed'}</span>
              </div>
            </div>
          ` : ''}
          <div class="claim-item">
            <span class="claim-label">Pseudonymous ID</span>
            <div class="claim-value">
              <code style="font-size: 11px; color: #8b5cf6;">${session.idTokenDecoded?.sub || 'N/A'}</code>
            </div>
          </div>
          ${session.zkClaims?.age?.proof_ref ? `
            <div class="claim-item">
              <span class="claim-label">Proof Reference</span>
              <div class="claim-value">
                <code style="font-size: 11px; color: #888;">${session.zkClaims.age.proof_ref.id || 'N/A'}</code>
              </div>
            </div>
          ` : ''}
        </div>
      </div>

      <div class="card">
        <h2>ID Token (decoded)</h2>
        <div class="token-display">${JSON.stringify(session.idTokenDecoded, null, 2)}</div>
      </div>

      <div class="card">
        <h2>Raw Token Response</h2>
        <div class="token-display">${JSON.stringify(session.tokens, null, 2)}</div>
      </div>

      <div style="text-align: center;">
        <a href="/logout?session=${Object.keys(Object.fromEntries(sessions)).find(k => sessions.get(k) === session)}" class="logout-link">← Start Over</a>
      </div>

    ` : session?.status === 'error' ? `
      <div class="card">
        <h2>Authentication Failed</h2>
        <div class="error-box">
          <div class="error-title">${session.error}</div>
          <div>${session.errorDescription || 'Unknown error'}</div>
        </div>
        <a href="/" class="logout-link">← Try Again</a>
      </div>
    ` : `
      <div class="card login-section">
        <h2 style="margin-bottom: 24px;">Select Claims to Verify</h2>

        <form action="/login" method="get">
          <div class="scope-select" id="scopeSelect">
            ${scopes.map((s, i) => `
              <button type="button" class="scope-btn ${i === 1 ? 'selected' : ''}"
                      onclick="selectScope(this, '${s.value}')">${s.label}</button>
            `).join('')}
          </div>
          <input type="hidden" name="scopes" id="scopesInput" value="openid zk:age:21+">

          <button type="submit" class="login-btn">
            <span class="logo-icon">F</span>
            Login with Fantasma
          </button>
        </form>

        <div class="flow-info">
          <h3>What happens when you click login:</h3>
          <div class="flow-steps">
            1. Redirect to <code>${CONFIG.fantasmaUrl}/authorize</code> with ZK scope<br>
            2. Fantasma shows consent screen, generates STARK proof<br>
            3. Redirect back with authorization code<br>
            4. Exchange code for ID token at <code>/token</code><br>
            5. ID token contains verified ZK claims (no personal data)
          </div>
        </div>
      </div>
    `}
  </div>

  <script>
    function selectScope(btn, scope) {
      document.querySelectorAll('.scope-btn').forEach(b => b.classList.remove('selected'));
      btn.classList.add('selected');
      document.getElementById('scopesInput').value = scope;
    }
  </script>
</body>
</html>`;
}

// Start server
app.listen(CONFIG.port, () => {
  console.log(`
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│   Demo Relying Party                                        │
│   http://localhost:${CONFIG.port}                                   │
│                                                             │
│   Fantasma URL: ${CONFIG.fantasmaUrl.padEnd(38)}  │
│                                                             │
│   Click "Login with Fantasma" to test the flow              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
`);
});
