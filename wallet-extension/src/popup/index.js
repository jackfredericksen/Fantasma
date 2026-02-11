/**
 * Fantasma Wallet Popup Script
 */

// Send message to background script
async function sendMessage(type, payload = {}) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ type, payload }, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (response.success) {
        resolve(response.data);
      } else {
        reject(new Error(response.error));
      }
    });
  });
}

// DOM Elements
const screens = {
  setup: document.getElementById('setupScreen'),
  lock: document.getElementById('lockScreen'),
  main: document.getElementById('mainScreen')
};

const forms = {
  setup: document.getElementById('setupForm'),
  unlock: document.getElementById('unlockForm')
};

const tabs = document.querySelectorAll('.tab');
const tabContents = {
  credentials: document.getElementById('credentialsTab'),
  activity: document.getElementById('activityTab'),
  settings: document.getElementById('settingsTab')
};

// State
let currentScreen = 'setup';

/**
 * Show a specific screen
 */
function showScreen(screen) {
  Object.values(screens).forEach(s => s.classList.remove('active'));
  screens[screen].classList.add('active');
  currentScreen = screen;

  // Show/hide lock button
  document.getElementById('lockBtn').style.display =
    screen === 'main' ? 'block' : 'none';
}

/**
 * Show error message
 */
function showError(elementId, message) {
  const el = document.getElementById(elementId);
  el.textContent = message;
  el.classList.add('visible');
  setTimeout(() => el.classList.remove('visible'), 5000);
}

/**
 * Initialize popup
 */
async function init() {
  try {
    const isInitialized = await sendMessage('isInitialized');

    if (!isInitialized) {
      showScreen('setup');
      return;
    }

    const isUnlocked = await sendMessage('isUnlocked');

    if (isUnlocked) {
      showScreen('main');
      await loadCredentials();
      await loadSettings();
    } else {
      showScreen('lock');
    }
  } catch (error) {
    console.error('Init error:', error);
    showScreen('setup');
  }
}

/**
 * Load and display credentials
 */
async function loadCredentials() {
  try {
    const credentials = await sendMessage('getCredentials');
    const list = document.getElementById('credentialList');
    const emptyState = document.getElementById('emptyCredentials');

    if (credentials.length === 0) {
      list.style.display = 'none';
      emptyState.style.display = 'block';
      return;
    }

    list.style.display = 'flex';
    emptyState.style.display = 'none';

    list.innerHTML = credentials.map(cred => {
      const icon = getCredentialIcon(cred.type);
      const title = getCredentialTitle(cred.type);
      const isExpired = cred.expiresAt && new Date(cred.expiresAt) < new Date();

      return `
        <div class="credential-card" data-id="${cred.id}">
          <div class="credential-header">
            <div class="credential-type">
              <div class="credential-icon">${icon}</div>
              <div class="credential-info">
                <h4>${title}</h4>
                <span>${cred.issuer}</span>
              </div>
            </div>
            <span class="credential-badge" style="${isExpired ? 'background: rgba(239, 68, 68, 0.2); color: #ef4444;' : ''}">
              ${isExpired ? 'Expired' : 'Valid'}
            </span>
          </div>
          <div class="credential-details">
            <div>
              <span>Issued</span>
              <span>${formatDate(cred.issuedAt)}</span>
            </div>
            ${cred.expiresAt ? `
              <div>
                <span>Expires</span>
                <span>${formatDate(cred.expiresAt)}</span>
              </div>
            ` : ''}
          </div>
        </div>
      `;
    }).join('');
  } catch (error) {
    console.error('Failed to load credentials:', error);
  }
}

/**
 * Load settings
 */
async function loadSettings() {
  try {
    const settings = await sendMessage('getSettings');
    document.getElementById('autoLockMinutes').value = settings.autoLockMinutes || 15;
  } catch (error) {
    console.error('Failed to load settings:', error);
  }
}

/**
 * Get credential icon
 */
function getCredentialIcon(type) {
  switch (type) {
    case 'identity': return 'ID';
    case 'kyc': return 'KY';
    case 'degree': return 'Dg';
    case 'license': return 'Lc';
    case 'membership': return 'Mb';
    default: return 'Cr';
  }
}

/**
 * Get credential title
 */
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

/**
 * Format date
 */
function formatDate(dateStr) {
  const date = new Date(dateStr);
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  });
}

// Event Listeners

// Setup form
forms.setup.addEventListener('submit', async (e) => {
  e.preventDefault();

  const password = document.getElementById('setupPassword').value;
  const confirm = document.getElementById('setupConfirm').value;

  if (password !== confirm) {
    showError('setupError', 'Passwords do not match');
    return;
  }

  if (password.length < 8) {
    showError('setupError', 'Password must be at least 8 characters');
    return;
  }

  try {
    await sendMessage('initialize', { password });
    showScreen('main');
    await loadCredentials();
    await loadSettings();
  } catch (error) {
    showError('setupError', error.message);
  }
});

// Unlock form
forms.unlock.addEventListener('submit', async (e) => {
  e.preventDefault();

  const password = document.getElementById('unlockPassword').value;

  try {
    await sendMessage('unlock', { password });
    document.getElementById('unlockPassword').value = '';
    showScreen('main');
    await loadCredentials();
    await loadSettings();
  } catch (error) {
    showError('unlockError', error.message);
  }
});

// Lock button
document.getElementById('lockBtn').addEventListener('click', async () => {
  await sendMessage('lock');
  showScreen('lock');
});

// Tabs
tabs.forEach(tab => {
  tab.addEventListener('click', () => {
    tabs.forEach(t => t.classList.remove('active'));
    tab.classList.add('active');

    const tabName = tab.dataset.tab;
    Object.entries(tabContents).forEach(([name, content]) => {
      content.style.display = name === tabName ? 'block' : 'none';
    });
  });
});

// Save settings
document.getElementById('saveSettings').addEventListener('click', async () => {
  const autoLockMinutes = parseInt(document.getElementById('autoLockMinutes').value);

  try {
    await sendMessage('updateSettings', { settings: { autoLockMinutes } });
    alert('Settings saved');
  } catch (error) {
    alert('Failed to save settings: ' + error.message);
  }
});

// Check connection status
async function updateStatus() {
  const dot = document.getElementById('statusDot');
  const text = document.getElementById('statusText');

  try {
    const response = await fetch('http://localhost:3000/health');
    if (response.ok) {
      dot.classList.remove('offline');
      text.textContent = 'Connected';
    } else {
      throw new Error('Server error');
    }
  } catch {
    dot.classList.add('offline');
    text.textContent = 'Offline';
  }
}

// Initialize
init();
updateStatus();
setInterval(updateStatus, 30000);
