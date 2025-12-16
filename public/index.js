const userIdInput = document.getElementById('userId');
const passwordInput = document.getElementById('password');
const keyInput = document.getElementById('key');
const valueInput = document.getElementById('value');
const requireSecret = document.getElementById('requireSecret');
const output = document.getElementById('output');
const currentUserLabel = document.getElementById('currentUser');
const paymentInfo = document.getElementById('paymentInfo');
const loginStatus = document.getElementById('loginStatus');
const loginSection = document.getElementById('loginSection');
const dashboard = document.getElementById('dashboard');
const logoutBtn = document.getElementById('logoutBtn');
let checkoutToken = null;
let stripeInstance = null;
let stripePublishableKey = null;
const entriesBody = document.getElementById('entriesBody');
const tableStatus = document.getElementById('tableStatus');
const pageInfo = document.getElementById('pageInfo');
const prevPageBtn = document.getElementById('prevPageBtn');
const nextPageBtn = document.getElementById('nextPageBtn');
const pageSize = 50;
let currentPage = 0;
let totalEntries = 0;
let keySecrets = {};
let currentUser = null;

const setCurrentUser = (user) => {
  currentUser = user;
  if (user) {
    currentUserLabel.textContent = `Current user: ${user.id} (${user.tier})`;
    localStorage.setItem('kvUser', JSON.stringify(user));
    loginStatus.textContent = `Logged in as ${user.id}`;
    dashboard.style.display = 'block';
    loginSection.style.display = 'none';
    loadSecretsForUser(user.id);
  } else {
    currentUserLabel.textContent = 'Current user: none';
    localStorage.removeItem('kvUser');
    loginStatus.textContent = 'Not logged in.';
    dashboard.style.display = 'none';
    loginSection.style.display = 'block';
  }
};

const loadSecretsForUser = (userId) => {
  try {
    const stored = localStorage.getItem(`kvSecrets:${userId}`);
    keySecrets = stored ? JSON.parse(stored) : {};
  } catch (_) {
    keySecrets = {};
  }
};

const log = (data) => {
  output.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
};

const renderEntries = (entries) => {
  if (!entries || entries.length === 0) {
    tableStatus.textContent = 'No keys yet.';
    entriesBody.innerHTML = '';
    return;
  }
  tableStatus.textContent = '';
  entriesBody.innerHTML = entries
    .map((e) => {
      const updated = e.updatedAt ? new Date(e.updatedAt).toLocaleString() : '';
      const requiresSecret = !!keySecrets[e.key] || e.value === null || e.value === undefined;
      let safeValue;
      if (requiresSecret && (e.value === null || e.value === undefined)) {
        safeValue = '(secret required)';
      } else {
        safeValue = typeof e.value === 'string' ? e.value : JSON.stringify(e.value);
      }
      return `<tr><td>${e.key}</td><td>${safeValue}</td><td>${updated} <button class="secondary shareBtn" data-key="${e.key}" data-requires-secret="${requiresSecret}">Share link</button></td></tr>`;
    })
    .join('');
};

const updatePagination = () => {
  const totalPages = Math.ceil(totalEntries / pageSize) || 1;
  pageInfo.textContent = `Page ${currentPage + 1} of ${totalPages} (${totalEntries} items)`;
  prevPageBtn.disabled = currentPage === 0;
  nextPageBtn.disabled = (currentPage + 1) * pageSize >= totalEntries;
};

const loadEntries = async (page = 0) => {
  if (!currentUser) return;
  const offset = page * pageSize;
  const res = await fetch(`/api/kv/${encodeURIComponent(currentUser.id)}?limit=${pageSize}&offset=${offset}`);
  const data = await res.json();
  if (!res.ok) {
    tableStatus.textContent = data.error || 'Failed to load keys';
    return;
  }
  currentPage = page;
  totalEntries = data.total || 0;
  renderEntries(data.entries || []);
  updatePagination();
};

// Restore last user if available
(() => {
  const saved = localStorage.getItem('kvUser');
  if (saved) {
    try {
      const parsed = JSON.parse(saved);
      if (parsed?.id) {
        setCurrentUser(parsed);
        userIdInput.value = parsed.id;
        log(`Restored session for ${parsed.id}`);
        loadEntries(0);
      }
    } catch (e) {
      localStorage.removeItem('kvUser');
    }
  }
})();

logoutBtn.onclick = () => {
  setCurrentUser(null);
  keySecrets = {};
  checkoutToken = null;
  paymentInfo.textContent = '';
  log('Logged out.');
  entriesBody.innerHTML = '';
  tableStatus.textContent = 'No data loaded.';
  pageInfo.textContent = '';
};

const loadStripeInstance = async () => {
  if (stripeInstance) return stripeInstance;
  const res = await fetch('/api/stripe/config');
  const data = await res.json();
  if (!res.ok || !data.publishableKey) {
    throw new Error(data.error || 'Stripe not configured');
  }
  stripePublishableKey = data.publishableKey;
  stripeInstance = Stripe(stripePublishableKey);
  return stripeInstance;
};

document.getElementById('createUserBtn').onclick = async () => {
  const userId = userIdInput.value.trim();
  const password = passwordInput.value;
  if (!userId) return log('Please provide a user id.');
  if (!password) return log('Please provide a password.');

  // Try login first
  const loginRes = await fetch('/api/users/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: userId, password })
  });
  const loginData = await loginRes.json();

  if (loginRes.ok && loginData.user) {
    setCurrentUser(loginData.user);
    await loadEntries(0);
    return log({ status: 'logged in', user: loginData.user });
  }

  if (loginRes.status !== 404) {
    return log({ error: loginData.error || 'Login failed' });
  }

  // If user not found, attempt signup
  const signupRes = await fetch('/api/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: userId, password })
  });
  const signupData = await signupRes.json();
  if (signupRes.ok && signupData.user) {
    setCurrentUser(signupData.user);
    await loadEntries(0);
    return log({ status: 'created', user: signupData.user });
  }
  return log({ error: signupData.error || 'Signup failed' });
};

document.getElementById('startCheckoutBtn').onclick = async () => {
  if (!currentUser) return log('Create or log in first.');
  let stripe;
  try {
    stripe = await loadStripeInstance();
  } catch (err) {
    return log({ error: err.message });
  }
  const res = await fetch('/api/stripe/checkout', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Console-Request': 'true' },
    body: JSON.stringify({ userId: currentUser.id })
  });
  const data = await res.json();
  if (res.ok) {
    checkoutToken = data.token;
    paymentInfo.textContent = `Checkout started. Redirecting to Stripe...`;
    const { error } = await stripe.redirectToCheckout({ sessionId: data.token });
    if (error) {
      log({ error: error.message });
    }
  } else {
    paymentInfo.textContent = '';
  }
  log(res.ok ? data : { error: data.error });
};

const confirmPayment = async (token) => {
  const res = await fetch('/api/stripe/confirm', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Console-Request': 'true' },
    body: JSON.stringify({ token })
  });
  const data = await res.json();
  if (res.ok && data.user) {
    setCurrentUser(data.user);
    checkoutToken = null;
    paymentInfo.textContent = 'Payment confirmed. You are premium.';
  }
  log(res.ok ? data : { error: data.error });
};

document.getElementById('setBtn').onclick = async () => {
  if (!currentUser) return log('Create or log in first.');
  const userId = currentUser.id;
  const key = keyInput.value.trim();
  const rawValue = valueInput.value.trim();
  const existingSecret = keySecrets[key];
  if (!key) return log('Please provide a key.');
  if (!rawValue) return log('Please provide a value.');

  let parsed = rawValue;
  try { parsed = JSON.parse(rawValue); } catch (_) {}

  const res = await fetch(`/api/kv/${encodeURIComponent(userId)}/${encodeURIComponent(key)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ value: parsed, secret: existingSecret || undefined, readRequiresSecret: requireSecret.checked })
  });
  const data = await res.json();
  log(res.ok ? data : { error: data.error });
  if (res.ok) {
    if (data.requiresSecret) {
      const secretToStore = data.secret || existingSecret;
      if (secretToStore) {
        keySecrets[key] = secretToStore;
        localStorage.setItem(`kvSecrets:${currentUser.id}`, JSON.stringify(keySecrets));
      }
    } else {
      delete keySecrets[key];
      localStorage.setItem(`kvSecrets:${currentUser.id}`, JSON.stringify(keySecrets));
    }
    await loadEntries(currentPage);
  }
};

document.getElementById('getBtn').onclick = async () => {
  if (!currentUser) return log('Create or log in first.');
  const userId = currentUser.id;
  const key = keyInput.value.trim();
  if (!key) return log('Please provide a key.');
  const secret = keySecrets[key];
  const secretQuery = secret ? `?secret=${encodeURIComponent(secret)}` : '';
  const res = await fetch(`/api/kv/${encodeURIComponent(userId)}/${encodeURIComponent(key)}${secretQuery}`);
  const data = await res.json();
  log(res.ok ? data : { error: data.error });
};

document.getElementById('clearBtn').onclick = () => log('Waiting for input…');

prevPageBtn.onclick = () => {
  if (currentPage === 0) return;
  loadEntries(currentPage - 1);
};
nextPageBtn.onclick = () => {
  if ((currentPage + 1) * pageSize >= totalEntries) return;
  loadEntries(currentPage + 1);
};

entriesBody.addEventListener('click', (e) => {
  const btn = e.target.closest('.shareBtn');
  if (!btn) return;
  const key = btn.getAttribute('data-key');
  const requiresSecret = btn.getAttribute('data-requires-secret') === 'true';
  if (!currentUser || !key) return;
  let url = `${window.location.origin}/api/kv/${encodeURIComponent(currentUser.id)}/${encodeURIComponent(key)}`;
  if (requiresSecret) {
    const s = keySecrets[key];
    if (!s) {
      return log('No secret stored for this key. Save the key again to generate a new shareable link.');
    }
    url += `?secret=${encodeURIComponent(s)}`;
  }
  navigator.clipboard?.writeText(url);
  log({ share: url });
});

// Auto-confirm if redirected back with session_id
const params = new URLSearchParams(window.location.search);
const sessionIdFromUrl = params.get('session_id');
if (sessionIdFromUrl) {
  checkoutToken = sessionIdFromUrl;
  confirmPayment(sessionIdFromUrl);
  // Clean URL
  const cleanUrl = window.location.origin + window.location.pathname;
  window.history.replaceState({}, document.title, cleanUrl);
}
