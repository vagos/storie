// detect page
const isLoginPage = !!document.getElementById('loginForm');
const isMainPage  = !!document.getElementById('dashboard');

const userIdInput = document.getElementById('userId');
const passwordInput = document.getElementById('password');
const loginStatus = document.getElementById('loginStatus');
const appBanner = document.getElementById('appBanner');

// main-page
const keyInput = document.getElementById('key');
const valueInput = document.getElementById('value');
const requireSecret = document.getElementById('requireSecret');
const output = document.getElementById('output');
const currentUserLabel = document.getElementById('currentUser');
const paymentInfo = document.getElementById('paymentInfo');
const loginSection = document.getElementById('loginSection'); // might not exist (commented out in index.html)
const dashboard = document.getElementById('dashboard');
const logoutBtn = document.getElementById('logoutBtn');

const entriesBody = document.getElementById('entriesBody');
const tableStatus = document.getElementById('tableStatus');
const pageInfo = document.getElementById('pageInfo');
const prevPageBtn = document.getElementById('prevPageBtn');
const nextPageBtn = document.getElementById('nextPageBtn');

// buttons that exist only on main page
const startCheckoutBtn = document.getElementById('startCheckoutBtn');
const setBtn = document.getElementById('setBtn');
const getBtn = document.getElementById('getBtn');
const clearBtn = document.getElementById('clearBtn');

// shared button id used on login page
const createUserBtn = document.getElementById('createUserBtn');

// state
let checkoutToken = null;
let stripeInstance = null;
let stripePublishableKey = null;

const pageSize = 50;
let currentPage = 0;
let totalEntries = 0;
let keySecrets = {};
let currentUser = null;

const banner = (msg, kind = 'ok') => {
  if (!appBanner) return;
  appBanner.style.display = 'block';
  appBanner.className = `banner ${kind}`;
  appBanner.textContent = msg;
};

const log = (data) => {
  if (!output) return;
  output.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
};

const loadSecretsForUser = (userId) => {
  try {
    const stored = localStorage.getItem(`kvSecrets:${userId}`);
    keySecrets = stored ? JSON.parse(stored) : {};
  } catch (_) {
    keySecrets = {};
  }
};

const setAuthHeroState = (user) => {
  // These exist only on the main page hero
  const authOut = document.getElementById('authBoxLoggedOut'); // Log in or create account box
  const authIn  = document.getElementById('authBoxLoggedIn');  // Current user + Log out" 
  const heroPill = document.getElementById('heroUserPill');
  const heroLogoutBtn = document.getElementById('heroLogoutBtn');

  if (user) {
    if (authOut) authOut.style.display = 'none';
    if (authIn) authIn.style.display = 'block';
    if (heroPill) heroPill.textContent = `${user.id} (${user.tier})`;

    if (heroLogoutBtn) {
    heroLogoutBtn.onclick = () => {
      setCurrentUser(null);
      keySecrets = {};
      checkoutToken = null;
      if (paymentInfo) paymentInfo.textContent = '';
      if (entriesBody) entriesBody.innerHTML = '';
      if (tableStatus) tableStatus.textContent = 'No data loaded.';
      if (pageInfo) pageInfo.textContent = '';
      log('Logged out.');
    };
  }
  } else {
    if (authOut) authOut.style.display = 'block';
    if (authIn) authIn.style.display = 'none';
    if (heroPill) heroPill.textContent = '';
  }
};

const setCurrentUser = (user) => {
  currentUser = user;

  setAuthHeroState(user);

  // loginStatus exists on pages
  if (loginStatus) loginStatus.textContent = user ? `Logged in as ${user.id}` : 'Not logged in.';

  if (user) {
    document.body.classList.add('logged-in');
    localStorage.setItem('kvUser', JSON.stringify(user));
    loadSecretsForUser(user.id);

    if (currentUserLabel) currentUserLabel.textContent = `Current user: ${user.id} (${user.tier})`;

    if (dashboard) dashboard.style.display = 'block';
    if (loginSection) loginSection.style.display = 'none';

    if (appBanner) appBanner.style.display = 'none';
  } else {
    document.body.classList.remove('logged-in');
    localStorage.removeItem('kvUser');

    if (currentUserLabel) currentUserLabel.textContent = 'Current user: none';

    if (dashboard) dashboard.style.display = 'none';
    if (loginSection) loginSection.style.display = 'block';

    if (appBanner) appBanner.style.display = 'none';
  }
};

const renderEntries = (entries) => {
  if (!entriesBody || !tableStatus) return;

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

      return `<tr>
        <td>${e.key}</td>
        <td>${safeValue}</td>
        <td>
          ${updated}
          <button class="secondary shareBtn" data-key="${e.key}" data-requires-secret="${requiresSecret}">Share link</button>
        </td>
      </tr>`;
    })
    .join('');
};

const updatePagination = () => {
  if (!pageInfo || !prevPageBtn || !nextPageBtn) return;
  const totalPages = Math.ceil(totalEntries / pageSize) || 1;
  pageInfo.textContent = `Page ${currentPage + 1} of ${totalPages} (${totalEntries} items)`;
  prevPageBtn.disabled = currentPage === 0;
  nextPageBtn.disabled = (currentPage + 1) * pageSize >= totalEntries;
};

const loadEntries = async (page = 0) => {
  if (!currentUser) return;
  if (!tableStatus) return;

  const offset = page * pageSize;
  const res = await fetch(`/api/kv/${encodeURIComponent(currentUser.id)}?limit=${pageSize}&offset=${offset}`);
  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    tableStatus.textContent = data.error || 'Failed to load keys';
    banner(tableStatus.textContent, 'err');
    return;
  }

  currentPage = page;
  totalEntries = data.total || 0;
  renderEntries(data.entries || []);
  updatePagination();
};

// stripe
const loadStripeInstance = async () => {
  if (stripeInstance) return stripeInstance;
  const res = await fetch('/api/stripe/config');
  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.publishableKey) {
    throw new Error(data.error || 'Stripe not configured');
  }
  stripePublishableKey = data.publishableKey;
  stripeInstance = Stripe(stripePublishableKey);
  return stripeInstance;
};

const confirmPayment = async (token) => {
  const res = await fetch('/api/stripe/confirm', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Console-Request': 'true' },
    body: JSON.stringify({ token })
  });
  const data = await res.json().catch(() => ({}));

  if (res.ok && data.user) {
    setCurrentUser(data.user);
    checkoutToken = null;
    if (paymentInfo) paymentInfo.textContent = 'Payment confirmed. You are premium.';
    banner('Payment confirmed. You are premium.', 'ok');
  } else {
    banner(data.error || 'Payment confirmation failed.', 'err');
  }
  log(res.ok ? data : { error: data.error });
};

(() => {
  const saved = localStorage.getItem('kvUser');
  if (!saved) {
    if (isMainPage) setCurrentUser(null);
    return;
  }

  try {
    const parsed = JSON.parse(saved);
    if (parsed?.id) {
      setCurrentUser(parsed);
      if (isLoginPage) {
        window.location.href = '/';
        return;
      }

      if (isMainPage) {
        log(`Restored session for ${parsed.id}`);
        loadEntries(0);
      }

      if (userIdInput && !userIdInput.value) userIdInput.value = parsed.id;
    }
  } catch (_) {
    localStorage.removeItem('kvUser');
    if (isMainPage) setCurrentUser(null);
  }
})();

if (isLoginPage && createUserBtn) {
  createUserBtn.onclick = async () => {
    const userId = userIdInput?.value.trim() || '';
    const password = passwordInput?.value || '';

    if (!userId) {
      banner('Please provide a user id.', 'err');
      return;
    }
    if (!password) {
      banner('Please provide a password.', 'err');
      return;
    }

    let res = await fetch('/api/users/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: userId, password })
    });

    let data = await res.json().catch(() => ({}));

    if (res.status === 404) {
      res = await fetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: userId, password })
      });
      data = await res.json().catch(() => ({}));
    }

    if (!res.ok || !data.user) {
      banner(data.error || 'Login/Create failed.', 'err');
      return;
    }

    setCurrentUser(data.user);
    window.location.href = '/';
  };
}

if (isMainPage) {
  if (logoutBtn) {
    logoutBtn.onclick = () => {
      setCurrentUser(null);
      keySecrets = {};
      checkoutToken = null;
      if (paymentInfo) paymentInfo.textContent = '';
      if (entriesBody) entriesBody.innerHTML = '';
      if (tableStatus) tableStatus.textContent = 'No data loaded.';
      if (pageInfo) pageInfo.textContent = '';
      log('Logged out.');
    };
  }

  if (startCheckoutBtn) {
    startCheckoutBtn.onclick = async () => {
      if (!currentUser) {
        banner('Create or log in first.', 'err');
        return log('Create or log in first.');
      }
      let stripe;
      try {
        stripe = await loadStripeInstance();
      } catch (err) {
        banner(err.message, 'err');
        return log({ error: err.message });
      }

      const res = await fetch('/api/stripe/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Console-Request': 'true' },
        body: JSON.stringify({ userId: currentUser.id })
      });
      const data = await res.json().catch(() => ({}));

      if (res.ok) {
        checkoutToken = data.token;
        if (paymentInfo) paymentInfo.textContent = `Checkout started. Redirecting to Stripe...`;
        banner('Redirecting to Stripe checkout…', 'ok');

        const { error } = await stripe.redirectToCheckout({ sessionId: data.token });
        if (error) {
          banner(error.message, 'err');
          log({ error: error.message });
        }
      } else {
        if (paymentInfo) paymentInfo.textContent = '';
        banner(data.error || 'Failed to start checkout.', 'err');
      }
      log(res.ok ? data : { error: data.error });
    };
  }

  if (setBtn) {
    setBtn.onclick = async () => {
      if (!currentUser) {
        banner('Create or log in first.', 'err');
        return log('Create or log in first.');
      }
      const userId = currentUser.id;
      const key = keyInput?.value.trim() || '';
      const rawValue = valueInput?.value.trim() || '';
      const existingSecret = keySecrets[key];

      if (!key) {
        banner('Please provide a key.', 'err');
        return log('Please provide a key.');
      }
      if (!rawValue) {
        banner('Please provide a value.', 'err');
        return log('Please provide a value.');
      }

      let parsed = rawValue;
      try { parsed = JSON.parse(rawValue); } catch (_) {}

      const res = await fetch(`/api/kv/${encodeURIComponent(userId)}/${encodeURIComponent(key)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          value: parsed,
          secret: existingSecret || undefined,
          readRequiresSecret: !!requireSecret?.checked
        })
      });

      const data = await res.json().catch(() => ({}));
      log(res.ok ? data : { error: data.error });

      if (res.ok) {
        banner(`Saved "${key}".`, 'ok');

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
      } else {
        banner(data.error || 'Failed to save key.', 'err');
      }
    };
  }

  if (getBtn) {
    getBtn.onclick = async () => {
      if (!currentUser) {
        banner('Create or log in first.', 'err');
        return log('Create or log in first.');
      }
      const userId = currentUser.id;
      const key = keyInput?.value.trim() || '';
      if (!key) {
        banner('Please provide a key.', 'err');
        return log('Please provide a key.');
      }

      const secret = keySecrets[key];
      const secretQuery = secret ? `?secret=${encodeURIComponent(secret)}` : '';
      const res = await fetch(`/api/kv/${encodeURIComponent(userId)}/${encodeURIComponent(key)}${secretQuery}`);
      const data = await res.json().catch(() => ({}));

      log(res.ok ? data : { error: data.error });
      banner(res.ok ? `Fetched "${key}".` : (data.error || 'Fetch failed.'), res.ok ? 'ok' : 'err');
    };
  }

  if (clearBtn) {
    clearBtn.onclick = () => {
      log('Waiting for input…');
      banner('Ready.', 'ok');
    };
  }

  if (prevPageBtn) {
    prevPageBtn.onclick = () => {
      if (currentPage === 0) return;
      loadEntries(currentPage - 1);
    };
  }

  if (nextPageBtn) {
    nextPageBtn.onclick = () => {
      if ((currentPage + 1) * pageSize >= totalEntries) return;
      loadEntries(currentPage + 1);
    };
  }

  if (entriesBody) {
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
          banner('No secret stored for this key. Save the key again to generate a new shareable link.', 'err');
          return log('No secret stored for this key. Save the key again to generate a new shareable link.');
        }
        url += `?secret=${encodeURIComponent(s)}`;
      }

      navigator.clipboard?.writeText(url);
      banner('Share link copied to clipboard.', 'ok');
      log({ share: url });
    });
  }

  const params = new URLSearchParams(window.location.search);
  const sessionIdFromUrl = params.get('session_id');
  if (sessionIdFromUrl) {
    checkoutToken = sessionIdFromUrl;
    confirmPayment(sessionIdFromUrl);
    const cleanUrl = window.location.origin + window.location.pathname;
    window.history.replaceState({}, document.title, cleanUrl);
  }
}
