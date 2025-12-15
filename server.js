const path = require('path');
const crypto = require('crypto');
const express = require('express');
const Database = require('better-sqlite3');
const { LRUCache } = require('lru-cache');
const bcrypt = require('bcryptjs');
const Stripe = require('stripe');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'kvstore.db');

const db = new Database(DB_PATH);
db.prepare(
  "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, tier TEXT NOT NULL CHECK(tier IN ('free','premium')), free_key TEXT, password_hash TEXT)"
).run();
db.prepare(
  'CREATE TABLE IF NOT EXISTS kv_entries (user_id TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, updated_at INTEGER NOT NULL, secret_hash TEXT, read_requires_secret INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(user_id, key))'
).run();
db.prepare(
  "CREATE TABLE IF NOT EXISTS payments (token TEXT PRIMARY KEY, user_id TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('pending','completed')), created_at INTEGER NOT NULL)"
).run();

// Ensure password_hash column exists if DB was created before this field
const userColumns = db.prepare("PRAGMA table_info(users)").all();
const hasPassword = userColumns.some((c) => c.name === 'password_hash');
if (!hasPassword) {
  db.prepare('ALTER TABLE users ADD COLUMN password_hash TEXT').run();
}
// Ensure kv_entries has secret_hash and read_requires_secret
const kvColumns = db.prepare("PRAGMA table_info(kv_entries)").all();
const hasSecretHash = kvColumns.some((c) => c.name === 'secret_hash');
const hasReadRequiresSecret = kvColumns.some((c) => c.name === 'read_requires_secret');
if (!hasSecretHash) {
  db.prepare('ALTER TABLE kv_entries ADD COLUMN secret_hash TEXT').run();
}
if (!hasReadRequiresSecret) {
  db.prepare('ALTER TABLE kv_entries ADD COLUMN read_requires_secret INTEGER NOT NULL DEFAULT 0').run();
}

const cache = new LRUCache({ max: 200, ttl: 1000 * 60 * 10 });

const requireConsoleRequest = (req, res, next) => {
  if (req.get('x-console-request') !== 'true') {
    return res.status(403).json({ error: 'Console-only endpoint' });
  }
  next();
};

function getStripeClient() {
  const secret = process.env.STRIPE_SECRET_KEY;
  if (!secret) return null;
  return new Stripe(secret, { apiVersion: '2024-06-20' });
}

const createUserStmt = db.prepare('INSERT INTO users (id, tier, password_hash) VALUES (?, ?, ?)');
const updateFreeKeyStmt = db.prepare('UPDATE users SET free_key = ? WHERE id = ?');
const updateTierStmt = db.prepare('UPDATE users SET tier = ? WHERE id = ?');
const readUserStmt = db.prepare('SELECT id, tier, free_key FROM users WHERE id = ?');
const readUserWithPasswordStmt = db.prepare('SELECT id, tier, free_key, password_hash FROM users WHERE id = ?');

const upsertStmt = db.prepare(
  'INSERT INTO kv_entries (user_id, key, value, updated_at, secret_hash, read_requires_secret) VALUES (?, ?, ?, ?, ?, ?) ' +
    'ON CONFLICT(user_id, key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at, ' +
    'secret_hash=COALESCE(excluded.secret_hash, kv_entries.secret_hash), read_requires_secret=excluded.read_requires_secret'
);
const readEntryStmt = db.prepare('SELECT key, value, updated_at, secret_hash, read_requires_secret FROM kv_entries WHERE user_id = ? AND key = ?');
const listEntriesStmt = db.prepare(
  'SELECT key, value, updated_at, secret_hash, read_requires_secret FROM kv_entries WHERE user_id = ? ORDER BY updated_at DESC LIMIT ? OFFSET ?'
);
const countEntriesStmt = db.prepare('SELECT COUNT(*) as count FROM kv_entries WHERE user_id = ?');
const deleteUserStmt = db.prepare('DELETE FROM users WHERE id = ?');
const createPaymentStmt = db.prepare('INSERT INTO payments (token, user_id, status, created_at) VALUES (?, ?, ?, ?)');
const readPaymentStmt = db.prepare('SELECT token, user_id, status FROM payments WHERE token = ?');
const completePaymentStmt = db.prepare("UPDATE payments SET status = 'completed' WHERE token = ?");
const readPublishableKey = () => process.env.STRIPE_PUBLISHABLE_KEY || null;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/users', (req, res) => {
  const { id, password } = req.body || {};
  const normalizedTier = 'free'; // All accounts start as free; upgrade via Stripe checkout.

  if (typeof id !== 'string' || id.trim() === '') {
    return res.status(400).json({ error: 'User id must be a non-empty string' });
  }
  if (typeof password !== 'string' || password.length < 4) {
    return res.status(400).json({ error: 'Password must be at least 4 characters' });
  }

  const hashed = bcrypt.hashSync(password, 10);
  try {
    createUserStmt.run(id, normalizedTier, hashed);
    const user = readUserStmt.get(id);
    return res.status(201).json({ user, created: true });
  } catch (err) {
    if (err && err.code === 'SQLITE_CONSTRAINT_PRIMARYKEY') {
      return res.status(409).json({ error: 'User already exists. Please log in.' });
    }
    console.error('Create user error', err);
    return res.status(500).json({ error: 'Failed to create user' });
  }
});

app.post('/api/users/login', (req, res) => {
  const { id, password } = req.body || {};
  if (typeof id !== 'string' || id.trim() === '') {
    return res.status(400).json({ error: 'User id must be provided' });
  }
  if (typeof password !== 'string') {
    return res.status(400).json({ error: 'Password must be provided' });
  }

  const user = readUserWithPasswordStmt.get(id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  if (!user.password_hash || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  return res.json({ user: { id: user.id, tier: user.tier, free_key: user.free_key } });
});

// Stripe Checkout creation (console-only)
app.post('/api/stripe/checkout', requireConsoleRequest, async (req, res) => {
  const { userId } = req.body || {};
  if (typeof userId !== 'string' || userId.trim() === '') {
    return res.status(400).json({ error: 'User id must be provided' });
  }

  const user = readUserStmt.get(userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.tier === 'premium') {
    return res.status(400).json({ error: 'User already premium' });
  }

  const stripeClient = getStripeClient();
  if (!stripeClient) {
    return res.status(500).json({ error: 'Stripe secret key not configured' });
  }

  const origin = process.env.CONSOLE_ORIGIN || 'http://localhost:3000';
  const successUrl = `${origin}/?session_id={CHECKOUT_SESSION_ID}`;
  const cancelUrl = `${origin}/?payment=cancel`;
  try {
    const session = await stripeClient.checkout.sessions.create({
      mode: 'payment',
      success_url: successUrl,
      cancel_url: cancelUrl,
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: { name: 'KV Store Premium' },
            unit_amount: 500
          },
          quantity: 1
        }
      ],
      metadata: { userId }
    });

    createPaymentStmt.run(session.id, userId, 'pending', Date.now());
    return res.status(201).json({ token: session.id, url: session.url, message: 'Redirecting to Stripe checkout.' });
  } catch (err) {
    console.error('Stripe checkout create error', err);
    return res.status(502).json({ error: 'Failed to create Stripe checkout session' });
  }
});

// Stripe confirmation (console-only)
app.post('/api/stripe/confirm', requireConsoleRequest, async (req, res) => {
  const { token } = req.body || {};
  if (typeof token !== 'string' || token.trim() === '') {
    return res.status(400).json({ error: 'Payment token is required' });
  }
  const payment = readPaymentStmt.get(token);
  if (!payment) {
    return res.status(404).json({ error: 'Payment not found' });
  }
  if (payment.status !== 'pending') {
    return res.status(400).json({ error: 'Payment already processed' });
  }

  const stripeClient = getStripeClient();
  if (!stripeClient) {
    return res.status(500).json({ error: 'Stripe secret key not configured' });
  }

  try {
    const session = await stripeClient.checkout.sessions.retrieve(token, { expand: ['payment_intent'] });
    if (session.payment_status !== 'paid') {
      return res.status(400).json({ error: 'Payment not completed yet' });
    }
    if (session.metadata?.userId !== payment.user_id) {
      return res.status(400).json({ error: 'Payment user mismatch' });
    }
  } catch (err) {
    console.error('Stripe checkout confirm error', err);
    return res.status(502).json({ error: 'Failed to verify Stripe checkout session' });
  }

  completePaymentStmt.run(token);
  updateTierStmt.run('premium', payment.user_id);
  const updatedUser = readUserStmt.get(payment.user_id);
  return res.json({ user: updatedUser, status: 'premium-activated' });
});

// Stripe config for client
app.get('/api/stripe/config', (req, res) => {
  const publishableKey = readPublishableKey();
  if (!publishableKey) {
    return res.status(500).json({ error: 'Stripe publishable key not configured' });
  }
  res.json({ publishableKey });
});

// List keys/values for a user with pagination
app.get('/api/kv/:userId', (req, res) => {
  const { userId } = req.params;
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
  const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
  const secret = req.query.secret || req.get('x-kv-secret');

  const user = readUserStmt.get(userId);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  const rows = listEntriesStmt.all(userId, limit, offset);
  const totalRow = countEntriesStmt.get(userId);
  const total = totalRow ? totalRow.count : 0;

  const entries = rows.map((row) => {
    const requiresSecret = !!row.read_requires_secret;
    let value = row.value;
    if (requiresSecret) {
      const match = secret && row.secret_hash ? bcrypt.compareSync(secret, row.secret_hash) : false;
      if (!match) {
        value = null;
      }
    }
    return { key: row.key, value, updatedAt: row.updated_at };
  });

  return res.json({ entries, total, limit, offset });
});

app.get('/api/kv/:userId/:key', (req, res) => {
  const { userId, key } = req.params;
  const secret = req.query.secret || req.get('x-kv-secret');
  if (!userId || !key) {
    return res.status(400).json({ error: 'User and key are required' });
  }

  const user = readUserStmt.get(userId);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  if (user.tier === 'free' && user.free_key && user.free_key !== key) {
    return res.status(403).json({ error: `Free tier can only access key \"${user.free_key}\"` });
  }

  const row = readEntryStmt.get(userId, key);
  if (!row) {
    return res.status(404).json({ error: 'Key not found' });
  }
  if (row.read_requires_secret) {
    const match = secret && row.secret_hash ? bcrypt.compareSync(secret, row.secret_hash) : false;
    if (!match) {
      return res.status(403).json({ error: 'Secret required to read this key' });
    }
  }

  if (!row.read_requires_secret) {
    const cacheKey = `${userId}::${key}`;
    cache.set(cacheKey, row.value);
  }
  return res.json({ key, value: row.value, updatedAt: row.updated_at });
});

app.post('/api/kv/:userId/:key', (req, res) => {
  const { userId, key } = req.params;
  const { value, secret, readRequiresSecret } = req.body || {};
  if (!userId || typeof key !== 'string' || key.trim() === '') {
    return res.status(400).json({ error: 'User and key must be provided' });
  }
  if (value === undefined || value === null) {
    return res.status(400).json({ error: 'Value is required' });
  }

  const user = readUserStmt.get(userId);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  const normalizedKey = key.trim();
  if (user.tier === 'free') {
    if (user.free_key && user.free_key !== normalizedKey) {
      return res.status(403).json({ error: `Free tier locked to key \"${user.free_key}\"` });
    }
    if (!user.free_key) {
      updateFreeKeyStmt.run(normalizedKey, userId);
    }
  }

  const existing = readEntryStmt.get(userId, normalizedKey);
  if (existing && existing.secret_hash) {
    const matches = secret && bcrypt.compareSync(secret, existing.secret_hash);
    if (!matches) {
      return res.status(403).json({ error: 'Secret required to update this key' });
    }
  }

  const serializedValue = typeof value === 'string' ? value : JSON.stringify(value);
  const now = Date.now();

  const desiredReadFlag =
    typeof readRequiresSecret === 'boolean'
      ? (readRequiresSecret ? 1 : 0)
      : existing
        ? existing.read_requires_secret
        : 0;

  let finalSecret = secret || null;
  let newSecretHash = existing ? existing.secret_hash : null;

  if (desiredReadFlag) {
    if (existing && existing.secret_hash) {
      // keep existing secret unless a new one is provided
      newSecretHash = secret ? bcrypt.hashSync(secret, 10) : existing.secret_hash;
    } else {
      // generate secret if none supplied
      if (!secret) {
        finalSecret = crypto.randomBytes(12).toString('hex');
      }
      newSecretHash = bcrypt.hashSync(finalSecret || secret, 10);
    }
  } else {
    // removing protection requires a matching secret above
    newSecretHash = null;
  }

  upsertStmt.run(userId, normalizedKey, serializedValue, now, newSecretHash, desiredReadFlag);
  const cacheKey = `${userId}::${normalizedKey}`;
  if (desiredReadFlag) {
    cache.delete(cacheKey);
  } else {
    cache.set(cacheKey, serializedValue);
  }

  return res.status(201).json({
    key: normalizedKey,
    value: serializedValue,
    updatedAt: now,
    requiresSecret: !!desiredReadFlag,
    secret: desiredReadFlag ? finalSecret : undefined
  });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.listen(PORT, () => {
  console.log(`KV store listening on http://localhost:${PORT}`);
});
