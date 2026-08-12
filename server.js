/**
 * server.js — Student to Nurse backend
 * -----------------------------------------------------------------------
 * Creates real Stripe Checkout Sessions and verifies payment server-side.
 * This is the piece that makes the paywall actually secure: the frontend
 * never sees your secret key, and it never decides on its own whether
 * someone paid — it always asks this server, which always asks Stripe.
 *
 * SETUP
 *   1. npm init -y
 *   2. npm install express stripe cors dotenv
 *   3. Create a file named .env in this same folder (never commit it):
 *        STRIPE_SECRET_KEY=sk_test_...your real secret key...
 *        FRONTEND_URL=http://localhost:3000
 *        STRIPE_WEBHOOK_SECRET=whsec_...from step 6 below...
 *   4. node server.js
 *
 * This will create a db.json file the first time someone checks out —
 * that file holds real (hashed) student passwords and payment status.
 * Treat it like .env: never share it, never commit it to a public repo.
 *
 * PRICES
 *   Create these once in your Stripe Dashboard (Product Catalog) and
 *   paste the resulting price IDs below. Using Price IDs (rather than
 *   hardcoding amounts here) keeps pricing changes in Stripe, not code.
 *
 * WEBHOOK (step 6 — do this before accepting real payments)
 *   Stripe Dashboard → Developers → Webhooks → Add endpoint
 *     URL: https://your-deployed-backend.com/api/webhook
 *     Event: checkout.session.completed
 *   Copy the "Signing secret" into STRIPE_WEBHOOK_SECRET in .env.
 *   For local testing, use the Stripe CLI instead:
 *     stripe listen --forward-to localhost:4242/api/webhook
 * -----------------------------------------------------------------------
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { Pool } = require('pg');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();
const PORT = process.env.PORT || 4242;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

/* ---------------------------------------------------------------------
   PERSISTENT ACCOUNT STORAGE — real Postgres database (e.g. Neon), not
   a local file. This is what actually survives server restarts and
   redeploys — a local JSON file does not, on most hosting platforms'
   free tiers (their disks are wiped between deploys).
   Set DATABASE_URL in your environment (Render → Environment tab) to
   the connection string your database provider gives you.
--------------------------------------------------------------------- */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // required by most hosted Postgres providers
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      email TEXT PRIMARY KEY,
      salt TEXT NOT NULL,
      hash TEXT NOT NULL,
      full_access BOOLEAN NOT NULL DEFAULT false,
      singles JSONB NOT NULL DEFAULT '[]'
    )
  `);
}

/* Passwords are never stored in plain text — only a salted hash. */
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

/* Called when someone starts checkout. Creates the account (unpaid)
   if it doesn't exist yet; leaves it alone if it does. */
async function createOrGetUser(email, password) {
  const existing = await pool.query('SELECT 1 FROM users WHERE email = $1', [email]);
  if (existing.rows.length === 0) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = hashPassword(password, salt);
    await pool.query(
      'INSERT INTO users (email, salt, hash, full_access, singles) VALUES ($1, $2, $3, false, $4)',
      [email, salt, hash, JSON.stringify([])]
    );
  }
}

/* Called when a webhook or verified session confirms real payment. */
async function grantEntitlement(email, plan, code) {
  const existing = await pool.query('SELECT 1 FROM users WHERE email = $1', [email]);
  if (existing.rows.length === 0) {
    // Shouldn't normally happen (account is created at checkout time),
    // but guard against it so payment is never silently lost.
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = hashPassword(crypto.randomBytes(16).toString('hex'), salt);
    await pool.query(
      'INSERT INTO users (email, salt, hash, full_access, singles) VALUES ($1, $2, $3, false, $4)',
      [email, salt, hash, JSON.stringify([])]
    );
  }
  if (plan === 'full') {
    await pool.query('UPDATE users SET full_access = true WHERE email = $1', [email]);
  }
  if (plan === 'single' && code) {
    await pool.query(
      `UPDATE users SET singles = 
         CASE WHEN singles @> $2::jsonb THEN singles ELSE singles || $2::jsonb END
       WHERE email = $1`,
      [email, JSON.stringify([code])]
    );
  }
}

/* Verifies email + password, timing-safe. Returns { full, singles } or null. */
async function verifyLogin(email, password) {
  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  if (result.rows.length === 0) return null;
  const user = result.rows[0];
  const attemptHash = Buffer.from(hashPassword(password, user.salt));
  const storedHash = Buffer.from(user.hash);
  if (attemptHash.length !== storedHash.length || !crypto.timingSafeEqual(attemptHash, storedHash)) return null;
  return { full: user.full_access, singles: user.singles };
}

/* ---- PRICE IDS — replace with your real Stripe Price IDs ---- */
const PRICES = {
  full: 'price_1U1IycCbo2Erb0YsBBwkemlS',
  single: 'price_1U1IzpCbo2Erb0Yst7NOp0S4' // same $27 price, reused for every department
};

const VALID_CODES = new Set([
  'NURS-299','NURS-301','NURS-310','NURS-318','NURS-325','NURS-332',
  'NURS-340','NURS-348','NURS-355','NURS-362','NURS-370','NURS-378',
  'NURS-385','NURS-392'
]);

// session_id -> { plan, code, email, paid }  (short-lived lookup cache
// used only to answer the frontend's post-redirect verification call)
const sessionCache = new Map();

/* IMPORTANT: the webhook route needs the raw request body for signature
   verification, so its raw-body parser must be registered BEFORE the
   general express.json() middleware below. */
app.post('/api/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      req.headers['stripe-signature'],
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const { plan, code } = session.metadata || {};
    const email = session.customer_details?.email || session.customer_email;

    if (email && plan) {
      await grantEntitlement(email, plan, code);
      sessionCache.set(session.id, { plan, code: code || null, email, paid: true });
      console.log(`✅ Payment confirmed via webhook: ${email} → ${plan}${code ? ' (' + code + ')' : ''}`);
    }
  }

  res.json({ received: true });
});

app.use(cors());
app.use(express.json());

/* Create a real Stripe Checkout Session */
app.post('/api/create-checkout-session', async (req, res) => {
  try {
    const { plan, code, email, password } = req.body;
    if (plan !== 'full' && plan !== 'single') {
      return res.status(400).json({ error: 'plan must be "full" or "single"' });
    }
    if (plan === 'single' && !VALID_CODES.has(code)) {
      return res.status(400).json({ error: 'unknown department code' });
    }
    if (!email || !password || password.length < 8) {
      return res.status(400).json({ error: 'email and an 8+ character password are required' });
    }

    // Create the account now (unpaid) so the password is set even if the
    // customer abandons checkout — payment only flips `full`/`singles` later.
    await createOrGetUser(email, password);

    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      line_items: [{ price: plan === 'full' ? PRICES.full : PRICES.single, quantity: 1 }],
      customer_email: email,
      metadata: { plan, code: code || '' },
      success_url: `${FRONTEND_URL}/?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${FRONTEND_URL}/`
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('Error creating checkout session:', err.message);
    res.status(500).json({ error: 'Could not create checkout session' });
  }
});

/* Verify a session after the customer returns from Stripe.
   This is a stopgap for instant UI feedback — the webhook above is the
   real source of truth. We double-check with Stripe directly here too,
   so access isn't granted even if the webhook is delayed or missing. */
app.get('/api/verify-session', async (req, res) => {
  try {
    const { session_id } = req.query;
    if (!session_id) return res.status(400).json({ error: 'session_id required' });

    const cached = sessionCache.get(session_id);
    if (cached) return res.json(cached);

    const session = await stripe.checkout.sessions.retrieve(session_id);
    const paid = session.payment_status === 'paid';
    const { plan, code } = session.metadata || {};
    const email = session.customer_details?.email || session.customer_email;

    if (paid && email && plan) {
      await grantEntitlement(email, plan, code);
      const result = { plan, code: code || null, email, paid: true };
      sessionCache.set(session_id, result);
      return res.json(result);
    }
    res.json({ paid: false });
  } catch (err) {
    console.error('Error verifying session:', err.message);
    res.status(500).json({ error: 'Could not verify session' });
  }
});

/* Real sign-in: requires the correct password before revealing anything
   about what a given email has access to. */
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ success: false, error: 'email and password required' });

  const user = await verifyLogin(email, password);
  if (!user) return res.status(401).json({ success: false, error: 'Incorrect email or password' });

  res.json({ success: true, full: user.full, singles: user.singles });
});

initDB()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Student to Nurse backend running on http://localhost:${PORT}`);
      console.log(`Expecting frontend at ${FRONTEND_URL}`);
      console.log('Database connected and users table ready.');
    });
  })
  .catch(err => {
    console.error('Failed to initialize database — check DATABASE_URL:', err.message);
    process.exit(1);
  });
