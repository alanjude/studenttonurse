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
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();
const PORT = process.env.PORT || 4242;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

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

/* ---------------------------------------------------------------------
   TEMPORARY DATA STORE
   In-memory Map — resets if the server restarts. Replace this with a
   real database (Postgres, SQLite, etc.) before handling real customers.
   Structure: email -> { full: bool, singles: Set<code> }
--------------------------------------------------------------------- */
const entitlements = new Map();
// session_id -> { plan, code, email, paid }  (short-lived lookup cache
// used only to answer the frontend's post-redirect verification call)
const sessionCache = new Map();

function grantEntitlement(email, plan, code) {
  if (!entitlements.has(email)) entitlements.set(email, { full: false, singles: new Set() });
  const rec = entitlements.get(email);
  if (plan === 'full') rec.full = true;
  if (plan === 'single' && code) rec.singles.add(code);
}

/* IMPORTANT: the webhook route needs the raw request body for signature
   verification, so its raw-body parser must be registered BEFORE the
   general express.json() middleware below. */
app.post('/api/webhook', express.raw({ type: 'application/json' }), (req, res) => {
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
      grantEntitlement(email, plan, code);
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
    const { plan, code, email } = req.body;
    if (plan !== 'full' && plan !== 'single') {
      return res.status(400).json({ error: 'plan must be "full" or "single"' });
    }
    if (plan === 'single' && !VALID_CODES.has(code)) {
      return res.status(400).json({ error: 'unknown department code' });
    }

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
      grantEntitlement(email, plan, code);
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

/* Look up what a signed-in student has access to (used by the portal) */
app.get('/api/entitlements', (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: 'email required' });
  const rec = entitlements.get(email) || { full: false, singles: new Set() };
  res.json({ full: rec.full, singles: Array.from(rec.singles) });
});

app.listen(PORT, () => {
  console.log(`Student to Nurse backend running on http://localhost:${PORT}`);
  console.log(`Expecting frontend at ${FRONTEND_URL}`);
});
