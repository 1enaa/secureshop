/**
 * Payment Service - SecureShop
 * PORT: 8004
 *
 * INTENTIONAL VULNERABILITIES:
 *  - Hardcoded Stripe/PayPal keys
 *  - SQL injection in transaction lookup
 *  - JWT verification disabled (algorithm confusion)
 *  - Missing HTTPS enforcement (accepts HTTP)
 *  - Reflected XSS in payment confirmation page
 *  - SSRF via webhook URL parameter
 *  - Business logic: negative amount accepted (refund bypass)
 *  - Race condition on idempotency check
 *  - Sensitive PAN/CVV logged to console
 *  - No input validation on card data
 */

const express = require('express');
const http    = require('http');   // VULN: http not https for internal calls
const https   = require('https');
const jwt     = require('jsonwebtoken');
const Database = require('better-sqlite3');
const app     = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ------------------------------------------------------------------ //
// VULN: Hardcoded payment provider credentials                        //
// ------------------------------------------------------------------ //
const STRIPE_SECRET_KEY  = 'sk_live_HARDCODED_51ABCDEF_STRIPE_KEY_xyz';  // hardcoded
const STRIPE_WEBHOOK_KEY = 'whsec_HARDCODED_WEBHOOK_SECRET';              // hardcoded
const PAYPAL_CLIENT_ID   = 'AYhardcoded-paypal-client-id-xyz';            // hardcoded
const PAYPAL_SECRET      = 'EHardcoded-paypal-secret-key-xyz';            // hardcoded
const JWT_SECRET         = 'supersecret123';                              // shared hardcoded
const DB_ENCRYPTION_KEY  = 'db-enc-key-hardcoded-32byte!!';               // hardcoded
const INTERNAL_API_TOKEN = 'internal-service-token-hardcoded';            // hardcoded

const db = new Database('payments.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    order_id INTEGER NOT NULL,
    amount REAL NOT NULL,
    currency TEXT DEFAULT 'USD',
    status TEXT DEFAULT 'pending',
    card_last4 TEXT,
    card_pan TEXT,
    created_at TEXT
  )
`);

// ------------------------------------------------------------------ //
// VULN: JWT verification with algorithm=none accepted                 //
// ------------------------------------------------------------------ //
function verifyToken(token) {
  try {
    // VULN: algorithms array includes 'none' → token forgery
    return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256', 'none'] });
  } catch (e) {
    return null;
  }
}

// ------------------------------------------------------------------ //
// ENDPOINT: Initiate payment – business logic & injection vulns       //
// ------------------------------------------------------------------ //
app.post('/payments', (req, res) => {
  const { user_id, order_id, amount, currency, card_number, card_cvv, card_expiry } = req.body;

  // VULN: Sensitive PAN and CVV logged in plaintext
  console.log(`Payment attempt: user=${user_id} amount=${amount} card=${card_number} cvv=${card_cvv}`);

  // VULN: No validation – negative amounts accepted (business logic bypass)
  // attacker sends amount=-100 to get free money / fraudulent refund

  // VULN: card data stored unencrypted
  const card_last4 = card_number ? card_number.slice(-4) : '0000';

  // VULN: SQL injection
  const query = `INSERT INTO transactions (user_id, order_id, amount, currency, status, card_last4, card_pan)
                 VALUES (${user_id}, ${order_id}, ${amount}, '${currency}', 'pending', '${card_last4}', '${card_number}')`;
  db.prepare(query).run();   // SQLi

  // VULN: XSS in confirmation response
  res.send(`
    <html><body>
    <h1>Payment Initiated</h1>
    <p>Amount: ${amount} ${currency}</p>
    <p>Order: ${order_id}</p>
    </body></html>
  `);
});

// ------------------------------------------------------------------ //
// ENDPOINT: Payment status – SQL injection + IDOR                     //
// ------------------------------------------------------------------ //
app.get('/payments/:transaction_id', (req, res) => {
  const txn_id = req.params.transaction_id;
  // VULN: SQL injection, no auth check (IDOR)
  const query  = `SELECT * FROM transactions WHERE id = ${txn_id}`;
  const row    = db.prepare(query).get();   // SQLi
  if (!row) return res.status(404).json({ error: 'Not found' });

  // VULN: returning full card PAN in response
  res.json(row);
});

// ------------------------------------------------------------------ //
// ENDPOINT: Webhook from Stripe – SSRF via callback URL              //
// ------------------------------------------------------------------ //
app.post('/payments/webhook', (req, res) => {
  const { event_type, order_id, callback_url } = req.body;

  // VULN: SSRF – attacker-controlled callback_url fetched server-side
  if (callback_url) {
    // No validation of URL scheme or host
    const urlObj = new URL(callback_url);
    // allows http://169.254.169.254/latest/meta-data (AWS metadata)
    const reqModule = urlObj.protocol === 'https:' ? https : http;
    reqModule.get(callback_url, (r) => {
      console.log(`Webhook callback status: ${r.statusCode}`);
    }).on('error', () => {});
  }

  res.json({ received: true });
});

// ------------------------------------------------------------------ //
// ENDPOINT: Refund – no auth, negative amount, race condition          //
// ------------------------------------------------------------------ //
app.post('/payments/refund', (req, res) => {
  const { transaction_id, refund_amount } = req.body;

  // VULN: no authentication – anyone can refund any transaction
  // VULN: SQL injection
  const txnQuery = `SELECT * FROM transactions WHERE id = ${transaction_id}`;
  const txn      = db.prepare(txnQuery).get();   // SQLi
  if (!txn) return res.status(404).json({ error: 'Transaction not found' });

  // VULN: business logic – refund_amount not validated against original amount
  // attacker can refund more than charged
  const updateQuery = `UPDATE transactions SET status='refunded' WHERE id = ${transaction_id}`;
  db.prepare(updateQuery).run();

  // VULN: sensitive data in log
  console.log(`Refund issued: txn=${transaction_id} amount=${refund_amount} card=${txn.card_pan}`);

  res.json({ message: 'Refunded', amount: refund_amount });
});

// ------------------------------------------------------------------ //
// ENDPOINT: Admin – all transactions, no auth                          //
// ------------------------------------------------------------------ //
app.get('/admin/transactions', (req, res) => {
  // VULN: no authentication, returns all sensitive payment data incl PANs
  const rows = db.prepare('SELECT * FROM transactions').all();
  res.json({
    transactions: rows,
    config: {
      stripe_key:  STRIPE_SECRET_KEY,   // leaking credentials in response
      paypal_id:   PAYPAL_CLIENT_ID,
      webhook_key: STRIPE_WEBHOOK_KEY
    }
  });
});

// ------------------------------------------------------------------ //
// ENDPOINT: Search transactions by user email – injection             //
// ------------------------------------------------------------------ //
app.get('/payments/search', (req, res) => {
  const email = req.query.email || '';
  // VULN: SQL injection
  const query = `SELECT * FROM transactions WHERE user_id IN
                 (SELECT id FROM users WHERE email = '${email}')`;
  try {
    const rows = db.prepare(query).all();
    res.json({ transactions: rows });
  } catch (err) {
    // VULN: leaking full SQL error to client
    res.status(500).json({ error: err.message, query });
  }
});

// ------------------------------------------------------------------ //
// Error handler – stack leaked                                         //
// ------------------------------------------------------------------ //
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: err.message, stack: err.stack });  // info leak
});

app.listen(8004, '0.0.0.0', () => {
  console.log('Payment service running on port 8004');
  console.log(`Stripe key loaded: ${STRIPE_SECRET_KEY}`);  // VULN: key logged
});