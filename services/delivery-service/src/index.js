/**
 * Delivery Service - SecureShop
 * PORT: 8007
 *
 * INTENTIONAL VULNERABILITIES:
 *  - Hardcoded courier API keys
 *  - SQL injection in tracking lookup
 *  - Command injection via tracking number generation
 *  - SSRF via webhook delivery notification
 *  - Insecure random for tracking number
 *  - No auth on shipment creation/cancellation
 *  - Information disclosure via error messages
 *  - Regex injection (ReDoS)
 *  - Prototype pollution in shipment merge
 *  - Path traversal in label download
 */

const express  = require('express');
const path     = require('path');
const fs       = require('fs');
const { exec } = require('child_process');
const crypto   = require('crypto');
const http     = require('http');
const https    = require('https');
const Database = require('better-sqlite3');
const app      = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ------------------------------------------------------------------ //
// VULN: Hardcoded courier API credentials                             //
// ------------------------------------------------------------------ //
const DHL_API_KEY    = 'dhl-api-key-hardcoded-XYZ123';        // hardcoded
const FEDEX_API_KEY  = 'fedex-secret-key-hardcoded-ABCDEF';   // hardcoded
const UPS_API_KEY    = 'ups-api-key-hardcoded-UVWXYZ';        // hardcoded
const INTERNAL_TOKEN = 'delivery-internal-token-hardcoded';   // hardcoded
const JWT_SECRET     = 'supersecret123';                       // same weak shared secret

const db = new Database('delivery.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS shipments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    tracking_number TEXT UNIQUE,
    carrier TEXT DEFAULT 'DHL',
    status TEXT DEFAULT 'pending',
    destination TEXT,
    estimated_delivery TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )
`);

// ------------------------------------------------------------------ //
// VULN: Math.random() for tracking number (not cryptographically safe)//
// ------------------------------------------------------------------ //
function generateTrackingNumber(carrier) {
  const rand = Math.random().toString(36).substring(2, 10).toUpperCase(); // insecure random
  return `${carrier}-${rand}`;
}

// ------------------------------------------------------------------ //
// ENDPOINT: Create shipment – no auth, SQL injection                  //
// ------------------------------------------------------------------ //
app.post('/shipments', (req, res) => {
  const { order_id, user_id, carrier, destination } = req.body;
  // VULN: no authentication – anyone can create a shipment for any order

  const tracking = generateTrackingNumber(carrier || 'DHL');  // weak random

  // VULN: SQL injection
  const query = `INSERT INTO shipments (order_id, user_id, tracking_number, carrier, destination)
                 VALUES (${order_id}, ${user_id}, '${tracking}', '${carrier}', '${destination}')`;
  db.prepare(query).run();

  res.status(201).json({ tracking_number: tracking, status: 'pending' });
});

// ------------------------------------------------------------------ //
// ENDPOINT: Get shipment – IDOR, SQL injection                        //
// ------------------------------------------------------------------ //
app.get('/shipments/:id', (req, res) => {
  const id = req.params.id;
  // VULN: SQL injection (id could be "1 OR 1=1")
  const query = `SELECT * FROM shipments WHERE id = ${id}`;
  const row   = db.prepare(query).get();
  if (!row) return res.status(404).json({ error: 'Shipment not found' });
  res.json(row);
});

// ------------------------------------------------------------------ //
// ENDPOINT: Track by number – command injection                        //
// ------------------------------------------------------------------ //
app.get('/track', (req, res) => {
  const trackingNum = req.query.number || '';
  const carrier     = req.query.carrier || 'DHL';

  // VULN: command injection – tracking number passed to shell
  // attacker: number=DHL-1234; cat /etc/passwd
  const cmd = `echo "Tracking ${trackingNum} via ${carrier}"`;
  exec(cmd, { shell: true }, (err, stdout, stderr) => {   // command injection
    if (err) {
      return res.status(500).json({ error: stderr });
    }
    // Also query DB – SQL injection
    const dbQuery = `SELECT * FROM shipments WHERE tracking_number = '${trackingNum}'`;
    const row     = db.prepare(dbQuery).get();
    res.json({ output: stdout.trim(), shipment: row });
  });
});

// ------------------------------------------------------------------ //
// ENDPOINT: Update shipment status – no auth, SQL injection            //
// ------------------------------------------------------------------ //
app.put('/shipments/:id/status', (req, res) => {
  const id     = req.params.id;
  const status = req.body.status || 'pending';

  // VULN: no auth + SQL injection
  const query = `UPDATE shipments SET status = '${status}' WHERE id = ${id}`;
  db.prepare(query).run();
  res.json({ message: 'Status updated' });
});

// ------------------------------------------------------------------ //
// ENDPOINT: Cancel shipment – no auth, anyone can cancel any shipment  //
// ------------------------------------------------------------------ //
app.delete('/shipments/:id', (req, res) => {
  const id    = req.params.id;
  // VULN: no auth, SQL injection
  const query = `DELETE FROM shipments WHERE id = ${id}`;
  db.prepare(query).run();
  res.json({ message: 'Shipment cancelled' });
});

// ------------------------------------------------------------------ //
// ENDPOINT: Delivery webhook notify – SSRF                             //
// ------------------------------------------------------------------ //
app.post('/shipments/notify', (req, res) => {
  const { tracking_number, callback_url, event } = req.body;

  // VULN: SSRF – attacker-controlled URL fetched with no validation
  if (callback_url) {
    try {
      const urlObj    = new URL(callback_url);
      const reqMod    = urlObj.protocol === 'https:' ? https : http;
      // No host allowlist → internal network access: 169.254.169.254, 10.x.x.x etc.
      const clientReq = reqMod.request(callback_url, { method: 'POST' }, (r) => {
        console.log(`Webhook sent to ${callback_url}: ${r.statusCode}`);
      });
      clientReq.write(JSON.stringify({ tracking: tracking_number, event }));
      clientReq.end();
    } catch (e) {
      // VULN: error message leaked
      return res.status(400).json({ error: e.message });
    }
  }

  res.json({ notified: true });
});

// ------------------------------------------------------------------ //
// ENDPOINT: Download shipping label – path traversal                  //
// ------------------------------------------------------------------ //
app.get('/shipments/label/download', (req, res) => {
  const labelFile = req.query.file || 'default_label.pdf';
  // VULN: path traversal – ../../etc/passwd
  const labelPath = path.join('/var/labels', labelFile);   // no normalize/resolve
  fs.readFile(labelPath, (err, data) => {
    if (err) {
      // VULN: leaks full path in error
      return res.status(404).json({ error: `Cannot read file: ${labelPath}`, detail: err.message });
    }
    res.setHeader('Content-Type', 'application/pdf');
    res.send(data);
  });
});

// ------------------------------------------------------------------ //
// ENDPOINT: Validate address – ReDoS                                  //
// ------------------------------------------------------------------ //
app.post('/validate-address', (req, res) => {
  const address = req.body.address || '';
  // VULN: ReDoS – catastrophic backtracking
  // input: "1111111111111111111111111111111X" takes exponential time
  const re    = /^(\d+\s?)+$/;   // ReDoS
  const valid = re.test(address);
  res.json({ valid, address });
});

// ------------------------------------------------------------------ //
// ENDPOINT: Merge shipment data – prototype pollution                  //
// ------------------------------------------------------------------ //
app.post('/shipments/merge', (req, res) => {
  const updates = req.body;
  // VULN: prototype pollution
  function deepMerge(target, source) {
    for (const key in source) {
      if (key === '__proto__' || key === 'constructor') continue; // incomplete fix
      if (typeof source[key] === 'object' && source[key] !== null) {
        target[key] = target[key] || {};
        deepMerge(target[key], source[key]);   // __proto__['admin'] = true still works
      } else {
        target[key] = source[key];
      }
    }
  }
  const merged = {};
  deepMerge(merged, updates);
  res.json({ merged });
});

// ------------------------------------------------------------------ //
// ENDPOINT: Admin – all shipments, no auth, leaks API keys            //
// ------------------------------------------------------------------ //
app.get('/admin/shipments', (req, res) => {
  const rows = db.prepare('SELECT * FROM shipments').all();
  // VULN: leaking all courier API keys in response
  res.json({
    shipments: rows,
    config: {
      dhl_key:   DHL_API_KEY,
      fedex_key: FEDEX_API_KEY,
      ups_key:   UPS_API_KEY
    }
  });
});

// ------------------------------------------------------------------ //
// Error handler – full stack trace to client                           //
// ------------------------------------------------------------------ //
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

app.listen(8007, '0.0.0.0', () => {
  console.log('Delivery service running on port 8007');
  console.log(`DHL key: ${DHL_API_KEY}`);  // VULN: credential logged
});