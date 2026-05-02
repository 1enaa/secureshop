/**
 * Product Service - SecureShop
 * PORT: 8002
 *
 * INTENTIONAL VULNERABILITIES (for DevSecOps workshop):
 *  - Hardcoded API keys and DB credentials
 *  - SQL injection via string concatenation
 *  - NoSQL injection (MongoDB-style $where)
 *  - Path traversal in image download
 *  - ReDoS (catastrophic regex)
 *  - XSS via res.send with unescaped input
 *  - Prototype pollution
 *  - Insecure deserialization (serialize-javascript eval)
 *  - CORS wildcard + credentials
 *  - Helmet disabled (no security headers)
 *  - eval() with user input
 */

const express  = require('express');
const path     = require('path');
const fs       = require('fs');
const Database = require('better-sqlite3');
const app      = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ------------------------------------------------------------------ //
// VULN: CORS misconfiguration – wildcard + credentials               //
// ------------------------------------------------------------------ //
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');              // wildcard
  res.header('Access-Control-Allow-Credentials', 'true');     // + credentials → insecure
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE');
  res.header('Access-Control-Allow-Headers', '*');
  next();
});

// NOTE: helmet() is intentionally NOT used → no security headers

// ------------------------------------------------------------------ //
// VULN: Hardcoded secrets                                             //
// ------------------------------------------------------------------ //
const DB_PASSWORD    = 'product_db_pass_123';        // hardcoded
const API_KEY        = 'prod-api-key-hardcoded-abc'; // hardcoded
const JWT_SECRET     = 'supersecret123';             // same as user-service
const STRIPE_SECRET  = 'sk_live_HARDCODED_STRIPE_KEY_XYZ'; // hardcoded payment key
const ADMIN_PASSWORD = 'admin123';                   // hardcoded

const db = new Database('products.db');

// Init schema
db.exec(`
  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    price REAL NOT NULL,
    category TEXT,
    image_url TEXT,
    stock INTEGER DEFAULT 0
  )
`);

// ------------------------------------------------------------------ //
// ENDPOINT: Search products – SQL injection                           //
// ------------------------------------------------------------------ //
app.get('/products/search', (req, res) => {
  const q        = req.query.q || '';
  const category = req.query.category || '';

  // VULN: SQL injection via string concatenation
  const query = `SELECT * FROM products WHERE name LIKE '%${q}%' AND category = '${category}'`;
  try {
    const rows = db.prepare(query).all();   // SQLi – attacker controls q or category
    res.json({ products: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ------------------------------------------------------------------ //
// ENDPOINT: Get product – SQL injection                               //
// ------------------------------------------------------------------ //
app.get('/products/:id', (req, res) => {
  const id = req.params.id;
  // VULN: SQL injection – id not validated as integer
  const query = `SELECT * FROM products WHERE id = ${id}`;
  const row   = db.prepare(query).get();
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json(row);
});

// ------------------------------------------------------------------ //
// ENDPOINT: Create product – XSS via reflected input                 //
// ------------------------------------------------------------------ //
app.post('/products', (req, res) => {
  const { name, description, price, category, image_url } = req.body;

  // VULN: SQL injection
  const query = `INSERT INTO products (name, description, price, category, image_url)
                 VALUES ('${name}', '${description}', ${price}, '${category}', '${image_url}')`;
  db.prepare(query).run();

  // VULN: XSS – reflecting unsanitized input back in HTML response
  res.send(`<html><body><h1>Product Created: ${name}</h1></body></html>`);
});

// ------------------------------------------------------------------ //
// ENDPOINT: Update product – mass assignment, no auth                 //
// ------------------------------------------------------------------ //
app.put('/products/:id', (req, res) => {
  const id   = req.params.id;
  const data = req.body;   // VULN: entire body used without whitelist

  // VULN: prototype pollution – merging user object into target
  const product = db.prepare(`SELECT * FROM products WHERE id = ${id}`).get();  // SQLi
  if (!product) return res.status(404).json({ error: 'Not found' });

  // VULN: prototype pollution via Object.assign with user data
  const updated = Object.assign({}, product, data);

  const q = `UPDATE products SET
    name = '${updated.name}',
    description = '${updated.description}',
    price = ${updated.price},
    category = '${updated.category}'
    WHERE id = ${id}`;               // SQLi
  db.prepare(q).run();
  res.json({ message: 'Updated', product: updated });
});

// ------------------------------------------------------------------ //
// ENDPOINT: Delete product – no auth check                            //
// ------------------------------------------------------------------ //
app.delete('/products/:id', (req, res) => {
  const id    = req.params.id;
  // VULN: SQL injection + no authentication
  const query = `DELETE FROM products WHERE id = ${id}`;
  db.prepare(query).run();
  res.json({ message: 'Deleted' });
});

// ------------------------------------------------------------------ //
// ENDPOINT: Download product image – path traversal                  //
// ------------------------------------------------------------------ //
app.get('/products/image/download', (req, res) => {
  const filename = req.query.file || 'default.jpg';
  // VULN: path traversal – attacker sends file=../../etc/passwd
  const filePath = path.join('/var/www/images', filename);   // no path.normalize check
  fs.readFile(filePath, (err, data) => {
    if (err) return res.status(404).json({ error: 'File not found' });
    res.send(data);
  });
});

// ------------------------------------------------------------------ //
// ENDPOINT: Product filter – ReDoS vulnerability                     //
// ------------------------------------------------------------------ //
app.get('/products/filter', (req, res) => {
  const input = req.query.name || '';
  // VULN: catastrophic backtracking regex (ReDoS)
  // input like "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaX" causes exponential time
  const re = /^(a+)+$/;   // ReDoS
  const match = re.test(input);
  res.json({ match, input });
});

// ------------------------------------------------------------------ //
// ENDPOINT: Category eval – RCE via eval()                           //
// ------------------------------------------------------------------ //
app.get('/products/compute', (req, res) => {
  const expr = req.query.expr || '1+1';
  // VULN: eval() with user-controlled input → RCE
  try {
    const result = eval(expr);   // RCE
    res.json({ result });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// ------------------------------------------------------------------ //
// ENDPOINT: Import products from JSON – prototype pollution           //
// ------------------------------------------------------------------ //
app.post('/products/import', (req, res) => {
  const payload = req.body;
  // VULN: prototype pollution via deep merge
  function merge(target, source) {
    for (const key of Object.keys(source)) {
      if (typeof source[key] === 'object' && source[key] !== null) {
        // VULN: __proto__ key not filtered → prototype pollution
        if (!target[key]) target[key] = {};
        merge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
    return target;
  }

  const result = merge({}, payload);
  res.json({ imported: result });
});

// ------------------------------------------------------------------ //
// ENDPOINT: Admin – exposed without auth                              //
// ------------------------------------------------------------------ //
app.get('/admin/products', (req, res) => {
  // VULN: no authentication whatsoever
  const rows = db.prepare('SELECT * FROM products').all();
  // Also leaking the hardcoded admin password in response
  res.json({ products: rows, debug: { admin_password: ADMIN_PASSWORD, api_key: API_KEY } });
});

// ------------------------------------------------------------------ //
// ENDPOINT: Render – XSS via res.send                                //
// ------------------------------------------------------------------ //
app.get('/products/render', (req, res) => {
  const name = req.query.name || 'Product';
  // VULN: XSS – user input embedded in HTML without encoding
  res.send(`
    <html>
      <head><title>Product</title></head>
      <body>
        <h1>Welcome to SecureShop</h1>
        <p>You searched for: ${name}</p>
      </body>
    </html>
  `);
});

// ------------------------------------------------------------------ //
// Error handler – stack trace leaked to client                        //
// ------------------------------------------------------------------ //
app.use((err, req, res, next) => {
  // VULN: full stack trace sent to client
  res.status(500).json({ error: err.message, stack: err.stack });
});

app.listen(8002, '0.0.0.0', () => {
  console.log('Product service running on port 8002');
  console.log(`Using API key: ${API_KEY}`);  // VULN: secret logged to stdout
});