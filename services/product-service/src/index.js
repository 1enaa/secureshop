'use strict';
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const app = express();
app.use(express.json());

const products = {
  'prod-001': { id:'prod-001', name:'Laptop Pro',    price:1299.99, category:'electronics', stock:100 },
  'prod-002': { id:'prod-002', name:'Wireless Mouse', price:29.99,  category:'electronics', stock:50  },
  'prod-003': { id:'prod-003', name:'Office Chair',   price:249.99, category:'furniture',   stock:200 },
};

app.get('/health', (_,res) => res.json({ status:'ok', service:'product-service' }));

app.get('/products', (req, res) => {
  const { category, search, page=1, limit=10 } = req.query;
  let results = Object.values(products);
  if (category) results = results.filter(p => p.category === category);
  if (search)   results = results.filter(p => p.name.toLowerCase().includes(search.toLowerCase()));
  const start = (Number(page)-1)*Number(limit);
  res.json({ total:results.length, page:Number(page), data:results.slice(start, start+Number(limit)) });
});

app.get('/products/:id', (req,res) => {
  const p = products[req.params.id];
  if (!p) return res.status(404).json({ detail:'Product not found' });
  res.json(p);
});

app.post('/products', (req,res) => {
  const { name, price, category } = req.body;
  if (!name || price==null || !category) return res.status(400).json({ detail:'name, price, category required' });
  if (typeof price !== 'number' || price <= 0) return res.status(400).json({ detail:'price must be positive number' });
  const id = uuidv4();
  products[id] = { id, name, price, category, stock:0 };
  res.status(201).json(products[id]);
});

app.put('/products/:id', (req,res) => {
  if (!products[req.params.id]) return res.status(404).json({ detail:'Not found' });
  Object.assign(products[req.params.id], req.body);
  res.json(products[req.params.id]);
});

app.delete('/products/:id', (req,res) => {
  if (!products[req.params.id]) return res.status(404).json({ detail:'Not found' });
  delete products[req.params.id];
  res.status(204).send();
});

app.get('/categories', (_,res) => {
  res.json({ categories:[...new Set(Object.values(products).map(p=>p.category))] });
});

const PORT = process.env.PORT || 8002;
app.listen(PORT, '0.0.0.0', () => console.log(`Product Service on :${PORT}`));
