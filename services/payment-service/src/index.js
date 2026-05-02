'use strict';
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const app = express();
app.use(express.json());

const transactions = {};

app.get('/health', (_,res) => res.json({ status:'ok', service:'payment-service' }));

app.post('/payments', (req,res) => {
  const { order_id, amount, currency='USD', method, card_last4 } = req.body;
  if (!order_id || !amount || !method) return res.status(400).json({ detail:'order_id, amount, method required' });
  if (typeof amount !== 'number' || amount <= 0) return res.status(400).json({ detail:'amount must be positive' });
  const tx = { id:uuidv4(), order_id, amount, currency, method, card_last4:card_last4||null,
                status:'completed', created_at:new Date().toISOString() };
  transactions[tx.id] = tx;
  res.status(201).json(tx);
});

app.get('/payments/:id', (req,res) => {
  const tx = transactions[req.params.id];
  if (!tx) return res.status(404).json({ detail:'Transaction not found' });
  res.json(tx);
});

app.get('/payments/order/:order_id', (req,res) => {
  const results = Object.values(transactions).filter(t => t.order_id === req.params.order_id);
  res.json({ order_id:req.params.order_id, transactions:results });
});

const PORT = process.env.PORT || 8004;
app.listen(PORT, '0.0.0.0', () => console.log(`Payment Service on :${PORT}`));
