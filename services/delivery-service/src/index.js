'use strict';
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const app = express();
app.use(express.json());

/**
 * Delivery Service — manages shipments for fulfilled orders.
 * Ports: 8007
 * Responsibilities:
 *  - Create shipment when an order is paid
 *  - Track delivery status lifecycle
 *  - Estimate delivery date
 *  - Assign courier / tracking number
 */

const STATUSES = ['pending','assigned','picked_up','in_transit','out_for_delivery','delivered','failed'];

const shipments = {};   // shipment_id → shipment object

function estimateDelivery(days = 3) {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d.toISOString().split('T')[0];
}

// ── Health ──────────────────────────────────────────────────────────────────
app.get('/health', (_,res) => res.json({ status:'ok', service:'delivery-service' }));

// ── Create Shipment ──────────────────────────────────────────────────────────
app.post('/shipments', (req,res) => {
  const { order_id, recipient_name, address, city, postal_code, country='DZ' } = req.body;
  if (!order_id || !recipient_name || !address || !city || !postal_code) {
    return res.status(400).json({ detail:'order_id, recipient_name, address, city, postal_code required' });
  }
  const shipment = {
    id:           uuidv4(),
    order_id,
    tracking_number: 'SS-' + Math.random().toString(36).substring(2,10).toUpperCase(),
    status:       'pending',
    courier:      null,
    recipient: { name:recipient_name, address, city, postal_code, country },
    estimated_delivery: estimateDelivery(3),
    events: [{ status:'pending', timestamp:new Date().toISOString(), note:'Shipment created' }],
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };
  shipments[shipment.id] = shipment;
  res.status(201).json(shipment);
});

// ── Get Shipment by ID ────────────────────────────────────────────────────────
app.get('/shipments/:id', (req,res) => {
  const s = shipments[req.params.id];
  if (!s) return res.status(404).json({ detail:'Shipment not found' });
  res.json(s);
});

// ── Get Shipment by Order ID ──────────────────────────────────────────────────
app.get('/shipments/order/:order_id', (req,res) => {
  const results = Object.values(shipments).filter(s => s.order_id === req.params.order_id);
  res.json({ order_id:req.params.order_id, shipments:results });
});

// ── Track by Tracking Number ──────────────────────────────────────────────────
app.get('/track/:tracking_number', (req,res) => {
  const s = Object.values(shipments).find(s => s.tracking_number === req.params.tracking_number);
  if (!s) return res.status(404).json({ detail:'Tracking number not found' });
  res.json({
    tracking_number: s.tracking_number,
    status:          s.status,
    estimated_delivery: s.estimated_delivery,
    events:          s.events,
  });
});

// ── Update Status (internal / courier callback) ───────────────────────────────
app.patch('/shipments/:id/status', (req,res) => {
  const s = shipments[req.params.id];
  if (!s) return res.status(404).json({ detail:'Shipment not found' });
  const { status, note, courier } = req.body;
  if (!STATUSES.includes(status)) {
    return res.status(400).json({ detail:`status must be one of: ${STATUSES.join(', ')}` });
  }
  s.status     = status;
  s.updated_at = new Date().toISOString();
  if (courier) s.courier = courier;
  s.events.push({ status, timestamp:new Date().toISOString(), note:note||'' });
  res.json(s);
});

// ── Assign Courier ────────────────────────────────────────────────────────────
app.patch('/shipments/:id/assign', (req,res) => {
  const s = shipments[req.params.id];
  if (!s) return res.status(404).json({ detail:'Shipment not found' });
  const { courier } = req.body;
  if (!courier) return res.status(400).json({ detail:'courier name required' });
  s.courier    = courier;
  s.status     = 'assigned';
  s.updated_at = new Date().toISOString();
  s.events.push({ status:'assigned', timestamp:new Date().toISOString(), note:`Assigned to ${courier}` });
  res.json(s);
});

// ── List All Shipments (admin) ────────────────────────────────────────────────
app.get('/shipments', (_,res) => {
  res.json({ total:Object.keys(shipments).length, data:Object.values(shipments) });
});

const PORT = process.env.PORT || 8007;
app.listen(PORT, '0.0.0.0', () => console.log(`Delivery Service on :${PORT}`));
