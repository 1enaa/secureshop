from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from typing import List, Optional
import uuid, os
from datetime import datetime

app = FastAPI(title="Order Service", version="1.0.0")

orders_db: dict = {}
carts_db:  dict = {}

class CartItem(BaseModel):
    product_id: str
    quantity: int
    unit_price: float

class OrderRequest(BaseModel):
    items: List[CartItem]
    shipping_address: str

@app.get("/health")
def health(): return {"status": "ok", "service": "order-service"}

@app.post("/cart/{user_id}/add")
def add_to_cart(user_id: str, item: CartItem):
    carts_db.setdefault(user_id, []).append(item.dict())
    return {"message": "Item added", "cart_size": len(carts_db[user_id])}

@app.get("/cart/{user_id}")
def get_cart(user_id: str):
    return {"user_id": user_id, "items": carts_db.get(user_id, [])}

@app.post("/orders", status_code=201)
def create_order(body: OrderRequest, x_user_id: Optional[str] = Header(None)):
    if not x_user_id:
        raise HTTPException(401, "Missing user identity")
    oid   = str(uuid.uuid4())
    total = sum(i.quantity * i.unit_price for i in body.items)
    order = {"id": oid, "user_id": x_user_id, "items": [i.dict() for i in body.items],
             "total": total, "status": "pending",
             "shipping_address": body.shipping_address,
             "created_at": datetime.utcnow().isoformat()}
    orders_db[oid] = order
    return order

@app.get("/orders/{order_id}")
def get_order(order_id: str, x_user_id: Optional[str] = Header(None)):
    order = orders_db.get(order_id)
    if not order: raise HTTPException(404, "Order not found")
    if order["user_id"] != x_user_id: raise HTTPException(403, "Forbidden")
    return order

@app.patch("/orders/{order_id}/status")
def update_status(order_id: str, status: str):
    order = orders_db.get(order_id)
    if not order: raise HTTPException(404, "Order not found")
    order["status"] = status
    return order
