from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict

app = FastAPI(title="Inventory Service", version="1.0.0")

stock_db: Dict[str, int] = {"prod-001":100, "prod-002":50, "prod-003":200}
reservations: Dict[str, Dict[str, int]] = {}

class StockUpdate(BaseModel):
    quantity: int

class ReservationRequest(BaseModel):
    order_id: str
    product_id: str
    quantity: int

@app.get("/health")
def health(): return {"status":"ok","service":"inventory-service"}

@app.get("/stock/{product_id}")
def get_stock(product_id: str):
    if product_id not in stock_db: raise HTTPException(404,"Product not found")
    return {"product_id":product_id,"available":stock_db[product_id]}

@app.put("/stock/{product_id}")
def update_stock(product_id: str, body: StockUpdate):
    if body.quantity < 0: raise HTTPException(400,"Quantity cannot be negative")
    stock_db[product_id] = body.quantity
    return {"product_id":product_id,"available":stock_db[product_id]}

@app.post("/reserve", status_code=201)
def reserve(body: ReservationRequest):
    if stock_db.get(body.product_id,0) < body.quantity:
        raise HTTPException(409,"Insufficient stock")
    stock_db[body.product_id] -= body.quantity
    reservations.setdefault(body.order_id,{})[body.product_id] = body.quantity
    return {"reserved":True,"order_id":body.order_id}

@app.post("/release")
def release(body: ReservationRequest):
    qty = reservations.get(body.order_id,{}).get(body.product_id,0)
    stock_db[body.product_id] = stock_db.get(body.product_id,0) + qty
    return {"released":True,"order_id":body.order_id}
