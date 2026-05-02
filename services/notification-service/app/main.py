from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List
import os, json, asyncio
from datetime import datetime

app = FastAPI(title="Notification Service", version="1.0.0")

RABBITMQ_URL = os.getenv("RABBITMQ_URL", "amqp://guest:guest@rabbitmq:5672")

sent_notifications: List[dict] = []

class NotifyRequest(BaseModel):
    type: str          # email | sms
    recipient: str
    subject: Optional[str] = None
    body: str

def _dispatch(notification: dict):
    """Simulate sending email/SMS — replace with real SMTP/Twilio in production."""
    print(f"[NOTIFY] {notification['type'].upper()} → {notification['recipient']}: {notification['subject']}")
    sent_notifications.append(notification)

@app.get("/health")
def health(): return {"status":"ok","service":"notification-service"}

@app.post("/notify", status_code=201)
def notify(body: NotifyRequest, bg: BackgroundTasks):
    if body.type not in ("email","sms"):
        raise HTTPException(400,"type must be 'email' or 'sms'")
    n = {"id": str(len(sent_notifications)+1), "type": body.type,
         "recipient": body.recipient, "subject": body.subject,
         "body": body.body, "sent_at": datetime.utcnow().isoformat(), "status":"sent"}
    bg.add_task(_dispatch, n)
    return n

@app.get("/notifications")
def list_notifications():
    return {"total": len(sent_notifications), "data": sent_notifications}

# Optional: lightweight RabbitMQ consumer on startup
@app.on_event("startup")
async def start_rabbitmq_consumer():
    try:
        import aio_pika
        connection = await aio_pika.connect_robust(RABBITMQ_URL)
        channel    = await connection.channel()
        queue      = await channel.declare_queue("order_notifications", durable=True)
        async def on_message(message: aio_pika.IncomingMessage):
            async with message.process():
                data = json.loads(message.body)
                _dispatch({"id":str(len(sent_notifications)+1), **data,
                           "sent_at":datetime.utcnow().isoformat(),"status":"sent"})
        await queue.consume(on_message)
        print("RabbitMQ consumer started")
    except Exception as e:
        print(f"RabbitMQ unavailable, skipping consumer: {e}")
