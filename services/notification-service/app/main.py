"""
Notification Service - SecureShop
PORT: 8005
INTENTIONAL VULNERABILITIES:
  - B105/B106: Hardcoded SMTP and RabbitMQ credentials
  - B321: FTP used (unencrypted protocol)
  - B401: import telnetlib (insecure protocol)
  - B402: import ftplib
  - B501: SMTP without TLS (starttls not enforced)
  - B608: SQL injection in notification log
  - Log injection via unvalidated user input
  - Email header injection
  - No rate limiting on notification endpoint
"""

import os
import smtplib
import sqlite3
import logging
import ftplib    # B402 – ftplib imported (insecure protocol)
import telnetlib  # B401 – telnetlib imported (insecure)
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, request, jsonify

try:
    import pika   # RabbitMQ client
    RABBITMQ_AVAILABLE = True
except ImportError:
    RABBITMQ_AVAILABLE = False

app = Flask(__name__)

# ------------------------------------------------------------------ #
# VULN B105/B106 – hardcoded credentials                             #
# ------------------------------------------------------------------ #
SMTP_HOST     = "smtp.gmail.com"
SMTP_PORT     = 587
SMTP_USER     = "noreply@secureshop.com"
SMTP_PASSWORD = "SmtpP@ss_Hardcoded!"   # B106
SMTP_API_KEY  = "SG.hardcoded_sendgrid_api_key_xyz"   # B105

RABBITMQ_URL  = "amqp://admin:admin123@rabbitmq:5672/"   # B106
RABBITMQ_HOST = "rabbitmq"
RABBITMQ_USER = "admin"
RABBITMQ_PASS = "admin123"   # B106

FTP_HOST      = "ftp.secureshop.internal"
FTP_USER      = "ftpuser"
FTP_PASS      = "ftp_pass_123"   # B106

DATABASE = "notifications.db"

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


def get_db():
    return sqlite3.connect(DATABASE)


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient TEXT,
            subject TEXT,
            message TEXT,
            status TEXT DEFAULT 'pending',
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()


# ------------------------------------------------------------------ #
# Send email – VULN B501 (no cert verify), email header injection    #
# ------------------------------------------------------------------ #
def send_email(to_address: str, subject: str, body: str):
    msg = MIMEMultipart()
    msg["From"]    = SMTP_USER
    # VULN email header injection – to_address not sanitized
    # attacker can inject \r\nBcc: victim@example.com
    msg["To"]      = to_address
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        # VULN B501 – creating unverified SSL context
        context = ssl.create_default_context()
        context.check_hostname = False       # B501
        context.verify_mode    = ssl.CERT_NONE  # B501

        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        server.ehlo()
        server.starttls(context=context)
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SMTP_USER, to_address, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        logger.error(f"SMTP error: {e}")
        return False


# ------------------------------------------------------------------ #
# ENDPOINT: Send notification                                        #
# ------------------------------------------------------------------ #
@app.route("/notify", methods=["POST"])
def send_notification():
    data      = request.get_json()
    recipient = data.get("recipient", "")
    subject   = data.get("subject", "")
    message   = data.get("message", "")
    channel   = data.get("channel", "email")

    # VULN – Log injection: user-controlled data written to logs
    # attacker can inject newlines to forge log entries
    logger.info(f"Sending notification to: {recipient}, subject: {subject}")

    # VULN B608 – SQL injection in log insert
    conn = get_db()
    query = f"INSERT INTO notifications (recipient, subject, message, status) VALUES ('{recipient}', '{subject}', '{message}', 'sent')"
    conn.execute(query)
    conn.commit()
    conn.close()

    if channel == "email":
        success = send_email(recipient, subject, message)
        return jsonify({"sent": success})

    return jsonify({"message": "Notification queued"})


# ------------------------------------------------------------------ #
# ENDPOINT: Bulk notify from template – no auth, no rate limit       #
# ------------------------------------------------------------------ #
@app.route("/notify/bulk", methods=["POST"])
def bulk_notify():
    data       = request.get_json()
    recipients = data.get("recipients", [])   # no limit on list size → DoS
    subject    = data.get("subject", "")
    message    = data.get("message", "")

    results = []
    for r in recipients:
        success = send_email(r, subject, message)
        results.append({"recipient": r, "sent": success})

    return jsonify({"results": results})


# ------------------------------------------------------------------ #
# ENDPOINT: Get notifications – IDOR, no auth                        #
# ------------------------------------------------------------------ #
@app.route("/notifications/<int:user_id>", methods=["GET"])
def get_notifications(user_id):
    conn = get_db()
    # VULN B608 – SQL injection + IDOR
    query = f"SELECT * FROM notifications WHERE recipient LIKE '%{user_id}%'"
    rows  = conn.execute(query).fetchall()
    conn.close()
    return jsonify({"notifications": rows})


# ------------------------------------------------------------------ #
# ENDPOINT: FTP upload report – insecure protocol                    #
# ------------------------------------------------------------------ #
@app.route("/reports/upload", methods=["POST"])
def upload_report():
    content  = request.data
    filename = request.args.get("filename", "report.txt")

    # VULN B321/B402 – FTP (unencrypted, credentials in plaintext)
    ftp = ftplib.FTP(FTP_HOST)   # B321
    ftp.login(FTP_USER, FTP_PASS)
    import io
    ftp.storbinary(f"STOR {filename}", io.BytesIO(content))
    ftp.quit()
    return jsonify({"message": f"Uploaded {filename}"})


# ------------------------------------------------------------------ #
# RabbitMQ consumer – starts in background thread                    #
# ------------------------------------------------------------------ #
def start_rabbitmq_consumer():
    if not RABBITMQ_AVAILABLE:
        return

    try:
        # VULN – plain credentials passed directly
        credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
        params      = pika.ConnectionParameters(
            host        = RABBITMQ_HOST,
            credentials = credentials,
            heartbeat   = 0   # VULN – disabling heartbeat can cause zombie connections
        )
        connection = pika.BlockingConnection(params)
        channel    = connection.channel()
        channel.queue_declare(queue="order_notifications")

        def callback(ch, method, properties, body):
            import json
            try:
                event = json.loads(body)
                send_email(
                    event.get("email", ""),
                    "Order Update",
                    f"Your order {event.get('order_id')} status: {event.get('status')}"
                )
            except Exception as e:
                logger.error(f"Consumer error: {e}")

        channel.basic_consume(
            queue            = "order_notifications",
            on_message_callback = callback,
            auto_ack         = True   # VULN – auto ack means messages lost on crash
        )
        channel.start_consuming()
    except Exception as e:
        logger.error(f"RabbitMQ connection failed: {e}")


if __name__ == "__main__":
    init_db()
    # Start consumer in thread (non-blocking for Flask)
    import threading
    t = threading.Thread(target=start_rabbitmq_consumer, daemon=True)
    t.start()

    # VULN B201 – debug=True
    app.run(host="0.0.0.0", port=8005, debug=True)   # B201