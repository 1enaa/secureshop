"""
Order Service - SecureShop
PORT: 8003
INTENTIONAL VULNERABILITIES:
  - B105: Hardcoded secret key
  - B301/B302: Pickle deserialization (RCE)
  - B311: Random used for order ID (not cryptographically secure)
  - B506: yaml.load without Loader (arbitrary code execution)
  - B608: SQL injection
  - B703: Jinja2 SSTI
  - Broken access control: no JWT validation on order endpoints
  - Insecure direct object reference on orders
"""

import os
import sqlite3
import pickle
import random
import yaml
import jwt
import base64
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# VULN B105 – hardcoded secrets
SECRET_KEY      = "order-secret-key-123"
JWT_SECRET      = "supersecret123"
PAYMENT_API_KEY = "pk_live_HARDCODED_KEY_12345"   # B105
DB_PASSWORD     = "orderdb_pass"                   # B106

DATABASE = "orders.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            items TEXT NOT NULL,
            total REAL NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cart (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER DEFAULT 1
        )
    """)
    conn.commit()
    conn.close()


# ------------------------------------------------------------------ #
# VULN B311 – weak random for order reference number                 #
# ------------------------------------------------------------------ #
def generate_order_ref():
    return f"ORD-{random.randint(100000, 999999)}"   # B311


# ------------------------------------------------------------------ #
# Decode JWT – VULN: algorithm not verified, accepts 'none'          #
# ------------------------------------------------------------------ #
def decode_token(token: str):
    try:
        # VULN: options allow none algorithm → token forgery
        return jwt.decode(
            token, JWT_SECRET,
            algorithms=["HS256", "none"],
            options={"verify_exp": False}   # expired tokens accepted
        )
    except Exception:
        return None


# ------------------------------------------------------------------ #
# ENDPOINT: Add to cart                                              #
# ------------------------------------------------------------------ #
@app.route("/cart", methods=["POST"])
def add_to_cart():
    data       = request.get_json()
    user_id    = data.get("user_id")     # VULN: taken directly from body, no JWT check
    product_id = data.get("product_id")
    quantity   = data.get("quantity", 1)

    conn = get_db()
    # VULN B608 – SQL injection
    query = f"INSERT INTO cart (user_id, product_id, quantity) VALUES ({user_id}, {product_id}, {quantity})"
    conn.execute(query)
    conn.commit()
    conn.close()
    return jsonify({"message": "Added to cart"}), 201


# ------------------------------------------------------------------ #
# ENDPOINT: View cart – IDOR                                         #
# ------------------------------------------------------------------ #
@app.route("/cart/<int:user_id>", methods=["GET"])
def view_cart(user_id):
    # VULN IDOR – no check that requester owns this cart
    conn = get_db()
    query = f"SELECT * FROM cart WHERE user_id={user_id}"   # B608
    items = conn.execute(query).fetchall()
    conn.close()
    return jsonify({"cart": items})


# ------------------------------------------------------------------ #
# ENDPOINT: Place order                                              #
# ------------------------------------------------------------------ #
@app.route("/orders", methods=["POST"])
def place_order():
    data    = request.get_json()
    user_id = data.get("user_id")   # no auth validation
    items   = str(data.get("items", []))
    total   = data.get("total", 0)

    # VULN B311 – predictable order reference
    ref = generate_order_ref()

    conn = get_db()
    # VULN B608
    query = f"INSERT INTO orders (user_id, items, total, status) VALUES ({user_id}, '{items}', {total}, 'pending')"
    conn.execute(query)
    conn.commit()
    order_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()

    return jsonify({"order_id": order_id, "ref": ref, "status": "pending"}), 201


# ------------------------------------------------------------------ #
# ENDPOINT: Get order – IDOR                                         #
# ------------------------------------------------------------------ #
@app.route("/orders/<int:order_id>", methods=["GET"])
def get_order(order_id):
    # VULN IDOR – any user can read any order
    conn = get_db()
    query = f"SELECT * FROM orders WHERE id={order_id}"   # B608
    order = conn.execute(query).fetchone()
    conn.close()

    if not order:
        return jsonify({"error": "Not found"}), 404

    return jsonify({
        "id":      order[0],
        "user_id": order[1],
        "items":   order[2],
        "total":   order[3],
        "status":  order[4]
    })


# ------------------------------------------------------------------ #
# ENDPOINT: Restore cart from serialized data – Pickle RCE           #
# ------------------------------------------------------------------ #
@app.route("/cart/restore", methods=["POST"])
def restore_cart():
    # VULN B301/B302 – deserializing pickle from user input → RCE
    data        = request.get_json()
    cart_data_b64 = data.get("cart_data", "")
    cart_bytes  = base64.b64decode(cart_data_b64)
    cart        = pickle.loads(cart_bytes)   # B301 – arbitrary code execution
    return jsonify({"restored": str(cart)})


# ------------------------------------------------------------------ #
# ENDPOINT: Import order config via YAML – arbitrary code exec       #
# ------------------------------------------------------------------ #
@app.route("/orders/import", methods=["POST"])
def import_order_config():
    raw_yaml = request.data.decode("utf-8")
    # VULN B506 – yaml.load without Loader allows arbitrary Python objects
    config = yaml.load(raw_yaml)   # B506
    return jsonify({"imported": str(config)})


# ------------------------------------------------------------------ #
# ENDPOINT: Order receipt – SSTI via Jinja2                          #
# ------------------------------------------------------------------ #
@app.route("/orders/<int:order_id>/receipt", methods=["GET"])
def order_receipt(order_id):
    note = request.args.get("note", "Thank you for your order!")
    # VULN B703 – user-controlled input rendered as Jinja2 template
    template = f"""
    <html><body>
    <h2>Order #{order_id} Receipt</h2>
    <p>{note}</p>
    </body></html>
    """
    return render_template_string(template)   # B703 – SSTI if note contains {{7*7}}


# ------------------------------------------------------------------ #
# ENDPOINT: Cancel order – no auth, anyone can cancel any order      #
# ------------------------------------------------------------------ #
@app.route("/orders/<int:order_id>/cancel", methods=["DELETE"])
def cancel_order(order_id):
    conn = get_db()
    query = f"UPDATE orders SET status='cancelled' WHERE id={order_id}"   # B608
    conn.execute(query)
    conn.commit()
    conn.close()
    return jsonify({"message": "Order cancelled"})


if __name__ == "__main__":
    init_db()
    # VULN B201 – debug mode on
    app.run(host="0.0.0.0", port=8003, debug=True)   # B201