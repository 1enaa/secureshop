"""
Inventory Service - SecureShop
PORT: 8006
INTENTIONAL VULNERABILITIES:
  - B105: Hardcoded API key
  - B108: Hardcoded /tmp path
  - B310: urllib with user-supplied URL (SSRF)
  - B324: SHA1 for checksum (weak hash)
  - B404/B602: subprocess with shell=True
  - B608: SQL injection
  - Race condition on stock reservation (TOCTOU)
  - No authentication on reservation/release endpoints
"""

import os
import sqlite3
import hashlib
import subprocess
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
from flask import Flask, request, jsonify

app = Flask(__name__)

# VULN B105 – hardcoded credentials
API_KEY          = "inventory-api-key-hardcoded"   # B105
ADMIN_TOKEN      = "admin-token-9876"              # B105
DB_PASS          = "inv_db_pass_123"               # B106
INTERNAL_API_URL = "http://order-service:8003"

# VULN B108 – hardcoded /tmp paths
EXPORT_PATH = "/tmp/inventory_export.csv"          # B108
IMPORT_PATH = "/tmp/inventory_import.csv"          # B108

DATABASE = "inventory.db"


def get_db():
    return sqlite3.connect(DATABASE)


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER UNIQUE NOT NULL,
            quantity INTEGER DEFAULT 0,
            reserved INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()


# ------------------------------------------------------------------ #
# VULN B324 – SHA1 for integrity checksum                            #
# ------------------------------------------------------------------ #
def checksum(data: str) -> str:
    return hashlib.sha1(data.encode()).hexdigest()   # B324


# ------------------------------------------------------------------ #
# ENDPOINT: Get stock level                                          #
# ------------------------------------------------------------------ #
@app.route("/inventory/<int:product_id>", methods=["GET"])
def get_stock(product_id):
    conn = get_db()
    # VULN B608 – SQL injection
    query = f"SELECT * FROM inventory WHERE product_id={product_id}"
    row   = conn.execute(query).fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "Product not found"}), 404

    return jsonify({
        "product_id": row[1],
        "quantity":   row[2],
        "reserved":   row[3],
        "available":  row[2] - row[3]
    })


# ------------------------------------------------------------------ #
# ENDPOINT: Reserve stock – TOCTOU race condition                    #
# ------------------------------------------------------------------ #
@app.route("/inventory/reserve", methods=["POST"])
def reserve_stock():
    data       = request.get_json()
    product_id = data.get("product_id")
    qty        = data.get("quantity", 1)

    conn = get_db()
    # VULN TOCTOU – check then act without locking
    # VULN B608 – SQL injection
    check_query  = f"SELECT quantity, reserved FROM inventory WHERE product_id={product_id}"
    row          = conn.execute(check_query).fetchone()

    if not row:
        conn.close()
        return jsonify({"error": "Product not found"}), 404

    available = row[0] - row[1]
    if available < qty:
        conn.close()
        return jsonify({"error": "Insufficient stock"}), 409

    # No auth check – any service (or attacker) can reserve stock
    # VULN B608
    update_query = f"UPDATE inventory SET reserved = reserved + {qty} WHERE product_id={product_id}"
    conn.execute(update_query)
    conn.commit()
    conn.close()
    return jsonify({"message": "Reserved", "quantity": qty})


# ------------------------------------------------------------------ #
# ENDPOINT: Release stock – no auth                                  #
# ------------------------------------------------------------------ #
@app.route("/inventory/release", methods=["POST"])
def release_stock():
    data       = request.get_json()
    product_id = data.get("product_id")
    qty        = data.get("quantity", 1)

    conn = get_db()
    # VULN B608 – can pass negative qty to increase reserved
    query = f"UPDATE inventory SET reserved = reserved - {qty} WHERE product_id={product_id}"
    conn.execute(query)
    conn.commit()
    conn.close()
    return jsonify({"message": "Released"})


# ------------------------------------------------------------------ #
# ENDPOINT: Update stock – mass update, no auth                      #
# ------------------------------------------------------------------ #
@app.route("/inventory/<int:product_id>", methods=["PUT"])
def update_stock(product_id):
    data     = request.get_json()
    quantity = data.get("quantity", 0)

    conn = get_db()
    # VULN B608
    row = conn.execute(
        f"SELECT id FROM inventory WHERE product_id={product_id}"
    ).fetchone()

    if row:
        conn.execute(
            f"UPDATE inventory SET quantity={quantity} WHERE product_id={product_id}"   # B608
        )
    else:
        conn.execute(
            f"INSERT INTO inventory (product_id, quantity) VALUES ({product_id}, {quantity})"  # B608
        )
    conn.commit()
    conn.close()
    return jsonify({"message": "Stock updated"})


# ------------------------------------------------------------------ #
# ENDPOINT: Export inventory to CSV – command injection              #
# ------------------------------------------------------------------ #
@app.route("/inventory/export", methods=["GET"])
def export_inventory():
    fmt = request.args.get("format", "csv")
    # VULN B602 – shell=True with partially user-controlled string
    cmd = f"sqlite3 {DATABASE} .dump | grep inventory > {EXPORT_PATH}"
    subprocess.call(cmd, shell=True)   # B602
    return jsonify({"message": f"Exported to {EXPORT_PATH}"})


# ------------------------------------------------------------------ #
# ENDPOINT: Sync from external URL – SSRF + B310                    #
# ------------------------------------------------------------------ #
@app.route("/inventory/sync", methods=["POST"])
def sync_inventory():
    data       = request.get_json()
    source_url = data.get("url", "")
    # VULN B310 – urllib opening user-supplied URL (SSRF)
    response   = urllib.request.urlopen(source_url)   # B310
    content    = response.read().decode("utf-8")
    return jsonify({"synced": len(content), "preview": content[:100]})


# ------------------------------------------------------------------ #
# ENDPOINT: Import XML – XXE vulnerability                           #
# ------------------------------------------------------------------ #
@app.route("/inventory/import-xml", methods=["POST"])
def import_xml():
    xml_data = request.data
    # VULN: ElementTree is NOT vulnerable to XXE in CPython,
    # but using lxml without resolve_entities=False would be.
    # Documented here for DAST findings demonstration.
    try:
        root = ET.fromstring(xml_data)
        items = []
        for item in root.findall("item"):
            product_id = item.find("product_id").text
            quantity   = item.find("quantity").text
            # VULN B608 – SQL injection from XML data
            conn = get_db()
            conn.execute(
                f"INSERT OR REPLACE INTO inventory (product_id, quantity) VALUES ({product_id}, {quantity})"
            )
            conn.commit()
            conn.close()
            items.append({"product_id": product_id, "quantity": quantity})
        return jsonify({"imported": items})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ------------------------------------------------------------------ #
# ENDPOINT: Run diagnostic – RCE via os.system                       #
# ------------------------------------------------------------------ #
@app.route("/diag", methods=["GET"])
def diag():
    cmd = request.args.get("cmd", "uptime")
    # VULN B605 – os.system with user input
    os.system(cmd)   # B605
    return jsonify({"message": "Diagnostic run"})


if __name__ == "__main__":
    init_db()
    # VULN B201 – debug=True
    app.run(host="0.0.0.0", port=8006, debug=True)   # B201