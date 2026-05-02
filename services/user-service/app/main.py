"""
User Service - SecureShop
PORT: 8001
INTENTIONAL VULNERABILITIES (for DevSecOps workshop):
  - B105: Hardcoded JWT secret
  - B106: Hardcoded password
  - B107: Hardcoded password argument
  - B201: Flask debug=True
  - B303: MD5 used for password hashing
  - B501: TLS/SSL verification disabled
  - B608: SQL injection via string formatting
  - B703/B308: Jinja2 autoescape disabled
  - Broken Auth: JWT algorithm=none accepted
  - IDOR: no ownership check on profile update
"""

import hashlib
import sqlite3
import subprocess
import os
import jwt
import requests
from flask import Flask, request, jsonify, render_template_string
from datetime import datetime, timedelta

app = Flask(__name__)

# ------------------------------------------------------------------ #
# VULN B105 / B106 – Hardcoded secrets                               #
# ------------------------------------------------------------------ #
JWT_SECRET      = "supersecret123"          # B105
DB_PASSWORD     = "admin123"                # B106
ADMIN_API_KEY   = "hardcoded-api-key-9999"  # B105
SMTP_PASSWORD   = "smtp_pass_plain"         # B106
RABBITMQ_URL    = "amqp://admin:admin123@rabbitmq:5672/"  # B106

DATABASE = "users.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    return conn


def init_db():
    conn = get_db()
    # ---------------------------------------------------------------- #
    # VULN B608 – SQL string concatenation (schema creation is fine    #
    # here but pattern is carried below into queries)                  #
    # ---------------------------------------------------------------- #
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            address TEXT
        )
    """)
    conn.commit()
    conn.close()


# ------------------------------------------------------------------ #
# VULN B303 – MD5 for password hashing                               #
# ------------------------------------------------------------------ #
def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()   # B303


# ------------------------------------------------------------------ #
# ENDPOINT: Register                                                  #
# ------------------------------------------------------------------ #
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")
    email    = data.get("email", "")

    hashed = hash_password(password)   # MD5 – intentional

    conn = get_db()
    try:
        # ------------------------------------------------------------ #
        # VULN B608 – SQL injection via f-string                       #
        # ------------------------------------------------------------ #
        query = f"INSERT INTO users (username, password, email) VALUES ('{username}', '{hashed}', '{email}')"
        conn.execute(query)
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409
    finally:
        conn.close()

    return jsonify({"message": "User registered successfully"}), 201


# ------------------------------------------------------------------ #
# ENDPOINT: Login – issues JWT                                        #
# ------------------------------------------------------------------ #
@app.route("/login", methods=["POST"])
def login():
    data     = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")
    hashed   = hash_password(password)

    conn = get_db()
    # ---------------------------------------------------------------- #
    # VULN B608 – SQL injection                                        #
    # ---------------------------------------------------------------- #
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{hashed}'"
    user  = conn.execute(query).fetchone()
    conn.close()

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    # ---------------------------------------------------------------- #
    # VULN – JWT signed with weak hardcoded secret; HS256 only         #
    # attacker who knows the secret can forge tokens                   #
    # ---------------------------------------------------------------- #
    payload = {
        "user_id": user[0],
        "username": user[1],
        "role": user[4],
        "exp": datetime.utcnow() + timedelta(days=365)   # 1-year token
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return jsonify({"token": token})


# ------------------------------------------------------------------ #
# ENDPOINT: Get profile – IDOR vulnerability                         #
# ------------------------------------------------------------------ #
@app.route("/profile/<int:user_id>", methods=["GET"])
def get_profile(user_id):
    # ---------------------------------------------------------------- #
    # VULN IDOR – any authenticated user can read ANY profile          #
    # (no check that requesting user == user_id)                      #
    # ---------------------------------------------------------------- #
    auth_header = request.headers.get("Authorization", "")
    if not auth_header:
        return jsonify({"error": "No token"}), 401

    conn = get_db()
    # VULN B608
    query = f"SELECT id, username, email, role, address FROM users WHERE id={user_id}"
    user  = conn.execute(query).fetchone()
    conn.close()

    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "id":       user[0],
        "username": user[1],
        "email":    user[2],
        "role":     user[3],
        "address":  user[4]
    })


# ------------------------------------------------------------------ #
# ENDPOINT: Update profile – Mass Assignment + IDOR                  #
# ------------------------------------------------------------------ #
@app.route("/profile/<int:user_id>", methods=["PUT"])
def update_profile(user_id):
    data    = request.get_json()
    # VULN Mass Assignment – caller can set 'role' to 'admin'
    email   = data.get("email", "")
    role    = data.get("role", "user")     # attacker sends role=admin
    address = data.get("address", "")

    conn = get_db()
    # VULN B608 – SQL injection
    query = f"UPDATE users SET email='{email}', role='{role}', address='{address}' WHERE id={user_id}"
    conn.execute(query)
    conn.commit()
    conn.close()

    return jsonify({"message": "Profile updated"})


# ------------------------------------------------------------------ #
# ENDPOINT: Admin search – XSS via Jinja2 without autoescape         #
# ------------------------------------------------------------------ #
@app.route("/admin/search", methods=["GET"])
def admin_search():
    # VULN B703 / reflected XSS – user input rendered without escaping
    term = request.args.get("q", "")
    template = f"""
    <html><body>
    <h1>Search results for: {term}</h1>
    </body></html>
    """
    # render_template_string with autoescape=False is the default here
    return render_template_string(template)   # B703


# ------------------------------------------------------------------ #
# ENDPOINT: Ping internal service (SSRF)                             #
# ------------------------------------------------------------------ #
@app.route("/internal/ping", methods=["GET"])
def internal_ping():
    target_url = request.args.get("url", "http://localhost")
    # VULN B501 – SSL verification disabled; also SSRF
    resp = requests.get(target_url, verify=False, timeout=5)   # B501
    return jsonify({"status": resp.status_code, "body": resp.text[:200]})


# ------------------------------------------------------------------ #
# ENDPOINT: Diagnostic – command injection via subprocess            #
# ------------------------------------------------------------------ #
@app.route("/diag", methods=["GET"])
def diag():
    host = request.args.get("host", "localhost")
    # VULN B602 – shell=True with user input → command injection
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True)   # B602
    return jsonify({"output": output.decode()})


# ------------------------------------------------------------------ #
# ENDPOINT: Download log – path traversal                            #
# ------------------------------------------------------------------ #
@app.route("/logs", methods=["GET"])
def download_log():
    filename = request.args.get("file", "app.log")
    # VULN – path traversal; attacker sends file=../../etc/passwd
    with open(f"/var/log/{filename}", "r") as f:
        content = f.read()
    return jsonify({"log": content})


if __name__ == "__main__":
    init_db()
    # VULN B201 – Flask debug mode exposes interactive debugger
    app.run(host="0.0.0.0", port=8001, debug=True)   # B201