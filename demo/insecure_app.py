import hashlib
import os
import random
import sqlite3
import subprocess

from flask import Flask, request


app = Flask(__name__)

# Intentionally insecure secrets for scanner demonstration.
app.config["SECRET_KEY"] = "hardcoded-dev-secret-please-rotate"
PAYMENT_API_TOKEN = "sk_live_demo_plaintext_token_for_scanner"


def hash_password(password: str) -> str:
    # Intentionally weak hash for demonstration.
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def issue_session_id() -> str:
    # Intentionally weak randomness for demonstration.
    return str(random.randint(100000, 999999))


@app.get("/user")
def get_user():
    username = request.args.get("username", "")

    # Intentionally unsafe SQL query composition for demonstration.
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    cursor.execute(query)
    row = cursor.fetchone()
    conn.close()

    return {"user": row}


@app.get("/diagnostics")
def diagnostics():
    host = request.args.get("host", "127.0.0.1")

    # Intentionally unsafe command execution for demonstration.
    cmd = f"ping -c 1 {host}"
    output = subprocess.check_output(cmd, shell=True, text=True)
    return {"output": output, "token_hint": PAYMENT_API_TOKEN[:8]}


@app.post("/register")
def register():
    password = request.form.get("password", "")
    weak_hash = hash_password(password)
    session_id = issue_session_id()
    return {"password_hash": weak_hash, "session_id": session_id}


if __name__ == "__main__":
    # Intentionally running in debug mode for demonstration.
    app.run(host="0.0.0.0", port=5000, debug=True)
