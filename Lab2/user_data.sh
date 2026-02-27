# app bootstrap
dnf update -y
dnf install -y python3-pip
python3 -m pip install flask pymysql boto3
systemctl stop nginx || true
systemctl disable nginx || true
set -euo pipefail

# Ensure app directories exist
mkdir -p /opt/rdsapp
mkdir -p /opt/rdsapp/static
tee >/opt/rdsapp/app.py <<'PY'
import json
import os
from datetime import datetime, timezone

import boto3
import pymysql
from flask import Flask, request, jsonify, send_from_directory

REGION = os.environ.get("AWS_REGION", "us-east-1")
SECRET_ID = os.environ.get("SECRET_ID", "megatron/lab1/rds/mysql")

secrets = boto3.client("secretsmanager", region_name=REGION)

def get_db_creds():
    resp = secrets.get_secret_value(SecretId=SECRET_ID)
    s = json.loads(resp["SecretString"])
    return s

def get_conn():
    c = get_db_creds()
    host = c["host"]
    user = c["username"]
    password = c["password"]
    port = int(c.get("port", 3306))
    db = c.get("dbname", "Cybertronsqldb")
    return pymysql.connect(
        host=host, user=user, password=password, port=port, database=db, autocommit=True
    )

app = Flask(__name__)

@app.get("/health")
def health():
    return "ok", 200

from flask import request, Response
import os
from email.utils import formatdate

STATIC_FILE = "/opt/rdsapp/static/index.html"
MAX_AGE = 5
ETAG_VALUE = '"chewie-v1"'  # keep constant for Injection A/B

def http_date_from_mtime(path: str) -> str:
    return formatdate(timeval=os.path.getmtime(path), usegmt=True)

@app.get("/static/index.html")
def static_index():
    if not os.path.exists(STATIC_FILE):
        return Response("Missing static file", status=500)

    last_modified = http_date_from_mtime(STATIC_FILE)

    # Conditional request (ETag-based)
    if request.headers.get("If-None-Match") == ETAG_VALUE:
        resp = Response(status=304)
    else:
        with open(STATIC_FILE, "rb") as f:
            body = f.read()
        resp = Response(body, status=200, mimetype="text/html")

    resp.headers["Cache-Control"] = f"public, max-age={MAX_AGE}"
    resp.headers["ETag"] = ETAG_VALUE
    resp.headers["Last-Modified"] = last_modified
    return resp

@app.route("/")
def home():
    return """
    <h2>EC2 → RDS Notes App</h2>
    <p>POST /add?note=hello</p>
    <p>GET /list</p>
    <p>GET /api/public-feed</p>
    <p>GET /api/list</p>
    <p>GET /static/index.html</p>
    """

@app.route("/init")
def init_db():
    c = get_db_creds()
    host = c["host"]
    user = c["username"]
    password = c["password"]
    port = int(c.get("port", 3306))

    conn = pymysql.connect(host=host, user=user, password=password, port=port, autocommit=True)
    cur = conn.cursor()
    cur.execute("CREATE DATABASE IF NOT EXISTS Cybertronsqldb;")
    cur.execute("USE Cybertronsqldb;")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INT AUTO_INCREMENT PRIMARY KEY,
            note VARCHAR(255) NOT NULL
        );
    """)
    cur.close()
    conn.close()
    return "Initialized Cybertronsqldb + notes table."

@app.route("/add", methods=["POST", "GET"])
def add_note():
    note = request.args.get("note", "").strip()
    if not note:
        return "Missing note param. Try: /add?note=hello", 400
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO notes(note) VALUES(%s);", (note,))
    cur.close()
    conn.close()
    return f"Inserted note: {note}"

@app.route("/list")
def list_notes():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, note FROM notes ORDER BY id DESC;")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    out = "<h3>Notes</h3><ul>"
    for r in rows:
        out += f"<li>{r[0]}: {r[1]}</li>"
    out += "</ul>"
    return out

@app.get("/api/public-feed")
def public_feed():
    now = datetime.now(timezone.utc)
    payload = {
        "message_of_the_minute": f"minute={now.strftime('%Y-%m-%dT%H:%MZ')}",
        "server_time_utc": now.isoformat()
    }
    resp = jsonify(payload)
    resp.headers["Cache-Control"] = "public, s-maxage=30, max-age=0"
    return resp

@app.get("/api/list")
def list_items():
    now = datetime.now(timezone.utc)
    resp = jsonify({
        "items": ["alpha", "bravo", "charlie"],
        "server_time_utc": now.isoformat()
    })
    resp.headers["Cache-Control"] = "private, no-store"
    return resp

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
PY

cat >/etc/systemd/system/rdsapp.service <<'SERVICE'
[Unit]
Description=EC2 to RDS Notes App
After=network.target

[Service]
WorkingDirectory=/opt/rdsapp
Environment=SECRET_ID=megatron/lab1/rds/mysql
ExecStart=/usr/bin/python3 /opt/rdsapp/app.py
Restart=always

[Install]
WantedBy=multi-user.target
SERVICE

# Write static file for Honors+ invalidation testing
tee /opt/rdsapp/static/index.html <<'HTML'
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Megatron Static Index</title>
</head>
<body>
  <h1>Megatron Static Index</h1>
  <p>Honors+ Be A Man baseline</p>
  <p id="marker">v1</p>
</body>
</html>
HTML


systemctl daemon-reload
systemctl enable rdsapp.service
sleep 30
systemctl restart rdsapp.service
systemctl status rdsapp.service --no-pager || true