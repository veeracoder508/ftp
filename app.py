import os
import threading
import time
from queue import Queue
from functools import wraps
from datetime import datetime

from flask import (
    Flask, render_template, render_template_string, jsonify,
    request, redirect, url_for, session, flash, send_from_directory
)
from flask_socketio import SocketIO, emit
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

# ---------------- CONFIG ----------------
FTP_LISTEN_HOST = "0.0.0.0"
FTP_PORT = 2121
FTP_HOME = os.path.abspath("ftp_home")

# FTP users: username -> password
FTP_USERS = {
    "user1": "pass1",
    "user2": "pass2",
    "user3": "pass3",
    "user4": "pass4",
    "user5": "pass5",
    "admin": "admin123"
}

# Web users (same as FTP), roles: 'admin' or 'user'
WEB_USERS = {
    "user1": {"password": "pass1", "role": "user"},
    "user2": {"password": "pass2", "role": "user"},
    "user3": {"password": "pass3", "role": "user"},
    "user4": {"password": "pass4", "role": "user"},
    "user5": {"password": "pass5", "role": "user"},
    "admin": {"password": "admin123", "role": "admin"}
}

HTTP_PORT = 5000
os.makedirs(FTP_HOME, exist_ok=True)

# ---------------- APP SETUP ----------------
app = Flask(__name__)
app.config['SECRET_KEY'] = "super_secret_key"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# Thread-safe event queue
events_q = Queue()

# ---------------- AUTH ----------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ---------------- FTP HANDLER ----------------
def push_event(evt_type, filename, remote_user=None):
    event = {
        "type": evt_type,
        "filename": filename,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user": remote_user
    }
    events_q.put(event)

class AuditFTPHandler(FTPHandler):
    def on_file_received(self, file):
        push_event("uploaded", os.path.relpath(file, FTP_HOME), self.username)

    def on_file_sent(self, file):
        push_event("downloaded", os.path.relpath(file, FTP_HOME), self.username)

    def on_file_removed(self, path):
        push_event("deleted", os.path.relpath(path, FTP_HOME), self.username)

# ---------------- FTP SERVER ----------------
def start_ftp_server():
    authorizer = DummyAuthorizer()
    for user, (pw, folder) in FTP_USERS.items():
        os.makedirs(folder, exist_ok=True)
        perm = "elradfmwMT" if user == "admin" else "elradfmw"
        authorizer.add_user(user, pw, folder, perm=perm)
    handler = AuditFTPHandler
    handler.authorizer = authorizer
    server = FTPServer((FTP_LISTEN_HOST, FTP_PORT), handler)
    print(f"[FTP] Server running at {FTP_LISTEN_HOST}:{FTP_PORT}")
    server.serve_forever()

# ---------------- EVENT PUSHER ----------------
def event_pusher():
    while True:
        event = events_q.get()
        if event is None:
            break
        socketio.emit("ftp_event", event, broadcast=True)
        time.sleep(0.01)

# ---------------- FLASK ROUTES ----------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = WEB_USERS.get(username)
        if user and user["password"] == password:
            session["user"] = username
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))
        flash("Invalid credentials", "danger")
        return redirect(url_for("login"))
    return render_template_string("""
<!doctype html>
<title>Login - FTP Dashboard</title>
<h2>Login</h2>
<form method="post">
  Username: <input type="text" name="username" required><br><br>
  Password: <input type="password" name="password" required><br><br>
  <input type="submit" value="Login">
</form>
{% with messages = get_flashed_messages(with_categories=true) %}
  {% if messages %}
    {% for category, message in messages %}
      <p style="color:red">{{ message }}</p>
    {% endfor %}
  {% endif %}
{% endwith %}
""")

@app.route("/dashboard")
@login_required
def dashboard():
    username = session["user"]
    role = session["role"]
    return render_template("dashboard.html", user=username, role=role)

@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    username = session["user"]
    if request.method == "POST":
        current = request.form.get("current_password")
        new_pw = request.form.get("new_password")
        confirm_pw = request.form.get("confirm_password")

        if not current or not new_pw or not confirm_pw:
            flash("All fields are required.", "danger")
            return redirect(url_for("change_password"))

        if WEB_USERS[username]["password"] != current:
            flash("Current password is incorrect.", "danger")
            return redirect(url_for("change_password"))

        if new_pw != confirm_pw:
            flash("New passwords do not match.", "danger")
            return redirect(url_for("change_password"))

        WEB_USERS[username]["password"] = new_pw
        if username in FTP_USERS:
            FTP_USERS[username] = new_pw

        flash("Password updated successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template_string("""
<!doctype html>
<title>Change Password</title>
<h2>Change Password for {{ user }}</h2>
<form method="post">
  Current Password: <input type="password" name="current_password" required><br><br>
  New Password: <input type="password" name="new_password" required><br><br>
  Confirm New Password: <input type="password" name="confirm_password" required><br><br>
  <input type="submit" value="Change Password">
</form>
<br>
<a href="/dashboard">Back to Dashboard</a>
{% with messages = get_flashed_messages(with_categories=true) %}
  {% if messages %}
    {% for category, message in messages %}
      <p style="color: {% if category=='danger' %}red{% else %}green{% endif %}">{{ message }}</p>
    {% endfor %}
  {% endif %}
{% endwith %}
""", user=username)

@app.route("/api/files")
@login_required
def list_files():
    username = session["user"]
    role = session["role"]

    if role == "admin":
        folders = [os.path.join(FTP_HOME, d) for d in os.listdir(FTP_HOME) if os.path.isdir(os.path.join(FTP_HOME, d))]
    else:
        folders = [FTP_USERS[username][1]]

    files = []
    for folder in folders:
        for root, dirs, filenames in os.walk(folder):
            for fname in filenames:
                full = os.path.join(root, fname)
                rel = os.path.relpath(full, FTP_HOME)
                stat = os.stat(full)
                files.append({
                    "name": rel,
                    "size": stat.st_size,
                    "mtime": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                })
    return jsonify(sorted(files, key=lambda x: x["name"]))

@app.route("/files/<path:filename>")
@login_required
def download_file(filename):
    safe_path = os.path.normpath(os.path.join(FTP_HOME, filename))
    if not safe_path.startswith(FTP_HOME) or not os.path.exists(safe_path):
        return "Not found", 404
    push_event("downloaded", filename, session["user"])
    return send_from_directory(FTP_HOME, filename, as_attachment=True)

@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    if "file" not in request.files:
        return "No file", 400
    f = request.files["file"]
    dest = os.path.join(FTP_HOME, f.filename)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    f.save(dest)
    push_event("uploaded", f.filename, session["user"])
    return redirect(url_for("dashboard"))

@app.route("/delete", methods=["POST"])
@login_required
def delete_file():
    name = request.form.get("name")
    if not name:
        return "Missing name", 400
    target = os.path.normpath(os.path.join(FTP_HOME, name))
    if not target.startswith(FTP_HOME) or not os.path.exists(target):
        return "Not found", 404
    os.remove(target)
    push_event("deleted", name, session["user"])
    return "", 204

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@socketio.on("request_events")
def handle_request_events(data):
    emit("events_ack", {"status": "ok"})

# ---------------- MAIN ----------------
if __name__ == "__main__":
    ftp_thread = threading.Thread(target=start_ftp_server, daemon=True)
    ftp_thread.start()

    pusher_thread = threading.Thread(target=event_pusher, daemon=True)
    pusher_thread.start()

    print(f"[WEB] Dashboard running on http://localhost:{HTTP_PORT}")
    socketio.run(app, host="0.0.0.0", port=HTTP_PORT)
