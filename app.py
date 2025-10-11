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

# FTP users: username -> (password, folder)
FTP_USERS = {
    "user1": ("pass1", "user1_files"),
    "user2": ("pass2", "user2_files"),
    "user3": ("pass3", "user3_files"),
    "user4": ("pass4", "user4_files"),
    "user5": ("pass5", "user5_files"),
    "admin": ("admin123", "")  # Admin has access to all
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
    for user, (pw, folder_name) in FTP_USERS.items():
        folder = os.path.join(FTP_HOME, folder_name)
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
<html>
  <head>
    <meta charset="utf-8" />
    <title>Login - FTP Dashboard</title>
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
  </head>
  <body class="bg-light d-flex align-items-center" style="height:100vh;">
    <div class="container">
      <div class="row justify-content-center">
        <div class="col-md-4">
          <div class="card shadow-sm">
            <div class="card-header text-center bg-primary text-white">
              <h5>FTP Dashboard Login</h5>
            </div>
            <div class="card-body">
              {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                  {% for category, message in messages %}
                    <div class="alert alert-{{ category }} py-1">{{ message }}</div>
                  {% endfor %}
                {% endif %}
              {% endwith %}
              <form method="post">
                <div class="mb-3">
                  <label for="username" class="form-label">Username</label>
                  <input type="text" name="username" id="username" class="form-control" required>
                </div>
                <div class="mb-3">
                  <label for="password" class="form-label">Password</label>
                  <input type="password" name="password" id="password" class="form-control" required>
                </div>
                <button class="btn btn-primary w-100" style="padding-top=10%">Login</button>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>
  </body>
</html>
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
            FTP_USERS[username] = (new_pw, FTP_USERS[username][1])

        flash("Password updated successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Change Password</title>
  
  <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}"> 

  <style>
    /*
    Color Scheme Inferred from Dashboard Context:
    - Primary Color (for actions/links): #3498db (Bright Blue)
    - Body Background: #ecf0f1 (Very Light Gray)
    - Card/Form Background: #ffffff (White)
    - Text/Header Color: #2c3e50 (Dark Navy)
    */

    /* --- GLOBAL STYLES --- */
    body {
      font-family: 'Roboto', sans-serif;
      background-color: #ecf0f1; /* Dashboard background color */
      display: flex;
      justify-content: center;
      align-items: flex-start; /* Start from the top */
      padding: 50px 20px;
      min-height: 100vh;
      margin: 0;
    }

    /* --- CONTAINER & CARD LAYOUT --- */
    .container {
      width: 100%;
      max-width: 420px; /* Standard width for a login/change password form */
    }

    .card {
      background-color: #ffffff;
      padding: 30px;
      border-radius: 8px;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05); /* Subtle shadow for a modern look */
      border-top: 5px solid #3498db; /* A blue accent line at the top */
    }

    h2 {
      color: #2c3e50; /* Darker text for headings */
      margin-top: 0;
      margin-bottom: 25px;
      font-weight: 500;
      text-align: center;
    }

    /* --- FORM ELEMENTS --- */
    form br {
      display: none; /* Control spacing with margin, not <br> */
    }
    
    label {
      font-weight: 500;
      color: #34495e;
      display: block;
      margin-top: 15px;
      margin-bottom: 5px;
    }

    input[type="password"] {
      width: 100%;
      padding: 12px 10px;
      border: 1px solid #bdc3c7;
      border-radius: 4px;
      box-sizing: border-box;
      transition: border-color 0.3s;
      margin-bottom: 10px;
    }
    
    input[type="password"]:focus {
      border-color: #3498db;
      outline: none;
    }

    /* --- BUTTONS & LINKS --- */
    input[type="submit"] {
      background-color: #3498db; /* Primary accent color */
      color: white;
      padding: 12px 20px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-weight: 500;
      width: 100%;
      margin-top: 25px;
      transition: background-color 0.3s;
    }
    input[type="submit"]:hover {
      background-color: #2980b9; /* Darker blue on hover */
    }

    a {
      color: #3498db;
      text-decoration: none;
      font-weight: 500;
      display: block; /* Make it take its own line */
      text-align: center;
      margin-top: 20px;
    }
    a:hover {
      text-decoration: underline;
      color: #2980b9;
    }

    /* --- FLASH MESSAGES --- */
    .flashed-messages {
      margin-top: 15px;
      text-align: center;
    }
    .flashed-messages p {
      padding: 10px;
      border-radius: 4px;
      margin-bottom: 10px;
      font-weight: 500;
      border: 1px solid;
    }
    .flashed-messages p[style*="red"] { /* Danger/Error */
      background-color: #fdd;
      border-color: #e74c3c;
    }
    .flashed-messages p[style*="green"] { /* Success */
      background-color: #dff0d8;
      border-color: #2ecc71;
    }
  </style>
</head>
<body>

  <div class="container">
    <div class="card">
      <h2>Change Password for {{ user }}</h2>
      <form method="post">
        <label for="current_password">Current Password:</label>
        <input type="password" id="current_password" name="current_password" required>
        
        <label for="new_password">New Password:</label>
        <input type="password" id="new_password" name="new_password" required>
        
        <label for="confirm_password">Confirm New Password:</label>
        <input type="password" id="confirm_password" name="confirm_password" required>
        
        <input type="submit" value="Change Password">
      </form>
      <a href="/dashboard">Back to Dashboard</a>
    </div>

    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        <div class="flashed-messages">
          {% for category, message in messages %}
            <p style="color: {% if category=='danger' %}red{% else %}green{% endif %}">{{ message }}</p>
          {% endfor %}
        </div>
      {% endif %}
    {% endwith %}

  </div>
</body>
</html>
""", user=username)

@app.route("/api/files")
@login_required
def list_files():
    username = session["user"]
    role = session["role"]

    files = []

    if role == "admin":
        # Admin: List all files with user info
        for root, dirs, filenames in os.walk(FTP_HOME):
            for filename in filenames:
                full_path = os.path.join(root, filename)
                rel_path = os.path.relpath(full_path, FTP_HOME)
                stat = os.stat(full_path)

                # Extract username from the path
                try:
                    user_folder = rel_path.split(os.sep)[0]  # Get the top-level folder
                    user = next((u for u, (pw, folder) in FTP_USERS.items() if folder == user_folder), "Unknown")
                except:
                    user = "Unknown"

                files.append({
                    "name": rel_path,
                    "size": stat.st_size,
                    "mtime": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    "user": user  # Add the username
                })
    else:
        # Regular user: List only files in their folder
        user_folder = FTP_USERS[username][1]
        user_path = os.path.join(FTP_HOME, user_folder)

        if os.path.exists(user_path):  # Check if the folder exists
            for root, dirs, filenames in os.walk(user_path):
                for filename in filenames:
                    full_path = os.path.join(root, filename)
                    rel_path = os.path.relpath(full_path, FTP_HOME)
                    stat = os.stat(full_path)
                    files.append({
                        "name": rel_path,
                        "size": stat.st_size,
                        "mtime": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                        "user": username
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
    username = session["user"]
    user_folder = FTP_USERS[username][1]
    dest_folder = os.path.join(FTP_HOME, user_folder)
    os.makedirs(dest_folder, exist_ok=True)  # Ensure the destination folder exists
    dest = os.path.join(dest_folder, f.filename)
    f.save(dest)
    push_event("uploaded", f.filename, username)
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
