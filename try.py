from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_file
from flask_socketio import SocketIO, emit
import sqlite3
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
import json
import logging
import psutil
import os
import shutil
from werkzeug.utils import secure_filename
import time
import threading
import pickle
import uuid
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
import base64

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Load all anomaly detection models ---
models = {}
model_files = {
    'logon': 'ml mode/anomaly_logon.pkl',
    'device': 'ml mode/anomaly_device.pkl',
    'file': 'ml mode/anomaly_file.pkl',
    'http': 'ml mode/anomaly_http.pkl'
}

for name, filename in model_files.items():
    try:
        with open(filename, 'rb') as f:
            models[name] = pickle.load(f)
        logger.info(f"Anomaly detection model '{name}' loaded successfully")
    except FileNotFoundError:
        logger.error(f"Model file not found: {filename}. Anomaly detection for '{name}' will be disabled.")
        models[name] = None
    except Exception as e:
        logger.error(f"Error loading model '{name}': {e}")
        models[name] = None


# Ensure directories exist
os.makedirs("users/admin", exist_ok=True)
for filename in ['usb_alerts.txt', 'anomaly_alerts.txt', 'admin_activity.log']:
    if not os.path.exists(f"users/admin/{filename}"):
        open(f"users/admin/{filename}", 'w').close()

# --- User Online Status and Risk Score Tracking ---
online_users = {}
client_sids = {}
webcam_watchers = {}
user_risk_scores = {} # NEW: For dynamic risk scoring

# --- NEW: Anomaly Point Values ---
ANOMALY_POINTS = {
    'logon': 10,
    'device': 15,
    'file': 20,
    'http': 20,
    'usb_file_copy': 30
}

def risk_score_decay():
    """Background thread to slowly decrease risk scores over time."""
    while True:
        with app.app_context():
            for user_id in list(user_risk_scores.keys()):
                if user_risk_scores[user_id] > 0:
                    user_risk_scores[user_id] -= 1 # Decay by 1 point
                    socketio.emit('update_risk_score', {
                        'user_id': user_id,
                        'score': user_risk_scores[user_id]
                    })
            socketio.sleep(3600) # Decay every hour

def check_offline_users():
    while True:
        try:
            offline_threshold = time.time() - 30
            offline_user_ids = [user_id for user_id, last_seen in list(online_users.items()) if last_seen < offline_threshold]
            
            for user_id in offline_user_ids:
                if user_id in online_users:
                    del online_users[user_id]
                    if user_id in client_sids:
                        del client_sids[user_id]
                    socketio.emit('user_offline', {'user_id': user_id})
                    logger.info(f"User {user_id} is offline.")
        except Exception as e:
            logger.error(f"Error in check_offline_users: {e}")
        socketio.sleep(15)

threading.Thread(target=check_offline_users, daemon=True).start()
threading.Thread(target=risk_score_decay, daemon=True).start() # NEW: Start decay thread


# Database Functions (remain unchanged)
def init_admin_db():
    try:
        conn = sqlite3.connect("admin.db")
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS admin_password (id INTEGER PRIMARY KEY, password TEXT)")
        c.execute("SELECT COUNT(*) FROM admin_password")
        if c.fetchone()[0] == 0:
            c.execute("INSERT INTO admin_password VALUES (1, 'p@ssw0rd')")
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error initializing admin DB: {e}")

def init_user_db():
    """Initializes the main user database and loads risk scores."""
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        
        # Add risk_score column if it doesn't exist (for backward compatibility)
        try:
            c.execute("ALTER TABLE user_data ADD COLUMN risk_score INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass # Column already exists

        c.execute("""
            CREATE TABLE IF NOT EXISTS user_data (
                user_id TEXT PRIMARY KEY, username TEXT UNIQUE, password TEXT, pc_name TEXT,
                platform TEXT, accepted INTEGER DEFAULT 0, logs TEXT DEFAULT '[]',
                network_traffic TEXT DEFAULT '{}', file_operations TEXT DEFAULT '[]',
                removable_media_transfers TEXT DEFAULT '[]', user_activity TEXT DEFAULT '[]',
                login_time TEXT DEFAULT '', logout_time TEXT DEFAULT '', login_duration INTEGER DEFAULT 0,
                internet_status TEXT DEFAULT '', usb_count INTEGER DEFAULT 0,
                system_info TEXT DEFAULT '{}', locations TEXT DEFAULT '[]',
                risk_score INTEGER DEFAULT 0
            )
        """)
        conn.commit()
        
        c.execute("SELECT user_id, risk_score FROM user_data")
        for row in c.fetchall():
            user_risk_scores[row[0]] = row[1] if row[1] is not None else 0

        conn.close()
    except Exception as e:
        logger.error(f"Error initializing user DB: {e}")

def init_user_databases(username):
    user_folder = get_user_folder(username)
    web_activity_db = os.path.join(user_folder, "web_activity.db")
    try:
        conn = sqlite3.connect(web_activity_db)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS web_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                title TEXT,
                visit_time TEXT,
                duration TEXT
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_web_activity_time ON web_activity(visit_time)")
        conn.commit()
    except Exception as e:
        logger.error(f"Error initializing web activity DB for {username}: {e}")
    finally:
        conn.close()
    
    online_data_db = os.path.join(user_folder, "online_data.db")
    try:
        conn = sqlite3.connect(online_data_db)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS website_visits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                title TEXT,
                timestamp TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS file_downloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                filename TEXT,
                timestamp TEXT,
                size TEXT
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_visits_time ON website_visits(timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_downloads_time ON file_downloads(timestamp)")
        conn.commit()
    except Exception as e:
        logger.error(f"Error initializing online data DB for {username}: {e}")
    finally:
        conn.close()
    
    network_activity_db = os.path.join(user_folder, "network_activity.db")
    try:
        conn = sqlite3.connect(network_activity_db)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS network_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                protocol TEXT,
                remote_ip TEXT,
                port INTEGER,
                status TEXT,
                pid INTEGER,
                interface TEXT,
                sent_bytes INTEGER,
                received_bytes INTEGER,
                timestamp TEXT
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_network_activity_time ON network_activity(timestamp)")
        conn.commit()
    except Exception as e:
        logger.error(f"Error initializing network activity DB for {username}: {e}")
    finally:
        conn.close()
    shared_folder = os.path.join(user_folder, "shared")
    os.makedirs(shared_folder, exist_ok=True)
    access_file = os.path.join(shared_folder, "file_access.txt")
    if not os.path.exists(access_file):
        with open(access_file, 'w') as f:
            f.write("read:False\nwrite:False\n")
init_admin_db()
init_user_db()


# --- Anomaly Detection Functions ---
def detect_logon_anomaly(data):
    if not models.get('logon'):
        logger.warning("Logon anomaly model not loaded.")
        return None
    try:
        df = pd.DataFrame([data])
        df["date"] = pd.to_datetime(df["date"])
        login_count_placeholder = 1
        logon_duration_placeholder = 0
        X = pd.DataFrame(
            [[login_count_placeholder, logon_duration_placeholder]], 
            columns=['login_count', 'logon_duration']
        )
        prediction = models['logon'].predict(X)[0]
        return {"is_anomaly": prediction == -1}
    except Exception as e:
        logger.error(f"Logon anomaly detection error: {e}")
        return None

def detect_file_anomaly(data):
    if not models.get('file'):
        return None
    try:
        df = pd.DataFrame([data])
        df['date'] = pd.to_datetime(df['date'], errors='coerce')
        df['activity_new'] = LabelEncoder().fit_transform(df['activity'])
        df['to_removable_media_new'] = LabelEncoder().fit_transform(df['to_removable_media'])
        df['from_removable_media_new'] = LabelEncoder().fit_transform(df['from_removable_media'])
        df['hour'] = df['date'].dt.hour
        features = df[['activity_new', 'to_removable_media_new', 'from_removable_media_new', 'hour']]
        prediction = models['file'].predict(features)[0]
        return {"is_anomaly": prediction == -1}
    except Exception as e:
        logger.error(f"File anomaly detection error: {e}")
        return None

def detect_http_anomaly(data):
    if not models.get('http'):
        return None
    try:
        df = pd.DataFrame([data])
        df['content_length'] = df['content'].apply(len)
        df['url_length'] = df['url'].apply(len)
        df['activity_encoded'] = LabelEncoder().fit_transform(df['activity'])
        features = df[['content_length', 'url_length', 'activity_encoded']]
        score = models['http'].decision_function(features)[0]
        prediction = models['http'].predict(features)[0]
        return {"score": score, "is_anomaly": prediction == -1}
    except Exception as e:
        logger.error(f"HTTP anomaly detection error: {e}")
        return None

def detect_device_anomaly(data):
    if not models.get('device'):
        return None
    try:
        df = pd.DataFrame([data])
        df["date"] = pd.to_datetime(df["date"])
        df["hour_of_day"] = df["date"].dt.hour
        df["day_of_week"] = df["date"].dt.dayofweek
        df["is_weekend"] = df["day_of_week"].apply(lambda x: 1 if x >= 5 else 0)
        df["is_midnight_activity"] = df["hour_of_day"].apply(lambda x: 1 if x < 5 else 0)
        df["time_since_last_activity"] = 0
        df["log_time_since_last_activity"] = np.log1p(df["time_since_last_activity"])
        df["activity_encoded"] = LabelEncoder().fit_transform(df["activity"])
        features = ["hour_of_day", "day_of_week", "is_weekend", "is_midnight_activity", "log_time_since_last_activity", "activity_encoded"]
        X = df[features]
        prediction = models['device'].predict(X)[0]
        return {"is_anomaly": prediction == -1}
    except Exception as e:
        logger.error(f"Device anomaly detection error: {e}")
        return None

def add_risk_score(user_id, anomaly_type):
    """Adds points to a user's risk score and emits an update."""
    if user_id not in user_risk_scores:
        user_risk_scores[user_id] = 0
    
    points = ANOMALY_POINTS.get(anomaly_type, 5) # Default to 5 points
    user_risk_scores[user_id] += points
    
    socketio.emit('update_risk_score', {
        'user_id': user_id, 
        'score': user_risk_scores[user_id]
    })


# Utility Functions
def get_user_folder(username):
    user_folder = os.path.join("users", username)
    os.makedirs(user_folder, exist_ok=True)
    os.makedirs(os.path.join(user_folder, "photos"), exist_ok=True)
    os.makedirs(os.path.join(user_folder, "screenshots"), exist_ok=True)
    return user_folder

def log_user_activity(username, message, logs=None):
    pass

def log_admin_activity(action):
    pass

def get_all_users():
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT user_id, username, pc_name, platform, accepted FROM user_data")
        return c.fetchall()
    except Exception as e:
        logger.error(f"Error getting users: {e}")
        return []
    finally:
        conn.close()

# --- Main Route (Updated to pass risk scores to template) ---
@app.route("/")
def dashboard():
    if 'admin_logged_in' not in session:
        return redirect(url_for('login'))
    
    # NEW: Pass the current risk scores to the dashboard
    return render_template(
        "dashboard.html", 
        users=get_all_users(), 
        online_user_ids=list(online_users.keys()),
        risk_scores=json.dumps(user_risk_scores)
    )

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        try:
            conn = sqlite3.connect("admin.db")
            c = conn.cursor()
            c.execute("SELECT password FROM admin_password WHERE id = 1")
            result = c.fetchone()
            if result and result[0] == password and username == "admin":
                session['admin_logged_in'] = True
                log_admin_activity("Admin logged in")
                return redirect(url_for('dashboard'))
        except Exception as e:
            logger.error(f"Login error: {e}")
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")

@app.route("/logout")
def logout():
    if 'admin_logged_in' in session:
        log_admin_activity("Admin logged out")
    session.pop('admin_logged_in', None)
    return redirect(url_for('login'))


# --- Anomaly Reporting Routes (Updated to call add_risk_score) ---
@app.route("/report_logon_activity", methods=["POST"])
def report_logon_activity():
    data = request.json
    username = data.get("user")
    user_id = data.get("user_id")
    anomaly_result = detect_logon_anomaly(data)
    
    if anomaly_result and anomaly_result["is_anomaly"]:
        add_risk_score(user_id, 'logon') # NEW
        alert_msg = f"Suspicious logon behavior detected for {username}"
        socketio.emit("logon_anomaly_alert", {"message": alert_msg, "user_id": user_id})
        log_user_activity(username, f"LOGON ANOMALY: {alert_msg}")
        
    return jsonify({"status": "processed"})

@app.route("/report_file_activity", methods=["POST"])
def report_file_activity():
    data = request.json
    username = data.get("user")
    user_id = data.get("user_id")
    anomaly_result = detect_file_anomaly(data)
    
    if anomaly_result and anomaly_result["is_anomaly"]:
        add_risk_score(user_id, 'file') # NEW
        alert_msg = f"Suspicious file activity detected for {username}: {data.get('activity')} on {data.get('filename')}"
        socketio.emit("file_anomaly_alert", {"message": alert_msg, "user_id": user_id})
        log_user_activity(username, f"FILE ANOMALY: {alert_msg}")
        
    return jsonify({"status": "processed"})

@app.route("/report_http_activity", methods=["POST"])
def report_http_activity():
    data = request.json
    username = data.get("user")
    user_id = data.get("user_id")
    anomaly_result = detect_http_anomaly(data)

    if anomaly_result and anomaly_result["is_anomaly"]:
        add_risk_score(user_id, 'http') # NEW
        alert_msg = f"Suspicious HTTP activity detected for {username} (URL: {data.get('url')[:30]}...)"
        socketio.emit("http_anomaly_alert", {"message": alert_msg, "user_id": user_id, "score": anomaly_result.get('score', 0)})
        log_user_activity(username, f"HTTP ANOMALY: {alert_msg}")

    return jsonify({"status": "processed"})
@app.route("/usb_event", methods=["POST"])
def usb_event():
    try:
        data = request.json
        username = data.get("username")
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT user_id, removable_media_transfers FROM user_data WHERE username = ?", (username,))
        result = c.fetchone()
        if not result:
            return jsonify({"error": "User not found"}), 404
        user_id = result[0]
        current_transfers = json.loads(result[1]) if result[1] else []

        operation = data.get("operation")
        device_data = {"date": data.get("timestamp"), "user": username, "activity": "Connect"}
        anomaly_result = detect_device_anomaly(device_data)

        is_file_copy_anomaly = "File Copied" in operation
        is_device_anomaly = anomaly_result and anomaly_result["is_anomaly"]
        
        # Add the new USB event to the user's log
        current_transfers.append({
            "operation": operation,
            "device_info": data.get("device_info"),
            "timestamp": data.get("timestamp"),
            "details": data.get("details", {})
        })
        c.execute("UPDATE user_data SET usb_count = usb_count + 1, removable_media_transfers = ? WHERE user_id = ?", (json.dumps(current_transfers), user_id))
        conn.commit()

        if is_file_copy_anomaly:
            add_risk_score(user_id, 'usb_file_copy')
            alert_msg = f"ANOMALY: USB file copy detected for {username}"
            socketio.emit("device_anomaly_alert", {"message": alert_msg, "user_id": user_id})
            with open('users/admin/anomaly_alerts.txt', 'a') as f:
                f.write(f"{datetime.now().isoformat()} - {alert_msg}\n")
        
        elif is_device_anomaly:
            add_risk_score(user_id, 'device')
            alert_msg = f"ANOMALY: Suspicious device connection for {username}"
            socketio.emit("device_anomaly_alert", {"message": alert_msg, "user_id": user_id})
            with open('users/admin/anomaly_alerts.txt', 'a') as f:
                f.write(f"{datetime.now().isoformat()} - {alert_msg}\n")
        
        else:
            alert_msg = f"{datetime.now().isoformat()} - USB Event: {operation} by {username}"
            with open('users/admin/usb_alerts.txt', 'a') as f:
                f.write(alert_msg + "\n")
            socketio.emit("usb_alert", {"message": alert_msg, "user_id": user_id})
        
        return jsonify({"status": "logged"})

    except Exception as e:
        logger.error(f"Error logging USB event: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# ... (All other routes like user management, file sharing, etc., remain the same) ...
# ... (Webcam and screenshot routes also remain the same) ...
@app.route("/report_location/<user_id>", methods=["POST"])
def report_location(user_id):
    try:
        data = request.json
        location = data.get("location")
        username = data.get("username")
        
        if not location:
            return jsonify({"error": "No location data"}), 400
            
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        
        # Get current locations
        c.execute("SELECT locations FROM user_data WHERE user_id = ?", (user_id,))
        result = c.fetchone()
        current_locations = json.loads(result[0]) if result and result[0] else []
        
        # Add new location (limit to last 50)
        current_locations.insert(0, location)
        current_locations = current_locations[:50]
        
        # Update database
        c.execute("""
            UPDATE user_data 
            SET locations = ? 
            WHERE user_id = ?
        """, (json.dumps(current_locations), user_id))
        conn.commit()
        
        log_user_activity(username, f"Location updated: {location}")
        return jsonify({"status": "location_updated"})
    except Exception as e:
        logger.error(f"Error updating location: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route("/clear_usb_alerts", methods=["POST"])
def clear_usb_alerts():
    try:
        with open('users/admin/usb_alerts.txt', 'w') as f:
            f.write("")
        return jsonify({"status": "cleared"})
    except Exception as e:
        logger.error(f"Error clearing USB alerts: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/clear_anomaly_alerts", methods=["POST"])
def clear_anomaly_alerts():
    try:
        with open('users/admin/anomaly_alerts.txt', 'w') as f:
            f.write("")
        return jsonify({"status": "cleared"})
    except Exception as e:
        logger.error(f"Error clearing anomaly alerts: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/get_usb_alerts", methods=["GET"])
def get_usb_alerts():
    try:
        with open('users/admin/usb_alerts.txt', 'r') as f:
            alerts = [line.strip() for line in f.readlines() if line.strip()]
        return jsonify({"alerts": alerts[-50:]})  # Last 50 alerts
    except Exception as e:
        logger.error(f"Error getting USB alerts: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/get_anomaly_alerts", methods=["GET"])
def get_anomaly_alerts():
    try:
        with open('users/admin/anomaly_alerts.txt', 'r') as f:
            alerts = [line.strip() for line in f.readlines() if line.strip()]
        return jsonify({"alerts": alerts[-50:]})  # Last 50 alerts
    except Exception as e:
        logger.error(f"Error getting anomaly alerts: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/validate_user_password", methods=["POST"])
def validate_user_password():
    try:
        data = request.json
        username = data.get("username")
        password = data.get("password")
        
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT password FROM user_data WHERE username = ?", (username,))
        result = c.fetchone()
        
        if result and result[0] == password:
            return jsonify({"status": "valid"})
        return jsonify({"status": "invalid"})
    except Exception as e:
        logger.error(f"Password validation error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route("/get_user_id/<username>", methods=["GET"])
def get_user_id(username):
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT user_id FROM user_data WHERE username = ?", (username,))
        result = c.fetchone()
        
        if result:
            return jsonify({"user_id": result[0]})
        return jsonify({"error": "User not found"}), 404
    except Exception as e:
        logger.error(f"Error getting user ID: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route("/add_user", methods=["POST"])
def add_user():
    data = request.json
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute(
            "INSERT INTO user_data (user_id, username, password, pc_name, platform) VALUES (?, ?, ?, ?, ?)",
            (data["user_id"], data["username"], data["password"], data["pc_name"], data["platform"])
        )
        conn.commit()
        
        # Initialize user-specific databases
        init_user_databases(data["username"])
        
        socketio.emit("new_user", {
            "user_id": data["user_id"],
            "username": data["username"],
            "pc_name": data["pc_name"],
            "platform": data["platform"]
        })
        
        log_admin_activity(f"Added new user: {data['username']}")
        log_user_activity(data["username"], "New user added")
        return jsonify({"status": "user_added"})
    except Exception as e:
        logger.error(f"Error adding user: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route("/accept_user/<user_id>", methods=["POST"])
def accept_user(user_id):
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        
        c.execute("SELECT username FROM user_data WHERE user_id = ?", (user_id,))
        user = c.fetchone()
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        c.execute("UPDATE user_data SET accepted = 1 WHERE user_id = ?", (user_id,))
        conn.commit()
        
        log_admin_activity(f"Accepted user {user[0]} (ID: {user_id})")
        socketio.emit("user_accepted", {"user_id": user_id})
        log_user_activity(user[0], "User accepted by admin")
        return jsonify({"status": "user_accepted"})
    except Exception as e:
        logger.error(f"Error accepting user: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route("/remove_user/<user_id>", methods=["POST"])
def remove_user(user_id):
    if 'admin_logged_in' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    admin_password = data.get("admin_password")
    
    try:
        # Verify admin password
        conn = sqlite3.connect("admin.db")
        c = conn.cursor()
        c.execute("SELECT password FROM admin_password WHERE id = 1")
        result = c.fetchone()
        
        if not result or result[0] != admin_password:
            return jsonify({"error": "Incorrect admin password"}), 401

        # Get username before deleting for logging
        conn_user = sqlite3.connect("users.db")
        c_user = conn_user.cursor()
        c_user.execute("SELECT username FROM user_data WHERE user_id = ?", (user_id,))
        user = c_user.fetchone()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        username = user[0]

        # Delete user from main database
        c_user.execute("DELETE FROM user_data WHERE user_id = ?", (user_id,))
        conn_user.commit()
        
        # Remove user folder (which contains all user-specific databases)
        user_folder = os.path.join("users", username)
        if os.path.exists(user_folder):
            shutil.rmtree(user_folder)
        
        log_admin_activity(f"Removed user {username} (ID: {user_id})")
        socketio.emit("user_removed", {"user_id": user_id})
        
        return jsonify({"status": "user_removed"})
    except Exception as e:
        logger.error(f"Error removing user: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()
        conn_user.close()

@app.route("/logout_user/<user_id>", methods=["POST"])
def logout_user(user_id):
    if 'admin_logged_in' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        
        # Get username and login_time for logging
        c.execute("SELECT username, login_time FROM user_data WHERE user_id = ?", (user_id,))
        user_data = c.fetchone()
        if not user_data:
            return jsonify({"error": "User not found"}), 404
        
        username = user_data[0]
        login_time_str = user_data[1]
        
        # Calculate login duration
        login_duration_sec = 0
        if login_time_str:
            login_time_dt = datetime.fromisoformat(login_time_str)
            login_duration_sec = int((datetime.now() - login_time_dt).total_seconds())

        # Update logout time and login duration
        c.execute("""
            UPDATE user_data SET 
                logout_time = ?,
                login_duration = ?
            WHERE user_id = ?
        """, (
            datetime.now().isoformat(),
            login_duration_sec,
            user_id
        ))
        conn.commit()
        
        log_admin_activity(f"Logged out user {username} (ID: {user_id})")
        socketio.emit("user_logged_out", {"user_id": user_id})
        
        return jsonify({"status": "user_logged_out"})
    except Exception as e:
        logger.error(f"Error logging out user: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route("/clear_risk_score/<user_id>", methods=["POST"])
def clear_risk_score(user_id):
    if 'admin_logged_in' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    try:
        user_risk_scores[user_id] = 0
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("UPDATE user_data SET risk_score = 0 WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()
        socketio.emit('update_risk_score', {'user_id': user_id, 'score': 0})
        log_admin_activity(f"Cleared risk score for user ID: {user_id}")
        return jsonify({"status": "score_cleared"})
    except Exception as e:
        logger.error(f"Error clearing risk score: {e}")
        return jsonify({"error": str(e)}), 500
    


@app.route("/user_details/<user_id>", methods=["GET"])
def user_details(user_id):
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("""
            SELECT user_id, username, password, pc_name, platform, accepted, 
                   logs, network_traffic, file_operations, removable_media_transfers, 
                   user_activity, login_time, logout_time, login_duration, 
                   internet_status, usb_count, system_info, locations
            FROM user_data 
            WHERE user_id = ?
        """, (user_id,))
        data = c.fetchone()

        if not data:
            return jsonify({"error": "User not found"}), 404

        return jsonify({
            "user_id": data[0],
            "username": data[1],
            "pc_name": data[3],
            "logs": data[6] if data[6] else "[]",
            "network_traffic": data[7] if data[7] else "{}",
            "file_operations": data[8] if data[8] else "[]",
            "removable_media_transfers": data[9] if data[9] else "[]",
            "user_activity": data[10] if data[10] else "[]",
            "login_time": data[11],
            "logout_time": data[12],
            "login_duration": data[13],
            "internet_status": data[14],
            "usb_count": data[15],
            "system_info": data[16] if data[16] else "{}",
            "locations": data[17] if data[17] else "[]",
            "accepted": data[5]
        })
    except Exception as e:
        logger.error(f"Error getting user details: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route("/report_web_activity/<user_id>", methods=["POST"])
def report_web_activity(user_id):
    try:
        data = request.json
        username = data.get("username")
        
        user_folder = get_user_folder(username)
        web_activity_db = os.path.join(user_folder, "web_activity.db")
        online_data_db = os.path.join(user_folder, "online_data.db")
        
        with sqlite3.connect(web_activity_db) as conn_web:
            c_web = conn_web.cursor()
            for activity in data.get("visited_sites", []):
                c_web.execute("""
                    INSERT INTO web_activity (url, title, visit_time, duration)
                    VALUES (?, ?, ?, ?)
                """, (
                    activity.get("url"), 
                    activity.get("title", ""), 
                    activity.get("time", ""), 
                    activity.get("duration", "")
                ))
        
        with sqlite3.connect(online_data_db) as conn_online:
            c_online = conn_online.cursor()
            for download in data.get("downloaded_files", []):
                c_online.execute("""
                    INSERT INTO file_downloads (url, filename, timestamp, size)
                    VALUES (?, ?, ?, ?)
                """, (
                    download.get("path", ""), 
                    download.get("filename", ""),
                    download.get("timestamp", ""),
                    download.get("size", "N/A")
                ))

        log_user_activity(username, "Web and download activity reported")
        return jsonify({"status": "success"})
    except Exception as e:
        logger.error(f"Error processing web activity: {e}")
        return jsonify({"error": str(e)}), 500
    

@app.route("/report_network_activity/<user_id>", methods=["POST"])
def report_network_activity(user_id):
    try:
        data = request.json
        username = data.get("username")
        
        user_folder = get_user_folder(username)
        network_activity_db = os.path.join(user_folder, "network_activity.db")
        conn = sqlite3.connect(network_activity_db)
        c = conn.cursor()
        
        for activity in data.get("network_activity", []):
            c.execute("""
                INSERT INTO network_activity (
                    protocol, remote_ip, port, status, pid, 
                    interface, sent_bytes, received_bytes, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                activity.get("protocol", "TCP"),
                activity.get("remote_ip", ""),
                activity.get("port", 0),
                activity.get("status", ""),
                activity.get("pid", 0),
                activity.get("interface", ""),
                activity.get("sent_bytes", 0),
                activity.get("received_bytes", 0),
                datetime.now().isoformat()
            ))
        
        conn.commit()
        
        log_user_activity(username, "Network activity reported")
        return jsonify({"status": "success"})
    except Exception as e:
        logger.error(f"Error processing network activity: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route("/user_logs/<user_id>")
def user_logs(user_id):
    try:
        user_data = None
        visits = []
        downloads = []
        web_activity = []
        network_activity = []
        system_info = {}
        locations = []
        
        with sqlite3.connect("users.db") as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM user_data WHERE user_id = ?", (user_id,))
            user_data = c.fetchone()
            
            if not user_data:
                return "User not found", 404
            
            is_online = user_id in online_users
            internet_status = "online" if is_online else "offline"

                
            username = user_data[1]
            user_folder = get_user_folder(username)
            
            online_data_db = os.path.join(user_folder, "online_data.db")
            if os.path.exists(online_data_db):
                with sqlite3.connect(online_data_db) as conn_online:
                    c_online = conn_online.cursor()
                    
                    c_online.execute("""
                        SELECT url, title, timestamp 
                        FROM website_visits 
                        ORDER BY timestamp DESC 
                        LIMIT 100
                    """)
                    visits = [{"url": row[0], "title": row[1], "timestamp": row[2]} 
                            for row in c_online.fetchall()]
                    
                    c_online.execute("""
                        SELECT url, filename, timestamp, size
                        FROM file_downloads 
                        ORDER BY timestamp DESC 
                        LIMIT 100
                    """)
                    downloads = [{"url": row[0], "filename": row[1], "timestamp": row[2], "size": row[3]} 
                                for row in c_online.fetchall()]
            
            web_activity_db = os.path.join(user_folder, "web_activity.db")
            if os.path.exists(web_activity_db):
                with sqlite3.connect(web_activity_db) as conn_web:
                    c_web = conn_web.cursor()
                    c_web.execute("""
                        SELECT url, title, visit_time, duration 
                        FROM web_activity 
                        ORDER BY visit_time DESC 
                        LIMIT 100
                    """)
                    web_activity = [{
                        "url": row[0],
                        "title": row[1],
                        "time": row[2],
                        "duration": row[3]
                    } for row in c_web.fetchall()]
            
            network_activity_db = os.path.join(user_folder, "network_activity.db")
            if os.path.exists(network_activity_db):
                with sqlite3.connect(network_activity_db) as conn_network:
                    c_network = conn_network.cursor()
                    c_network.execute("""
                        SELECT protocol, remote_ip, port, status, sent_bytes, received_bytes, timestamp
                        FROM network_activity
                        ORDER BY timestamp DESC
                        LIMIT 100
                    """)
                    network_activity = [{
                        "protocol": row[0],
                        "remote_ip": row[1],
                        "port": row[2],
                        "status": row[3],
                        "sent_bytes": row[4],
                        "received_bytes": row[5],
                        "timestamp": row[6]
                    } for row in c_network.fetchall()]
            
            system_info = json.loads(user_data[16]) if user_data[16] else {}
            
            locations = json.loads(user_data[17]) if user_data[17] else []
            
            # Convert login duration seconds to a readable format
            duration_sec = user_data[13] if user_data[13] is not None else 0
            if duration_sec > 0:
                hours, remainder = divmod(duration_sec, 3600)
                minutes, seconds = divmod(remainder, 60)
                login_duration_str = f"{int(hours)}h {int(minutes)}m {int(seconds)}s"
            else:
                login_duration_str = "0h 0m 0s"
            
            return render_template("user_logs.html",
                user_id=user_id,
                pc_name=user_data[3],
                logs=json.loads(user_data[6]) if user_data[6] else [],
                network_traffic=json.loads(user_data[7]) if user_data[7] else {},
                file_operations=json.loads(user_data[8]) if user_data[8] else [],
                removable_media_transfers=json.loads(user_data[9]) if user_data[9] else [],
                user_activity=json.loads(user_data[10]) if user_data[10] else [],
                login_time=user_data[11] if user_data[11] else "N/A",
                logout_time=user_data[12] if user_data[12] else "N/A",
                login_duration=login_duration_str,
                internet_status=internet_status,
                usb_count=user_data[15] if user_data[15] else 0,
                website_visits=visits,
                downloaded_files=downloads,
                web_activity=web_activity,
                network_activity=network_activity,
                system_info=system_info,
                locations=locations,
                last_update=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            )
            
    except Exception as e:
        logger.error(f"Error loading user logs: {str(e)}")
        return render_template("error.html", 
                             error_message=f"Error loading logs: {str(e)}",
                             user_id=user_id)

@app.route("/update_activity/<user_id>", methods=["POST"])
def update_activity(user_id):
    try:
        data = request.json
        
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT username, usb_count FROM user_data WHERE user_id = ?", (user_id,))
        user = c.fetchone()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        username = user[0]

        # Calculate duration if login_time and logout_time are provided
        login_time_str = data.get("login_time")
        logout_time_str = data.get("logout_time")
        login_duration_sec = 0
        if login_time_str and logout_time_str:
            login_time_dt = datetime.fromisoformat(login_time_str)
            logout_time_dt = datetime.fromisoformat(logout_time_str)
            login_duration_sec = int((logout_time_dt - login_time_dt).total_seconds())

        c.execute("""
            UPDATE user_data SET
                logs = ?,
                network_traffic = ?,
                login_time = ?,
                logout_time = ?,
                system_info = ?,
                usb_count = ?,
                login_duration = ?
            WHERE user_id = ?
        """, (
            data.get("logs", "[]"),
            data.get("network_traffic", "{}"),
            login_time_str,
            logout_time_str,
            data.get("system_info", "{}"),
            data.get("usb_count", 0),
            login_duration_sec,
            user_id
        ))
        conn.commit()
        
        socketio.emit("update_logs", {
            "user_id": user_id,
            "logs": json.loads(data.get("logs", "[]")),
            "network_traffic": json.loads(data.get("network_traffic", "{}"))
        })
        
        return jsonify({"status": "updated"})
    
    except Exception as e:
        logger.error(f"Error updating activity: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route("/webcam/<user_id>")
def webcam(user_id):
    if 'admin_logged_in' not in session:
        return redirect(url_for('login'))
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT username, pc_name FROM user_data WHERE user_id = ?", (user_id,))
        user = c.fetchone()
        if not user: return "User not found", 404
        return render_template("webcam.html", user_id=user_id, username=user[0], pc_name=user[1])
    except Exception as e:
        logger.error(f"Error loading webcam page: {e}")
        return "Error loading page", 500
    finally:
        conn.close()


@app.route("/get_user_media/<media_type>/<user_id>", methods=["GET"])
def get_user_media(media_type, user_id):
    if 'admin_logged_in' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT username FROM user_data WHERE user_id = ?", (user_id,))
        user = c.fetchone()
        if not user: return jsonify({"error": "User not found"}), 404
        
        username = user[0]
        media_folder = os.path.join(get_user_folder(username), media_type)
        if not os.path.exists(media_folder):
            return jsonify({"files": []})
        
        files = sorted(os.listdir(media_folder), reverse=True)
        return jsonify({"files": files})
    except Exception as e:
        logger.error(f"Error getting user media: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route("/view_media/<media_type>/<user_id>/<filename>")
def view_media(media_type, user_id, filename):
    if 'admin_logged_in' not in session:
        return "Unauthorized", 401
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT username FROM user_data WHERE user_id = ?", (user_id,))
        user = c.fetchone()
        if not user: return "User not found", 404
        
        username = user[0]
        media_path = os.path.join(get_user_folder(username), media_type, secure_filename(filename))
        if not os.path.exists(media_path):
            return "File not found", 404
        return send_file(media_path)
    except Exception as e:
        logger.error(f"Error sending media file: {e}")
        return "Error", 500
    finally:
        conn.close()


@app.route("/get_admin_activity", methods=["GET"])
def get_admin_activity():
    try:
        with open('users/admin/admin_activity.log', 'r') as f:
            activities = [line.strip() for line in f.readlines() if line.strip()]
        return jsonify({"activities": activities[-50:]})
    except Exception as e:
        logger.error(f"Error getting admin activity: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/overall_network_usage", methods=["GET"])
def overall_network_usage():
    try:
        return jsonify(psutil.net_io_counters()._asdict())
    except Exception as e:
        logger.error(f"Error getting network usage: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/create_shared_folder/<user_id>", methods=["POST"])
def create_shared_folder(user_id):
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT username FROM user_data WHERE user_id = ?", (user_id,))
        result = c.fetchone()
        
        if not result:
            return jsonify({"error": "User not found"}), 404
            
        username = result[0]
        shared_folder = os.path.join(get_user_folder(username), "shared")
        os.makedirs(shared_folder, exist_ok=True)
        
        access_file = os.path.join(shared_folder, "file_access.txt")
        if not os.path.exists(access_file):
            with open(access_file, 'w') as f:
                f.write("read:False\nwrite:False\n")
        
        return jsonify({"status": "folder_created"})
    except Exception as e:
        logger.error(f"Error creating shared folder: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route("/update_file_access/<user_id>", methods=["POST"])
def update_file_access(user_id):
    try:
        data = request.json
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT username FROM user_data WHERE user_id = ?", (user_id,))
        result = c.fetchone()
        
        if not result:
            return jsonify({"error": "User not found"}), 404
            
        username = result[0]
        access_file = os.path.join(get_user_folder(username), "shared", "file_access.txt")
        with open(access_file, 'w') as f:
            f.write(f"read:{data.get('read', False)}\n")
            f.write(f"write:{data.get('write', False)}\n")
        
        return jsonify({"status": "access_updated"})
    except Exception as e:
        logger.error(f"Error updating file access: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route("/get_file_access/<user_id>", methods=["GET"])
def get_file_access(user_id):
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT username FROM user_data WHERE user_id = ?", (user_id,))
        result = c.fetchone()
        
        if not result:
            return jsonify({"error": "User not found"}), 404
            
        username = result[0]
        access_file = os.path.join(get_user_folder(username), "shared", "file_access.txt")
        access = {"read": False, "write": False}
        
        if os.path.exists(access_file):
            with open(access_file, 'r') as f:
                for line in f:
                    if line.startswith("read:"):
                        access["read"] = line.split(":")[1].strip().lower() == "true"
                    elif line.startswith("write:"):
                        access["write"] = line.split(":")[1].strip().lower() == "true"
        
        return jsonify(access)
    except Exception as e:
        logger.error(f"Error getting file access: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route("/list_shared_files/<user_id>", methods=["GET"])
def list_shared_files(user_id):
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT username FROM user_data WHERE user_id = ?", (user_id,))
        result = c.fetchone()
        
        if not result:
            return jsonify({"error": "User not found"}), 404
            
        username = result[0]
        shared_folder = os.path.join(get_user_folder(username), "shared")
        files = []
        
        os.makedirs(shared_folder, exist_ok=True)
        
        access_file = os.path.join(shared_folder, "file_access.txt")
        if not os.path.exists(access_file):
            with open(access_file, 'w') as f:
                f.write("read:False\nwrite:False\n")
        
        for f in os.listdir(shared_folder):
            if f != "file_access.txt" and os.path.isfile(os.path.join(shared_folder, f)):
                stat = os.stat(os.path.join(shared_folder, f))
                files.append({
                    "name": f,
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
        
        return jsonify({"files": files})
    except Exception as e:
        logger.error(f"Error listing shared files: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route("/upload_file/<user_id>", methods=["POST"])
def upload_file(user_id):
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT username FROM user_data WHERE user_id = ?", (user_id,))
        result = c.fetchone()
        
        if not result:
            return jsonify({"error": "User not found"}), 404
            
        username = result[0]
        shared_folder = os.path.join(get_user_folder(username), "shared")
        os.makedirs(shared_folder, exist_ok=True)
        
        if 'file' not in request.files:
            return jsonify({"error": "No file part"}), 400
            
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400
            
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(shared_folder, filename))
            return jsonify({"status": "file_uploaded", "filename": filename})
    except Exception as e:
        logger.error(f"Error uploading file: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route("/download_file/<user_id>/<filename>", methods=["GET"])
def download_file(user_id, filename):
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT username FROM user_data WHERE user_id = ?", (user_id,))
        result = c.fetchone()
        
        if not result:
            return jsonify({"error": "User not found"}), 404
            
        username = result[0]
        shared_folder = os.path.join(get_user_folder(username), "shared")
        file_path = os.path.join(shared_folder, secure_filename(filename))
        
        if not os.path.exists(file_path):
            return jsonify({"error": "File not found"}), 404
            
        return send_file(file_path, as_attachment=True)
    except Exception as e:
        logger.error(f"Error downloading file: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route("/delete_file/<user_id>/<filename>", methods=["DELETE"])
def delete_file(user_id, filename):
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT username FROM user_data WHERE user_id = ?", (user_id,))
        result = c.fetchone()
        
        if not result:
            return jsonify({"error": "User not found"}), 404
            
        username = result[0]
        shared_folder = os.path.join(get_user_folder(username), "shared")
        file_path = os.path.join(shared_folder, secure_filename(filename))
        
        if not os.path.exists(file_path):
            return jsonify({"error": "File not found"}), 404
            
        os.remove(file_path)
        return jsonify({"status": "file_deleted"})
    except Exception as e:
        logger.error(f"Error deleting file: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route("/file_manager/<user_id>")
def file_manager(user_id):
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT username, pc_name FROM user_data WHERE user_id = ?", (user_id,))
        user = c.fetchone()
        
        if not user:
            return "User not found", 404
            
        return render_template("file_manager.html", user_id=user_id, pc_name=user[1])
    except Exception as e:
        logger.error(f"Error loading file manager: {e}")
        return "Error loading file manager", 500
    finally:
        conn.close()

# SocketIO events
@socketio.on('user_heartbeat')
def handle_user_heartbeat(data):
    user_id = data.get('user_id')
    if user_id:
        if user_id not in online_users:
            socketio.emit('user_online', {'user_id': user_id})
            logger.info(f"User {user_id} is online.")
        online_users[user_id] = time.time()
        client_sids[user_id] = request.sid


@socketio.on('watch_webcam')
def handle_watch_webcam(data):
    user_id = data.get('user_id')
    client_sid = client_sids.get(user_id)
    if client_sid:
        webcam_watchers[request.sid] = user_id
        emit('start_webcam_stream', {'user_id': user_id}, to=client_sid)
        logger.info(f"Admin {request.sid} started watching webcam for user {user_id}")
    else:
        emit('client_not_connected', {'user_id': user_id})

@socketio.on('webcam_frame')
def handle_webcam_frame(data):
    user_id = data.get('user_id')
    for admin_sid, watched_user_id in webcam_watchers.items():
        if watched_user_id == user_id:
            emit('webcam_stream', {'user_id': user_id, 'frame': data['frame']}, to=admin_sid)

@socketio.on('request_screenshot')
def handle_request_screenshot(data):
    user_id = data.get('user_id')
    client_sid = client_sids.get(user_id)
    if client_sid:
        emit('take_screenshot', {'user_id': user_id}, to=client_sid)
        logger.info(f"Admin requested screenshot from user {user_id}")

@socketio.on('screenshot_data')
def handle_screenshot_data(data):
    user_id = data.get('user_id')
    for admin_sid, watched_user_id in webcam_watchers.items():
        if watched_user_id == user_id:
            emit('screenshot_stream', {'user_id': user_id, 'frame': data['frame']}, to=admin_sid)

@socketio.on('save_capture')
def handle_save_capture(data):
    user_id = data.get('user_id')
    media_type = data.get('type', 'photos')
    b64_data = data.get('frame')
    
    conn = None
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT username FROM user_data WHERE user_id = ?", (user_id,))
        user = c.fetchone()
        if not user: 
            return
        
        username = user[0]
        media_folder = os.path.join(get_user_folder(username), media_type)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{timestamp}.jpg"
        filepath = os.path.join(media_folder, filename)
        
        image_data = base64.b64decode(b64_data)
        with open(filepath, 'wb') as f:
            f.write(image_data)
        
        logger.info(f"Saved {media_type} for {username} as {filename}")

        for admin_sid, watched_user_id in list(webcam_watchers.items()):
            if watched_user_id == user_id:
                emit('capture_saved', {'user_id': user_id, 'filename': filename, 'type': media_type}, to=admin_sid)

    except Exception as e:
        logger.error(f"Error saving capture: {e}")
    finally:
        if conn:
            conn.close()


@socketio.on('stop_watching_webcam')
def handle_stop_watching_webcam(data):
    admin_sid = request.sid
    if admin_sid in webcam_watchers:
        user_id = webcam_watchers[admin_sid]
        client_sid = client_sids.get(user_id)
        if client_sid:
            emit('stop_webcam_stream', to=client_sid)
        del webcam_watchers[admin_sid]
        logger.info(f"Admin {admin_sid} stopped watching {user_id}")



@socketio.on('disconnect')
def handle_disconnect():
    admin_sid = request.sid
    if admin_sid in webcam_watchers:
        user_id = webcam_watchers[admin_sid]
        client_sid = client_sids.get(user_id)
        if client_sid:
            emit('stop_webcam_stream', to=client_sid)
        del webcam_watchers[admin_sid]
        logger.info(f"Admin {admin_sid} disconnected, stopped watching {user_id}")

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True, allow_unsafe_werkzeug=True)