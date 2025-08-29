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
from sklearn.preprocessing import LabelEncoder, MinMaxScaler

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
    'logon': 'anomaly_logon.pkl',
    'device': 'anomaly_device.pkl',
    'file': 'anomaly_file.pkl',
    'http': 'anomaly_http.pkl'
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

# --- User Online Status Tracking ---
online_users = {}  # user_id: last_seen_timestamp

def check_offline_users():
    while True:
        try:
            offline_threshold = time.time() - 30  # 30 seconds timeout
            offline_user_ids = [user_id for user_id, last_seen in list(online_users.items()) if last_seen < offline_threshold]
            
            for user_id in offline_user_ids:
                if user_id in online_users:
                    del online_users[user_id]
                    socketio.emit('user_offline', {'user_id': user_id})
                    logger.info(f"User {user_id} is offline.")
        except Exception as e:
            logger.error(f"Error in check_offline_users: {e}")
        socketio.sleep(15) # Check every 15 seconds

# Start the background thread
threading.Thread(target=check_offline_users, daemon=True).start()


# Database Functions
def init_admin_db():
    try:
        conn = sqlite3.connect("admin.db")
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS admin_password (
                id INTEGER PRIMARY KEY, 
                password TEXT
            )
        """)
        c.execute("SELECT COUNT(*) FROM admin_password")
        if c.fetchone()[0] == 0:
            c.execute("INSERT INTO admin_password VALUES (1, 'p@ssw0rd')")
        conn.commit()
    except Exception as e:
        logger.error(f"Error initializing admin DB: {e}")
    finally:
        conn.close()

def init_user_db():
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS user_data (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE,
                password TEXT,
                pc_name TEXT,
                platform TEXT,
                accepted INTEGER DEFAULT 0,
                logs TEXT DEFAULT '[]',
                network_traffic TEXT DEFAULT '{}',
                file_operations TEXT DEFAULT '[]',
                removable_media_transfers TEXT DEFAULT '[]',
                user_activity TEXT DEFAULT '[]',
                login_time TEXT DEFAULT '',
                logout_time TEXT DEFAULT '',
                login_duration TEXT DEFAULT '',
                internet_status TEXT DEFAULT '',
                usb_count INTEGER DEFAULT 0,
                system_info TEXT DEFAULT '{}',
                locations TEXT DEFAULT '[]'
            )
        """)
        conn.commit()
    except Exception as e:
        logger.error(f"Error initializing user DB: {e}")
    finally:
        conn.close()

def init_user_databases(username):
    """Initialize all user-specific databases in their folder"""
    user_folder = get_user_folder(username)
    
    # Web Activity Database
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
    
    # Online Data Database
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
                timestamp TEXT
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_visits_time ON website_visits(timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_downloads_time ON file_downloads(timestamp)")
        conn.commit()
    except Exception as e:
        logger.error(f"Error initializing online data DB for {username}: {e}")
    finally:
        conn.close()
    
    # Network Activity Database
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

    # Create shared folder and access file
    shared_folder = os.path.join(user_folder, "shared")
    os.makedirs(shared_folder, exist_ok=True)
    access_file = os.path.join(shared_folder, "file_access.txt")
    if not os.path.exists(access_file):
        with open(access_file, 'w') as f:
            f.write("read:False\nwrite:False\n")

# Initialize admin and main user databases
init_admin_db()
init_user_db()

# --- Anomaly Detection Functions ---

def detect_logon_anomaly(data):
    """
    Detects anomalies in logon data.
    FIX: This function now creates features that match the trained model,
    which appears to be trained on device-like features (time-based).
    """
    if not models.get('logon'):
        logger.warning("Logon anomaly model not loaded.")
        return None
    try:
        df = pd.DataFrame([data])
        
        # --- Feature Engineering (must match the model's training) ---
        df["date"] = pd.to_datetime(df["date"])
        df["hour_of_day"] = df["date"].dt.hour
        df["day_of_week"] = df["date"].dt.dayofweek
        df["is_weekend"] = df["day_of_week"].apply(lambda x: 1 if x >= 5 else 0)
        df["is_midnight_activity"] = df["hour_of_day"].apply(lambda x: 1 if x < 5 else 0)
        
        # For a single prediction, we can't calculate time since last activity without history.
        # We'll use a neutral value (0) for this feature.
        df["log_time_since_last_activity"] = np.log1p(0)
        
        # The model expects the 'activity' to be encoded.
        # We'll assume 'Logon' is one category and 'Logoff' is another.
        # A more robust solution would save the LabelEncoder from training.
        df["activity_encoded"] = df["activity"].apply(lambda x: 1 if x == 'Logon' else 0)

        features_for_model = [
            "hour_of_day", "day_of_week", "is_weekend", 
            "is_midnight_activity", "log_time_since_last_activity", "activity_encoded"
        ]
        X = df[features_for_model]

        # --- Prediction ---
        prediction = models['logon'].predict(X)[0]
        
        return {"is_anomaly": prediction == -1}

    except Exception as e:
        logger.error(f"Logon anomaly detection error: {e}")
        return None

def detect_file_anomaly(data):
    """Detects anomalies in file access data based on model_file.ipynb."""
    if not models.get('file'):
        return None
    try:
        df = pd.DataFrame([data])
        df['date'] = pd.to_datetime(df['date'], errors='coerce')
        
        # Feature Engineering to match the notebook
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
    """Detects anomalies in HTTP data based on model_http.ipynb."""
    if not models.get('http'):
        return None
    try:
        df = pd.DataFrame([data])
        
        # Feature Engineering
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

# Utility Functions
def get_user_folder(username):
    user_folder = os.path.join("users", username)
    os.makedirs(user_folder, exist_ok=True)
    os.makedirs(os.path.join(user_folder, "photos"), exist_ok=True)
    os.makedirs(os.path.join(user_folder, "videos"), exist_ok=True)
    os.makedirs(os.path.join(user_folder, "frames"), exist_ok=True)
    return user_folder

def log_user_activity(username, message, logs=None):
    try:
        user_folder = get_user_folder(username)
        log_file = os.path.join(user_folder, "activity_log.txt")
        
        with open(log_file, 'a') as f:
            timestamp = datetime.now().isoformat()
            f.write(f"{timestamp} - {message}\n")
            
            if logs and isinstance(logs, list):
                f.write("User Logs:\n")
                for log in logs:
                    if isinstance(log, dict):
                        f.write(f"  PID: {log.get('pid', 'N/A')}, ")
                        f.write(f"Name: {log.get('name', 'N/A')}, ")
                        f.write(f"CPU: {log.get('cpu_percent', 0)}%, ")
                        f.write(f"Memory: {log.get('memory_percent', 0)}%\n")
    except Exception as e:
        logger.error(f"Error logging activity: {e}")

def log_admin_activity(action):
    try:
        with open('users/admin/admin_activity.log', 'a') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"{timestamp} - {action}\n")
    except Exception as e:
        logger.error(f"Error logging admin activity: {e}")

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

# --- Main Routes ---
@app.route("/")
def dashboard():
    if 'admin_logged_in' not in session:
        return redirect(url_for('login'))
    return render_template("dashboard.html", users=get_all_users(), online_user_ids=list(online_users.keys()))

# ... (login, logout routes remain the same) ...
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


# --- New Anomaly Detection Routes ---

@app.route("/report_logon_activity", methods=["POST"])
def report_logon_activity():
    data = request.json
    username = data.get("user")
    user_id = data.get("user_id")
    anomaly_result = detect_logon_anomaly(data)
    
    if anomaly_result and anomaly_result["is_anomaly"]:
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
        alert_msg = f"Suspicious HTTP activity detected for {username} (URL: {data.get('url')[:30]}...)"
        socketio.emit("http_anomaly_alert", {"message": alert_msg, "user_id": user_id, "score": anomaly_result.get('score', 0)})
        log_user_activity(username, f"HTTP ANOMALY: {alert_msg}")

    return jsonify({"status": "processed"})

# ... (Existing routes like /report_location, /clear_usb_alerts, etc. remain the same) ...
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
        
        # Get username for logging
        c.execute("SELECT username FROM user_data WHERE user_id = ?", (user_id,))
        user = c.fetchone()
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        # Update logout time
        c.execute("""
            UPDATE user_data SET 
                logout_time = ?,
                login_duration = ?
            WHERE user_id = ?
        """, (
            datetime.now().isoformat(),
            "0",  # Reset login duration
            user_id
        ))
        conn.commit()
        
        log_admin_activity(f"Logged out user {user[0]} (ID: {user_id})")
        socketio.emit("user_logged_out", {"user_id": user_id})
        
        return jsonify({"status": "user_logged_out"})
    except Exception as e:
        logger.error(f"Error logging out user: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

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
        
        # Ensure user folder exists
        user_folder = get_user_folder(username)
        web_activity_db = os.path.join(user_folder, "web_activity.db")
        
        # Store in database
        conn = sqlite3.connect(web_activity_db)
        c = conn.cursor()
        
        for activity in data.get("visited_sites", []):
            c.execute("""
                INSERT INTO web_activity (url, title, visit_time, duration)
                VALUES (?, ?, ?, ?)
            """, (
                activity.get("url"), 
                activity.get("title", ""), 
                activity.get("time", ""), 
                activity.get("duration", "")
            ))
        
        conn.commit()
        
        # Store in user's folder
        with open(os.path.join(user_folder, "web_activity.txt"), 'a') as f:
            for activity in data.get("visited_sites", []):
                f.write(f"{activity.get('time', '')} | {activity.get('url', '')} | {activity.get('title', '')}\n")
        
        log_user_activity(username, "Web activity reported")
        return jsonify({"status": "success"})
    except Exception as e:
        logger.error(f"Error processing web activity: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route("/report_network_activity/<user_id>", methods=["POST"])
def report_network_activity(user_id):
    try:
        data = request.json
        username = data.get("username")
        
        # Store in database
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
        # Initialize all variables with default values
        user_data = None
        visits = []
        downloads = []
        web_activity = []
        network_activity = []
        system_info = {}
        locations = []
        
        # Get user data
        with sqlite3.connect("users.db") as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM user_data WHERE user_id = ?", (user_id,))
            user_data = c.fetchone()
            
            if not user_data:
                return "User not found", 404
                
            username = user_data[1]
            user_folder = get_user_folder(username)
            
            # Initialize online_data.db if it exists
            online_data_db = os.path.join(user_folder, "online_data.db")
            if os.path.exists(online_data_db):
                with sqlite3.connect(online_data_db) as conn_online:
                    c_online = conn_online.cursor()
                    
                    # Get website visits
                    c_online.execute("""
                        SELECT url, title, timestamp 
                        FROM website_visits 
                        ORDER BY timestamp DESC 
                        LIMIT 100
                    """)
                    visits = [{"url": row[0], "title": row[1], "timestamp": row[2]} 
                            for row in c_online.fetchall()]
                    
                    # Get file downloads
                    c_online.execute("""
                        SELECT url, filename, timestamp 
                        FROM file_downloads 
                        ORDER BY timestamp DESC 
                        LIMIT 100
                    """)
                    downloads = [{"url": row[0], "filename": row[1], "timestamp": row[2]} 
                                for row in c_online.fetchall()]
            
            # Initialize web_activity.db if it exists
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
            
            # Initialize network_activity.db if it exists
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
            
            # Get system info
            system_info = json.loads(user_data[16]) if user_data[16] else {}
            
            # Get locations
            locations = json.loads(user_data[17]) if user_data[17] else []
            
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
                login_duration=user_data[13] if user_data[13] else "N/A",
                internet_status=user_data[14] if user_data[14] else "offline",
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
        
        # Update user data with client-provided network usage
        c.execute("""
            UPDATE user_data SET
                logs = ?,
                network_traffic = ?,
                login_time = ?,
                logout_time = ?,
                system_info = ?,
                usb_count = ?
            WHERE user_id = ?
        """, (
            data.get("logs", "[]"),
            data.get("network_traffic", "{}"),
            data.get("login_time", ""),
            data.get("logout_time", ""),
            data.get("system_info", "{}"),
            data.get("usb_count", 0),
            user_id
        ))
        conn.commit()
        
        # Emit socket update
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

@app.route("/usb_event", methods=["POST"])
def usb_event():
    try:
        data = request.json
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        
        # Update USB count
        c.execute("""
            UPDATE user_data 
            SET usb_count = usb_count + 1 
            WHERE username = ?
        """, (data["username"],))
        conn.commit()
        
        # Log the event
        log_message = f"USB {data['event_type']}: {data['device_info']}"
        log_user_activity(data["username"], log_message)
        
        # Get user_id for socket emit
        c.execute("SELECT user_id FROM user_data WHERE username = ?", (data["username"],))
        user_id = c.fetchone()[0]
        
        # Write to USB alerts file
        alert_msg = f"{datetime.now().isoformat()} - USB {data['event_type']} by {data['username']}: {data['device_info']}"
        with open('users/admin/usb_alerts.txt', 'a') as f:
            f.write(alert_msg + "\n")
        
        socketio.emit("usb_alert", {
            "message": alert_msg,
            "user_id": user_id
        })
        
        # --- Device Anomaly Detection ---
        device_data = {
            "id": data.get("id", str(uuid.uuid4())),
            "date": data.get("timestamp", datetime.now().isoformat()),
            "user": data.get("username"),
            "pc": data.get("pc_name", ""),
            "activity": "Connect" if "Inserted" in data.get("event_type") else "Disconnect"
        }
        # anomaly_result = detect_device_anomaly(device_data)
        # if anomaly_result and anomaly_result["is_anomaly"]:
        #     alert_msg = f"Suspicious device activity detected for {data['username']}"
        #     socketio.emit("device_anomaly_alert", {"message": alert_msg, "user_id": user_id})
        #     log_user_activity(data['username'], f"DEVICE ANOMALY: {alert_msg}")

        return jsonify({"status": "logged"})
    except Exception as e:
        logger.error(f"Error logging USB event: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# ... (Other routes like /get_admin_activity, etc. remain the same) ...
@app.route("/get_admin_activity", methods=["GET"])
def get_admin_activity():
    try:
        with open('users/admin/admin_activity.log', 'r') as f:
            activities = [line.strip() for line in f.readlines() if line.strip()]
        return jsonify({"activities": activities[-50:]})  # Last 50 activities
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

# --- File Sharing Routes ---
# ... (All file sharing routes remain the same) ...
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
        
        # Initialize access control file
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
        
        # Create shared folder if it doesn't exist
        os.makedirs(shared_folder, exist_ok=True)
        
        # Create access file if it doesn't exist
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

@socketio.on('disconnect')
def handle_disconnect():
    pass

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
