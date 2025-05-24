from flask import Flask, render_template, request, jsonify
from datetime import datetime
from collections import defaultdict
import threading
import sqlite3

app = Flask(__name__)

# In-memory storage for client data with thread locking
clients_data = defaultdict(dict)
data_lock = threading.Lock()

def init_web_activity_db():
    try:
        conn = sqlite3.connect("user_web_activity.db")
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS web_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                url TEXT,
                title TEXT,
                visit_time TEXT,
                duration TEXT
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_web_activity_user ON web_activity(user_id)")
        conn.commit()
    except Exception as e:
        print(f"Error initializing web activity DB: {e}")
    finally:
        conn.close()

init_web_activity_db()

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/report', methods=['POST'])
def receive_report():
    try:
        data = request.json
        if not data or 'client_id' not in data:
            return jsonify({'status': 'error', 'message': 'Invalid data format'}), 400

        client_id = data['client_id']
        visited_sites = data.get('visited_sites', [])

        client_data = {
            'last_update': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'visited_sites': visited_sites,
            'downloaded_files': data.get('downloaded_files', []),
            'system_info': data.get('system_info', {}),
            'network_activity': data.get('network_activity', []),
            'timestamp': data.get('timestamp', '')
        }

        with data_lock:
            clients_data[client_id] = client_data

        # Save visited sites to SQLite database
        try:
            conn = sqlite3.connect("user_web_activity.db")
            c = conn.cursor()
            for site in visited_sites:
                c.execute("""
                    INSERT INTO web_activity (user_id, url, title, visit_time, duration)
                    VALUES (?, ?, ?, ?, ?)
                """, (client_id, site['url'], site['title'], site['time'], 'unknown'))
            conn.commit()
        except Exception as e:
            print(f"Error saving web activity: {e}")
        finally:
            conn.close()

        return jsonify({'status': 'success'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/clients', methods=['GET'])
def get_clients():
    try:
        with data_lock:
            clients = {k: {'last_update': v['last_update'], 'system_info': v['system_info']} for k, v in clients_data.items()}
        return jsonify({'clients': clients})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/client/<client_id>', methods=['GET'])
def get_client_data(client_id):
    try:
        with data_lock:
            if client_id in clients_data:
                return jsonify(clients_data[client_id])
            return jsonify({'error': 'Client not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/web_activity/<client_id>', methods=['GET'])
def get_web_activity(client_id):
    try:
        conn = sqlite3.connect("user_web_activity.db")
        c = conn.cursor()
        c.execute("SELECT url, title, visit_time FROM web_activity WHERE user_id = ? ORDER BY visit_time DESC LIMIT 20", (client_id,))
        history = [{'url': row[0], 'title': row[1], 'visit_time': row[2]} for row in c.fetchall()]
        conn.close()
        return jsonify({'web_activity': history})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
