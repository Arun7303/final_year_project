import requests
import platform
import uuid
import json
import time
import psutil
import sys
import logging
from datetime import datetime
import os
import threading
import sqlite3
import shutil
import socket
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import webbrowser
import cv2
from PIL import Image, ImageTk
import threading

# Windows-specific imports
if platform.system() == "Windows":
    try:
        import win32api
        import win32con
        import win32file
        import wmi
    except ImportError:
        print("Warning: pywin32 modules not installed. Some Windows-specific features may not work.")
else:
    # Optional: define dummy variables or handlers to prevent errors if code tries to call these
    win32api = None
    win32con = None
    win32file = None
    try:
        import pyudev
    except ImportError:
        print("Warning: pyudev not installed. USB monitoring won't work on Linux.")

# Configuration
SERVER_URL = "http://10.135.82.88:5000"  # Replace with actual server IP
REPORT_INTERVAL = 30  # 5 minutes for web activity reports
LOG_UPDATE_INTERVAL = 10  # 10 seconds for regular logs
FILE_SYNC_INTERVAL = 60  # 1 minute for file sync
LOCATION_UPDATE_INTERVAL = 3600  # 1 hour for location updates

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('client.log'),
        logging.StreamHandler()
    ]
)

# Ensure directories exist
os.makedirs("logs", exist_ok=True)
os.makedirs("shared", exist_ok=True)

class FileSharingGUI:
    def __init__(self, root, user_id, username):
        self.root = root
        self.user_id = user_id
        self.username = username
        self.root.title(f"File Sharing - {username}")
        
        # Setup GUI
        self.setup_ui()
        
        # Start periodic refresh
        self.refresh_files()
        
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        self.update_status("Ready")
        
        # File list
        self.tree = ttk.Treeview(main_frame, columns=('name', 'size', 'modified'), show='headings')
        self.tree.heading('name', text='File Name')
        self.tree.heading('size', text='Size')
        self.tree.heading('modified', text='Modified')
        self.tree.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        # Buttons
        ttk.Button(button_frame, text="Refresh", command=self.refresh_files).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Download", command=self.download_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Upload", command=self.upload_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Open Local Folder", command=self.open_local_folder).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="View Online", command=self.view_online).pack(side=tk.LEFT, padx=5)
        
    def update_status(self, message):
        self.status_var.set(message)
    
        
    def refresh_files(self):
        try:
            # Clear existing items
            for item in self.tree.get_children():
                self.tree.delete(item)
                
            self.update_status("Refreshing file list...")
            
            # Get file list from server
            list_resp = requests.get(f"{SERVER_URL}/list_shared_files/{self.user_id}")
            if list_resp.status_code == 200:
                server_files = {f['name']: f for f in list_resp.json().get("files", [])}
                
                # Add files to treeview
                for filename, file_info in server_files.items():
                    size_mb = round(file_info['size'] / (1024 * 1024), 2)
                    size_str = f"{size_mb} MB" if size_mb >= 1 else f"{round(file_info['size'] / 1024, 2)} KB"
                    self.tree.insert('', 'end', values=(
                        filename,
                        size_str,
                        file_info['modified']
                    ))
                
                # Also show local files that haven't been synced yet
                for f in os.listdir("shared"):
                    if f != "file_access.txt" and os.path.isfile(os.path.join("shared", f)):
                        if f not in server_files:
                            stat = os.stat(os.path.join("shared", f))
                            size_mb = round(stat.st_size / (1024 * 1024), 2)
                            size_str = f"{size_mb} MB" if size_mb >= 1 else f"{round(stat.st_size / 1024, 2)} KB"
                            self.tree.insert('', 'end', values=(
                                f + " (local)",
                                size_str,
                                datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                            ), tags=('local',))
                
                self.tree.tag_configure('local', foreground='blue')
                self.update_status(f"Found {len(server_files)} server files")
            else:
                self.update_status("Error refreshing files")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh files: {e}")
            self.update_status("Error refreshing files")
            
        # Schedule next refresh
        self.root.after(5000, self.refresh_files)
        
    def download_file(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a file to download")
            return
            
        item = self.tree.item(selected[0])
        filename = item['values'][0].replace(" (local)", "")
        
        try:
            # Check if file exists locally
            local_path = os.path.join("shared", filename)
            if os.path.exists(local_path):
                if not messagebox.askyesno("Confirm", f"{filename} already exists. Overwrite?"):
                    return
            
            self.update_status(f"Downloading {filename}...")
            
            # Download from server
            download_resp = requests.get(f"{SERVER_URL}/download_file/{self.user_id}/{filename}", stream=True)
            if download_resp.status_code == 200:
                with open(local_path, 'wb') as f:
                    for chunk in download_resp.iter_content(1024):
                        if chunk:
                            f.write(chunk)
                messagebox.showinfo("Success", f"{filename} downloaded successfully")
                self.update_status(f"Downloaded {filename}")
            else:
                messagebox.showerror("Error", f"Failed to download {filename}")
                self.update_status("Download failed")
        except Exception as e:
            messagebox.showerror("Error", f"Download failed: {e}")
            self.update_status("Download failed")
            
    def upload_file(self):
        filepath = filedialog.askopenfilename(title="Select file to upload")
        if not filepath:
            return
            
        filename = os.path.basename(filepath)
        
        try:
            # Check access permissions
            access_resp = requests.get(f"{SERVER_URL}/get_file_access/{self.user_id}")
            if access_resp.status_code == 200:
                access = access_resp.json()
                if not access.get("write"):
                    messagebox.showerror("Error", "You don't have write access")
                    return
            
            self.update_status(f"Uploading {filename}...")
            
            with open(filepath, 'rb') as f:
                files = {'file': (filename, f)}
                upload_resp = requests.post(
                    f"{SERVER_URL}/upload_file/{self.user_id}",
                    files=files
                )
                
                if upload_resp.status_code == 200:
                    messagebox.showinfo("Success", f"{filename} uploaded successfully")
                    self.update_status(f"Uploaded {filename}")
                else:
                    messagebox.showerror("Error", f"Failed to upload {filename}")
                    self.update_status("Upload failed")
        except Exception as e:
            messagebox.showerror("Error", f"Upload failed: {e}")
            self.update_status("Upload failed")
            
    def open_local_folder(self):
        shared_path = os.path.abspath("shared")
        if platform.system() == "Windows":
            os.startfile(shared_path)
        elif platform.system() == "Darwin":
            os.system(f"open '{shared_path}'")
        else:
            os.system(f"xdg-open '{shared_path}'")
            
    def view_online(self):
        webbrowser.open(f"{SERVER_URL}/file_manager/{self.user_id}")

def validate_password(username, password):
    try:
        resp = requests.post(
            f"{SERVER_URL}/validate_user_password",
            json={"username": username, "password": password}
        )
        return resp.status_code == 200 and resp.json().get("status") == "valid"
    except Exception as e:
        logging.error(f"Server connection error: {e}")
        return False

def register_user(username, password):
    user_id = str(uuid.uuid4())
    pc_name = platform.node()
    platform_name = platform.system()

    try:
        resp = requests.post(
            f"{SERVER_URL}/add_user",
            json={
                "user_id": user_id,
                "username": username,
                "password": password,
                "pc_name": pc_name,
                "platform": platform_name
            }
        )
        if resp.status_code == 200 and resp.json().get("status") == "user_added":
            logging.info("User added successfully. Waiting for admin acceptance...")
            return user_id
        logging.error("Failed to add user.")
        return None
    except Exception as e:
        logging.error(f"Error sending initial data: {e}")
        return None

def check_acceptance(user_id):
    while True:
        try:
            response = requests.get(f"{SERVER_URL}/user_details/{user_id}")
            if response.status_code == 200:
                user_data = response.json()
                if "error" in user_data:
                    logging.error(user_data["error"])
                    sys.exit(1)
                
                accepted_status = user_data.get("accepted")
                if accepted_status == 1:
                    logging.info("User accepted by admin. Starting monitoring...")
                    return True
                elif accepted_status == -1:
                    logging.error("Request rejected by admin. Exiting...")
                    sys.exit(1)
                logging.info("Waiting for admin acceptance...")
            else:
                logging.error(f"Error fetching user details. Status: {response.status_code}")
        except Exception as e:
            logging.error(f"Error checking acceptance status: {e}")
        time.sleep(5)

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
    try:
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
    except Exception as e:
        logging.error(f"Error getting network connections: {e}")
    return connections

def get_browser_history():
    history = []
    browsers = {
        "chrome": {
            "windows": os.path.join(os.getenv('LOCALAPPDATA', ''), 'Google', 'Chrome', 'User Data', 'Default', 'History'),
            "linux": os.path.expanduser("~/.config/google-chrome/Default/History"),
            "darwin": os.path.expanduser("~/Library/Application Support/Google/Chrome/Default/History")
        },
        "firefox": {
            "windows": os.path.join(os.getenv('APPDATA', ''), 'Mozilla', 'Firefox', 'Profiles'),
            "linux": os.path.expanduser("~/.mozilla/firefox"),
            "darwin": os.path.expanduser("~/Library/Application Support/Firefox/Profiles")
        }
    }

    def fetch_chrome_history(db_path):
        if db_path and os.path.exists(db_path):
            try:
                temp_db = db_path + "_temp"
                shutil.copy2(db_path, temp_db)
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT url, title, last_visit_time 
                    FROM urls 
                    ORDER BY last_visit_time DESC 
                    LIMIT 50
                """)
                for row in cursor.fetchall():
                    history.append({
                        'url': row[0],
                        'title': row[1],
                        'time': datetime.fromtimestamp(row[2]/1000000-11644473600).strftime('%Y-%m-%d %H:%M:%S')
                    })
                conn.close()
                if os.path.exists(temp_db):
                    os.remove(temp_db)
            except Exception as e:
                logging.error(f"Error fetching Chrome history: {e}")

    def fetch_firefox_history(profile_path):
        if profile_path and os.path.exists(profile_path):
            try:
                # Find the latest profile
                profiles = [d for d in os.listdir(profile_path) 
                          if os.path.isdir(os.path.join(profile_path, d)) and d.endswith('.default')]
                if not profiles:
                    return
                    
                latest_profile = profiles[0]
                db_path = os.path.join(profile_path, latest_profile, 'places.sqlite')
                
                if os.path.exists(db_path):
                    temp_db = db_path + "_temp"
                    shutil.copy2(db_path, temp_db)
                    conn = sqlite3.connect(temp_db)
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT url, title, last_visit_date 
                        FROM moz_places 
                        JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id 
                        ORDER BY last_visit_date DESC 
                        LIMIT 50
                    """)
                    for row in cursor.fetchall():
                        history.append({
                            'url': row[0],
                            'title': row[1],
                            'time': datetime.fromtimestamp(row[2]/1000000).strftime('%Y-%m-%d %H:%M:%S')
                        })
                    conn.close()
                    if os.path.exists(temp_db):
                        os.remove(temp_db)
            except Exception as e:
                logging.error(f"Error fetching Firefox history: {e}")

    # Try Chrome first
    system = platform.system().lower()
    if system == 'windows':
        fetch_chrome_history(browsers["chrome"]["windows"])
        fetch_firefox_history(browsers["firefox"]["windows"])
    elif system == 'linux':
        fetch_chrome_history(browsers["chrome"]["linux"])
        fetch_firefox_history(browsers["firefox"]["linux"])
    elif system == 'darwin':  # macOS
        fetch_chrome_history(browsers["chrome"]["darwin"])
        fetch_firefox_history(browsers["firefox"]["darwin"])
    
    return history

def get_downloads():
    downloads = []
    try:
        if platform.system() == 'Windows':
            downloads_path = os.path.join(os.getenv('USERPROFILE', ''), 'Downloads')
            # Also check Edge/Chrome download history
            try:
                edge_history = os.path.join(os.getenv('LOCALAPPDATA', ''), 
                                          'Microsoft', 'Edge', 'User Data', 'Default', 'History')
                chrome_history = os.path.join(os.getenv('LOCALAPPDATA', ''), 
                                           'Google', 'Chrome', 'User Data', 'Default', 'History')
                
                for history_db in [edge_history, chrome_history]:
                    if os.path.exists(history_db):
                        temp_db = history_db + "_temp"
                        shutil.copy2(history_db, temp_db)
                        conn = sqlite3.connect(temp_db)
                        cursor = conn.cursor()
                        cursor.execute("""
                            SELECT target_path, total_bytes, start_time 
                            FROM downloads 
                            ORDER BY start_time DESC 
                            LIMIT 20
                        """)
                        for row in cursor.fetchall():
                            if os.path.exists(row[0]):
                                filename = os.path.basename(row[0])
                                downloads.append({
                                    'filename': filename,
                                    'path': row[0],
                                    'size': f"{round(row[1] / (1024*1024), 2)} MB" if row[1] else "N/A",
                                    'timestamp': datetime.fromtimestamp(row[2]/1000000-11644473600).strftime('%Y-%m-%d %H:%M:%S')
                                })
                        conn.close()
                        if os.path.exists(temp_db):
                            os.remove(temp_db)
            except Exception as e:
                logging.error(f"Error reading browser download history: {e}")
        else:
            downloads_path = os.path.expanduser('~/Downloads')
        
        # Add files from downloads folder
        if os.path.exists(downloads_path):
            for f in os.listdir(downloads_path):
                full_path = os.path.join(downloads_path, f)
                if os.path.isfile(full_path):
                    stat = os.stat(full_path)
                    # Only add if not already in list
                    if not any(d['path'] == full_path for d in downloads):
                        downloads.append({
                            'filename': f,
                            'path': full_path,
                            'size': f"{round(stat.st_size / (1024*1024), 2)} MB",
                            'timestamp': datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
                        })
    except Exception as e:
        logging.error(f"Error getting downloads: {e}")
    
    return sorted(downloads, key=lambda x: x['timestamp'], reverse=True)[:20]

def collect_web_activity(username):
    return {
        "visited_sites": get_browser_history(),
        "downloaded_files": get_downloads(),
        "username": username
    }

def report_web_activity(user_id, username):
    while True:
        try:
            activity = collect_web_activity(username)
            if not activity.get("visited_sites") and not activity.get("downloaded_files"):
                logging.info("No web activity to report")
                time.sleep(REPORT_INTERVAL)
                continue
                
            resp = requests.post(
                f"{SERVER_URL}/report_web_activity/{user_id}",
                json=activity
            )
            if resp.status_code == 200:
                logging.info("Web activity reported successfully")
            else:
                logging.error(f"Failed to report web activity: {resp.text}")
        except Exception as e:
            logging.error(f"Error reporting web activity: {e}")
        time.sleep(REPORT_INTERVAL)

def report_network_activity(user_id, username):
    while True:
        try:
            activity = {
                "network_activity": get_network_connections(),
                "username": username
            }
            resp = requests.post(
                f"{SERVER_URL}/report_network_activity/{user_id}",
                json=activity
            )
            if resp.status_code == 200:
                logging.info("Network activity reported successfully")
            else:
                logging.error(f"Failed to report network activity: {resp.text}")
        except Exception as e:
            logging.error(f"Error reporting network activity: {e}")
        time.sleep(REPORT_INTERVAL)

def get_geolocation():
    try:
        # Get public IP
        ip = requests.get('https://api.ipify.org').text
        # Get location data from ip-api.com
        response = requests.get(f'http://ip-api.com/json/{ip}')
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                return {
                    'ip': ip,
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('regionName', 'Unknown'),
                    'country': data.get('country', 'Unknown'),
                    'lat': data.get('lat', 0),
                    'lon': data.get('lon', 0),
                    'time': datetime.now().isoformat()
                }
    except Exception as e:
        logging.error(f"Error getting geolocation: {e}")
    return None

def report_location(user_id, username):
    while True:
        try:
            location = get_geolocation()
            if location:
                response = requests.post(
                    f"{SERVER_URL}/report_location/{user_id}",
                    json={
                        "username": username,
                        "location": location
                    }
                )
                if response.status_code == 200:
                    logging.info("Location reported successfully")
        except Exception as e:
            logging.error(f"Error reporting location: {e}")
        time.sleep(LOCATION_UPDATE_INTERVAL)

def log_usb_event(event_type, device_info, username):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("logs/usb.txt", "a") as f:
        f.write(f"{timestamp} - {event_type}: {device_info}\n")
    
    try:
        requests.post(
            f"{SERVER_URL}/usb_event",
            json={
                "username": username,
                "event_type": event_type,
                "device_info": device_info,
                "timestamp": timestamp
            }
        )
    except Exception as e:
        logging.error(f"Error sending USB event: {e}")

def monitor_usb_windows(username):
    c = wmi.WMI()
    insert_watcher = c.Win32_USBControllerDevice.watch_for("creation")
    remove_watcher = c.Win32_USBControllerDevice.watch_for("deletion")

    logging.info("USB monitoring started for Windows")
    while True:
        try:
            insert_event = insert_watcher(timeout_ms=2000)
            if insert_event:
                device_info = insert_event.Dependent
                logging.info(f"USB Inserted: {device_info}")
                log_usb_event("USB Inserted", str(device_info), username)

            remove_event = remove_watcher(timeout_ms=2000)
            if remove_event:
                device_info = remove_event.Dependent
                logging.info(f"USB Removed: {device_info}")
                log_usb_event("USB Removed", str(device_info), username)
        except Exception as e:
            logging.error(f"USB monitoring error: {e}")

def monitor_usb_linux(username):
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem='usb')

    logging.info("USB monitoring started for Linux")
    for device in iter(monitor.poll, None):
        if device.action == "add":
            logging.info(f"USB Inserted: {device.device_path}")
            log_usb_event("USB Inserted", str(device.device_path), username)
        elif device.action == "remove":
            logging.info(f"USB Removed: {device.device_path}")
            log_usb_event("USB Removed", str(device.device_path), username)

def sync_shared_files(user_id, username):
    while True:
        try:
            # Check current access permissions
            access_resp = requests.get(f"{SERVER_URL}/get_file_access/{user_id}")
            if access_resp.status_code == 200:
                access = access_resp.json()
                if not access.get("read"):
                    time.sleep(FILE_SYNC_INTERVAL)
                    continue

            # Get list of files from server
            list_resp = requests.get(f"{SERVER_URL}/list_shared_files/{user_id}")
            if list_resp.status_code == 200:
                server_files = {f['name']: f for f in list_resp.json().get("files", [])}
                
                # Sync files from server to local shared folder
                for filename, file_info in server_files.items():
                    local_path = os.path.join("shared", filename)
                    server_mtime = datetime.fromisoformat(file_info['modified']).timestamp()
                    
                    # Download if file doesn't exist or is outdated
                    if not os.path.exists(local_path) or os.path.getmtime(local_path) < server_mtime:
                        logging.info(f"Downloading file: {filename}")
                        download_resp = requests.get(f"{SERVER_URL}/download_file/{user_id}/{filename}", stream=True)
                        if download_resp.status_code == 200:
                            with open(local_path, 'wb') as f:
                                for chunk in download_resp.iter_content(1024):
                                    if chunk:
                                        f.write(chunk)
                            # Set modified time to match server
                            os.utime(local_path, (server_mtime, server_mtime))
            
            # Check if we have write access before uploading local changes
            if access.get("write"):
                # Get list of local files
                local_files = {}
                for f in os.listdir("shared"):
                    if f != "file_access.txt":
                        full_path = os.path.join("shared", f)
                        if os.path.isfile(full_path):
                            stat = os.stat(full_path)
                            local_files[f] = {
                                "size": stat.st_size,
                                "modified": stat.st_mtime
                            }
                
                # Upload new or modified files to server
                for filename, file_info in local_files.items():
                    if filename not in server_files or file_info['modified'] > datetime.fromisoformat(server_files[filename]['modified']).timestamp():
                        logging.info(f"Uploading file: {filename}")
                        with open(os.path.join("shared", filename), 'rb') as f:
                            files = {'file': (filename, f)}
                            upload_resp = requests.post(
                                f"{SERVER_URL}/upload_file/{user_id}",
                                files=files
                            )
                            if upload_resp.status_code != 200:
                                logging.error(f"Failed to upload file {filename}: {upload_resp.text}")

        except Exception as e:
            logging.error(f"Error syncing files: {e}")
        
        time.sleep(FILE_SYNC_INTERVAL)

def send_system_logs(user_id, username):
    login_time = datetime.now().isoformat()
    
    while True:
        try:
            # Check if user is still accepted
            response = requests.get(f"{SERVER_URL}/user_details/{user_id}")
            if response.status_code != 200 or response.json().get("accepted") != 1:
                logging.error("User no longer accepted. Exiting...")
                sys.exit(1)

            # Collect process logs
            logs = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'create_time']):
                try:
                    logs.append({
                        "pid": proc.info['pid'],
                        "name": proc.info['name'],
                        "cpu_percent": proc.info['cpu_percent'],
                        "memory_percent": proc.info['memory_percent'],
                        "create_time": proc.info['create_time']
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Collect network traffic
            net_io = psutil.net_io_counters()
            network_traffic = {
                "bytes_sent": net_io.bytes_sent,
                "bytes_recv": net_io.bytes_recv,
                "packets_sent": net_io.packets_sent,
                "packets_recv": net_io.packets_recv,
                "errin": net_io.errin,
                "errout": net_io.errout,
                "dropin": net_io.dropin,
                "dropout": net_io.dropout
            }

            # Get USB count (updated by USB monitoring thread)
            usb_count = 0  # This would be updated by your USB monitoring code

            # Prepare data
            data = {
                "logs": json.dumps(logs),
                "network_traffic": json.dumps(network_traffic),
                "login_time": login_time,
                "logout_time": datetime.now().isoformat(),
                "system_info": json.dumps(get_system_info()),
                "usb_count": usb_count
            }

            # Send to server
            resp = requests.post(
                f"{SERVER_URL}/update_activity/{user_id}",
                json=data
            )
            if resp.status_code == 200:
                logging.debug("System logs updated")
            else:
                logging.error(f"Failed to update logs: {resp.text}")

        except Exception as e:
            logging.error(f"Error in system log collection: {e}")
        
        time.sleep(LOG_UPDATE_INTERVAL)


def main():
    print("Monitoring Client\n" + "="*20)
    print("1. New User\n2. Existing User")
    choice = input("Select option (1/2): ").strip()

    if choice == "1":
        admin_pass = input("Admin password: ").strip()
        if admin_pass != "p@ssw0rd":
            logging.error("Invalid admin password")
            return

        username = input("Username: ").strip()
        password = input("Password: ").strip()
        user_id = register_user(username, password)
        if not user_id:
            return

    elif choice == "2":
        username = input("Username: ").strip()
        password = input("Password: ").strip()
        if not validate_password(username, password):
            return

        try:
            response = requests.get(f"{SERVER_URL}/get_user_id/{username}")
            if response.status_code == 200:
                user_id = response.json().get("user_id")
            else:
                logging.error("User not found")
                return
        except Exception as e:
            logging.error(f"Error fetching user ID: {e}")
            return
    else:
        logging.error("Invalid choice")
        return

    if not check_acceptance(user_id):
        return

    # Start monitoring threads
    threads = []
    
    # USB Monitoring
    if platform.system() == "Windows":
        usb_thread = threading.Thread(target=monitor_usb_windows, args=(username,))
    elif platform.system() == "Linux":
        usb_thread = threading.Thread(target=monitor_usb_linux, args=(username,))
    else:
        logging.error("Unsupported OS for USB monitoring")
        usb_thread = None
    
    if usb_thread:
        usb_thread.daemon = True
        threads.append(usb_thread)
        usb_thread.start()

    # System Logs
    syslog_thread = threading.Thread(target=send_system_logs, args=(user_id, username))
    syslog_thread.daemon = True
    threads.append(syslog_thread)
    syslog_thread.start()

    # Web Activity
    web_thread = threading.Thread(target=report_web_activity, args=(user_id, username))
    web_thread.daemon = True
    threads.append(web_thread)
    web_thread.start()

    # Network Activity
    network_thread = threading.Thread(target=report_network_activity, args=(user_id, username))
    network_thread.daemon = True
    threads.append(network_thread)
    network_thread.start()

    # File Sync
    file_thread = threading.Thread(target=sync_shared_files, args=(user_id, username))
    file_thread.daemon = True
    threads.append(file_thread)
    file_thread.start()

    # Location Reporting
    location_thread = threading.Thread(target=report_location, args=(user_id, username))
    location_thread.daemon = True
    threads.append(location_thread)
    location_thread.start()

    # Start GUI
    root = tk.Tk()
    FileSharingGUI(root, user_id, username)
    root.mainloop()

if __name__ == "__main__":
    main()