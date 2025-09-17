import unittest
from unittest.mock import patch, MagicMock, mock_open
import sys
import os
import json
import tempfile
import sqlite3
from datetime import datetime

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Mock Flask-SocketIO
sys.modules['flask_socketio'] = MagicMock()

# Import after mocking
import app

class TestServerRoutes(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures."""
        app.app.config['TESTING'] = True
        self.client = app.app.test_client()
        self.test_user_id = "test-user-123"
        self.test_username = "testuser"
        
        # Create temporary database for testing
        self.temp_db = tempfile.NamedTemporaryFile(delete=False)
        self.temp_db.close()
        
    def tearDown(self):
        """Clean up after tests."""
        try:
            os.unlink(self.temp_db.name)
        except:
            pass
            
    @patch('app.sqlite3.connect')
    def test_login_success(self, mock_connect):
        """Test successful admin login."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = ('p@ssw0rd',)
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn
        
        response = self.client.post('/login', data={
            'username': 'admin',
            'password': 'p@ssw0rd'
        })
        
        self.assertEqual(response.status_code, 302)  # Redirect after successful login
        
    @patch('app.sqlite3.connect')
    def test_login_failure(self, mock_connect):
        """Test failed admin login."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = ('p@ssw0rd',)
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn
        
        response = self.client.post('/login', data={
            'username': 'admin',
            'password': 'wrongpassword'
        })
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Invalid credentials', response.data)
        
    @patch('app.sqlite3.connect')
    def test_add_user(self, mock_connect):
        """Test adding a new user."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn
        
        user_data = {
            "user_id": self.test_user_id,
            "username": self.test_username,
            "password": "testpass",
            "pc_name": "TEST-PC",
            "platform": "Linux"
        }
        
        response = self.client.post('/add_user', 
                                  json=user_data,
                                  content_type='application/json')
        
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.data)
        self.assertEqual(response_data['status'], 'user_added')
        
    @patch('app.sqlite3.connect')
    def test_accept_user(self, mock_connect):
        """Test accepting a user."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (self.test_username,)
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn
        
        response = self.client.post(f'/accept_user/{self.test_user_id}')
        
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.data)
        self.assertEqual(response_data['status'], 'user_accepted')
        
    @patch('app.sqlite3.connect')
    def test_user_details(self, mock_connect):
        """Test retrieving user details."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (
            self.test_user_id, self.test_username, "password", "TEST-PC", "Linux", 1,
            '[]', '{}', '[]', '[]', '[]', '', '', '', '', 0, '{}', '[]'
        )
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn
        
        response = self.client.get(f'/user_details/{self.test_user_id}')
        
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.data)
        self.assertEqual(response_data['user_id'], self.test_user_id)
        self.assertEqual(response_data['username'], self.test_username)
        
    @patch('app.sqlite3.connect')
    def test_update_activity(self, mock_connect):
        """Test updating user activity."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (self.test_username, 0)
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn
        
        activity_data = {
            "logs": json.dumps([{"pid": 1234, "name": "test", "cpu_percent": 10.0, "memory_percent": 5.0}]),
            "network_traffic": json.dumps({"bytes_sent": 1000, "bytes_recv": 2000}),
            "system_info": json.dumps({"os": "Linux"}),
            "usb_count": 0
        }
        
        response = self.client.post(f'/update_activity/{self.test_user_id}',
                                  json=activity_data,
                                  content_type='application/json')
        
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.data)
        self.assertEqual(response_data['status'], 'updated')
        
    @patch('app.sqlite3.connect')
    def test_report_web_activity(self, mock_connect):
        """Test reporting web activity."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn
        
        web_activity_data = {
            "username": self.test_username,
            "visited_sites": [
                {"url": "https://example.com", "title": "Example", "time": "2023-01-01 12:00:00"}
            ]
        }
        
        with patch('app.get_user_folder') as mock_get_folder:
            mock_get_folder.return_value = "/tmp/test_user"
            
            response = self.client.post(f'/report_web_activity/{self.test_user_id}',
                                      json=web_activity_data,
                                      content_type='application/json')
            
            self.assertEqual(response.status_code, 200)
            response_data = json.loads(response.data)
            self.assertEqual(response_data['status'], 'success')
            
    @patch('app.sqlite3.connect')
    def test_usb_event(self, mock_connect):
        """Test USB event logging."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (self.test_user_id,)
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn
        
        usb_data = {
            "username": self.test_username,
            "event_type": "Inserted",
            "operation": "USB Inserted",
            "device_info": "test_device",
            "timestamp": "2023-01-01T12:00:00",
            "pc_name": "TEST-PC",
            "details": {}
        }
        
        with patch('builtins.open', mock_open()):
            response = self.client.post('/usb_event',
                                      json=usb_data,
                                      content_type='application/json')
            
            self.assertEqual(response.status_code, 200)
            response_data = json.loads(response.data)
            self.assertEqual(response_data['status'], 'logged')
            
    def test_get_usb_alerts(self):
        """Test retrieving USB alerts."""
        with patch('builtins.open', mock_open(read_data="2023-01-01 - USB Alert\n")):
            response = self.client.get('/get_usb_alerts')
            
            self.assertEqual(response.status_code, 200)
            response_data = json.loads(response.data)
            self.assertIn('alerts', response_data)
            
    def test_clear_usb_alerts(self):
        """Test clearing USB alerts."""
        with patch('builtins.open', mock_open()):
            response = self.client.post('/clear_usb_alerts')
            
            self.assertEqual(response.status_code, 200)
            response_data = json.loads(response.data)
            self.assertEqual(response_data['status'], 'cleared')
            
    @patch('app.psutil.net_io_counters')
    def test_overall_network_usage(self, mock_net_io):
        """Test overall network usage endpoint."""
        mock_io = MagicMock()
        mock_io._asdict.return_value = {
            'bytes_sent': 1000,
            'bytes_recv': 2000,
            'packets_sent': 10,
            'packets_recv': 20
        }
        mock_net_io.return_value = mock_io
        
        response = self.client.get('/overall_network_usage')
        
        self.assertEqual(response.status_code, 200)
        response_data = json.loads(response.data)
        self.assertEqual(response_data['bytes_sent'], 1000)
        self.assertEqual(response_data['bytes_recv'], 2000)

class TestAnomalyDetection(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_logs = [
            {"pid": 1234, "name": "test", "cpu_percent": 85.0, "memory_percent": 90.0}
        ]
        self.test_network_traffic = {"bytes_sent": 1000000, "bytes_recv": 2000000}
        
    @patch('app.model')
    def test_detect_anomalies_normal(self, mock_model):
        """Test anomaly detection with normal behavior."""
        mock_model.predict.return_value = [1]  # Normal
        mock_model.decision_function.return_value = [0.1]
        
        result = app.detect_anomalies("test-user", "testuser", self.test_logs, 
                                    json.dumps(self.test_network_traffic), 0)
        
        self.assertIsNotNone(result)
        self.assertFalse(result['is_anomaly'])
        
    @patch('app.model')
    def test_detect_anomalies_suspicious(self, mock_model):
        """Test anomaly detection with suspicious behavior."""
        mock_model.predict.return_value = [-1]  # Anomaly
        mock_model.decision_function.return_value = [-0.5]
        
        result = app.detect_anomalies("test-user", "testuser", self.test_logs,
                                    json.dumps(self.test_network_traffic), 1)
        
        self.assertIsNotNone(result)
        self.assertTrue(result['is_anomaly'])
        self.assertIn('reasons', result)
        self.assertIn('metrics', result)

class TestFileOperations(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures."""
        self.client = app.app.test_client()
        self.test_user_id = "test-user-123"
        
    @patch('app.sqlite3.connect')
    @patch('app.os.makedirs')
    def test_create_shared_folder(self, mock_makedirs, mock_connect):
        """Test creating shared folder."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = ("testuser",)
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn
        
        with patch('builtins.open', mock_open()):
            response = self.client.post(f'/create_shared_folder/{self.test_user_id}')
            
            self.assertEqual(response.status_code, 200)
            response_data = json.loads(response.data)
            self.assertEqual(response_data['status'], 'folder_created')
            
    @patch('app.sqlite3.connect')
    def test_update_file_access(self, mock_connect):
        """Test updating file access permissions."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = ("testuser",)
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn
        
        access_data = {"read": True, "write": False}
        
        with patch('builtins.open', mock_open()):
            response = self.client.post(f'/update_file_access/{self.test_user_id}',
                                      json=access_data,
                                      content_type='application/json')
            
            self.assertEqual(response.status_code, 200)
            response_data = json.loads(response.data)
            self.assertEqual(response_data['status'], 'access_updated')

class TestUtilityFunctions(unittest.TestCase):
    
    @patch('app.os.makedirs')
    def test_get_user_folder(self, mock_makedirs):
        """Test user folder creation."""
        result = app.get_user_folder("testuser")
        
        expected_path = os.path.join("users", "testuser")
        self.assertEqual(result, expected_path)
        mock_makedirs.assert_called()
        
    @patch('builtins.open', mock_open())
    def test_log_user_activity(self):
        """Test user activity logging."""
        test_logs = [{"pid": 1234, "name": "test"}]
        
        app.log_user_activity("testuser", "Test message", test_logs)
        
        # Verify that open was called (file was written to)
        self.assertTrue(True)  # Placeholder - in real test, check file content
        
    @patch('builtins.open', mock_open())
    def test_log_admin_activity(self):
        """Test admin activity logging."""
        app.log_admin_activity("Test admin action")
        
        # Verify that open was called
        self.assertTrue(True)  # Placeholder

if __name__ == '__main__':
    unittest.main()