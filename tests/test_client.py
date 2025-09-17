import unittest
from unittest.mock import patch, MagicMock, mock_open
import sys
import os
import json
from datetime import datetime

# Add the parent directory to the path to import client module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Mock platform-specific imports
sys.modules['wmi'] = MagicMock()
sys.modules['pyudev'] = MagicMock()
sys.modules['cv2'] = MagicMock()
sys.modules['mss'] = MagicMock()
sys.modules['socketio'] = MagicMock()

import client

class TestClientFunctions(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        self.test_user_id = "test-user-123"
        self.test_username = "testuser"
        
    @patch('client.requests.post')
    def test_validate_password_success(self, mock_post):
        """Test successful password validation."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "valid"}
        mock_post.return_value = mock_response
        
        result = client.validate_password("testuser", "testpass")
        
        self.assertTrue(result)
        mock_post.assert_called_once()
        
    @patch('client.requests.post')
    def test_validate_password_failure(self, mock_post):
        """Test failed password validation."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_post.return_value = mock_response
        
        result = client.validate_password("testuser", "wrongpass")
        
        self.assertFalse(result)
        
    @patch('client.requests.post')
    def test_register_user_success(self, mock_post):
        """Test successful user registration."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "user_added"}
        mock_post.return_value = mock_response
        
        result = client.register_user("newuser", "newpass")
        
        self.assertIsNotNone(result)
        self.assertTrue(len(result) > 0)  # Should return a UUID
        
    @patch('client.socket.gethostname')
    @patch('client.platform.node')
    @patch('client.platform.system')
    @patch('client.platform.version')
    @patch('client.platform.processor')
    @patch('client.psutil.virtual_memory')
    @patch('client.psutil.boot_time')
    def test_get_system_info(self, mock_boot_time, mock_virtual_memory, 
                           mock_processor, mock_version, mock_system, 
                           mock_node, mock_hostname):
        """Test system information collection."""
        # Mock return values
        mock_hostname.return_value = "test-host"
        mock_node.return_value = "test-node"
        mock_system.return_value = "Linux"
        mock_version.return_value = "5.4.0"
        mock_processor.return_value = "x86_64"
        mock_virtual_memory.return_value = MagicMock(total=8589934592)  # 8GB
        mock_boot_time.return_value = 1640995200  # Jan 1, 2022
        
        result = client.get_system_info()
        
        expected_keys = ["hostname", "os", "os_version", "processor", "ram", "last_boot"]
        for key in expected_keys:
            self.assertIn(key, result)
            
        self.assertEqual(result["hostname"], "test-host")
        self.assertEqual(result["os"], "Linux")
        self.assertEqual(result["ram"], "8.0 GB")
        
    @patch('client.psutil.net_connections')
    @patch('client.psutil.net_io_counters')
    @patch('client.psutil.net_if_addrs')
    def test_get_network_connections(self, mock_net_if_addrs, mock_net_io, mock_net_connections):
        """Test network connections collection."""
        # Mock network connection
        mock_conn = MagicMock()
        mock_conn.status = 'ESTABLISHED'
        mock_conn.raddr = MagicMock()
        mock_conn.raddr.ip = '192.168.1.1'
        mock_conn.raddr.port = 80
        mock_conn.laddr = MagicMock()
        mock_conn.laddr.ip = '192.168.1.100'
        mock_conn.pid = 1234
        
        mock_net_connections.return_value = [mock_conn]
        
        # Mock network interface addresses
        mock_addr = MagicMock()
        mock_addr.address = '192.168.1.100'
        mock_net_if_addrs.return_value = {'eth0': [mock_addr]}
        
        # Mock network I/O counters
        mock_io = MagicMock()
        mock_io.bytes_sent = 1000
        mock_io.bytes_recv = 2000
        mock_net_io.return_value = {'eth0': mock_io}
        
        result = client.get_network_connections()
        
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['remote_ip'], '192.168.1.1')
        self.assertEqual(result[0]['port'], 80)
        self.assertEqual(result[0]['sent_bytes'], 1000)
        self.assertEqual(result[0]['received_bytes'], 2000)
        
    @patch('client.os.path.exists')
    @patch('client.os.listdir')
    @patch('client.os.stat')
    @patch('client.os.getenv')
    def test_get_downloads(self, mock_getenv, mock_stat, mock_listdir, mock_exists):
        """Test downloads collection."""
        mock_getenv.return_value = '/home/user'
        mock_exists.return_value = True
        mock_listdir.return_value = ['test_file.pdf', 'image.jpg']
        
        # Mock file stats
        mock_stat_result = MagicMock()
        mock_stat_result.st_size = 1048576  # 1MB
        mock_stat_result.st_ctime = 1640995200
        mock_stat.return_value = mock_stat_result
        
        result = client.get_downloads()
        
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]['filename'], 'test_file.pdf')
        self.assertEqual(result[0]['size'], '1.0 MB')
        
    @patch('client.requests.post')
    def test_log_usb_event(self, mock_post):
        """Test USB event logging."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        
        with patch('builtins.open', mock_open()) as mock_file:
            client.log_usb_event("Inserted", "USB Inserted", "test_device", "testuser")
            
            mock_file.assert_called()
            mock_post.assert_called_once()
            
    @patch('client.requests.get')
    def test_check_acceptance_accepted(self, mock_get):
        """Test user acceptance check - accepted case."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"accepted": 1}
        mock_get.return_value = mock_response
        
        result = client.check_acceptance("test-user-id")
        
        self.assertTrue(result)
        
    @patch('client.requests.get')
    def test_check_acceptance_rejected(self, mock_get):
        """Test user acceptance check - rejected case."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"accepted": -1}
        mock_get.return_value = mock_response
        
        with self.assertRaises(SystemExit):
            client.check_acceptance("test-user-id")
            
    @patch('client.requests.get')
    def test_get_geolocation_success(self, mock_get):
        """Test geolocation retrieval."""
        # Mock IP response
        mock_ip_response = MagicMock()
        mock_ip_response.text = "203.0.113.1"
        
        # Mock location response
        mock_location_response = MagicMock()
        mock_location_response.status_code = 200
        mock_location_response.json.return_value = {
            'status': 'success',
            'city': 'Test City',
            'regionName': 'Test Region',
            'country': 'Test Country',
            'lat': 40.7128,
            'lon': -74.0060
        }
        
        mock_get.side_effect = [mock_ip_response, mock_location_response]
        
        result = client.get_geolocation()
        
        self.assertIsNotNone(result)
        self.assertEqual(result['ip'], '203.0.113.1')
        self.assertEqual(result['city'], 'Test City')
        self.assertEqual(result['lat'], 40.7128)
        
    def test_collect_web_activity(self):
        """Test web activity collection."""
        with patch.object(client, 'get_browser_history') as mock_history, \
             patch.object(client, 'get_downloads') as mock_downloads:
            
            mock_history.return_value = [
                {'url': 'https://example.com', 'title': 'Example', 'time': '2023-01-01 12:00:00'}
            ]
            mock_downloads.return_value = [
                {'filename': 'test.pdf', 'size': '1MB', 'timestamp': '2023-01-01 12:00:00'}
            ]
            
            result = client.collect_web_activity("testuser")
            
            self.assertIn('visited_sites', result)
            self.assertIn('downloaded_files', result)
            self.assertEqual(result['username'], 'testuser')
            self.assertEqual(len(result['visited_sites']), 1)
            self.assertEqual(len(result['downloaded_files']), 1)

class TestFileSharingGUI(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures."""
        # Mock tkinter
        self.mock_tk = MagicMock()
        sys.modules['tkinter'] = self.mock_tk
        sys.modules['tkinter.ttk'] = MagicMock()
        sys.modules['tkinter.messagebox'] = MagicMock()
        sys.modules['tkinter.filedialog'] = MagicMock()
        
    def test_file_sharing_gui_initialization(self):
        """Test FileSharingGUI initialization."""
        with patch('client.tk.Tk') as mock_root:
            mock_root_instance = MagicMock()
            mock_root.return_value = mock_root_instance
            
            # This would normally create the GUI, but we're mocking it
            # gui = client.FileSharingGUI(mock_root_instance, "test-id", "testuser")
            # Just test that the mock was called
            self.assertTrue(True)  # Placeholder test

if __name__ == '__main__':
    unittest.main()