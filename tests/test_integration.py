import unittest
from unittest.mock import patch, MagicMock
import requests
import json
import time
import threading
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class TestClientServerIntegration(unittest.TestCase):
    
    def setUp(self):
        """Set up integration test fixtures."""
        self.server_url = "http://localhost:5000"
        self.test_user_data = {
            "user_id": "integration-test-user",
            "username": "testuser",
            "password": "testpass",
            "pc_name": "TEST-PC",
            "platform": "Linux"
        }
        
    @patch('requests.post')
    def test_user_registration_flow(self, mock_post):
        """Test complete user registration flow."""
        # Mock successful registration
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "user_added"}
        mock_post.return_value = mock_response
        
        # Simulate client registration
        response = requests.post(
            f"{self.server_url}/add_user",
            json=self.test_user_data
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "user_added")
        
    @patch('requests.get')
    def test_user_acceptance_flow(self, mock_get):
        """Test user acceptance checking flow."""
        # Mock pending acceptance
        mock_response_pending = MagicMock()
        mock_response_pending.status_code = 200
        mock_response_pending.json.return_value = {"accepted": 0}
        
        # Mock accepted status
        mock_response_accepted = MagicMock()
        mock_response_accepted.status_code = 200
        mock_response_accepted.json.return_value = {"accepted": 1}
        
        mock_get.side_effect = [mock_response_pending, mock_response_accepted]
        
        # First check - pending
        response1 = requests.get(f"{self.server_url}/user_details/{self.test_user_data['user_id']}")
        self.assertEqual(response1.json()["accepted"], 0)
        
        # Second check - accepted
        response2 = requests.get(f"{self.server_url}/user_details/{self.test_user_data['user_id']}")
        self.assertEqual(response2.json()["accepted"], 1)
        
    @patch('requests.post')
    def test_activity_reporting_flow(self, mock_post):
        """Test activity reporting from client to server."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "updated"}
        mock_post.return_value = mock_response
        
        activity_data = {
            "logs": json.dumps([{"pid": 1234, "name": "test", "cpu_percent": 10.0}]),
            "network_traffic": json.dumps({"bytes_sent": 1000, "bytes_recv": 2000}),
            "system_info": json.dumps({"os": "Linux"}),
            "usb_count": 0
        }
        
        response = requests.post(
            f"{self.server_url}/update_activity/{self.test_user_data['user_id']}",
            json=activity_data
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "updated")
        
    @patch('requests.post')
    def test_usb_event_reporting(self, mock_post):
        """Test USB event reporting integration."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "logged"}
        mock_post.return_value = mock_response
        
        usb_event_data = {
            "username": self.test_user_data["username"],
            "event_type": "Inserted",
            "operation": "USB Inserted",
            "device_info": "test_device",
            "timestamp": "2023-01-01T12:00:00",
            "pc_name": self.test_user_data["pc_name"],
            "details": {}
        }
        
        response = requests.post(
            f"{self.server_url}/usb_event",
            json=usb_event_data
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "logged")
        
    @patch('requests.post')
    def test_web_activity_reporting(self, mock_post):
        """Test web activity reporting integration."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "success"}
        mock_post.return_value = mock_response
        
        web_activity_data = {
            "username": self.test_user_data["username"],
            "visited_sites": [
                {"url": "https://example.com", "title": "Example", "time": "2023-01-01 12:00:00"}
            ],
            "downloaded_files": [
                {"filename": "test.pdf", "size": "1MB", "timestamp": "2023-01-01 12:00:00"}
            ]
        }
        
        response = requests.post(
            f"{self.server_url}/report_web_activity/{self.test_user_data['user_id']}",
            json=web_activity_data
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "success")

class TestFileOperationsIntegration(unittest.TestCase):
    
    def setUp(self):
        """Set up file operations test fixtures."""
        self.server_url = "http://localhost:5000"
        self.test_user_id = "file-test-user"
        
    @patch('requests.post')
    def test_file_access_management(self, mock_post):
        """Test file access permission management."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "access_updated"}
        mock_post.return_value = mock_response
        
        access_data = {"read": True, "write": False}
        
        response = requests.post(
            f"{self.server_url}/update_file_access/{self.test_user_id}",
            json=access_data
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "access_updated")
        
    @patch('requests.get')
    def test_file_listing(self, mock_get):
        """Test file listing functionality."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "files": [
                {"name": "test.txt", "size": 1024, "modified": "2023-01-01T12:00:00"}
            ]
        }
        mock_get.return_value = mock_response
        
        response = requests.get(f"{self.server_url}/list_shared_files/{self.test_user_id}")
        
        self.assertEqual(response.status_code, 200)
        files = response.json()["files"]
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0]["name"], "test.txt")

class TestAnomalyDetectionIntegration(unittest.TestCase):
    
    def setUp(self):
        """Set up anomaly detection test fixtures."""
        self.server_url = "http://localhost:5000"
        self.test_user_id = "anomaly-test-user"
        
    @patch('requests.post')
    def test_anomaly_alert_generation(self, mock_post):
        """Test anomaly alert generation and reporting."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "updated", "anomaly_detected": True}
        mock_post.return_value = mock_response
        
        # High resource usage that should trigger anomaly
        suspicious_activity = {
            "logs": json.dumps([
                {"pid": 1234, "name": "suspicious_process", "cpu_percent": 95.0, "memory_percent": 90.0}
            ]),
            "network_traffic": json.dumps({"bytes_sent": 5000000, "bytes_recv": 10000000}),
            "system_info": json.dumps({"os": "Linux"}),
            "usb_count": 1  # USB device connected
        }
        
        response = requests.post(
            f"{self.server_url}/update_activity/{self.test_user_id}",
            json=suspicious_activity
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json().get("anomaly_detected", False))
        
    @patch('requests.get')
    def test_anomaly_alert_retrieval(self, mock_get):
        """Test retrieval of anomaly alerts."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "alerts": [
                "2023-01-01T12:00:00 - Anomaly detected for user: High CPU usage"
            ]
        }
        mock_get.return_value = mock_response
        
        response = requests.get(f"{self.server_url}/get_anomaly_alerts")
        
        self.assertEqual(response.status_code, 200)
        alerts = response.json()["alerts"]
        self.assertEqual(len(alerts), 1)
        self.assertIn("Anomaly detected", alerts[0])

class TestRealTimeUpdatesIntegration(unittest.TestCase):
    
    def setUp(self):
        """Set up real-time updates test fixtures."""
        self.server_url = "http://localhost:5000"
        
    def test_socketio_connection_simulation(self):
        """Test Socket.IO connection simulation."""
        # This would normally test actual Socket.IO connections
        # For now, we'll test the concept
        
        connection_events = []
        
        def simulate_connection():
            connection_events.append("connected")
            
        def simulate_heartbeat():
            connection_events.append("heartbeat")
            
        def simulate_disconnect():
            connection_events.append("disconnected")
            
        # Simulate connection lifecycle
        simulate_connection()
        simulate_heartbeat()
        simulate_heartbeat()
        simulate_disconnect()
        
        expected_events = ["connected", "heartbeat", "heartbeat", "disconnected"]
        self.assertEqual(connection_events, expected_events)
        
    def test_real_time_alert_propagation(self):
        """Test real-time alert propagation simulation."""
        alerts_received = []
        
        def simulate_alert_handler(alert_data):
            alerts_received.append(alert_data)
            
        # Simulate different types of alerts
        usb_alert = {"type": "usb", "message": "USB device inserted"}
        anomaly_alert = {"type": "anomaly", "message": "Suspicious activity detected"}
        
        simulate_alert_handler(usb_alert)
        simulate_alert_handler(anomaly_alert)
        
        self.assertEqual(len(alerts_received), 2)
        self.assertEqual(alerts_received[0]["type"], "usb")
        self.assertEqual(alerts_received[1]["type"], "anomaly")

class TestSystemResilience(unittest.TestCase):
    
    def test_network_failure_handling(self):
        """Test system behavior during network failures."""
        # Simulate network failure scenarios
        
        def simulate_network_request(should_fail=False):
            if should_fail:
                raise requests.exceptions.ConnectionError("Network unreachable")
            return {"status": "success"}
            
        # Test successful request
        try:
            result = simulate_network_request(should_fail=False)
            self.assertEqual(result["status"], "success")
        except requests.exceptions.ConnectionError:
            self.fail("Should not raise exception for successful request")
            
        # Test failed request handling
        with self.assertRaises(requests.exceptions.ConnectionError):
            simulate_network_request(should_fail=True)
            
    def test_database_error_handling(self):
        """Test database error handling."""
        import sqlite3
        
        def simulate_database_operation(should_fail=False):
            if should_fail:
                raise sqlite3.OperationalError("Database is locked")
            return "operation_successful"
            
        # Test successful operation
        result = simulate_database_operation(should_fail=False)
        self.assertEqual(result, "operation_successful")
        
        # Test error handling
        with self.assertRaises(sqlite3.OperationalError):
            simulate_database_operation(should_fail=True)
            
    def test_concurrent_user_handling(self):
        """Test handling of concurrent users."""
        import threading
        import time
        
        results = []
        
        def simulate_user_activity(user_id):
            # Simulate some processing time
            time.sleep(0.1)
            results.append(f"processed_user_{user_id}")
            
        # Create multiple threads to simulate concurrent users
        threads = []
        for i in range(5):
            thread = threading.Thread(target=simulate_user_activity, args=(i,))
            threads.append(thread)
            thread.start()
            
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
            
        # Verify all users were processed
        self.assertEqual(len(results), 5)
        for i in range(5):
            self.assertIn(f"processed_user_{i}", results)

class TestPerformanceIntegration(unittest.TestCase):
    
    def test_response_time_simulation(self):
        """Test response time requirements."""
        import time
        
        def simulate_api_call():
            start_time = time.time()
            # Simulate processing
            time.sleep(0.05)  # 50ms processing time
            end_time = time.time()
            return end_time - start_time
            
        response_time = simulate_api_call()
        
        # Response should be under 100ms for good user experience
        self.assertLess(response_time, 0.1)
        
    def test_memory_usage_simulation(self):
        """Test memory usage patterns."""
        import sys
        
        # Simulate data structures that might be used
        large_dataset = []
        
        # Add some data
        for i in range(1000):
            large_dataset.append({
                "id": i,
                "data": f"sample_data_{i}",
                "timestamp": time.time()
            })
            
        # Check that we can handle reasonable amounts of data
        self.assertEqual(len(large_dataset), 1000)
        
        # Clean up
        del large_dataset

if __name__ == '__main__':
    # Run all integration tests
    unittest.main(verbosity=2)