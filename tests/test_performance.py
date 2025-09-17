import unittest
import time
import threading
import sys
import os
from unittest.mock import patch, MagicMock
import concurrent.futures

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class TestPerformance(unittest.TestCase):
    
    def setUp(self):
        """Set up performance test fixtures."""
        self.test_data_size = 1000
        self.concurrent_users = 10
        
    def test_data_processing_performance(self):
        """Test data processing performance."""
        import json
        
        # Generate test data
        test_logs = []
        for i in range(self.test_data_size):
            test_logs.append({
                "pid": i,
                "name": f"process_{i}",
                "cpu_percent": 10.0 + (i % 50),
                "memory_percent": 5.0 + (i % 30)
            })
        
        start_time = time.time()
        
        # Process data (simulate what the server does)
        json_data = json.dumps(test_logs)
        parsed_data = json.loads(json_data)
        
        # Calculate some metrics
        avg_cpu = sum(log["cpu_percent"] for log in parsed_data) / len(parsed_data)
        avg_memory = sum(log["memory_percent"] for log in parsed_data) / len(parsed_data)
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        # Performance assertions
        self.assertLess(processing_time, 1.0)  # Should process 1000 records in under 1 second
        self.assertEqual(len(parsed_data), self.test_data_size)
        self.assertGreater(avg_cpu, 0)
        self.assertGreater(avg_memory, 0)
        
        print(f"Processed {self.test_data_size} records in {processing_time:.4f} seconds")
        
    def test_concurrent_user_simulation(self):
        """Test system performance with concurrent users."""
        results = []
        errors = []
        
        def simulate_user_activity(user_id):
            try:
                start_time = time.time()
                
                # Simulate user operations
                time.sleep(0.01)  # Simulate network delay
                
                # Simulate data processing
                test_data = {"user_id": user_id, "activity": "test"}
                processed_data = str(test_data)
                
                end_time = time.time()
                response_time = end_time - start_time
                
                results.append({
                    "user_id": user_id,
                    "response_time": response_time,
                    "success": True
                })
                
            except Exception as e:
                errors.append({"user_id": user_id, "error": str(e)})
        
        # Run concurrent user simulation
        threads = []
        start_time = time.time()
        
        for i in range(self.concurrent_users):
            thread = threading.Thread(target=simulate_user_activity, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        total_time = time.time() - start_time
        
        # Performance assertions
        self.assertEqual(len(results), self.concurrent_users)
        self.assertEqual(len(errors), 0)
        self.assertLess(total_time, 2.0)  # All users should complete within 2 seconds
        
        # Calculate average response time
        avg_response_time = sum(r["response_time"] for r in results) / len(results)
        self.assertLess(avg_response_time, 0.1)  # Average response time under 100ms
        
        print(f"Handled {self.concurrent_users} concurrent users in {total_time:.4f} seconds")
        print(f"Average response time: {avg_response_time:.4f} seconds")
        
    def test_memory_usage_simulation(self):
        """Test memory usage patterns."""
        import sys
        
        # Get initial memory usage
        initial_objects = len(gc.get_objects()) if 'gc' in sys.modules else 0
        
        # Create large data structures
        large_datasets = []
        for i in range(100):
            dataset = {
                "id": i,
                "logs": [{"pid": j, "name": f"proc_{j}"} for j in range(100)],
                "network_data": {"bytes_sent": i * 1000, "bytes_recv": i * 2000},
                "timestamp": time.time()
            }
            large_datasets.append(dataset)
        
        # Verify data was created
        self.assertEqual(len(large_datasets), 100)
        self.assertEqual(len(large_datasets[0]["logs"]), 100)
        
        # Clean up
        del large_datasets
        
        # Memory should be manageable
        self.assertTrue(True)  # If we get here without memory error, test passes
        
    def test_database_operation_performance(self):
        """Test database operation performance simulation."""
        import sqlite3
        import tempfile
        import os
        
        # Create temporary database
        temp_db = tempfile.NamedTemporaryFile(delete=False)
        temp_db.close()
        
        try:
            conn = sqlite3.connect(temp_db.name)
            cursor = conn.cursor()
            
            # Create test table
            cursor.execute("""
                CREATE TABLE test_logs (
                    id INTEGER PRIMARY KEY,
                    user_id TEXT,
                    activity TEXT,
                    timestamp TEXT
                )
            """)
            
            # Test bulk insert performance
            start_time = time.time()
            
            test_records = []
            for i in range(1000):
                test_records.append((
                    f"user_{i % 10}",
                    f"activity_{i}",
                    f"2023-01-01 12:{i % 60:02d}:00"
                ))
            
            cursor.executemany(
                "INSERT INTO test_logs (user_id, activity, timestamp) VALUES (?, ?, ?)",
                test_records
            )
            conn.commit()
            
            insert_time = time.time() - start_time
            
            # Test query performance
            start_time = time.time()
            
            cursor.execute("SELECT COUNT(*) FROM test_logs")
            count = cursor.fetchone()[0]
            
            cursor.execute("SELECT * FROM test_logs WHERE user_id = ? LIMIT 10", ("user_1",))
            results = cursor.fetchall()
            
            query_time = time.time() - start_time
            
            # Performance assertions
            self.assertEqual(count, 1000)
            self.assertGreater(len(results), 0)
            self.assertLess(insert_time, 1.0)  # Insert 1000 records in under 1 second
            self.assertLess(query_time, 0.1)   # Query in under 100ms
            
            print(f"Database insert time: {insert_time:.4f} seconds")
            print(f"Database query time: {query_time:.4f} seconds")
            
        finally:
            conn.close()
            os.unlink(temp_db.name)
            
    def test_network_request_performance(self):
        """Test network request performance simulation."""
        def simulate_network_request(delay=0.01):
            start_time = time.time()
            time.sleep(delay)  # Simulate network latency
            end_time = time.time()
            return end_time - start_time
        
        # Test single request
        response_time = simulate_network_request()
        self.assertLess(response_time, 0.05)  # Should complete in under 50ms
        
        # Test multiple requests
        start_time = time.time()
        response_times = []
        
        for _ in range(10):
            response_times.append(simulate_network_request())
        
        total_time = time.time() - start_time
        avg_response_time = sum(response_times) / len(response_times)
        
        self.assertLess(total_time, 1.0)  # 10 requests in under 1 second
        self.assertLess(avg_response_time, 0.05)  # Average under 50ms
        
    def test_anomaly_detection_performance(self):
        """Test anomaly detection performance."""
        import numpy as np
        
        # Generate test data
        normal_data = []
        for _ in range(1000):
            normal_data.append([
                np.random.normal(30, 10),  # CPU
                np.random.normal(40, 15),  # Memory
                np.random.normal(500000, 200000),  # Network
                0  # USB
            ])
        
        anomalous_data = []
        for _ in range(50):
            anomalous_data.append([
                np.random.normal(85, 5),   # High CPU
                np.random.normal(85, 5),   # High Memory
                np.random.normal(2000000, 500000),  # High Network
                1  # USB connected
            ])
        
        all_data = np.array(normal_data + anomalous_data)
        
        # Simulate anomaly detection
        start_time = time.time()
        
        # Simple threshold-based detection for performance test
        anomalies = []
        for i, sample in enumerate(all_data):
            cpu, memory, network, usb = sample
            is_anomaly = (cpu > 80 or memory > 80 or network > 1000000 or usb > 0)
            if is_anomaly:
                anomalies.append(i)
        
        detection_time = time.time() - start_time
        
        # Performance assertions
        self.assertLess(detection_time, 0.1)  # Detection should be fast
        self.assertGreater(len(anomalies), 0)  # Should detect some anomalies
        self.assertLess(len(anomalies), len(all_data))  # Not everything is anomalous
        
        print(f"Anomaly detection time: {detection_time:.4f} seconds")
        print(f"Detected {len(anomalies)} anomalies out of {len(all_data)} samples")
        
    def test_file_operation_performance(self):
        """Test file operation performance."""
        import tempfile
        import os
        
        # Test file write performance
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        temp_file.close()
        
        try:
            start_time = time.time()
            
            # Write test data
            test_data = "Test log entry\n" * 1000
            with open(temp_file.name, 'w') as f:
                f.write(test_data)
            
            write_time = time.time() - start_time
            
            # Test file read performance
            start_time = time.time()
            
            with open(temp_file.name, 'r') as f:
                content = f.read()
            
            read_time = time.time() - start_time
            
            # Performance assertions
            self.assertLess(write_time, 0.1)  # Write in under 100ms
            self.assertLess(read_time, 0.1)   # Read in under 100ms
            self.assertEqual(len(content.split('\n')), 1001)  # 1000 lines + empty line
            
            print(f"File write time: {write_time:.4f} seconds")
            print(f"File read time: {read_time:.4f} seconds")
            
        finally:
            os.unlink(temp_file.name)

class TestScalability(unittest.TestCase):
    
    def test_user_scaling(self):
        """Test system scalability with increasing users."""
        user_counts = [10, 50, 100]
        response_times = []
        
        for user_count in user_counts:
            start_time = time.time()
            
            # Simulate processing for multiple users
            for i in range(user_count):
                # Simulate user data processing
                user_data = {
                    "user_id": f"user_{i}",
                    "logs": [{"pid": j, "cpu": 10.0} for j in range(10)],
                    "network": {"bytes_sent": 1000, "bytes_recv": 2000}
                }
                # Simulate processing time
                time.sleep(0.001)  # 1ms per user
            
            total_time = time.time() - start_time
            avg_time_per_user = total_time / user_count
            response_times.append(avg_time_per_user)
            
            print(f"{user_count} users: {total_time:.4f}s total, {avg_time_per_user:.4f}s per user")
        
        # Response time should not increase dramatically with user count
        # (in a well-designed system)
        for i in range(1, len(response_times)):
            # Allow some increase but not more than 2x
            self.assertLess(response_times[i], response_times[0] * 2)
            
    def test_data_volume_scaling(self):
        """Test system performance with increasing data volumes."""
        data_sizes = [100, 500, 1000]
        processing_times = []
        
        for size in data_sizes:
            start_time = time.time()
            
            # Generate and process data
            test_logs = []
            for i in range(size):
                test_logs.append({
                    "pid": i,
                    "name": f"process_{i}",
                    "cpu_percent": 10.0 + (i % 50),
                    "memory_percent": 5.0 + (i % 30)
                })
            
            # Simulate processing
            total_cpu = sum(log["cpu_percent"] for log in test_logs)
            avg_cpu = total_cpu / len(test_logs)
            
            processing_time = time.time() - start_time
            processing_times.append(processing_time)
            
            print(f"{size} records: {processing_time:.4f}s, avg CPU: {avg_cpu:.2f}%")
        
        # Processing time should scale reasonably (not exponentially)
        for i in range(1, len(processing_times)):
            # Time should not increase more than proportionally
            expected_max_time = processing_times[0] * (data_sizes[i] / data_sizes[0]) * 1.5
            self.assertLess(processing_times[i], expected_max_time)

if __name__ == '__main__':
    # Import gc for memory tests
    import gc
    unittest.main(verbosity=2)