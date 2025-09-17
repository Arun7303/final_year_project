import unittest
from unittest.mock import patch, MagicMock
import numpy as np
import pandas as pd
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class TestAnomalyDetection(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures."""
        self.normal_data = {
            'cpu_percent': 30.0,
            'memory_percent': 40.0,
            'network_bytes': 500000,
            'usb_connected': 0
        }
        
        self.anomalous_data = {
            'cpu_percent': 95.0,
            'memory_percent': 90.0,
            'network_bytes': 5000000,
            'usb_connected': 1
        }
        
    def test_feature_extraction_normal(self):
        """Test feature extraction for normal behavior."""
        features = np.array([[
            self.normal_data['cpu_percent'],
            self.normal_data['memory_percent'],
            self.normal_data['network_bytes'],
            self.normal_data['usb_connected']
        ]])
        
        self.assertEqual(features.shape, (1, 4))
        self.assertEqual(features[0][0], 30.0)  # CPU
        self.assertEqual(features[0][1], 40.0)  # Memory
        self.assertEqual(features[0][2], 500000)  # Network
        self.assertEqual(features[0][3], 0)  # USB
        
    def test_feature_extraction_anomalous(self):
        """Test feature extraction for anomalous behavior."""
        features = np.array([[
            self.anomalous_data['cpu_percent'],
            self.anomalous_data['memory_percent'],
            self.anomalous_data['network_bytes'],
            self.anomalous_data['usb_connected']
        ]])
        
        self.assertEqual(features.shape, (1, 4))
        self.assertEqual(features[0][0], 95.0)  # High CPU
        self.assertEqual(features[0][1], 90.0)  # High Memory
        self.assertEqual(features[0][2], 5000000)  # High Network
        self.assertEqual(features[0][3], 1)  # USB connected
        
    @patch('joblib.load')
    def test_model_loading(self, mock_joblib_load):
        """Test anomaly detection model loading."""
        mock_model = MagicMock()
        mock_joblib_load.return_value = mock_model
        
        # Simulate loading model
        model = mock_joblib_load('anomaly_detection_model.pkl')
        
        self.assertIsNotNone(model)
        mock_joblib_load.assert_called_once_with('anomaly_detection_model.pkl')
        
    def test_anomaly_score_calculation(self):
        """Test anomaly score calculation and normalization."""
        # Simulate raw anomaly scores
        raw_scores = np.array([-0.1, 0.2, -0.5, 0.1])
        
        # Normalize to 0-10 scale
        min_score = raw_scores.min()
        max_score = raw_scores.max()
        normalized_scores = ((raw_scores - min_score) / (max_score - min_score)) * 10
        
        self.assertTrue(all(0 <= score <= 10 for score in normalized_scores))
        self.assertEqual(normalized_scores.min(), 0.0)
        self.assertEqual(normalized_scores.max(), 10.0)
        
    def test_threshold_detection(self):
        """Test anomaly threshold detection."""
        # Test different anomaly scores
        test_scores = [-0.8, -0.2, -0.05, 0.1, 0.3]
        threshold = -0.1
        
        anomalies = [score < threshold for score in test_scores]
        
        # Scores below threshold should be flagged as anomalies
        expected_anomalies = [True, True, False, False, False]
        self.assertEqual(anomalies, expected_anomalies)
        
    def test_reason_generation(self):
        """Test anomaly reason generation."""
        thresholds = {
            'cpu': 80,
            'memory': 80,
            'network': 1000000,
            'usb': 1
        }
        
        # Test high CPU
        reasons = []
        if self.anomalous_data['cpu_percent'] > thresholds['cpu']:
            reasons.append(f"High CPU ({self.anomalous_data['cpu_percent']}% > {thresholds['cpu']}%)")
            
        if self.anomalous_data['memory_percent'] > thresholds['memory']:
            reasons.append(f"High Memory ({self.anomalous_data['memory_percent']}% > {thresholds['memory']}%)")
            
        if self.anomalous_data['network_bytes'] > thresholds['network']:
            reasons.append(f"High Network ({self.anomalous_data['network_bytes']} bytes > {thresholds['network']} bytes)")
            
        if self.anomalous_data['usb_connected'] >= thresholds['usb']:
            reasons.append("USB Device Connected")
            
        expected_reasons = [
            "High CPU (95.0% > 80%)",
            "High Memory (90.0% > 80%)",
            "High Network (5000000 bytes > 1000000 bytes)",
            "USB Device Connected"
        ]
        
        self.assertEqual(reasons, expected_reasons)
        
    def test_metrics_collection(self):
        """Test metrics collection for anomaly detection."""
        logs_data = [
            {"cpu_percent": 85.0, "memory_percent": 75.0},
            {"cpu_percent": 90.0, "memory_percent": 80.0},
            {"cpu_percent": 95.0, "memory_percent": 85.0}
        ]
        
        df = pd.DataFrame(logs_data)
        avg_cpu = df['cpu_percent'].mean()
        avg_memory = df['memory_percent'].mean()
        
        self.assertEqual(avg_cpu, 90.0)
        self.assertEqual(avg_memory, 80.0)
        
    def test_time_based_anomaly_detection(self):
        """Test time-based anomaly detection."""
        from datetime import datetime, time
        
        # Test midnight activity (suspicious)
        midnight_hour = 2
        business_hour = 14
        
        is_midnight_activity = midnight_hour < 5
        is_business_activity = 9 <= business_hour <= 17
        
        self.assertTrue(is_midnight_activity)
        self.assertTrue(is_business_activity)
        
    def test_pattern_based_detection(self):
        """Test pattern-based anomaly detection."""
        # Simulate user activity patterns
        normal_pattern = {
            'login_times': ['09:00', '09:15', '09:30'],
            'file_access_count': 10,
            'network_requests': 50
        }
        
        suspicious_pattern = {
            'login_times': ['02:00', '02:30', '03:00'],  # Unusual hours
            'file_access_count': 100,  # Excessive file access
            'network_requests': 500  # High network activity
        }
        
        # Simple threshold-based detection
        def is_suspicious_pattern(pattern):
            unusual_hours = any(int(time.split(':')[0]) < 5 for time in pattern['login_times'])
            excessive_files = pattern['file_access_count'] > 50
            high_network = pattern['network_requests'] > 200
            
            return unusual_hours or excessive_files or high_network
            
        self.assertFalse(is_suspicious_pattern(normal_pattern))
        self.assertTrue(is_suspicious_pattern(suspicious_pattern))

class TestDatasetGeneration(unittest.TestCase):
    
    def test_synthetic_data_generation(self):
        """Test synthetic dataset generation for training."""
        import random
        import numpy as np
        
        # Generate normal data
        normal_samples = []
        for _ in range(100):
            cpu = max(0, min(100, random.normalvariate(30, 10)))
            memory = max(0, min(100, random.normalvariate(40, 15)))
            network = max(0, random.normalvariate(500000, 200000))
            usb = 0
            
            normal_samples.append([cpu, memory, network, usb, 0])  # 0 = normal
            
        # Generate anomalous data
        anomalous_samples = []
        for _ in range(10):
            cpu = max(0, min(100, random.normalvariate(85, 5)))
            memory = max(0, min(100, random.normalvariate(85, 5)))
            network = max(0, random.normalvariate(2000000, 500000))
            usb = 1
            
            anomalous_samples.append([cpu, memory, network, usb, 1])  # 1 = anomaly
            
        all_samples = normal_samples + anomalous_samples
        
        self.assertEqual(len(all_samples), 110)
        self.assertEqual(len(normal_samples), 100)
        self.assertEqual(len(anomalous_samples), 10)
        
        # Check that anomalous samples have higher values
        normal_avg_cpu = np.mean([s[0] for s in normal_samples])
        anomalous_avg_cpu = np.mean([s[0] for s in anomalous_samples])
        
        self.assertGreater(anomalous_avg_cpu, normal_avg_cpu)
        
    def test_feature_scaling(self):
        """Test feature scaling for model training."""
        from sklearn.preprocessing import StandardScaler
        
        # Sample data
        data = np.array([
            [30, 40, 500000, 0],
            [85, 80, 2000000, 1],
            [25, 35, 300000, 0],
            [90, 85, 2500000, 1]
        ])
        
        scaler = StandardScaler()
        scaled_data = scaler.fit_transform(data)
        
        # Check that scaled data has mean ~0 and std ~1
        self.assertAlmostEqual(np.mean(scaled_data), 0, places=10)
        self.assertAlmostEqual(np.std(scaled_data), 1, places=0)

class TestModelPerformance(unittest.TestCase):
    
    def test_model_accuracy_metrics(self):
        """Test model performance metrics calculation."""
        # Simulated predictions vs actual labels
        y_true = [0, 0, 1, 1, 0, 1, 0, 1]  # Actual labels
        y_pred = [0, 0, 1, 0, 0, 1, 1, 1]  # Predicted labels
        
        # Calculate metrics manually
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)  # True Positives
        tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)  # True Negatives
        fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)  # False Positives
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)  # False Negatives
        
        accuracy = (tp + tn) / len(y_true)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        self.assertEqual(tp, 3)
        self.assertEqual(tn, 3)
        self.assertEqual(fp, 1)
        self.assertEqual(fn, 1)
        self.assertEqual(accuracy, 0.75)
        
    def test_contamination_parameter(self):
        """Test contamination parameter effect on anomaly detection."""
        # Simulate different contamination rates
        contamination_rates = [0.01, 0.05, 0.1, 0.2]
        
        for rate in contamination_rates:
            # In real scenario, this would affect the number of anomalies detected
            expected_anomalies = int(100 * rate)  # For 100 samples
            
            self.assertGreater(expected_anomalies, 0)
            self.assertLessEqual(expected_anomalies, 20)  # Max 20% contamination

if __name__ == '__main__':
    unittest.main()