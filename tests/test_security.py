import unittest
from unittest.mock import patch, MagicMock
import hashlib
import base64
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class TestSecurityFeatures(unittest.TestCase):
    
    def setUp(self):
        """Set up security test fixtures."""
        self.test_password = "testpassword123"
        self.test_admin_password = "p@ssw0rd"
        
    def test_password_validation(self):
        """Test password validation security."""
        # Test strong password
        strong_password = "StrongP@ssw0rd123!"
        self.assertTrue(len(strong_password) >= 8)
        self.assertTrue(any(c.isupper() for c in strong_password))
        self.assertTrue(any(c.islower() for c in strong_password))
        self.assertTrue(any(c.isdigit() for c in strong_password))
        self.assertTrue(any(c in "!@#$%^&*" for c in strong_password))
        
        # Test weak password
        weak_password = "123456"
        self.assertFalse(len(weak_password) >= 8)
        
    def test_admin_password_protection(self):
        """Test admin password protection."""
        # Simulate admin password check
        def check_admin_password(provided_password, stored_password):
            return provided_password == stored_password
            
        # Test correct password
        self.assertTrue(check_admin_password(self.test_admin_password, self.test_admin_password))
        
        # Test incorrect password
        self.assertFalse(check_admin_password("wrongpassword", self.test_admin_password))
        
    def test_sql_injection_prevention(self):
        """Test SQL injection prevention."""
        # Simulate parameterized query (safe)
        def safe_query(user_id):
            # This represents a parameterized query
            query = "SELECT * FROM users WHERE user_id = ?"
            params = (user_id,)
            return {"query": query, "params": params}
            
        # Test normal input
        result = safe_query("user123")
        self.assertEqual(result["params"], ("user123",))
        
        # Test malicious input (should be safely parameterized)
        malicious_input = "'; DROP TABLE users; --"
        result = safe_query(malicious_input)
        self.assertEqual(result["params"], (malicious_input,))
        
    def test_input_sanitization(self):
        """Test input sanitization."""
        def sanitize_input(user_input):
            # Remove potentially dangerous characters
            dangerous_chars = ["<", ">", "&", "\"", "'", ";"]
            sanitized = user_input
            for char in dangerous_chars:
                sanitized = sanitized.replace(char, "")
            return sanitized
            
        # Test XSS attempt
        xss_input = "<script>alert('XSS')</script>"
        sanitized = sanitize_input(xss_input)
        self.assertNotIn("<script>", sanitized)
        self.assertNotIn("</script>", sanitized)
        
    def test_session_management(self):
        """Test session management security."""
        import uuid
        import time
        
        class SessionManager:
            def __init__(self):
                self.sessions = {}
                self.session_timeout = 3600  # 1 hour
                
            def create_session(self, user_id):
                session_id = str(uuid.uuid4())
                self.sessions[session_id] = {
                    "user_id": user_id,
                    "created_at": time.time(),
                    "last_activity": time.time()
                }
                return session_id
                
            def validate_session(self, session_id):
                if session_id not in self.sessions:
                    return False
                    
                session = self.sessions[session_id]
                current_time = time.time()
                
                # Check if session has expired
                if current_time - session["last_activity"] > self.session_timeout:
                    del self.sessions[session_id]
                    return False
                    
                # Update last activity
                session["last_activity"] = current_time
                return True
                
        session_manager = SessionManager()
        
        # Test session creation
        session_id = session_manager.create_session("user123")
        self.assertIsNotNone(session_id)
        self.assertTrue(session_manager.validate_session(session_id))
        
        # Test invalid session
        self.assertFalse(session_manager.validate_session("invalid_session"))
        
    def test_data_encryption_simulation(self):
        """Test data encryption simulation."""
        def simple_encrypt(data, key):
            # Simple XOR encryption for testing
            encrypted = ""
            for i, char in enumerate(data):
                encrypted += chr(ord(char) ^ ord(key[i % len(key)]))
            return base64.b64encode(encrypted.encode()).decode()
            
        def simple_decrypt(encrypted_data, key):
            # Simple XOR decryption for testing
            encrypted = base64.b64decode(encrypted_data.encode()).decode()
            decrypted = ""
            for i, char in enumerate(encrypted):
                decrypted += chr(ord(char) ^ ord(key[i % len(key)]))
            return decrypted
            
        original_data = "sensitive_information"
        encryption_key = "secret_key"
        
        # Test encryption
        encrypted = simple_encrypt(original_data, encryption_key)
        self.assertNotEqual(encrypted, original_data)
        
        # Test decryption
        decrypted = simple_decrypt(encrypted, encryption_key)
        self.assertEqual(decrypted, original_data)
        
    def test_access_control(self):
        """Test access control mechanisms."""
        class AccessControl:
            def __init__(self):
                self.user_permissions = {
                    "admin": ["read", "write", "delete", "admin"],
                    "user": ["read", "write"],
                    "guest": ["read"]
                }
                
            def check_permission(self, user_role, required_permission):
                if user_role not in self.user_permissions:
                    return False
                return required_permission in self.user_permissions[user_role]
                
        access_control = AccessControl()
        
        # Test admin permissions
        self.assertTrue(access_control.check_permission("admin", "delete"))
        self.assertTrue(access_control.check_permission("admin", "admin"))
        
        # Test user permissions
        self.assertTrue(access_control.check_permission("user", "read"))
        self.assertTrue(access_control.check_permission("user", "write"))
        self.assertFalse(access_control.check_permission("user", "delete"))
        
        # Test guest permissions
        self.assertTrue(access_control.check_permission("guest", "read"))
        self.assertFalse(access_control.check_permission("guest", "write"))
        
    def test_rate_limiting(self):
        """Test rate limiting for API endpoints."""
        import time
        from collections import defaultdict
        
        class RateLimiter:
            def __init__(self, max_requests=10, time_window=60):
                self.max_requests = max_requests
                self.time_window = time_window
                self.requests = defaultdict(list)
                
            def is_allowed(self, client_id):
                current_time = time.time()
                client_requests = self.requests[client_id]
                
                # Remove old requests outside time window
                client_requests[:] = [req_time for req_time in client_requests 
                                    if current_time - req_time < self.time_window]
                
                # Check if under limit
                if len(client_requests) < self.max_requests:
                    client_requests.append(current_time)
                    return True
                    
                return False
                
        rate_limiter = RateLimiter(max_requests=3, time_window=60)
        
        # Test normal usage
        self.assertTrue(rate_limiter.is_allowed("client1"))
        self.assertTrue(rate_limiter.is_allowed("client1"))
        self.assertTrue(rate_limiter.is_allowed("client1"))
        
        # Test rate limit exceeded
        self.assertFalse(rate_limiter.is_allowed("client1"))
        
        # Test different client
        self.assertTrue(rate_limiter.is_allowed("client2"))
        
    def test_secure_file_operations(self):
        """Test secure file operations."""
        import os
        import tempfile
        
        def secure_file_path(filename):
            # Prevent directory traversal attacks
            filename = os.path.basename(filename)
            # Remove potentially dangerous characters
            safe_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_"
            safe_filename = "".join(c for c in filename if c in safe_chars)
            return safe_filename
            
        # Test normal filename
        normal_file = "document.pdf"
        self.assertEqual(secure_file_path(normal_file), "document.pdf")
        
        # Test directory traversal attempt
        malicious_file = "../../../etc/passwd"
        safe_file = secure_file_path(malicious_file)
        self.assertEqual(safe_file, "passwd")
        self.assertNotIn("..", safe_file)
        self.assertNotIn("/", safe_file)
        
    def test_logging_security(self):
        """Test secure logging practices."""
        import re
        
        def secure_log_message(message):
            # Remove sensitive information from logs
            sensitive_patterns = [
                r'password[=:]\s*\S+',
                r'token[=:]\s*\S+',
                r'key[=:]\s*\S+',
                r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'  # Credit card pattern
            ]
            
            sanitized_message = message
            for pattern in sensitive_patterns:
                sanitized_message = re.sub(pattern, '[REDACTED]', sanitized_message, flags=re.IGNORECASE)
                
            return sanitized_message
            
        # Test normal log message
        normal_log = "User logged in successfully"
        self.assertEqual(secure_log_message(normal_log), normal_log)
        
        # Test sensitive information removal
        sensitive_log = "Login attempt with password=secret123"
        sanitized = secure_log_message(sensitive_log)
        self.assertIn("[REDACTED]", sanitized)
        self.assertNotIn("secret123", sanitized)

class TestNetworkSecurity(unittest.TestCase):
    
    def test_https_enforcement(self):
        """Test HTTPS enforcement simulation."""
        def is_secure_url(url):
            return url.startswith("https://")
            
        # Test secure URL
        secure_url = "https://example.com/api"
        self.assertTrue(is_secure_url(secure_url))
        
        # Test insecure URL
        insecure_url = "http://example.com/api"
        self.assertFalse(is_secure_url(insecure_url))
        
    def test_cors_configuration(self):
        """Test CORS configuration."""
        allowed_origins = [
            "https://trusted-domain.com",
            "https://another-trusted.com"
        ]
        
        def is_origin_allowed(origin):
            return origin in allowed_origins
            
        # Test allowed origin
        self.assertTrue(is_origin_allowed("https://trusted-domain.com"))
        
        # Test disallowed origin
        self.assertFalse(is_origin_allowed("https://malicious-site.com"))
        
    def test_request_validation(self):
        """Test request validation."""
        def validate_request_size(content_length, max_size=1024*1024):  # 1MB
            return content_length <= max_size
            
        def validate_content_type(content_type, allowed_types):
            return content_type in allowed_types
            
        # Test valid request size
        self.assertTrue(validate_request_size(1024))  # 1KB
        
        # Test oversized request
        self.assertFalse(validate_request_size(2*1024*1024))  # 2MB
        
        # Test valid content type
        allowed_types = ["application/json", "multipart/form-data"]
        self.assertTrue(validate_content_type("application/json", allowed_types))
        
        # Test invalid content type
        self.assertFalse(validate_content_type("text/html", allowed_types))

class TestDataProtection(unittest.TestCase):
    
    def test_pii_detection(self):
        """Test PII (Personally Identifiable Information) detection."""
        import re
        
        def detect_pii(text):
            pii_patterns = {
                'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
                'ssn': r'\b\d{3}-\d{2}-\d{4}\b'
            }
            
            detected_pii = {}
            for pii_type, pattern in pii_patterns.items():
                matches = re.findall(pattern, text)
                if matches:
                    detected_pii[pii_type] = matches
                    
            return detected_pii
            
        # Test text with PII
        text_with_pii = "Contact John at john.doe@example.com or call 555-123-4567"
        pii_found = detect_pii(text_with_pii)
        
        self.assertIn('email', pii_found)
        self.assertIn('phone', pii_found)
        self.assertEqual(pii_found['email'][0], 'john.doe@example.com')
        
        # Test text without PII
        text_without_pii = "This is a normal message without sensitive information"
        pii_found = detect_pii(text_without_pii)
        self.assertEqual(len(pii_found), 0)
        
    def test_data_anonymization(self):
        """Test data anonymization techniques."""
        import hashlib
        
        def anonymize_user_id(user_id, salt="random_salt"):
            # Hash the user ID with salt for anonymization
            return hashlib.sha256((user_id + salt).encode()).hexdigest()[:16]
            
        def mask_sensitive_data(data, mask_char="*"):
            # Mask all but first and last 2 characters
            if len(data) <= 4:
                return mask_char * len(data)
            return data[:2] + mask_char * (len(data) - 4) + data[-2:]
            
        # Test user ID anonymization
        original_id = "user123"
        anonymized_id = anonymize_user_id(original_id)
        
        self.assertNotEqual(original_id, anonymized_id)
        self.assertEqual(len(anonymized_id), 16)
        
        # Test consistent anonymization
        self.assertEqual(anonymize_user_id(original_id), anonymize_user_id(original_id))
        
        # Test data masking
        sensitive_data = "1234567890"
        masked_data = mask_sensitive_data(sensitive_data)
        
        self.assertEqual(masked_data, "12******90")
        self.assertNotEqual(sensitive_data, masked_data)

if __name__ == '__main__':
    unittest.main(verbosity=2)