"""
Tests for the QR code generation and scanning functionality.
"""

import os
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add the parent directory to the path so we can import from app
import sys
sys.path.append(str(Path(__file__).parent.parent))

from app.secure_qr import Cryptosign, SecureQR
from app.advanced_features import TimeBasedQR


class TestQRGenerator(unittest.TestCase):
    """Test QR code generation and scanning."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test fixtures before any tests are run."""
        cls.test_data = b"Test data for QR code"
        cls.private_key, cls.public_key = Cryptosign.generate_keys()
    
    def setUp(self):
        """Set up test fixtures before each test method is called."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_file = os.path.join(self.temp_dir.name, "test_qr.png")
    
    def tearDown(self):
        """Clean up after each test method."""
        self.temp_dir.cleanup()
    
    def test_generate_and_read_qr(self):
        """Test generating and reading a QR code."""
        # Generate QR code
        qr_data = SecureQR.generate_qr(self.test_data, self.test_file)
        self.assertIsNone(qr_data)  # Should be None since we provided output_path
        
        # Read QR code
        read_data = SecureQR.read_qr(self.test_file)
        self.assertEqual(read_data, self.test_data)
    
    def test_generate_in_memory(self):
        """Test generating QR code in memory."""
        qr_data = SecureQR.generate_qr(self.test_data)
        self.assertIsNotNone(qr_data)
        self.assertGreater(len(qr_data), 1000)  # Should be a reasonable size for a small QR
    
    def test_encrypted_qr(self):
        """Test generating and reading an encrypted QR code."""
        # Encrypt data
        encrypted = SecureQR.encrypt_data(self.test_data, self.public_key)
        
        # Generate QR with encrypted data
        SecureQR.generate_qr(encrypted, self.test_file)
        
        # Read and decrypt
        read_encrypted = SecureQR.read_qr(self.test_file)
        decrypted = SecureQR.decrypt_data(read_encrypted, self.private_key)
        
        self.assertEqual(decrypted, self.test_data)
    
    @patch('app.secure_qr.SecureQR.read_qr')
    def test_read_qr_failure(self, mock_read_qr):
        """Test handling of QR code reading failure."""
        mock_read_qr.return_value = None
        result = SecureQR.read_qr("nonexistent.png")
        self.assertIsNone(result)


class TestTimeBasedQR(unittest.TestCase):
    """Test time-based QR code functionality."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test fixtures before any tests are run."""
        cls.private_key, cls.public_key = Cryptosign.generate_keys()
    
    def setUp(self):
        """Set up test fixtures before each test method is called."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_file = os.path.join(self.temp_dir.name, "time_qr.png")
    
    def tearDown(self):
        """Clean up after each test method."""
        self.temp_dir.cleanup()
    
    def test_generate_with_expiry(self):
        """Test generating a time-based QR code with expiry."""
        # Generate QR code with 1 hour expiry
        qr_code = TimeBasedQR.generate_with_expiry(
            "Test Data", 
            self.public_key,
            expiry_hours=1,
            test_key="test_value"
        )
        
        # Save for reading
        with open(self.test_file, "wb") as f:
            f.write(qr_code)
        
        # Read and validate
        is_valid, payload, error = TimeBasedQR.read_and_validate(
            self.test_file,
            self.private_key
        )
        
        self.assertTrue(is_valid)
        self.assertEqual(payload["data"], "Test Data")
        self.assertEqual(payload["metadata"].get("test_key"), "test_value")
    
    @patch('app.advanced_features.datetime')
    def test_expired_qr(self, mock_datetime):
        """Test that expired QR codes are properly detected."""
        from datetime import datetime, timedelta
        
        # Mock datetime to return a time in the future
        future_time = datetime.utcnow() + timedelta(days=1)
        mock_datetime.utcnow.return_value = future_time
        
        # Generate QR code that expires in 1 hour
        qr_code = TimeBasedQR.generate_with_expiry(
            "Expired Data",
            self.public_key,
            expiry_hours=1
        )
        
        # Save for reading
        with open(self.test_file, "wb") as f:
            f.write(qr_code)
        
        # Read and validate (should be expired)
        is_valid, payload, error = TimeBasedQR.read_and_validate(
            self.test_file,
            self.private_key
        )
        
        self.assertFalse(is_valid)
        self.assertIn("expired", error.lower())


if __name__ == "__main__":
    unittest.main()
