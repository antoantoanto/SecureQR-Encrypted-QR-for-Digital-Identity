"""
Tests for the SecureQR application
"""

import unittest
import os
import json
from pathlib import Path

# Add the project root to the Python path
import sys
sys.path.append(str(Path(__file__).parent.parent))

from app.encryption_module import EncryptionManager
from app.qr_generator import QRGenerator
from app.qr_scanner import QRScanner
from app.data_formatter import DataFormatter

class TestSecureQR(unittest.TestCase):
    """Test cases for SecureQR application"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        cls.test_data = {
            "name": "Test User",
            "id_number": "TEST12345",
            "department": "Testing",
            "role": "QA Engineer"
        }
        cls.test_data_str = json.dumps(cls.test_data)
        
        # Create a test key file
        cls.key_path = "test_key.key"
        cls.enc_manager = EncryptionManager(cls.key_path)
        
        # Initialize other components
        cls.qr_generator = QRGenerator()
        cls.qr_scanner = QRScanner()
        cls.data_formatter = DataFormatter()
    
    @classmethod
    def tearDownClass(cls):
        """Clean up test files"""
        if os.path.exists(cls.key_path):
            os.remove(cls.key_path)
        if os.path.exists("test_qr.png"):
            os.remove("test_qr.png")
    
    def test_encryption_decryption(self):
        """Test encryption and decryption of data"""
        # Test encryption
        iv, encrypted = self.enc_manager.encrypt_data(self.test_data_str)
        self.assertIsNotNone(iv)
        self.assertIsNotNone(encrypted)
        
        # Test decryption
        decrypted = self.enc_manager.decrypt_data(iv, encrypted)
        self.assertEqual(decrypted, self.test_data_str)
    
    def test_qr_generation(self):
        """Test QR code generation and saving"""
        # Generate and save QR code
        qr_img = self.qr_generator.create_qr_code(
            self.test_data_str, 
            "test_qr.png"
        )
        
        # Verify file was created
        self.assertTrue(os.path.exists("test_qr.png"))
        
        # Verify QR code can be read
        qr_data = self.qr_scanner.scan_from_image("test_qr.png")
        self.assertEqual(qr_data, self.test_data_str)
    
    def test_data_formatting(self):
        """Test data formatting and parsing"""
        # Format data
        formatted = self.data_formatter.format_identity_data(
            name=self.test_data["name"],
            id_number=self.test_data["id_number"],
            additional_info={
                "department": self.test_data["department"],
                "role": self.test_data["role"]
            }
        )
        
        # Parse data back
        parsed = self.data_formatter.parse_identity_data(formatted)
        
        # Verify data integrity
        self.assertEqual(parsed["name"], self.test_data["name"])
        self.assertEqual(parsed["id_number"], self.test_data["id_number"])
        self.assertEqual(parsed["department"], self.test_data["department"])
        self.assertEqual(parsed["role"], self.test_data["role"])

if __name__ == "__main__":
    unittest.main()
