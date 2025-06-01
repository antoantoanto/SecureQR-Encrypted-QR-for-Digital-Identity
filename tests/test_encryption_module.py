"""
Tests for the encryption and decryption functionality.
"""

import unittest
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add the parent directory to the path so we can import from app
import sys
sys.path.append(str(Path(__file__).parent.parent))

from app.secure_qr import Cryptosign, SecureQR


class TestCryptosign(unittest.TestCase):
    """Test the Cryptosign class for signing and verification."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test fixtures before any tests are run."""
        cls.test_data = b"Test data for signing"
        cls.private_key, cls.public_key = Cryptosign.generate_keys()
    
    def test_key_generation(self):
        """Test that key generation produces valid keys."""
        # Check that keys were generated
        self.assertIsNotNone(self.private_key)
        self.assertIsNotNone(self.public_key)
        
        # Check key sizes
        self.assertEqual(self.private_key.size_in_bits(), 2048)
        self.assertEqual(self.public_key.size_in_bits(), 2048)
    
    def test_export_import_keys(self):
        """Test exporting and importing keys."""
        # Export keys
        private_pem = Cryptosign.export_key(self.private_key)
        public_pem = Cryptosign.export_key(self.public_key)
        
        # Import keys
        imported_private = Cryptosign.import_key(private_pem)
        imported_public = Cryptosign.import_key(public_pem)
        
        # Test that imported keys work
        signature = Cryptosign.sign_document(imported_private, self.test_data)
        is_valid = Cryptosign.verify_signature(imported_public, signature, self.test_data)
        self.assertTrue(is_valid)
    
    def test_sign_verify(self):
        """Test signing and verification of data."""
        # Sign the test data
        signature = Cryptosign.sign_document(self.private_key, self.test_data)
        
        # Verify the signature
        is_valid = Cryptosign.verify_signature(self.public_key, signature, self.test_data)
        self.assertTrue(is_valid)
        
        # Test with wrong data
        wrong_data = b"Tampered data"
        is_valid = Cryptosign.verify_signature(self.public_key, signature, wrong_data)
        self.assertFalse(is_valid)
    
    def test_invalid_signature(self):
        """Test verification with invalid signature."""
        # Create a random signature (invalid)
        random_signature = os.urandom(256)  # RSA-2048 signature is 256 bytes
        
        # Should not verify
        is_valid = Cryptosign.verify_signature(
            self.public_key, 
            random_signature, 
            self.test_data
        )
        self.assertFalse(is_valid)


class TestSecureQR(unittest.TestCase):
    """Test the SecureQR class for encryption and decryption."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test fixtures before any tests are run."""
        cls.test_data = b"Test data for encryption"
        cls.private_key, cls.public_key = Cryptosign.generate_keys()
    
    def test_encrypt_decrypt(self):
        """Test encryption and decryption of data."""
        # Encrypt the data
        encrypted = SecureQR.encrypt_data(self.test_data, self.public_key)
        
        # Should be different from original
        self.assertNotEqual(encrypted, self.test_data)
        
        # Decrypt the data
        decrypted = SecureQR.decrypt_data(encrypted, self.private_key)
        
        # Should match original
        self.assertEqual(decrypted, self.test_data)
    
    def test_encrypt_with_wrong_key(self):
        """Test decryption with wrong private key."""
        # Generate a different key pair
        _, wrong_public_key = Cryptosign.generate_keys()
        wrong_private_key, _ = Cryptosign.generate_keys()
        
        # Encrypt with the correct public key
        encrypted = SecureQR.encrypt_data(self.test_data, self.public_key)
        
        # Try to decrypt with wrong private key (should fail)
        with self.assertRaises(ValueError):
            SecureQR.decrypt_data(encrypted, wrong_private_key)
    
    def test_encrypt_large_data(self):
        """Test encryption of data larger than the RSA key size."""
        # Create a large data block (larger than RSA key size)
        large_data = os.urandom(500)  # 500 bytes > 190 bytes limit for RSA-2048
        
        # This should raise an error as the data is too large
        with self.assertRaises(ValueError):
            SecureQR.encrypt_data(large_data, self.public_key)


class TestIntegration(unittest.TestCase):
    """Integration tests for the entire encryption/decryption flow."""
    
    def test_full_flow(self):
        """Test the complete flow: generate keys, sign, verify, encrypt, decrypt."""
        # Generate keys
        private_key, public_key = Cryptosign.generate_keys()
        
        # Test data
        data = b"This is a test message"
        
        # Sign the data
        signature = Cryptosign.sign_document(private_key, data)
        
        # Verify the signature
        is_valid = Cryptosign.verify_signature(public_key, signature, data)
        self.assertTrue(is_valid)
        
        # Create a payload with the data and signature
        payload = {
            "data": data.decode('utf-8'),
            "signature": signature.hex()
        }
        
        # Convert to bytes
        payload_bytes = json.dumps(payload).encode('utf-8')
        
        # Encrypt the payload
        encrypted = SecureQR.encrypt_data(payload_bytes, public_key)
        
        # Decrypt the payload
        decrypted = SecureQR.decrypt_data(encrypted, private_key)
        
        # Parse the decrypted payload
        decrypted_payload = json.loads(decrypted.decode('utf-8'))
        
        # Verify the signature again
        is_valid = Cryptosign.verify_signature(
            public_key,
            bytes.fromhex(decrypted_payload["signature"]),
            decrypted_payload["data"].encode('utf-8')
        )
        self.assertTrue(is_valid)


if __name__ == "__main__":
    unittest.main()
