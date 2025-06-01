from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os
from pathlib import Path

class EncryptionManager:
    def __init__(self, key_path='../keys/aes.key'):
        self.key_path = key_path
        self.key = self._load_or_generate_key()
    
    def _load_or_generate_key(self):
        """Load existing key or generate a new one if it doesn't exist"""
        key_file = Path(self.key_path)
        key_file.parent.mkdir(parents=True, exist_ok=True)
        
        if key_file.exists():
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = get_random_bytes(32)  # 256-bit key for AES-256
            with open(key_file, 'wb') as f:
                f.write(key)
            return key
    
    def encrypt_data(self, data: str) -> tuple[bytes, bytes]:
        """Encrypt data using AES-256-CBC"""
        cipher = AES.new(self.key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
        return cipher.iv, ct_bytes
    
    def decrypt_data(self, iv: bytes, encrypted_data: bytes) -> str:
        """Decrypt data using AES-256-CBC"""
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        return pt.decode('utf-8')

# Example usage
if __name__ == "__main__":
    manager = EncryptionManager()
    
    # Test encryption/decryption
    test_data = "Name: John Doe, ID: 12345"
    print(f"Original: {test_data}")
    
    iv, encrypted = manager.encrypt_data(test_data)
    print(f"Encrypted: {encrypted.hex()}")
    
    decrypted = manager.decrypt_data(iv, encrypted)
    print(f"Decrypted: {decrypted}")
