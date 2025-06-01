"""
Secure QR Code Implementation with RSA Signing and Verification
"""

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
import qrcode
from qrcode.image.styledpil import StyledPilImage
from qrcode.image.styles.colormasks import RadialGradiantColorMask
from io import BytesIO
import base64
from typing import Tuple, Optional, Union
import os

class Cryptosign:
    """
    Handles RSA key generation, document signing, and signature verification.
    """
    
    KEY_SIZE = 2048  # 2048-bit RSA key
    
    @staticmethod
    def generate_keys(key_size: int = KEY_SIZE) -> Tuple[RSA.RsaKey, RSA.RsaKey]:
        """
        Generate RSA key pair.
        
        Args:
            key_size: Key size in bits (default: 2048)
            
        Returns:
            Tuple of (private_key, public_key)
        """
        key = RSA.generate(key_size)
        return key, key.publickey()
    
    @staticmethod
    def export_key(key: RSA.RsaKey, passphrase: str = None) -> bytes:
        """
        Export RSA key to PEM format.
        
        Args:
            key: RSA key to export
            passphrase: Optional passphrase for encryption
            
        Returns:
            PEM-encoded key as bytes
        """
        return key.export_key(passphrase=passphrase)
    
    @staticmethod
    def import_key(key_data: bytes, passphrase: str = None) -> RSA.RsaKey:
        """
        Import RSA key from PEM format.
        
        Args:
            key_data: PEM-encoded key data
            passphrase: Passphrase if the key is encrypted
            
        Returns:
            RSA key object
        """
        return RSA.import_key(key_data, passphrase=passphrase)
    
    @staticmethod
    def sign_document(private_key: RSA.RsaKey, document: bytes) -> bytes:
        """
        Sign a document using the private key.
        
        Args:
            private_key: RSA private key for signing
            document: Document content as bytes
            
        Returns:
            Digital signature as bytes
        """
        h = SHA256.new(document)
        signature = pkcs1_15.new(private_key).sign(h)
        return signature
    
    @staticmethod
    def verify_signature(public_key: RSA.RsaKey, signature: bytes, document: bytes) -> bool:
        """
        Verify a document's signature using the public key.
        
        Args:
            public_key: RSA public key for verification
            signature: Signature to verify
            document: Original document content as bytes
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        h = SHA256.new(document)
        try:
            pkcs1_15.new(public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False


class SecureQR:
    """
    Handles secure QR code generation and scanning with data encryption.
    """
    
    @staticmethod
    def encrypt_data(data: bytes, public_key: RSA.RsaKey) -> bytes:
        """
        Encrypt data using RSA-OAEP.
        
        Args:
            data: Data to encrypt (max 190 bytes for 2048-bit key)
            public_key: RSA public key for encryption
            
        Returns:
            Encrypted data as bytes
        """
        cipher = PKCS1_OAEP.new(public_key)
        return cipher.encrypt(data)
    
    @staticmethod
    def decrypt_data(encrypted_data: bytes, private_key: RSA.RsaKey) -> bytes:
        """
        Decrypt data using RSA-OAEP.
        
        Args:
            encrypted_data: Data to decrypt
            private_key: RSA private key for decryption
            
        Returns:
            Decrypted data as bytes
        """
        cipher = PKCS1_OAEP.new(private_key)
        return cipher.decrypt(encrypted_data)
    
    @staticmethod
    def generate_qr(data: Union[str, bytes], output_path: str = None, 
                   size: int = 10, border: int = 4) -> Optional[bytes]:
        """
        Generate a QR code from data.
        
        Args:
            data: Data to encode (string or bytes)
            output_path: Optional path to save the QR code image
            size: QR code size (1-40, 1 is 21x21)
            border: Border size in modules (min=4)
            
        Returns:
            QR code image as bytes if output_path is None, else None
        """
        if isinstance(data, bytes):
            # Convert bytes to base64 for QR code
            data = base64.b64encode(data).decode('utf-8')
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=size,
            border=border,
        )
        
        qr.add_data(data)
        qr.make(fit=True)
        
        # Create a styled QR code
        img = qr.make_image(
            image_factory=StyledPilImage,
            color_mask=RadialGradiantColorMask(
                center_color=(70, 130, 180),  # Steel blue
                edge_color=(25, 25, 112)      # Midnight blue
            )
        )
        
        if output_path:
            img.save(output_path)
            return None
        else:
            # Return image as bytes
            img_byte_arr = BytesIO()
            img.save(img_byte_arr, format='PNG')
            return img_byte_arr.getvalue()
    
    @staticmethod
    def read_qr(image_path: str) -> Optional[bytes]:
        """
        Read data from a QR code image.
        
        Args:
            image_path: Path to the QR code image
            
        Returns:
            Decoded data as bytes, or None if no QR code found
        """
        try:
            import cv2
            
            # Read the image
            img = cv2.imread(image_path)
            if img is None:
                raise ValueError(f"Could not read image: {image_path}")
            
            # Initialize the QR code detector
            qr_detector = cv2.QRCodeDetector()
            
            # Detect and decode QR code
            data, points, _ = qr_detector.detectAndDecode(img)
            
            if not data or not points.any():
                return None
            
            # Try to decode as base64
            try:
                return base64.b64decode(data.encode('utf-8'))
            except:
                return data.encode('utf-8')
                
        except ImportError:
            raise ImportError("OpenCV is required for QR code scanning")


def test_cryptosign():
    """Test the Cryptosign class"""
    print("Testing Cryptosign...")
    
    # Generate keys
    private_key, public_key = Cryptosign.generate_keys()
    print("Generated RSA keys")
    
    # Test signing and verification
    message = b"Hello, Secure QR!"
    signature = Cryptosign.sign_document(private_key, message)
    print(f"Signature: {signature.hex()[:32]}...")
    
    # Verify signature
    is_valid = Cryptosign.verify_signature(public_key, signature, message)
    print(f"Signature valid: {is_valid}")
    
    # Test with wrong message
    wrong_message = b"Tampered message"
    is_valid = Cryptosign.verify_signature(public_key, signature, wrong_message)
    print(f"Tampered signature valid: {is_valid}")


def test_secure_qr():
    """Test the SecureQR class"""
    print("\nTesting SecureQR...")
    
    # Generate keys
    private_key, public_key = Cryptosign.generate_keys()
    
    # Test data
    data = b"This is a secret message!"
    print(f"Original data: {data}")
    
    # Encrypt data
    encrypted_data = SecureQR.encrypt_data(data, public_key)
    print(f"Encrypted data: {encrypted_data.hex()[:32]}...")
    
    # Generate QR code
    qr_data = SecureQR.generate_qr(encrypted_data)
    print(f"Generated QR code ({len(qr_data) if qr_data else 0} bytes)")
    
    # Save QR code for testing
    with open("test_qr.png", "wb") as f:
        f.write(qr_data)
    print("Saved QR code as 'test_qr.png'")
    
    # Read QR code
    read_data = SecureQR.read_qr("test_qr.png")
    print(f"Read data from QR: {read_data.hex()[:32]}...")
    
    # Decrypt data
    decrypted_data = SecureQR.decrypt_data(read_data, private_key)
    print(f"Decrypted data: {decrypted_data}")
    
    # Clean up
    try:
        os.remove("test_qr.png")
    except:
        pass


if __name__ == "__main__":
    test_cryptosign()
    test_secure_qr()
