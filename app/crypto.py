"""
Cryptographic operations for the SecureQR application.
Handles key generation, encryption, decryption, and QR code operations.
"""

import os
import base64
import json
import zlib
import datetime
from pathlib import Path
from typing import Optional, Tuple, Union, Dict, Any
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
import qrcode
from qrcode.image.styledpil import StyledPilImage
from qrcode.image.styles.moduledrawers import RoundedModuleDrawer
from qrcode.image.styles.colormasks import RadialGradiantColorMask
from app.config import KEYS_DIR, PRIVATE_KEY_EXTENSION, PUBLIC_KEY_EXTENSION, DATA_DIR

class CryptoManager:
    """
    Manages cryptographic operations for SecureQR.
    Handles hybrid encryption (RSA + AES), digital signatures, and QR code generation.
    """
    
    # Default key sizes
    RSA_KEY_SIZE = 2048  # bits
    AES_KEY_SIZE = 32    # bytes (256 bits)
    
    # QR Code settings
    QR_VERSION = 10  # Higher version = more data capacity
    QR_BOX_SIZE = 10
    QR_BORDER = 4
    QR_FILL_COLOR = "black"
    QR_BACK_COLOR = "white"
    
    def __init__(self, keys_dir: Optional[Path] = None, data_dir: Optional[Path] = None):
        """
        Initialize the crypto manager.
        
        Args:
            keys_dir: Directory to store/load keys (defaults to app's keys directory)
            data_dir: Directory to store data files (defaults to app's data directory)
        """
        self.private_key = None
        self.public_key = None
        self.keys_dir = keys_dir if keys_dir else KEYS_DIR
        self.data_dir = data_dir if data_dir else DATA_DIR
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_key_pair(self, key_name: str = "default") -> Tuple[Path, Path]:
        """
        Generate a new RSA key pair and save to files.
        
        Args:
            key_name: Name for the key pair (used in filenames)
            
        Returns:
            Tuple of (private_key_path, public_key_path)
        """
        # Generate new key pair
        key = RSA.generate(self.RSA_KEY_SIZE)
        
        # Define file paths
        private_key_path = self.keys_dir / f"{key_name}{PRIVATE_KEY_EXTENSION}"
        public_key_path = self.keys_dir / f"{key_name}{PUBLIC_KEY_EXTENSION}"
        
        # Save private key
        with open(private_key_path, 'wb') as f:
            f.write(key.export_key())
            
        # Save public key
        with open(public_key_path, 'wb') as f:
            f.write(key.publickey().export_key())
            
        # Store keys in memory
        self.private_key = key
        self.public_key = key.publickey()
        
        return private_key_path, public_key_path
    
    def load_key_pair(self, key_name: str = "default") -> bool:
        """
        Load an existing key pair from files.
        
        Args:
            key_name: Name of the key pair to load
            
        Returns:
            bool: True if keys were loaded successfully, False otherwise
        """
        private_key_path = self.keys_dir / f"{key_name}{PRIVATE_KEY_EXTENSION}"
        public_key_path = self.keys_dir / f"{key_name}{PUBLIC_KEY_EXTENSION}"
        
        if not private_key_path.exists() or not public_key_path.exists():
            return False
            
        try:
            # Load private key
            with open(private_key_path, 'rb') as f:
                self.private_key = RSA.import_key(f.read())
                
            # Load public key
            with open(public_key_path, 'rb') as f:
                self.public_key = RSA.import_key(f.read())
                
            return True
            
        except Exception as e:
            print(f"Error loading key pair: {e}")
            self.private_key = None
            self.public_key = None
            return False
    
    def generate_aes_key(self) -> bytes:
        """Generate a random AES key."""
        return Random.get_random_bytes(self.AES_KEY_SIZE)
    
    def encrypt_data(self, data: Union[str, dict], public_key: Optional[RSA.RsaKey] = None) -> Dict[str, str]:
        """
        Encrypt data using hybrid encryption (RSA + AES).
        
        Args:
            data: Data to encrypt (string or dictionary)
            public_key: Optional RSA public key (uses loaded key if None)
            
        Returns:
            Dictionary containing encrypted data and metadata
        """
        if public_key is None:
            if not self.public_key:
                raise ValueError("No public key available for encryption")
            public_key = self.public_key
        
        # Convert data to JSON if it's a dictionary
        if isinstance(data, dict):
            data = json.dumps(data, ensure_ascii=False)
        
        # Generate a random AES key and IV
        aes_key = self.generate_aes_key()
        iv = Random.get_random_bytes(16)
        
        # Encrypt the data with AES
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_data = pad(data.encode('utf-8'), AES.block_size)
        encrypted_data = cipher_aes.encrypt(padded_data)
        
        # Encrypt the AES key with RSA
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_key = cipher_rsa.encrypt(aes_key)
        
        # Return the encrypted data and metadata
        return {
            'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8'),
            'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'key_size': public_key.size_in_bits(),
            'timestamp': datetime.datetime.utcnow().isoformat()
        }
    
    def decrypt_data(self, encrypted_data: Dict[str, str], private_key: Optional[RSA.RsaKey] = None) -> str:
        """
        Decrypt data using hybrid encryption (RSA + AES).
        
        Args:
            encrypted_data: Dictionary containing encrypted data and metadata
            private_key: Optional RSA private key (uses loaded key if None)
            
        Returns:
            Decrypted data as a string
        """
        if private_key is None:
            if not self.private_key:
                raise ValueError("No private key available for decryption")
            private_key = self.private_key
        
        try:
            # Extract and decode the encrypted data
            iv = base64.b64decode(encrypted_data['iv'])
            encrypted_key = base64.b64decode(encrypted_data['encrypted_key'])
            encrypted_data_bytes = base64.b64decode(encrypted_data['encrypted_data'])
            
            # Decrypt the AES key with RSA
            cipher_rsa = PKCS1_OAEP.new(private_key)
            aes_key = cipher_rsa.decrypt(encrypted_key)
            
            # Decrypt the data with AES
            cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher_aes.decrypt(encrypted_data_bytes), AES.block_size)
            
            return decrypted_data.decode('utf-8')
            
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def generate_qr_code(self, data: Union[str, dict], output_path: Optional[Union[str, Path]] = None,
                        size: int = 10, border: int = 4) -> Tuple[bytes, Path]:
        """
        Generate a QR code from the given data.
        
        Args:
            data: Data to encode in the QR code (string or dictionary)
            output_path: Optional path to save the QR code image
            size: QR code size (pixels per module)
            border: QR code border size in modules
            
        Returns:
            Tuple of (image_data, output_path)
        """
        # Convert data to JSON if it's a dictionary
        if isinstance(data, dict):
            data = json.dumps(data, ensure_ascii=False)
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=size,
            border=border,
        )
        qr.add_data(data)
        qr.make(fit=True)
        
        # Create styled image
        img = qr.make_image(
            image_factory=StyledPilImage,
            module_drawer=RoundedModuleDrawer(),
            color_mask=RadialGradiantColorMask(
                back_color=self.QR_BACK_COLOR,
                center_color=self.QR_FILL_COLOR,
                edge_color=self.QR_FILL_COLOR
            )
        )
        
        # Save to file if output path is provided
        if output_path is None:
            output_path = self.data_dir / f"qr_{int(datetime.datetime.now().timestamp())}.png"
        else:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
        
        img.save(output_path)
        
        # Return image data and path
        with open(output_path, 'rb') as f:
            image_data = f.read()
            
        return image_data, output_path
    
    def read_qr_code(self, image_path: Union[str, Path]) -> str:
        """
        Read data from a QR code image.
        
        Args:
            image_path: Path to the QR code image
            
        Returns:
            Decoded data as a string
            
        Raises:
            ValueError: If no QR code is found or there's an error reading it
        """
        try:
            import cv2
            import numpy as np
            
            # Read the image
            img = cv2.imread(str(image_path))
            if img is None:
                raise ValueError(f"Could not read image: {image_path}")
            
            # Initialize the QR code detector
            qr_detector = cv2.QRCodeDetector()
            
            # Detect and decode QR code
            data, points, _ = qr_detector.detectAndDecode(img)
            
            if not data or not points.any():
                raise ValueError("No QR code found in the image")
                
            return data
            
        except Exception as e:
            raise ValueError(f"Failed to read QR code: {str(e)}")
    
    def sign_document(self, document_path: Union[str, Path], output_path: Optional[Union[str, Path]] = None) -> Tuple[Optional[bytes], str]:
        """
        Sign a document with the loaded private key using SHA-256 hashing.
        
        Args:
            document_path: Path to the document to sign (PDF, text, or image)
            output_path: Optional path to save the signature (will use .sig extension if not provided)
            
        Returns:
            Tuple of (signature_bytes, signature_base64)
            
        Raises:
            ValueError: If no private key is loaded or document is invalid
            IOError: If there are issues reading/writing files
        """
        if not self.private_key:
            raise ValueError("No private key loaded for signing")
            
        if not os.path.exists(document_path):
            raise FileNotFoundError(f"Document not found: {document_path}")
            
        try:
            # Read the document in binary mode
            with open(document_path, 'rb') as f:
                document_data = f.read()
            
            if not document_data:
                raise ValueError("Document is empty")
                
            # Create hash of the document using SHA-256
            document_hash = SHA256.new(document_data)
            
            # Sign the hash using RSA with PKCS#1 v1.5 padding
            signature = pkcs1_15.new(self.private_key).sign(document_hash)
            
            # Convert signature to base64 for easy storage/transmission
            signature_b64 = base64.b64encode(signature).decode('utf-8')
            
            # Determine output path if not provided
            if output_path is None:
                output_path = str(Path(document_path).with_suffix('.sig'))
            
            # Save signature with metadata
            signature_data = {
                'algorithm': 'SHA256withRSA',
                'key_size': self.private_key.size_in_bits(),
                'document_hash': document_hash.hexdigest(),
                'document_size': len(document_data),
                'signature': signature_b64,
                'timestamp': datetime.datetime.utcnow().isoformat()
            }
            
            with open(output_path, 'w') as f:
                json.dump(signature_data, f, indent=2)
                
            return signature, signature_b64
            
        except Exception as e:
            raise IOError(f"Error signing document: {str(e)}")
    
    def verify_signature(self, document_path: Union[str, Path], 
                        signature_path: Union[str, Path], 
                        public_key_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
        """
        Verify a document's signature and check for alterations.
        
        Args:
            document_path: Path to the signed document
            signature_path: Path to the signature file (.sig)
            public_key_path: Optional path to a public key to use for verification
                            If not provided, uses the loaded public key
                            
        Returns:
            Dict containing verification results with keys:
            - valid (bool): Whether the signature is valid
            - altered (bool): Whether the document was altered
            - details (str): Human-readable status message
            - metadata (dict): Signature metadata if available
            
        Raises:
            ValueError: If verification data is invalid
            IOError: If there are issues reading files
        """
        result = {
            'valid': False,
            'altered': True,
            'details': 'Verification failed',
            'metadata': {}
        }
        
        try:
            # Read the signature file
            with open(signature_path, 'r') as f:
                try:
                    signature_data = json.load(f)
                    signature_b64 = signature_data.get('signature')
                    if not signature_b64:
                        raise ValueError("Invalid signature file format: missing signature")
                        
                    # Store metadata in result
                    result['metadata'] = {
                        k: v for k, v in signature_data.items() 
                        if k != 'signature'
                    }
                    
                    # Get the stored document hash
                    stored_hash = signature_data.get('document_hash')
                    if not stored_hash:
                        raise ValueError("Invalid signature file: missing document hash")
                        
                    # Load the public key
                    if public_key_path:
                        with open(public_key_path, 'rb') as key_file:
                            public_key = RSA.import_key(key_file.read())
                    elif self.public_key:
                        public_key = self.public_key
                    else:
                        raise ValueError("No public key available for verification")
                    
                    # Read the current document
                    with open(document_path, 'rb') as doc_file:
                        document_data = doc_file.read()
                    
                    # Calculate current hash
                    current_hash = SHA256.new(document_data).hexdigest()
                    
                    # Check if document was altered
                    if current_hash != stored_hash:
                        result.update({
                            'valid': False,
                            'altered': True,
                            'details': 'Document has been altered!',
                        })
                        return result
                    
                    # Decode the signature
                    try:
                        signature = base64.b64decode(signature_b64)
                    except Exception as e:
                        raise ValueError(f"Invalid base64 signature: {str(e)}")
                    
                    # Verify the signature
                    document_hash = SHA256.new(document_data)
                    try:
                        pkcs1_15.new(public_key).verify(document_hash, signature)
                        result.update({
                            'valid': True,
                            'altered': False,
                            'details': 'Signature is valid and document is unaltered',
                        })
                    except (ValueError, TypeError):
                        result.update({
                            'valid': False,
                            'altered': True,
                            'details': 'Invalid signature',
                        })
                    
                    return result
                    
                except json.JSONDecodeError:
                    # Fall back to old format if not JSON
                    with open(signature_path, 'rb') as f:
                        signature = f.read()
                    
                    # This is the old verification logic for backward compatibility
                    with open(document_path, 'rb') as f:
                        document_data = f.read()
                    
                    h = SHA256.new(document_data)
                    
                    if public_key_path:
                        with open(public_key_path, 'rb') as f:
                            public_key = RSA.import_key(f.read())
                    elif self.public_key:
                        public_key = self.public_key
                    else:
                        raise ValueError("No public key available for verification")
                    
                    try:
                        pkcs1_15.new(public_key).verify(h, signature)
                        result.update({
                            'valid': True,
                            'altered': False,
                            'details': 'Legacy signature is valid (no document hash available)',
                        })
                    except (ValueError, TypeError):
                        result.update({
                            'valid': False,
                            'altered': True,
                            'details': 'Invalid legacy signature',
                        })
                    
                    return result
                    
        except Exception as e:
            result['details'] = f"Verification error: {str(e)}"
            return result
            
    def encrypt_and_sign_identity(self, identity_data: dict, public_key: Optional[RSA.RsaKey] = None) -> dict:
        """
        Encrypt identity data and sign it.
        
        Args:
            identity_data: Dictionary containing identity information
            public_key: Optional RSA public key (uses loaded key if None)
            
        Returns:
            Dictionary containing encrypted data and signature
        """
        # Encrypt the identity data
        encrypted_data = self.encrypt_data(identity_data, public_key)
        
        # Sign the encrypted data
        signature_data = json.dumps(encrypted_data, sort_keys=True).encode('utf-8')
        document_hash = SHA256.new(signature_data)
        signature = pkcs1_15.new(self.private_key).sign(document_hash)
        
        # Return the encrypted data and signature
        return {
            'encrypted_data': encrypted_data,
            'signature': base64.b64encode(signature).decode('utf-8'),
            'algorithm': 'RSA-AES-Hybrid',
            'timestamp': datetime.datetime.utcnow().isoformat()
        }
        
    def verify_and_decrypt_identity(self, encrypted_data: dict, public_key: Optional[RSA.RsaKey] = None) -> dict:
        """
        Verify and decrypt identity data.
        
        Args:
            encrypted_data: Dictionary containing encrypted data and signature
            public_key: Optional RSA public key for verification (uses loaded key if None)
            
        Returns:
            Decrypted identity data as a dictionary
        """
        # Verify the signature
        if public_key is None:
            if not self.public_key:
                raise ValueError("No public key available for verification")
            public_key = self.public_key
            
        # Extract the signature and data
        signature = base64.b64decode(encrypted_data['signature'])
        data_to_verify = json.dumps(encrypted_data['encrypted_data'], sort_keys=True).encode('utf-8')
        
        # Verify the signature
        try:
            document_hash = SHA256.new(data_to_verify)
            pkcs1_15.new(public_key).verify(document_hash, signature)
        except (ValueError, TypeError):
            raise ValueError("Signature verification failed")
        
        # Decrypt the data
        decrypted_data = self.decrypt_data(encrypted_data['encrypted_data'])
        
        try:
            return json.loads(decrypted_data)
        except json.JSONDecodeError:
            return {'data': decrypted_data}
    
    def get_public_key_pem(self) -> bytes:
        """
        Get the public key in PEM format.
        
        Returns:
            bytes: The public key in PEM format
            
        Raises:
            ValueError: If no public key is loaded
        """
        if not self.public_key:
            raise ValueError("No public key loaded")
        return self.public_key.export_key()
    
    def get_private_key_pem(self) -> bytes:
        """
        Get the private key in PEM format.
        
        Returns:
            bytes: The private key in PEM format
            
        Raises:
            ValueError: If no private key is loaded
        """
        if not self.private_key:
            raise ValueError("No private key loaded")
        return self.private_key.export_key()
    
    def get_public_key_fingerprint(self) -> str:
        """
        Get a fingerprint of the public key for display purposes.
        
        Returns:
            str: A fingerprint of the public key
        """
        if not self.public_key:
            return "No public key loaded"
            
        # Get the public key in PEM format
        key_pem = self.get_public_key_pem()
        
        # Remove header/footer and whitespace
        key_data = b''.join([line.strip() for line in key_pem.splitlines() 
                          if line and not line.startswith(b'-----')])
        
        # Create a fingerprint
        import hashlib
        key_hash = hashlib.sha256(key_data).hexdigest()
        
        # Format as groups of 4 characters for better readability
        return ' '.join([key_hash[i:i+4] for i in range(0, len(key_hash), 4)])

def test_crypto():
    """Test the cryptographic functions."""
    import tempfile
    import shutil
    
    print("Testing cryptographic functions...")
    
    # Create a temporary directory for testing
    temp_dir = Path(tempfile.mkdtemp())
    try:
        print(f"Using temporary directory: {temp_dir}")
        
        # Initialize crypto manager
        crypto = CryptoManager(keys_dir=temp_dir)
        
        # Test key generation
        print("\n1. Generating test key pair...")
        priv_path, pub_path = crypto.generate_key_pair("test_key")
        print(f"  - Private key: {priv_path}")
        print(f"  - Public key: {pub_path}")
        
        # Verify files were created
        assert priv_path.exists(), "Private key file not created"
        assert pub_path.exists(), "Public key file not created"
        print("  ✓ Key files created successfully")
        
        # Test document signing
        test_doc = temp_dir / "test_document.txt"
        with open(test_doc, 'w', encoding='utf-8') as f:
            f.write("This is a test document for signature verification.")
        
        print("\n2. Signing test document...")
        sig_path = temp_dir / "test.sig"
        signature = crypto.sign_document(test_doc, sig_path)
        print(f"  - Signature: {signature[:16].hex()}... (truncated)")
        print(f"  - Signature saved to: {sig_path}")
        
        # Verify signature file was created
        assert sig_path.exists(), "Signature file not created"
        print("  ✓ Signature file created successfully")
        
        # Test signature verification
        print("\n3. Verifying signature...")
        is_valid = crypto.verify_signature(test_doc, sig_path)
        print(f"  - Signature is {'valid' if is_valid else 'invalid'}")
        assert is_valid, "Signature verification failed with correct key"
        print("  ✓ Signature verified successfully with correct key")
        
        # Test with wrong key (should fail)
        print("\n4. Testing with wrong key...")
        crypto2 = CryptoManager(keys_dir=temp_dir)
        crypto2.generate_key_pair("wrong_key")
        is_valid = crypto2.verify_signature(test_doc, sig_path)
        print(f"  - Verification with wrong key: {'PASS' if not is_valid else 'FAIL'}")
        assert not is_valid, "Signature verification should fail with wrong key"
        
        # Test loading keys
        print("\n5. Testing key loading...")
        crypto3 = CryptoManager(keys_dir=temp_dir)
        loaded = crypto3.load_key_pair("test_key")
        print(f"  - Key loading: {'SUCCESS' if loaded else 'FAIL'}")
        assert loaded, "Failed to load existing key pair"
        print("  ✓ Key pair loaded successfully")
        
        # Test key fingerprint
        print("\n6. Testing key fingerprint...")
        fingerprint = crypto3.get_public_key_fingerprint()
        print(f"  - Public key fingerprint: {fingerprint}")
        assert fingerprint != "No public key loaded", "Failed to get key fingerprint"
        print("  ✓ Key fingerprint generated successfully")
        
        print("\n✓ All tests passed!")
        
    finally:
        # Clean up
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
            print(f"\nCleaned up temporary directory: {temp_dir}")

if __name__ == "__main__":
    test_crypto()
