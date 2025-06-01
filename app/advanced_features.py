"""
Advanced features for SecureQR including time-based QR codes, 2FA, and blockchain notarization.
"""

from datetime import datetime, timedelta
import json
import base64
from typing import Dict, Any, Optional, Tuple
import pyotp
from web3 import Web3, HTTPProvider
from eth_account import Account
from eth_typing import ChecksumAddress
from eth_utils import to_checksum_address
from Crypto.PublicKey import RSA

from .secure_qr import SecureQR, Cryptosign


class TimeBasedQR:
    """Handle time-based QR code generation and validation."""
    
    @staticmethod
    def generate_with_expiry(
        data: str, 
        public_key: RSA.RsaKey, 
        expiry_hours: int = 24,
        **metadata
    ) -> bytes:
        """
        Generate a time-based QR code with an expiration time.
        
        Args:
            data: Data to be included in the QR code
            public_key: RSA public key for encryption
            expiry_hours: Number of hours until the QR code expires
            **metadata: Additional metadata to include in the payload
            
        Returns:
            QR code image as bytes
        """
        payload = {
            "data": data,
            "timestamp": datetime.utcnow().isoformat(),
            "expiry": (datetime.utcnow() + timedelta(hours=expiry_hours)).isoformat(),
            "metadata": metadata or {}
        }
        
        # Convert to JSON and encrypt
        json_payload = json.dumps(payload).encode('utf-8')
        encrypted = SecureQR.encrypt_data(json_payload, public_key)
        
        # Generate QR code
        return SecureQR.generate_qr(encrypted)
    
    @staticmethod
    def validate_expiry(expiry_str: str) -> bool:
        """Check if the QR code has expired."""
        expiry_time = datetime.fromisoformat(expiry_str)
        return datetime.utcnow() < expiry_time
    
    @classmethod
    def read_and_validate(
        cls, 
        qr_image_path: str, 
        private_key: RSA.RsaKey,
        check_expiry: bool = True
    ) -> Tuple[bool, Dict[str, Any], Optional[str]]:
        """
        Read and validate a time-based QR code.
        
        Returns:
            Tuple of (is_valid, payload, error_message)
        """
        try:
            # Read and decrypt the QR code
            encrypted_data = SecureQR.read_qr(qr_image_path)
            if not encrypted_data:
                return False, {}, "No QR code found or could not read QR code"
                
            decrypted = SecureQR.decrypt_data(encrypted_data, private_key)
            payload = json.loads(decrypted.decode('utf-8'))
            
            # Check expiry if required
            if check_expiry and not cls.validate_expiry(payload['expiry']):
                return False, payload, "QR code has expired"
                
            return True, payload, None
            
        except Exception as e:
            return False, {}, f"Error processing QR code: {str(e)}"


class TwoFactorAuth:
    """Handle Two-Factor Authentication using TOTP."""
    
    @staticmethod
    def setup_2fa(user_email: str, issuer_name: str = "SecureQR") -> Dict[str, str]:
        """
        Set up 2FA for a user.
        
        Args:
            user_email: User's email address
            issuer_name: Name of the service/issuer
            
        Returns:
            Dictionary containing secret and provisioning URI
        """
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        qr_uri = totp.provisioning_uri(
            name=user_email,
            issuer_name=issuer_name
        )
        
        return {
            'secret': secret,
            'qr_uri': qr_uri,
            'qr_code': SecureQR.generate_qr(qr_uri.encode('utf-8'))
        }
    
    @staticmethod
    def verify_2fa(secret: str, token: str) -> bool:
        """
        Verify a 2FA token.
        
        Args:
            secret: The shared secret
            token: The token to verify
            
        Returns:
            bool: True if token is valid
        """
        totp = pyotp.TOTP(secret)
        return totp.verify(token)


class BlockchainNotarizer:
    """Handle document notarization on the blockchain."""
    
    def __init__(self, 
                 provider_url: str = None,
                 contract_address: str = None,
                 private_key: str = None):
        """
        Initialize the blockchain notarizer.
        
        Args:
            provider_url: URL of the Ethereum node (e.g., Infura)
            contract_address: Address of the notarization smart contract
            private_key: Private key for signing transactions
        """
        self.provider_url = provider_url or "http://localhost:8545"  # Default to local node
        self.contract_address = contract_address
        self.private_key = private_key
        self.w3 = Web3(HTTPProvider(self.provider_url))
        self.contract = None
        
        if contract_address:
            self._load_contract()
    
    def _load_contract(self):
        """Load the notarization contract ABI and initialize the contract."""
        # This is a simplified ABI for demonstration
        # In a real application, you would load this from the compiled contract
        contract_abi = [
            {
                "inputs": [
                    {"internalType": "bytes32", "name": "documentHash", "type": "bytes32"}
                ],
                "name": "storeHash",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [
                    {"internalType": "bytes32", "name": "documentHash", "type": "bytes32"}
                ],
                "name": "verifyHash",
                "outputs": [
                    {"internalType": "bool", "name": "", "type": "bool"},
                    {"internalType": "uint256", "name": "", "type": "uint256"}
                ],
                "stateMutability": "view",
                "type": "function"
            }
        ]
        
        self.contract = self.w3.eth.contract(
            address=to_checksum_address(self.contract_address),
            abi=contract_abi
        )
    
    def notarize_document(self, document_hash: str) -> str:
        """
        Store a document hash on the blockchain.
        
        Args:
            document_hash: SHA-256 hash of the document
            
        Returns:
            Transaction hash
        """
        if not self.private_key or not self.contract:
            raise ValueError("Private key and contract must be set")
        
        # Convert hash to bytes32
        bytes_hash = Web3.keccak(text=document_hash)
        
        # Get account from private key
        account = Account.from_key(self.private_key)
        
        # Build transaction
        nonce = self.w3.eth.get_transaction_count(account.address)
        
        tx = self.contract.functions.storeHash(bytes_hash).build_transaction({
            'chainId': self.w3.eth.chain_id,
            'gas': 200000,
            'gasPrice': self.w3.eth.gas_price,
            'nonce': nonce,
        })
        
        # Sign and send transaction
        signed_tx = self.w3.eth.account.sign_transaction(tx, self.private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        
        return tx_hash.hex()
    
    def verify_document(self, document_hash: str) -> Tuple[bool, int]:
        """
        Verify if a document hash exists on the blockchain.
        
        Args:
            document_hash: SHA-256 hash of the document
            
        Returns:
            Tuple of (exists, block_number)
        """
        if not self.contract:
            raise ValueError("Contract not initialized")
            
        bytes_hash = Web3.keccak(text=document_hash)
        exists, block_number = self.contract.functions.verifyHash(bytes_hash).call()
        return exists, block_number


def test_time_based_qr():
    """Test time-based QR code functionality."""
    print("Testing Time-Based QR...")
    
    # Generate keys
    private_key, public_key = Cryptosign.generate_keys()
    
    # Generate QR code
    qr_code = TimeBasedQR.generate_with_expiry(
        "Test Data", 
        public_key,
        expiry_hours=1,
        user_id=123,
        purpose="test"
    )
    
    # Save for testing
    with open("time_based_qr.png", "wb") as f:
        f.write(qr_code)
    print("Saved time-based QR code as 'time_based_qr.png'")
    
    # Read and validate
    is_valid, payload, error = TimeBasedQR.read_and_validate(
        "time_based_qr.png",
        private_key
    )
    
    print(f"QR Code Valid: {is_valid}")
    if is_valid:
        print(f"Data: {payload['data']}")
        print(f"Expires: {payload['expiry']}")
    else:
        print(f"Error: {error}")


def test_2fa():
    """Test 2FA setup and verification."""
    print("\nTesting 2FA...")
    
    # Setup 2FA for a user
    user_email = "user@example.com"
    result = TwoFactorAuth.setup_2fa(user_email)
    
    print(f"2FA Secret: {result['secret']}")
    print("Scan the following QR code with Google Authenticator or a similar app:")
    
    # Save QR code for testing
    with open("2fa_qr.png", "wb") as f:
        f.write(result['qr_code'])
    print("Saved 2FA QR code as '2fa_qr.png'")
    
    # Simulate user entering a code (in real app, this would come from user input)
    test_code = input("\nEnter the 6-digit code from your authenticator app: ")
    
    # Verify the code
    is_valid = TwoFactorAuth.verify_2fa(result['secret'], test_code)
    print(f"Code {'valid' if is_valid else 'invalid'}")


def test_blockchain():
    """Test blockchain notarization (requires local Ethereum node)."""
    print("\nTesting Blockchain Notarization...")
    
    # This is a simplified test that won't actually work without a real node and contract
    print("Note: This test requires a local Ethereum node and deployed contract")
    print("Skipping actual blockchain operations...")
    
    # Example usage with a mock
    notarizer = BlockchainNotarizer()
    print("Initialized blockchain notarizer with mock data")
    
    # This would be the actual document hash in a real scenario
    doc_hash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    
    # In a real scenario, you would call:
    # tx_hash = notarizer.notarize_document(doc_hash)
    # print(f"Document notarized in transaction: {tx_hash}")
    # 
    # exists, block = notarizer.verify_document(doc_hash)
    # print(f"Document exists in blockchain: {exists} (Block: {block})")


if __name__ == "__main__":
    test_time_based_qr()
    test_2fa()
    test_blockchain()
