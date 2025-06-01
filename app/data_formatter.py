import json
from typing import Dict, Any, Optional
import re

class DataFormatter:
    """
    Handles formatting and parsing of identity data for encryption/decryption
    """
    
    @staticmethod
    def format_identity_data(
        name: str,
        id_number: str,
        additional_info: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Format identity data into a standardized string format
        
        Args:
            name: Full name of the individual
            id_number: Unique identification number
            additional_info: Optional dictionary of additional fields
            
        Returns:
            str: Formatted identity string
        """
        data = {
            "name": name.strip(),
            "id_number": str(id_number).strip(),
            "timestamp": DataFormatter._get_current_timestamp(),
        }
        
        if additional_info and isinstance(additional_info, dict):
            # Sanitize additional info
            for key, value in additional_info.items():
                if isinstance(value, str):
                    data[key] = value.strip()
                else:
                    data[key] = value
        
        return json.dumps(data, ensure_ascii=False)
    
    @staticmethod
    def parse_identity_data(data_str: str) -> Dict[str, Any]:
        """
        Parse identity data from a formatted string
        
        Args:
            data_str: Formatted identity string
            
        Returns:
            dict: Parsed identity data
            
        Raises:
            ValueError: If data format is invalid
        """
        try:
            data = json.loads(data_str)
            
            # Validate required fields
            if not all(key in data for key in ["name", "id_number"]):
                raise ValueError("Missing required fields in identity data")
                
            return data
            
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid data format: {e}")
    
    @staticmethod
    def validate_id_number(id_number: str, pattern: str = r'^[A-Za-z0-9-]+$') -> bool:
        """
        Validate ID number format using regex
        
        Args:
            id_number: ID number to validate
            pattern: Regex pattern for validation
            
        Returns:
            bool: True if ID number is valid
        """
        return bool(re.match(pattern, str(id_number)))
    
    @staticmethod
    def _get_current_timestamp() -> str:
        """Get current timestamp in ISO format"""
        from datetime import datetime
        return datetime.utcnow().isoformat()

# Example usage
if __name__ == "__main__":
    # Create sample identity data
    identity = {
        "name": "John Doe",
        "id_number": "ID12345678",
        "department": "Engineering",
        "role": "Senior Developer"
    }
    
    # Format the data
    formatted = DataFormatter.format_identity_data(
        name=identity["name"],
        id_number=identity["id_number"],
        additional_info={
            "department": identity["department"],
            "role": identity["role"]
        }
    )
    
    print(f"Formatted data: {formatted}")
    
    # Parse the data back
    try:
        parsed = DataFormatter.parse_identity_data(formatted)
        print(f"Parsed data: {parsed}")
    except ValueError as e:
        print(f"Error parsing data: {e}")
