"""
Test script to verify the SecureQR application can be run.
"""

import sys
import os
from pathlib import Path

def check_imports():
    """Check if all required packages are installed."""
    required_packages = [
        'Crypto',
        'qrcode',
        'opencv-python',
        'PIL',
        'pyzbar',
        'numpy'
    ]
    
    missing = []
    for package in required_packages:
        try:
            __import__(package.split('.')[0])
            print(f"✓ {package} is installed")
        except ImportError:
            missing.append(package)
    
    if missing:
        print("\nThe following required packages are missing:")
        for pkg in missing:
            print(f"- {pkg}")
        print("\nInstall them using: pip install -r requirements.txt")
        return False
    
    return True

def check_project_structure():
    """Verify the project structure is correct."""
    required_dirs = [
        'app',
        'ui',
        'ui/assets',
        'keys',
        'scans',
        'tests'
    ]
    
    missing = []
    for dir_path in required_dirs:
        if not os.path.isdir(dir_path):
            missing.append(dir_path)
    
    if missing:
        print("\nThe following directories are missing:")
        for d in missing:
            print(f"- {d}")
        return False
    
    return True

def main():
    """Run the application tests."""
    print("=== SecureQR Application Test ===\n")
    
    print("1. Checking Python version...")
    print(f"Python {sys.version.split()[0]} detected")
    
    print("\n2. Checking required packages...")
    if not check_imports():
        return 1
    
    print("\n3. Checking project structure...")
    if not check_project_structure():
        return 1
    
    print("\nAll checks passed!")
    print("\nYou can now run the application using: python main.py")
    return 0

if __name__ == "__main__":
    sys.exit(main())
