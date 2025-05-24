#!/usr/bin/env python3
"""
Cryptosign - Digital Signature Application

This application provides a solution for creating and verifying digital signatures
using RSA + SHA-256 public key cryptography. It's designed for digital documents
that require legal validity or high integrity.
"""

import sys
import os
import tkinter as tk
from pathlib import Path

# Add the project root to the Python path
sys.path.append(str(Path(__file__).parent))

# Import the main application window
from ui.main_window import CryptoSignApp

def main():
    """Main entry point for the application."""
    try:
        # Initialize the root window
        root = tk.Tk()
        
        # Create and run the application
        app = CryptoSignApp(root)
        
        # Start the main event loop
        root.mainloop()
        
    except Exception as e:
        import traceback
        error_msg = f"An error occurred: {str(e)}\n\n{traceback.format_exc()}"
        print(error_msg)
        tk.messagebox.showerror("Error", f"A fatal error occurred. Please see console for details.\n\n{str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
