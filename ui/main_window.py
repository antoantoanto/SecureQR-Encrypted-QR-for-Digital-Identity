# Standard library imports
import datetime
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List, Union

# Third-party imports
import cv2
import numpy as np
from PIL import Image, ImageTk
from pyzbar.pyzbar import decode
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext

# Local application imports
from app.crypto import CryptoManager
from app.config import (
    APP_TITLE, THEME_COLORS, DEFAULT_WINDOW_SIZE,
    MIN_WINDOW_SIZE, DEFAULT_KEY_NAME
)

# Make QR scanner optional
try:
    from app.qr_scanner import QRScanner
    QR_SCANNER_AVAILABLE = True
except ImportError as e:
    print(f"Warning: QR Scanner not available: {e}")
    QR_SCANNER_AVAILABLE = False

# Import QR Generator (should work without OpenCV)
try:
    from app.qr_generator import QRGenerator
    from app.data_formatter import DataFormatter
    QR_GENERATOR_AVAILABLE = True
except ImportError as e:
    print(f"Warning: QR Generator not available: {e}")
    QR_GENERATOR_AVAILABLE = False

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class CryptoSignApp:
    """Main application window for Cryptosign digital signature tool."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("SecureQR: Encrypted QR for Digital Identity")
        self.root.geometry("900x700")
        
        # Initialize crypto manager
        self.crypto = CryptoManager()
        
        # Current document and signature paths
        self.current_doc_path = ""
        self.current_sig_path = ""
        self.current_key_name = "default"
        
        # Scanner state
        self.scanner = None
        self.scanning = False
        self.after_id = None
        
        # Configure styles
        self.setup_styles()
        
        # Setup UI
        self.setup_ui()
        
        # Load keys if they exist
        self.load_keys()
        
        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def setup_styles(self):
        """Configure ttk styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('TFrame', background='#f0f0f0')
        style.configure('TLabel', background='#f0f0f0')
        style.configure('TButton', padding=6, font=('Segoe UI', 10))
        style.configure('TNotebook', background='#f0f0f0')
        style.configure('TNotebook.Tab', padding=[20, 5], font=('Segoe UI', 10, 'bold'))
        style.map('TButton',
                 background=[('active', '#4a7a8c')],
                 foreground=[('active', 'white')])
        
        # Custom styles
        style.configure('Header.TLabel', 
                      font=('Segoe UI', 14, 'bold'),
                      background='#f0f0f0')
        style.configure('Status.TLabel', 
                      font=('Segoe UI', 9),
                      background='#e0e0e0',
                      relief='sunken',
                      padding=5)
        style.configure('KeyInfo.TLabel',
                      font=('Consolas', 9),
                      background='white',
                      relief='sunken',
                      padding=5,
                      wraplength=400)
    
    def setup_ui(self):
        """Set up the main user interface"""
        # Main container
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        header_frame = ttk.Frame(self.main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(
            header_frame, 
            text="Cryptosign - Digital Signature Tool",
            style='Header.TLabel'
        ).pack(side=tk.LEFT)
        
        # Tab control
        self.tab_control = ttk.Notebook(self.main_frame)
        self.tab_control.pack(expand=1, fill="both")
        
        # Create tabs
        self.create_sign_tab()
        self.create_verify_tab()
        self.create_qr_tab()  # Add QR code tab
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(
            self.main_frame, 
            textvariable=self.status_var,
            style='Status.TLabel',
            anchor=tk.W
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X, pady=(10, 0))
    
    def create_sign_tab(self):
        """Create the Sign Document tab"""
        tab = ttk.Frame(self.tab_control)
        self.tab_control.add(tab, text='Sign Document')
        
        # Document selection
        doc_frame = ttk.LabelFrame(tab, text="Document to Sign", padding=10)
        doc_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(
            doc_frame,
            text="Select Document",
            command=self.select_document
        ).pack(side=tk.LEFT, padx=5)
        
        self.doc_path_var = tk.StringVar(value="No document selected")
        ttk.Label(doc_frame, textvariable=self.doc_path_var).pack(side=tk.LEFT, padx=5)
        
        # Key selection
        key_frame = ttk.LabelFrame(tab, text="Signing Key", padding=10)
        key_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(key_frame, text="Key Name:").pack(side=tk.LEFT)
        self.key_name_var = tk.StringVar(value="default")
        key_entry = ttk.Entry(key_frame, textvariable=self.key_name_var, width=20)
        key_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            key_frame,
            text="Generate New Key Pair",
            command=self.generate_key_pair_ui
        ).pack(side=tk.LEFT, padx=5)
        
        # Sign button
        sign_btn = ttk.Button(
            tab,
            text="Sign Document",
            command=self.sign_document,
            style='Accent.TButton'
        )
        sign_btn.pack(pady=20)
        
        # Key info frame
        key_info_frame = ttk.LabelFrame(tab, text="Public Key Info", padding=10)
        key_info_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Text widget for key information
        self.key_info_text = scrolledtext.ScrolledText(
            key_info_frame,
            wrap=tk.WORD,
            font=('Consolas', 9),
            height=8
        )
        self.key_info_text.pack(fill=tk.BOTH, expand=True)
        self.key_info_text.insert(tk.END, "No key loaded")
        self.key_info_text.config(state='disabled')
        
        # Update key info if keys are already loaded
        if hasattr(self.crypto, 'public_key'):
            self.update_key_info()
    
    def create_verify_tab(self):
        """Create the Verify Signature tab"""
        tab = ttk.Frame(self.tab_control)
        self.tab_control.add(tab, text='Verify Signature')
        
        # Document selection
        doc_frame = ttk.LabelFrame(tab, text="Document to Verify", padding=10)
        doc_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(
            doc_frame,
            text="Select Document",
            command=self.select_verify_document
        ).pack(side=tk.LEFT, padx=5)
        
        self.verify_doc_var = tk.StringVar(value="No document selected")
        ttk.Label(doc_frame, textvariable=self.verify_doc_var).pack(side=tk.LEFT, padx=5)
        
        # Signature file selection
        sig_frame = ttk.LabelFrame(tab, text="Signature File", padding=10)
        sig_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(
            sig_frame,
            text="Select Signature File",
            command=self.select_signature_file
        ).pack(side=tk.LEFT, padx=5)
        
        self.sig_path_var = tk.StringVar(value="No signature file selected")
        ttk.Label(sig_frame, textvariable=self.sig_path_var).pack(side=tk.LEFT, padx=5)
        
        # Public key selection
        pubkey_frame = ttk.LabelFrame(tab, text="Public Key (optional)", padding=10)
        pubkey_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(
            pubkey_frame,
            text="Select Public Key",
            command=self.select_public_key
        ).pack(side=tk.LEFT, padx=5)
        
        self.pubkey_path_var = tk.StringVar(value="Use default key")
        ttk.Label(pubkey_frame, textvariable=self.pubkey_path_var).pack(side=tk.LEFT, padx=5)
        
        # Verify button
        verify_btn = ttk.Button(
            tab,
            text="Verify Signature",
            command=self.verify_signature,
            style='Accent.TButton'
        )
        verify_btn.pack(pady=20)
        
        # Verification status and result
        self.verify_status_var = tk.StringVar(value="")
        status_label = ttk.Label(
            tab,
            textvariable=self.verify_status_var,
            font=('Segoe UI', 10)
        )
        status_label.pack(pady=(10, 5))
        
        self.verify_result_var = tk.StringVar(value="")
        result_label = ttk.Label(
            tab,
            textvariable=self.verify_result_var,
            font=('Segoe UI', 12, 'bold')
        )
        result_label.pack(pady=5)
    
    def create_keys_tab(self):
        """Create the Manage Keys tab"""
        tab = ttk.Frame(self.tab_control)
        self.tab_control.add(tab, text='Manage Keys')
        
        # Key generation
        gen_frame = ttk.LabelFrame(tab, text="Generate New Key Pair", padding=10)
        gen_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(gen_frame, text="Key Name:").pack(side=tk.LEFT)
        self.new_key_name = tk.StringVar()
        ttk.Entry(gen_frame, textvariable=self.new_key_name, width=20).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            gen_frame,
            text="Generate",
            command=self.generate_key_pair_ui
        ).pack(side=tk.LEFT, padx=5)
        
        # Key info
        key_info_frame = ttk.LabelFrame(tab, text="Current Key Information", padding=10)
        key_info_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.key_info_text = scrolledtext.ScrolledText(
            key_info_frame,
            wrap=tk.WORD,
            height=10,
            font=('Consolas', 9)
        )
        self.key_info_text.pack(fill=tk.BOTH, expand=True)
        self.update_key_info()
        
        # Export buttons
        btn_frame = ttk.Frame(key_info_frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(
            btn_frame,
            text="Export Public Key",
            command=self.export_public_key
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            btn_frame,
            text="Export Private Key",
            command=self.export_private_key
        ).pack(side=tk.LEFT, padx=5)
    
    # Core functionality methods
    
    def load_keys(self):
        """Load the default key pair if it exists"""
        if self.crypto.load_key_pair(self.current_key_name):
            self.update_key_info()
            self.status_var.set(f"Loaded key pair: {self.current_key_name}")
    
    def update_key_info(self):
        """Update the key information display"""
        if hasattr(self, 'key_info_text') and self.crypto.public_key:
            pub_key = self.crypto.get_public_key_pem().decode('utf-8')
            key_info = f"Public Key (SHA-256): {self.get_key_fingerprint(pub_key)}\n\n{pub_key}"
            self.key_info_text.delete(1.0, tk.END)
            self.key_info_text.insert(tk.END, key_info)
    
    def get_key_fingerprint(self, key_pem: str) -> str:
        """Generate a fingerprint for the key"""
        import hashlib
        # Remove header/footer and whitespace
        key_data = ''.join([line.strip() for line in key_pem.split('\n') 
                          if '-----' not in line])
        key_bytes = key_data.encode('utf-8')
        return hashlib.sha256(key_bytes).hexdigest()
    
    def select_document(self):
        """Open file dialog to select a document to sign"""
        file_path = filedialog.askopenfilename(
            title="Select Document to Sign",
            filetypes=[("All files", "*.*")]
        )
        if file_path:
            self.current_doc_path = file_path
            self.doc_path_var.set(file_path.split('/')[-1])
    
    def select_verify_document(self):
        """Open file dialog to select a document to verify"""
        file_path = filedialog.askopenfilename(
            title="Select Document to Verify",
            filetypes=[("All files", "*.*")]
        )
        if file_path:
            self.verify_doc_var.set(file_path)  # Store full path
            self.current_verify_doc_path = file_path  # Store the full path for verification
    
    def select_signature_file(self):
        """Open file dialog to select a signature file"""
        file_path = filedialog.askopenfilename(
            title="Select Signature File",
            filetypes=[("Signature files", "*.sig"), ("All files", "*.*")]
        )
        if file_path:
            self.current_sig_path = file_path
            self.sig_path_var.set(file_path.split('/')[-1])
    
    def select_public_key(self):
        """Open file dialog to select a public key"""
        file_path = filedialog.askopenfilename(
            title="Select Public Key",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        if file_path:
            self.pubkey_path_var.set(file_path.split('/')[-1])
    
    def generate_key_pair_ui(self):
        """Generate a new key pair from the UI"""
        key_name = self.new_key_name.get().strip()
        if not key_name:
            messagebox.showerror("Error", "Please enter a key name")
            return
            
        try:
            priv_path, pub_path = self.crypto.generate_key_pair(key_name)
            self.current_key_name = key_name
            self.key_name_var.set(key_name)
            self.update_key_info()
            self.status_var.set(f"Generated new key pair: {key_name}")
            messagebox.showinfo("Success", f"Key pair generated successfully in: {priv_path.parent}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate key pair: {str(e)}")
    
    def sign_document(self):
        """Sign the selected document with enhanced options"""
        if not hasattr(self, 'current_doc_path') or not self.current_doc_path:
            messagebox.showerror("Error", "Please select a document to sign")
            return
            
        # Check if we have a private key
        if not self.crypto.private_key:
            messagebox.showerror("Error", "No private key available for signing")
            return
            
        # Get output path for signature
        default_name = f"{Path(self.current_doc_path).stem}.sig"
        output_path = filedialog.asksaveasfilename(
            title="Save Signature As",
            defaultextension=".sig",
            initialfile=default_name,
            filetypes=[
                ("Signature files", "*.sig"), 
                ("JSON files", "*.json"),
                ("All files", "*.*")
            ]
        )
        
        if not output_path:
            return  # User cancelled
            
        try:
            # Show progress
            self.status_var.set("Signing document...")
            self.root.update()
            
            # Sign the document
            signature, signature_b64 = self.crypto.sign_document(self.current_doc_path, output_path)
            
            # Update status
            doc_name = Path(self.current_doc_path).name
            sig_name = Path(output_path).name
            status_msg = f"✓ Document '{doc_name}' signed successfully"
            
            # Show success message with details
            details = (
                f"Document: {doc_name}\n"
                f"Signature saved to: {sig_name}\n"
                f"Signature size: {len(signature)} bytes\n"
                f"Algorithm: SHA256withRSA\n"
                f"Key size: {self.crypto.private_key.size_in_bits()} bits"
            )
            
            self.status_var.set(status_msg)
            messagebox.showinfo("Signing Successful", details)
            
            # Update key info display
            self.update_key_info()
            
        except Exception as e:
            error_msg = f"Failed to sign document: {str(e)}"
            self.status_var.set(f"Error: {error_msg}")
            messagebox.showerror("Signing Failed", error_msg, detail=str(e))
    
    def verify_signature(self):
        """Verify a document's signature with enhanced validation"""
        # Get the document path from the stored variable instead of the display text
        doc_path = getattr(self, 'current_verify_doc_path', '')
        sig_path = self.current_sig_path
        pubkey_path = self.pubkey_path_var.get()
        
        if not doc_path or not sig_path:
            messagebox.showerror("Error", "Please select both document and signature file")
            return
            
        # Use default key if no custom key is selected
        pubkey = pubkey_path if pubkey_path and pubkey_path != "Use default key" else None
        
        try:
            # Show progress
            self.verify_status_var.set("Verifying signature...")
            self.root.update()
            
            # Verify the signature with enhanced validation
            result = self.crypto.verify_signature(doc_path, sig_path, pubkey)
            
            # Prepare verification details
            doc_name = Path(doc_path).name
            sig_name = Path(sig_path).name
            
            # Format the verification results
            if result['valid'] and not result['altered']:
                # Successful verification
                status_icon = "✓"
                status_text = "Signature is valid and document is unaltered"
                message_title = "Verification Successful"
                message_type = "showinfo"
            else:
                # Failed verification
                status_icon = "✗"
                if result['altered']:
                    status_text = "Document has been altered!"
                else:
                    status_text = "Signature is invalid!"
                message_title = "Verification Failed"
                message_type = "showerror"
            
            # Update status
            self.verify_status_var.set(f"{status_icon} {status_text}")
            
            # Prepare detailed message
            details = [
                f"Document: {doc_name}",
                f"Signature: {sig_name}",
                f"Status: {status_text}",
                "",
                "Verification Details:",
                f"- Signature valid: {'Yes' if result['valid'] else 'No'}",
                f"- Document altered: {'Yes' if result['altered'] else 'No'}",
            ]
            
            # Add metadata if available
            if result.get('metadata'):
                details.append("\nSignature Metadata:")
                for key, value in result['metadata'].items():
                    if key != 'signature':  # Don't show the actual signature
                        details.append(f"- {key.replace('_', ' ').title()}: {value}")
            
            # Show the appropriate message box
            getattr(messagebox, message_type)(
                message_title,
                "\n".join(details)
            )
            
            # Log the verification result
            try:
                scans_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'scans')
                os.makedirs(scans_dir, exist_ok=True)
                log_file_path = os.path.join(scans_dir, 'scan_log.txt')
                with open(log_file_path, 'a', encoding='utf-8') as log_file:
                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    log_file.write(
                        f"[{timestamp}] Verification - "
                        f"Document: {os.path.basename(doc_path)}, "
                        f"Signature: {os.path.basename(sig_path)}, "
                        f"Key: {'default' if pubkey is None else os.path.basename(pubkey)}, "
                        f"Result: {'VALID' if result['valid'] else 'INVALID'}\n"
                    )
            except Exception as log_error:
                print(f"Failed to write to log file: {log_error}")
                
        except Exception as e:
            error_msg = f"Verification failed: {str(e)}"
            self.verify_status_var.set(f"✗ {error_msg}")
            messagebox.showerror("Verification Error", error_msg, detail=str(e))
            
            # Log the error
            try:
                scans_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'scans')
                os.makedirs(scans_dir, exist_ok=True)
                log_file_path = os.path.join(scans_dir, 'scan_log.txt')
                with open(log_file_path, 'a', encoding='utf-8') as log_file:
                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    log_file.write(f"[{timestamp}] ERROR: {error_msg}\n")
            except Exception as log_error:
                print(f"Failed to write error to log file: {log_error}")
    
    def export_public_key(self):
        """Export the public key to a file"""
        if not self.crypto.public_key:
            messagebox.showerror("Error", "No public key available to export")
            return
            
        output_path = filedialog.asksaveasfilename(
            title="Save Public Key As",
            defaultextension=".pem",
            initialfile=f"{self.current_key_name}_public.pem",
            filetypes=[("PEM files", "*.pem"), ("All files", "*")]
        )
        
        if output_path:
            try:
                with open(output_path, 'wb') as f:
                    f.write(self.crypto.get_public_key_pem())
                self.status_var.set(f"Public key exported to: {output_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export public key: {str(e)}")
    
    def export_private_key(self):
        """Export the private key to a file (with warning)"""
        if not messagebox.askyesno(
            "Security Warning",
            "WARNING: Your private key should be kept secure. "
            "Only export it if you know what you're doing.\n\n"
            "Are you sure you want to export your private key?"
        ):
            return
            
        if not self.crypto.private_key:
            messagebox.showerror("Error", "No private key available to export")
            return
            
        output_path = filedialog.asksaveasfilename(
            title="Save Private Key As",
            defaultextension=".pem",
            initialfile=f"{self.current_key_name}_private.pem",
            filetypes=[("PEM files", "*.pem"), ("All files", "*")]
        )
        
        if output_path:
            try:
                with open(output_path, 'wb') as f:
                    f.write(self.crypto.get_private_key_pem())
                self.status_var.set(f"Private key exported to: {output_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export private key: {str(e)}")
    
    def create_qr_tab(self):
        """Create the QR Code tab for generating and scanning QR codes"""
        tab = ttk.Frame(self.tab_control)
        self.tab_control.add(tab, text='QR Code')
        
        # Configure grid weights
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)
        
        # Create notebook for QR operations
        qr_notebook = ttk.Notebook(tab)
        qr_notebook.grid(row=0, column=0, sticky='nsew', padx=5, pady=5)
        
        # Create QR Generator tab if available
        if QR_GENERATOR_AVAILABLE:
            self.create_qr_generator_tab(qr_notebook)
        else:
            tab = ttk.Frame(qr_notebook)
            ttk.Label(tab, text="QR Generator not available. Please install required dependencies.").pack(pady=20)
            qr_notebook.add(tab, text='Generate QR')
        
        # Create QR Scanner tab if available
        if QR_SCANNER_AVAILABLE:
            self.create_qr_scanner_tab(qr_notebook)
        else:
            tab = ttk.Frame(qr_notebook)
            ttk.Label(tab, text="QR Scanner not available. Please install OpenCV and other required dependencies.").pack(pady=20)
            qr_notebook.add(tab, text='Scan QR')
    
    def create_qr_generator_tab(self, parent):
        """Create QR code generator tab with improved layout"""
        # Main container frame with padding
        tab = ttk.Frame(parent, padding=10)
        parent.add(tab, text='Generate QR')
        
        # Configure grid weights
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)
        
        # Input frame with scrollbar
        input_frame = ttk.LabelFrame(tab, text="Input Data", padding=10)
        input_frame.grid(row=0, column=0, sticky='nsew', padx=5, pady=5)
        input_frame.columnconfigure(1, weight=1)
        
        # Name field
        ttk.Label(input_frame, text="Name:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.qr_name_var = tk.StringVar()
        name_entry = ttk.Entry(input_frame, textvariable=self.qr_name_var)
        name_entry.grid(row=0, column=1, sticky='ew', padx=5, pady=5)
        
        # ID field
        ttk.Label(input_frame, text="ID/NIK:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.qr_id_var = tk.StringVar()
        id_entry = ttk.Entry(input_frame, textvariable=self.qr_id_var)
        id_entry.grid(row=1, column=1, sticky='ew', padx=5, pady=5)
        
        # Additional info
        ttk.Label(input_frame, text="Additional Info (JSON):").grid(row=2, column=0, sticky=tk.NW, pady=5)
        
        # Create a frame for the JSON text and scrollbar
        json_frame = ttk.Frame(input_frame)
        json_frame.grid(row=2, column=1, sticky='nsew', padx=5, pady=5)
        json_frame.columnconfigure(0, weight=1)
        json_frame.rowconfigure(0, weight=1)
        
        # JSON text area with scrollbar
        self.extra_info_text = scrolledtext.ScrolledText(
            json_frame, 
            width=40, 
            height=10,
            wrap=tk.WORD,
            font=('Consolas', 9)
        )
        self.extra_info_text.grid(row=0, column=0, sticky='nsew')
        
        # Right side - QR Code Preview
        qr_frame = ttk.LabelFrame(tab, text="QR Code Preview", padding=15)
        qr_frame.grid(row=0, column=1, padx=5, pady=5, sticky='nsew')
        qr_frame.columnconfigure(0, weight=1)
        qr_frame.rowconfigure(1, weight=1)
        
        # QR Code display
        self.qr_code_label = ttk.Label(qr_frame, text="QR Code will appear here", 
                                    font=('Arial', 10, 'italic'),
                                    relief='solid', 
                                    padding=20)
        self.qr_code_label.grid(row=0, column=0, pady=20, sticky='n')
        
        # Status label
        self.qr_status_label = ttk.Label(qr_frame, 
                                      text="Enter information and click 'Generate'",
                                      foreground='green',
                                      font=('Arial', 9))
        self.qr_status_label.grid(row=1, column=0, pady=10, sticky='s')
        
        # Button frame at bottom
        button_frame = ttk.Frame(tab)
        button_frame.grid(row=1, column=1, sticky='sew', padx=5, pady=5)
        button_frame.columnconfigure(0, weight=1)
        
        # Action buttons
        btn_frame = ttk.Frame(button_frame)
        btn_frame.grid(row=0, column=0, sticky='e')
        
        # Generate button
        ttk.Button(
            btn_frame,
            text="🔄 Generate QR Code",
            command=self.generate_qr_code,
            style='Accent.TButton',
            width=20,
            padding=5
        ).pack(side=tk.LEFT, padx=5)
        
        # Save button
        self.save_qr_btn = ttk.Button(
            btn_frame,
            text="💾 Save QR Code",
            command=self.save_qr_code,
            state=tk.DISABLED,
            style='Accent.TButton',
            width=20,
            padding=5
        )
        self.save_qr_btn.pack(side=tk.LEFT, padx=5)
        
        # Configure styles
        style = ttk.Style()
        style.configure('Accent.TButton', 
                      font=('Arial', 10, 'bold'),
                      foreground='white',
                      padding=10)
        style.configure('TLabel', font=('Arial', 10))
        style.configure('TEntry', font=('Arial', 10))
        
        # Status bar
        status_bar = ttk.Frame(tab, height=25, style='Status.TFrame')
        status_bar.grid(row=3, column=0, sticky='ew', pady=(5, 0))
        status_bar.columnconfigure(0, weight=1)
        
        self.qr_status_var = tk.StringVar()
        status_label = ttk.Label(
            status_bar, 
            textvariable=self.qr_status_var, 
            foreground="green",
            anchor='w',
            padding=(5, 2)
        )
        status_label.grid(row=0, column=0, sticky='ew')
        
        # Set initial focus to name field
        name_entry.focus_set()
    
    def create_qr_scanner_tab(self, parent):
        """Create QR code scanner tab"""
        tab = ttk.Frame(parent)
        parent.add(tab, text='Scan QR')
        
        # Video frame
        self.video_frame = ttk.Label(tab)
        self.video_frame.pack(pady=10)
        
        # Scan button
        self.scan_btn = ttk.Button(
            tab,
            text="Start Scanning",
            command=self.toggle_scanning
        )
        self.scan_btn.pack(pady=5)
        
        # Scanned data
        ttk.Label(tab, text="Scanned Data:", font=('Arial', 10, 'bold')).pack(pady=5)
        self.scanned_data_text = scrolledtext.ScrolledText(tab, width=50, height=10, state='disabled')
        self.scanned_data_text.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)
        
        # Scanner state
        self.scanner = None
        self.scanning = False
        self.after_id = None
    
    def toggle_scanning(self):
        """Toggle QR code scanning on/off"""
        if not self.scanning:
            self.start_scanning()
        else:
            self.stop_scanning()
    
    def start_scanning(self):
        """Start the QR code scanner"""
        try:
            if self.scanner is None:
                self.scanner = QRScanner()
                if not self.scanner.start_camera():
                    messagebox.showerror("Error", "Could not access camera. Make sure no other application is using the camera.")
                    self.scanner = None
                    return
            
            self.scanning = True
            self.scan_btn.config(text="Stop Scanning", style='Accent.TButton')
            self.scanned_data_text.config(state='normal')
            self.scanned_data_text.delete(1.0, tk.END)
            self.scanned_data_text.insert(tk.END, "Camera started. Point the camera at a QR code...")
            self.scanned_data_text.config(state='disabled')
            self.update_scanner()
        except Exception as e:
            messagebox.showerror("Camera Error", f"Failed to start camera: {str(e)}")
            self.stop_scanning()
    
    def stop_scanning(self):
        """Stop the QR code scanner"""
        self.scanning = False
        if hasattr(self, 'scan_btn'):
            self.scan_btn.config(text="Start Scanning", style='TButton')
        if hasattr(self, 'after_id') and self.after_id:
            self.root.after_cancel(self.after_id)
            self.after_id = None
            
        # Clear the video frame
        if hasattr(self, 'video_frame'):
            self.video_frame.config(image='')
            
        # Release camera resources
        if hasattr(self, 'scanner') and self.scanner:
            self.scanner.stop_camera()
            self.scanner = None
    
    def update_scanner(self):
        """Update the scanner frame"""
        if not self.scanning or not self.scanner:
            return
            
        try:
            ret, frame = self.scanner.cap.read()
            if not ret:
                self.scanned_data_text.config(state='normal')
                self.scanned_data_text.delete(1.0, tk.END)
                self.scanned_data_text.insert(tk.END, "Error: Could not read from camera")
                self.scanned_data_text.config(state='disabled')
                self.stop_scanning()
                return
                
            # Convert to RGB and resize for display
            frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            frame = cv2.resize(frame, (640, 480))  # Larger preview
            
            # Draw a rectangle in the center to guide the user
            h, w, _ = frame.shape
            center_x, center_y = w // 2, h // 2
            size = min(w, h) // 2
            cv2.rectangle(
                frame,
                (center_x - size, center_y - size),
                (center_x + size, center_y + size),
                (0, 255, 0),  # Green color
                2
            )
            
            # Only process QR codes in the center rectangle
            roi = frame[center_y-size:center_y+size, center_x-size:center_x+size]
            
            # Try to decode QR code
            decoded_objects = decode(roi)
            if decoded_objects:
                data = decoded_objects[0].data.decode('utf-8')
                self.process_scanned_data(data)
                self.stop_scanning()
                return
            
            # Convert to PhotoImage and update label
            img = Image.fromarray(frame)
            imgtk = ImageTk.PhotoImage(image=img)
            self.video_frame.imgtk = imgtk
            self.video_frame.configure(image=imgtk)
            
        except Exception as e:
            self.scanned_data_text.config(state='normal')
            self.scanned_data_text.delete(1.0, tk.END)
            self.scanned_data_text.insert(tk.END, f"Error during scanning: {str(e)}")
            self.scanned_data_text.config(state='disabled')
            self.stop_scanning()
            return
        
        # Schedule next update (30 FPS)
        self.after_id = self.root.after(33, self.update_scanner)
    
    def process_scanned_data(self, data):
        """Process and display scanned QR code data"""
        try:
            # Try to parse as JSON
            parsed_data = json.loads(data)
            formatted_data = json.dumps(parsed_data, indent=2, ensure_ascii=False)
            data_type = "JSON Data"
        except json.JSONDecodeError:
            # If not JSON, display as plain text
            formatted_data = data
            data_type = "Text Data"
        
        # Update the UI in a thread-safe way
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.scanned_data_text.config(state='normal')
        self.scanned_data_text.delete(1.0, tk.END)
        self.scanned_data_text.insert(tk.END, f"=== QR Code Scanned at {timestamp} ===\n")
        self.scanned_data_text.insert(tk.END, f"Type: {data_type}\n\n")
        self.scanned_data_text.insert(tk.END, formatted_data)
        self.scanned_data_text.config(state='disabled')
        
        # Auto-scroll to the bottom
        self.scanned_data_text.see(tk.END)
        
        # Play a beep sound to indicate successful scan
        try:
            import winsound
            winsound.Beep(1000, 200)  # Frequency: 1000Hz, Duration: 200ms
        except:
            pass  # Beep is not critical, so we can ignore errors
    
    def validate_json(self):
        """Validate the JSON in the additional info field"""
        try:
            extra_info = self.extra_info_text.get('1.0', tk.END).strip()
            if extra_info:  # Only validate if there's content
                json.loads(extra_info)
                messagebox.showinfo("Success", "JSON is valid!")
            return True
        except json.JSONDecodeError as e:
            messagebox.showerror("JSON Error", f"Invalid JSON: {str(e)}\n\nPlease check your JSON syntax.")
            return False
    
    def generate_qr_code(self):
        """Generate a QR code from the input data"""
        name = self.qr_name_var.get().strip()
        id_num = self.qr_id_var.get().strip()
        extra_info = self.extra_info_text.get('1.0', tk.END).strip()
        
        if not name or not id_num:
            messagebox.showerror("Error", "Name and ID are required")
            return
        
        try:
            # Handle additional info - if empty, use None, otherwise parse as JSON
            extra_data = None
            if extra_info:  # Only parse if there's content
                try:
                    parsed = json.loads(extra_info)
                    if not isinstance(parsed, dict):
                        raise ValueError("Additional info must be a JSON object")
                    extra_data = parsed
                except json.JSONDecodeError as e:
                    raise ValueError(f"Invalid JSON in additional info: {str(e)}")
                except ValueError as e:
                    raise ValueError(f"Invalid data format: {str(e)}")
            
            # Format data
            formatter = DataFormatter()
            try:
                data = formatter.format_identity_data(
                    name=name,
                    id_number=id_num,
                    additional_info=extra_data if extra_data else None  # Pass None if empty dict
                )
            except Exception as e:
                # Play error sound if available
                try:
                    import winsound
                    winsound.Beep(500, 300)  # Low pitch beep for error
                except:
                    pass
                raise ValueError(f"Failed to format data: {str(e)}")
                
            # Generate QR code
            try:
                qr_gen = QRGenerator()
                self.qr_image = qr_gen.create_qr_code(data)
            except Exception as e:
                raise ValueError(f"Failed to generate QR code: {str(e)}")
            
            # Display QR code
            self.display_qr_code(self.qr_image)
            
            # Don't clear the additional info field after generation
            # as the user might want to generate multiple similar QR codes
            
            # Play success sound if available
            try:
                import winsound
                winsound.Beep(1000, 200)  # High pitch beep for success
            except:
                pass
            
        except Exception as e:
            error_msg = f"Failed to generate QR code: {str(e)}"
            self.qr_status_label.config(text=error_msg, foreground='red')
            messagebox.showerror("Error", error_msg)
            
            # Play error sound if available
            try:
                import winsound
                winsound.Beep(500, 300)  # Low pitch beep for error
            except:
                pass
    
    def display_qr_code(self, image):
        """Display the generated QR code with enhanced visualization"""
        try:
            # Store the original image for saving
            self.qr_image = image
            
            # Resize the image to make it smaller (e.g., 200x200)
            size = (200, 200)
            display_image = image.resize(size, Image.Resampling.LANCZOS)
            
            # Convert PIL Image to PhotoImage and keep a reference
            self.qr_photo = ImageTk.PhotoImage(display_image)
            
            # Update the QR code label with centered image
            self.qr_code_label.config(
                image=self.qr_photo,
                text='',  # Remove any placeholder text
                compound='center',  # Center the image in the label
                anchor='center'     # Center the image in the label
            )
            
            # Update status
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            self.qr_status_label.config(
                text=f"QR code generated at {timestamp}",
                foreground='green'
            )
            
            # Enable save button
            self.save_qr_btn.config(state=tk.NORMAL)
            
            # Play success sound if available
            try:
                import winsound
                winsound.Beep(1000, 200)  # High pitch beep for success
            except:
                pass
                
        except Exception as e:
            error_msg = f"Failed to display QR code: {str(e)}"
            self.qr_status_label.config(text=error_msg, foreground='red')
            messagebox.showerror("Error", error_msg)

    def save_qr_code(self):
        """Save the generated QR code to a file with enhanced options"""
        if not hasattr(self, 'qr_image'):
            messagebox.showerror("Error", "No QR code to save. Please generate a QR code first.")
            return

        try:
            # Get name and ID from the input fields
            name = self.name_entry.get().strip() or "qr_code"
            id_num = self.id_entry.get().strip() or ""

            # Clean up the name for filename
            clean_name = "".join([c if c.isalnum() or c in ('_', '-') else '_' for c in name])
            clean_id = "".join([c if c.isalnum() or c in ('_', '-') else '_' for c in id_num])

            # Create default filename with timestamp
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            default_name = f"{clean_name}_{clean_id}_{timestamp}.png" if clean_id else f"{clean_name}_{timestamp}.png"

            # Open file dialog
            file_path = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[
                    ("PNG files", "*.png"),
                    ("JPEG files", "*.jpg;*.jpeg"),
                    ("All files", "*.*")
                ],
                initialfile=default_name,
                title="Save QR Code As"
            )

            if file_path:
                # Save the image with high quality
                self.qr_image.save(file_path, quality=95)
                
                # Update status
                self.qr_status_label.config(
                    text=f"QR code saved to: {file_path}",
                    foreground='green'
                )
                
                # Play success sound if available
                try:
                    import winsound
                    winsound.Beep(1000, 200)  # High pitch beep for success
                except:
                    pass
                
        except PermissionError:
            error_msg = "Permission denied. Please choose a different location or check file permissions."
            self.qr_status_label.config(text=error_msg, foreground='red')
            messagebox.showerror("Save Error", error_msg)
        except Exception as e:
            error_msg = f"Failed to save QR code: {str(e)}"
            self.qr_status_label.config(text=error_msg, foreground='red')
            messagebox.showerror("Save Error", error_msg)
                
        except Exception as e:
            error_msg = f"Failed to save QR code: {str(e)}"
            self.qr_status_label.config(text=error_msg, foreground='red')
            messagebox.showerror("Error", error_msg)
            
            ttk.Label(
                title_frame,
                text="QR Code Generated Successfully",
                font=('Arial', 12, 'bold')
            ).pack(side=tk.LEFT)
            
            # Create a container for QR code and metadata side by side
            content_frame = ttk.Frame(self.qr_display_frame)
            content_frame.pack(fill=tk.BOTH, expand=True)
            
            # Left side - QR Code
            qr_frame = ttk.LabelFrame(
                content_frame,
                text=" Scan Me ",
                padding=15,
                style='Card.TFrame'
            )
            qr_frame.pack(side=tk.LEFT, padx=(0, 15), fill=tk.BOTH, expand=True)
            
            # Convert to PhotoImage with better scaling and padding
            qr_img = image.resize((280, 280), Image.Resampling.LANCZOS)
            self.qr_photo = ImageTk.PhotoImage(qr_img)
            
            # Display QR code with a subtle border
            qr_label = ttk.Label(
                qr_frame, 
                image=self.qr_photo,
                borderwidth=2,
                relief="solid",
                padding=5
            )
            qr_label.pack(expand=True)
            
            # Right side - Metadata
            metadata_frame = ttk.LabelFrame(
                content_frame,
                text=" Information ",
                padding=15,
                style='Card.TFrame'
            )
            metadata_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            
            # Display basic info with better formatting
            name = self.qr_name_var.get().strip()
            id_num = self.qr_id_var.get().strip()
            
            # Create a styled label for better readability
            info_style = ttk.Style()
            info_style.configure('Info.TLabel', font=('Arial', 10))
            
            # Name field
            ttk.Label(
                metadata_frame,
                text="Name:",
                font=('Arial', 10, 'bold'),
                foreground='#555555'
            ).pack(anchor=tk.W, pady=(0, 2))
            
            ttk.Label(
                metadata_frame,
                text=name,
                style='Info.TLabel',
                wraplength=250
            ).pack(anchor=tk.W, pady=(0, 10))
            
            # ID field
            ttk.Label(
                metadata_frame,
                text="ID Number:",
                font=('Arial', 10, 'bold'),
                foreground='#555555'
            ).pack(anchor=tk.W, pady=(0, 2))
            
            ttk.Label(
                metadata_frame,
                text=id_num,
                style='Info.TLabel'
            ).pack(anchor=tk.W, pady=(0, 10))
            
            # Timestamp
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ttk.Label(
                metadata_frame,
                text="Generated on:",
                font=('Arial', 9, 'italic'),
                foreground='#777777'
            ).pack(anchor=tk.W, pady=(10, 2))
            
            ttk.Label(
                metadata_frame,
                text=timestamp,
                font=('Arial', 9),
                foreground='#555555'
            ).pack(anchor=tk.W)
            
            # Make save button more prominent and visible
            self.save_qr_btn.config(
                state=tk.NORMAL,
                style='Accent.TButton'
            )
            # Ensure save button is visible and enabled
            self.save_qr_btn.config(state=tk.NORMAL)
            self.save_qr_btn.lift()
            self.root.update_idletasks()
            
            # Add a subtle animation effect
            try:
                self.qr_display_frame.after(50, lambda: self.qr_display_frame.configure(style='Card.TFrame'))
            except:
                pass
            
        except Exception as e:
            error_msg = f"Failed to display QR code: {str(e)}"
            self.qr_status_var.set("Error: " + error_msg)
            messagebox.showerror("Display Error", error_msg)
    
    def save_qr_code(self):
        """Save the generated QR code to a file with enhanced options"""
        if not hasattr(self, 'qr_image'):
            messagebox.showerror("Error", "No QR code available to save")
            return
            
        # Suggest a filename based on the name and ID
        default_name = f"QR_{self.qr_name_var.get().strip()}_{self.qr_id_var.get().strip()}.png"
        default_name = "".join(c if c.isalnum() or c in ('_', '-') else '_' for c in default_name)
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".png",
            initialfile=default_name,
            filetypes=[
                ("PNG files", "*.png"),
                ("JPEG files", "*.jpg;*.jpeg"),
                ("All files", "*.*")
            ],
            title="Save QR Code As"
        )
        
        if file_path:
            try:
                # Create the directory if it doesn't exist
                os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
                
                # Save with high quality
                self.qr_image.save(file_path, quality=95)
                
                # Show success message with path
                success_msg = f"QR code successfully saved to:\n{os.path.abspath(file_path)}"
                self.qr_status_var.set("✓ " + success_msg)
                messagebox.showinfo("Success", success_msg)
                
            except PermissionError:
                error_msg = "Permission denied. Please choose a different location or check file permissions."
                self.qr_status_var.set("Error: " + error_msg)
                messagebox.showerror("Save Error", error_msg)
            except Exception as e:
                error_msg = f"Failed to save QR code: {str(e)}"
                self.qr_status_var.set("Error: " + error_msg)
                messagebox.showerror("Save Error", error_msg)
    
    def on_close(self):
        """Handle window close event"""
        try:
            # Stop any running scans
            if hasattr(self, 'stop_scanning'):
                self.stop_scanning()
            
            # Clean up any resources
            if hasattr(self, 'scanner') and self.scanner:
                self.scanner.stop_camera()
                self.scanner = None
                
            # Close the window
            self.root.destroy()
        except Exception as e:
            print(f"Error during close: {e}")
            self.root.destroy()
    
    def cleanup_qr_code_stuff(self):
        """Clean up any remaining QR code related attributes"""
        self.stop_scanning()
        if hasattr(self, 'scanner') and self.scanner:
            self.scanner.stop_camera()
            self.scanner = None
        
    def update_key_info(self):
        """Update the key information display"""
        if hasattr(self, 'key_info_text') and self.crypto.public_key:
            try:
                pub_key = self.crypto.get_public_key_pem().decode('utf-8')
                key_info = f"Public Key (SHA-256): {self.get_key_fingerprint(pub_key)}\n\n{pub_key}"
                self.key_info_text.delete(1.0, tk.END)
                self.key_info_text.insert(tk.END, key_info)
            except Exception as e:
                self.key_info_text.delete(1.0, tk.END)
                self.key_info_text.insert(tk.END, f"Error loading key info: {str(e)}")
    
    def get_key_fingerprint(self, key_pem: str) -> str:
        """Generate a fingerprint for the key"""
        # Remove header/footer and whitespace
        key_data = ''.join([line.strip() for line in key_pem.split('\n') 
                          if '-----' not in line])
        key_bytes = key_data.encode('utf-8')
        return hashlib.sha256(key_bytes).hexdigest()
    
    def generate_key_pair_ui(self):
        """Generate a new key pair from the UI"""
        key_name = self.key_name_var.get().strip()
        if not key_name:
            messagebox.showerror("Error", "Please enter a key name")
            return
            
        try:
            priv_path, pub_path = self.crypto.generate_key_pair(key_name)
            self.current_key_name = key_name
            self.key_name_var.set(key_name)
            self.update_key_info()
            self.status_var.set(f"Generated new key pair: {key_name}")
            messagebox.showinfo("Success", f"Key pair generated successfully in: {self.crypto.keys_dir}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate key pair: {str(e)}")

def main():
    """Main entry point for the application."""
    root = tk.Tk()
    app = CryptoSignApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
