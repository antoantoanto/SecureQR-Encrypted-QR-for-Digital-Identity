"""
QR Display Window for SecureQR Application

This module provides a window to display QR codes with additional functionality
like zooming, saving, and displaying metadata.
"""

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
from datetime import datetime
from typing import Optional, Dict, Any, Union, Tuple
import json


class QRDisplayWindow(tk.Toplevel):
    """A window to display QR codes with additional functionality."""
    
    def __init__(
        self, 
        parent,
        qr_data: Union[bytes, str],
        title: str = "QR Code",
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        """
        Initialize the QR display window.
        
        Args:
            parent: The parent window
            qr_data: The QR code data (bytes or string)
            title: Window title
            metadata: Optional metadata to display
            **kwargs: Additional arguments to pass to Toplevel
        """
        super().__init__(parent, **kwargs)
        self.parent = parent
        self.title(title)
        self.qr_data = qr_data if isinstance(qr_data, bytes) else qr_data.encode('utf-8')
        self.metadata = metadata or {}
        self.zoom_level = 1.0
        self.photo_image = None
        
        # Configure window
        self.geometry("600x700")
        self.minsize(400, 500)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Create UI
        self.create_widgets()
        self.display_qr_code()
        
        # Center the window
        self.update_idletasks()
        self.center_window()
    
    def create_widgets(self):
        """Create and arrange the widgets in the window."""
        # Main container
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # QR code display area
        qr_frame = ttk.LabelFrame(main_frame, text="QR Code", padding="10")
        qr_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Canvas for QR code with scrollbars
        self.canvas = tk.Canvas(qr_frame, bg='white', highlightthickness=0)
        
        # Add scrollbars
        v_scroll = ttk.Scrollbar(qr_frame, orient="vertical", command=self.canvas.yview)
        h_scroll = ttk.Scrollbar(qr_frame, orient="horizontal", command=self.canvas.xview)
        self.canvas.configure(
            yscrollcommand=v_scroll.set,
            xscrollcommand=h_scroll.set
        )
        
        # Grid layout for canvas and scrollbars
        self.canvas.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")
        qr_frame.grid_rowconfigure(0, weight=1)
        qr_frame.grid_columnconfigure(0, weight=1)
        
        # Metadata display
        if self.metadata:
            self.create_metadata_display(main_frame)
        
        # Button frame
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        # Buttons
        ttk.Button(
            btn_frame, 
            text="Save QR Code", 
            command=self.save_qr_code
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            btn_frame, 
            text="Zoom In", 
            command=lambda: self.adjust_zoom(1.2)
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            btn_frame, 
            text="Zoom Out", 
            command=lambda: self.adjust_zoom(0.8)
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            btn_frame, 
            text="Copy to Clipboard", 
            command=self.copy_to_clipboard
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            btn_frame, 
            text="Close", 
            command=self.on_close
        ).pack(side=tk.RIGHT, padx=5)
        
        # Configure grid weights
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(0, weight=1)
    
    def create_metadata_display(self, parent):
        """Create a display for the metadata."""
        metadata_frame = ttk.LabelFrame(parent, text="QR Code Information", padding="10")
        metadata_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Create a text widget with scrollbar
        text_frame = ttk.Frame(metadata_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        text = tk.Text(
            text_frame, 
            wrap=tk.WORD, 
            height=6,
            font=('Consolas', 9),
            padx=5,
            pady=5
        )
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(text_frame, command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)
        
        # Grid layout
        text.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        text_frame.columnconfigure(0, weight=1)
        text_frame.rowconfigure(0, weight=1)
        
        # Insert metadata as formatted JSON
        try:
            formatted_json = json.dumps(self.metadata, indent=2, ensure_ascii=False)
            text.insert(tk.END, formatted_json)
        except Exception as e:
            text.insert(tk.END, f"Error formatting metadata: {str(e)}")
        
        # Make text read-only
        text.config(state=tk.DISABLED)
    
    def display_qr_code(self):
        """Display the QR code in the canvas."""
        try:
            # Create a PhotoImage from the QR code data
            image = Image.open(io.BytesIO(self.qr_data))
            
            # Apply zoom
            new_width = int(image.width * self.zoom_level)
            new_height = int(image.height * self.zoom_level)
            image = image.resize((new_width, new_height), Image.Resampling.LANCZOS)
            
            # Convert to PhotoImage
            self.photo_image = ImageTk.PhotoImage(image)
            
            # Clear canvas and display the image
            self.canvas.delete("all")
            self.canvas.create_image(0, 0, anchor=tk.NW, image=self.photo_image)
            
            # Update scroll region
            self.canvas.config(
                scrollregion=self.canvas.bbox(tk.ALL),
                width=new_width,
                height=min(new_height, 400)  # Limit height
            )
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to display QR code: {str(e)}")
    
    def adjust_zoom(self, factor: float):
        """Adjust the zoom level of the QR code.
        
        Args:
            factor: The zoom factor (e.g., 1.2 for zoom in, 0.8 for zoom out)
        """
        self.zoom_level *= factor
        self.zoom_level = max(0.1, min(self.zoom_level, 5.0))  # Limit zoom range
        self.display_qr_code()
    
    def save_qr_code(self):
        """Save the QR code to a file."""
        try:
            # Suggest a filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_filename = f"qr_code_{timestamp}.png"
            
            # Open file dialog
            file_path = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[
                    ("PNG files", "*.png"),
                    ("JPEG files", "*.jpg;*.jpeg"),
                    ("All files", "*.*")
                ],
                initialfile=default_filename,
                title="Save QR Code As"
            )
            
            if file_path:
                # Save the QR code
                with open(file_path, 'wb') as f:
                    f.write(self.qr_data)
                messagebox.showinfo("Success", f"QR code saved to:\n{file_path}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save QR code: {str(e)}")
    
    def copy_to_clipboard(self):
        """Copy the QR code to the clipboard."""
        try:
            import win32clipboard
            from io import BytesIO
            
            # Convert to image and copy to clipboard
            image = Image.open(BytesIO(self.qr_data))
            output = BytesIO()
            image.convert('RGB').save(output, 'BMP')
            data = output.getvalue()[14:]  # Remove BMP header
            output.close()
            
            win32clipboard.OpenClipboard()
            win32clipboard.EmptyClipboard()
            win32clipboard.SetClipboardData(win32clipboard.CF_DIB, data)
            win32clipboard.CloseClipboard()
            
            messagebox.showinfo("Success", "QR code copied to clipboard")
            
        except ImportError:
            messagebox.showerror("Error", "Clipboard functionality requires pywin32")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy to clipboard: {str(e)}")
    
    def center_window(self):
        """Center the window on the screen."""
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')
    
    def on_close(self):
        """Handle window close event."""
        if self.photo_image:
            self.photo_image = None  # Prevent memory leaks
        self.destroy()


# Example usage
if __name__ == "__main__":
    import io
    import qrcode
    
    # Create a sample QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data("https://example.com")
    qr.make(fit=True)
    
    # Convert to bytes
    img = qr.make_image(fill_color="black", back_color="white")
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    qr_data = img_byte_arr.getvalue()
    
    # Sample metadata
    metadata = {
        "type": "URL",
        "url": "https://example.com",
        "generated_at": datetime.now().isoformat(),
        "size": f"{img.size[0]}x{img.size[1]} pixels",
        "format": "PNG"
    }
    
    # Create and run the application
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    
    # Create and display the QR code window
    qr_window = QRDisplayWindow(
        root,
        qr_data,
        title="Example QR Code",
        metadata=metadata
    )
    
    # Run the application
    root.mainloop()
