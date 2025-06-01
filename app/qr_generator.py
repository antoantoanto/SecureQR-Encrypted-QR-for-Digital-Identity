import qrcode
from qrcode.image.styledpil import StyledPilImage
from qrcode.image.styles.colormasks import RadialGradiantColorMask
from io import BytesIO
import base64
from PIL import Image
import os

class QRGenerator:
    def __init__(self, version=1, box_size=10, border=4, error_correction=qrcode.constants.ERROR_CORRECT_H):
        """Initialize QR code generator with specified parameters"""
        self.version = version
        self.box_size = box_size
        self.border = border
        self.error_correction = error_correction
    
    def create_qr_code(self, data: str, output_path: str = None) -> Image.Image:
        """
        Create a QR code from the given data
        
        Args:
            data: Data to encode in QR code
            output_path: Optional path to save the QR code image
            
        Returns:
            PIL.Image: The generated QR code image
        """
        qr = qrcode.QRCode(
            version=self.version,
            error_correction=self.error_correction,
            box_size=self.box_size,
            border=self.border,
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
        
        # Add logo if available
        logo_path = os.path.join(os.path.dirname(__file__), '..', 'ui', 'assets', 'logo.png')
        if os.path.exists(logo_path):
            self._add_logo(img, logo_path)
        
        if output_path:
            img.save(output_path)
            
        return img
    
    def _add_logo(self, qr_img: Image.Image, logo_path: str, size_ratio: float = 0.2) -> None:
        """Add logo to the center of the QR code"""
        logo = Image.open(logo_path)
        
        # Calculate logo size (20% of QR code size)
        base_width = int(qr_img.size[0] * size_ratio)
        w_percent = (base_width / float(logo.size[0]))
        h_size = int((float(logo.size[1]) * float(w_percent)))
        logo = logo.resize((base_width, h_size), Image.Resampling.LANCZOS)
        
        # Calculate position to center the logo
        pos = (
            (qr_img.size[0] - logo.size[0]) // 2,
            (qr_img.size[1] - logo.size[1]) // 2
        )
        
        # Paste the logo
        qr_img.paste(logo, pos, logo if logo.mode == 'RGBA' else None)
    
    def get_qr_base64(self, data: str) -> str:
        """Get base64 encoded string of the QR code image"""
        img = self.create_qr_code(data)
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        return base64.b64encode(buffered.getvalue()).decode('utf-8')

# Example usage
if __name__ == "__main__":
    qr_gen = QRGenerator()
    test_data = "Name: John Doe, ID: 12345, Role: Developer"
    
    # Save QR code to file
    qr_gen.create_qr_code(test_data, "test_qr.png")
    print("QR code generated successfully!")
