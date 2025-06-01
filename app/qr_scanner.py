import cv2
import numpy as np
from typing import Optional, Tuple, List, Dict, Any
import time

class QRScanner:
    def __init__(self, camera_id: int = 0):
        """
        Initialize QR code scanner
        
        Args:
            camera_id: ID of the camera to use (default is 0 for default camera)
        """
        self.camera_id = camera_id
        self.cap = None
    
    def start_camera(self) -> bool:
        """Initialize the camera for scanning"""
        self.cap = cv2.VideoCapture(self.camera_id)
        return self.cap.isOpened()
    
    def stop_camera(self) -> None:
        """Release the camera resources"""
        if self.cap and self.cap.isOpened():
            self.cap.release()
    
    def scan_qr(self, timeout: float = 30.0) -> Tuple[Optional[str], Optional[np.ndarray]]:
        """
        Scan for QR codes using the camera
        
        Args:
            timeout: Maximum time in seconds to scan for a QR code
            
        Returns:
            tuple: (decoded_data, frame) where frame is the image frame where QR was detected
                   Returns (None, None) if no QR code is found within timeout
        """
        if not self.cap or not self.cap.isOpened():
            if not self.start_camera():
                return None, None
        
        start_time = time.time()
        qr_detector = cv2.QRCodeDetector()
        
        while time.time() - start_time < timeout:
            ret, frame = self.cap.read()
            if not ret:
                continue
                
            # Detect and decode QR code
            decoded_info, points, _ = qr_detector.detectAndDecode(frame)
            
            # If we found a QR code
            if points is not None and len(decoded_info) > 0 and decoded_info[0]:
                qr_data = decoded_info[0]
                # Draw the QR code boundary
                points = points[0].astype(np.int32)
                cv2.polylines(frame, [points], True, (0, 255, 0), 3)
                return qr_data, frame
                
            # Add a small delay to prevent high CPU usage
            time.sleep(0.1)
            
            # Show the frame (for debugging)
            cv2.imshow('QR Scanner', frame)
            
            # Break the loop if 'q' is pressed
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break
        
        return None, None
    
    def scan_from_image(self, image_path: str) -> Optional[str]:
        """
        Scan QR code from an image file
        
        Args:
            image_path: Path to the image file containing a QR code
            
        Returns:
            str: Decoded data from the QR code, or None if no QR code is found
        """
        try:
            image = cv2.imread(image_path)
            if image is None:
                return None
                
            # Convert to grayscale
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            
            # Try to decode QR codes
            decoded_objects = decode(gray)
            
            if decoded_objects:
                return decoded_objects[0].data.decode('utf-8')
                
        except Exception as e:
            print(f"Error scanning image: {e}")
            
        return None

# Example usage
if __name__ == "__main__":
    scanner = QRScanner()
    
    try:
        print("Scanning for QR codes... (Press 'q' to exit)")
        data, frame = scanner.scan_qr(timeout=30)
        
        if data:
            print(f"QR Code detected! Data: {data}")
            
            # Save the frame where QR was detected
            if frame is not None:
                cv2.imwrite("detected_qr.png", frame)
                print("Saved the frame with detected QR code as 'detected_qr.png'")
        else:
            print("No QR code detected within the timeout period.")
            
    finally:
        scanner.stop_camera()
        cv2.destroyAllWindows()
