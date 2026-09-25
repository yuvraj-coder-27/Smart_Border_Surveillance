import os
import logging
import datetime
from logging.handlers import RotatingFileHandler
import sys

from config import settings

class SurveillanceLogger:
    def __init__(self):
        self.logger = logging.getLogger("BorderSurveillance")
        self.logger.setLevel(getattr(logging, settings.LOG_LEVEL))
        
        # Create logs directory if it doesn't exist
        log_dir = os.path.dirname(settings.LOG_FILE)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Set up file handler with rotation
        file_handler = RotatingFileHandler(
            settings.LOG_FILE,
            maxBytes=10*1024*1024,  # 10 MB
            backupCount=5
        )
        
        # Set up console handler
        console_handler = logging.StreamHandler(sys.stdout)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers to logger
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def get_logger(self):
        return self.logger
    
    def log_detection(self, detection_type, confidence, location=None):
        """Log a detection event"""
        location_str = f" at {location}" if location else ""
        self.logger.info(f"DETECTION: {detection_type} (conf: {confidence:.2f}){location_str}")
    
    def log_alert(self, alert_type, message, recipients=None):
        """Log an alert being sent"""
        recipient_str = f" to {recipients}" if recipients else ""
        self.logger.warning(f"ALERT: {alert_type} - {message}{recipient_str}")
    
    def log_error(self, component, error_msg):
        """Log an error"""
        self.logger.error(f"ERROR in {component}: {error_msg}")
    
    def log_system_status(self, status_info):
        """Log system status information"""
        self.logger.info(f"SYSTEM: {status_info}")

# Create a global logger instance
logger = SurveillanceLogger().get_logger() 