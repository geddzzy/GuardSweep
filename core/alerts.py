# In core/alerts.py
from datetime import datetime
import logging

def alert(message, severity="ALERT"):
    """
    Logs a message with a specific severity level.
    The logging configuration in config.py handles all formatting and output.
    """
    
    if severity == "ALERT":
        # Using CRITICAL for alerts makes them stand out more.
        logging.critical(message)
    elif severity == "WARNING":
        logging.warning(message)
    else:
        # Default to INFO for general messages.
        logging.info(message)