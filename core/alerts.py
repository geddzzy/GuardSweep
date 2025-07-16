from datetime import datetime
import logging

def alert(message, severity="ALERT"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted_msg = f"[{timestamp}] [{severity}] {message}"
    print(formatted_msg)
    if severity == "ALERT":
        logging.info(formatted_msg)
    elif severity == "WARNING":
        logging.warning(formatted_msg)
    else:
        logging.info(formatted_msg)
