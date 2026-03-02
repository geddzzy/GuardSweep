import logging

SEVERITY_TO_LEVEL = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
    # Backward-compatible alias used across this codebase.
    "ALERT": logging.CRITICAL,
}


def alert(message, severity="ALERT"):
    """Log a message with a normalized severity level."""
    level = SEVERITY_TO_LEVEL.get(str(severity).upper(), logging.INFO)
    logging.log(level, message)
