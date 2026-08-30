# status_check.py
# Simple server health check


def status_check():
    """Returns a simple status OK response."""
    return {
        "status": "ok",
        "message": "QuickPrint API is running.",
        "version": "1.0.0"
    }
