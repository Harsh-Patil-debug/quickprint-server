# db_connection.py
# MongoDB connection for QuickPrint
# Mirrors khelomore-server/.../Handlers/db_connection.py exactly.
# ─────────────────────────────────────────────

import os
import pymongo
from pathlib import Path
from dotenv import load_dotenv

# Ensure .env is loaded using absolute path
BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
load_dotenv(BASE_DIR / '.env')

MONGO_URL = os.getenv("MONGO_URL")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "QuickPrintDB")

_client = None

def get_db():
    global _client
    if _client is None:
        if not MONGO_URL:
            # Fail loud: pymongo.MongoClient(None) silently falls back to localhost, which
            # would connect to (or spin up expectations of) the wrong database undetected.
            print("[QuickPrint] MONGO_URL environment variable is not set.")
            return None
        try:
            _client = pymongo.MongoClient(MONGO_URL, serverSelectionTimeoutMS=5000)
            # Ping database to force connection check
            _client.admin.command('ping')
            print(f"[QuickPrint] MongoDB connected successfully - database: '{MONGO_DB_NAME}'")
        except Exception as e:
            print(f"[QuickPrint] Failed to connect to MongoDB: {e}")
            _client = None
            return None
    return _client[MONGO_DB_NAME]


def get_client():
    """Returns the raw MongoClient (not a database) — needed for multi-document ACID
    transactions (client.start_session()), which operate at the client level, not the
    database level. Atlas connections are always backed by a replica set, so transactions
    are supported."""
    if get_db() is None:  # ensures _client is connected, reuses the same connect-once logic
        return None
    return _client


class _DbProxy:
    """
    Lazy MongoDB proxy.
    auth_handler.py does: `from .db_connection import db_main`
    Each attribute access (e.g. db_main.users) calls get_db() so the
    connection is never attempted at import time.
    """
    def __getattr__(self, name: str):
        db = get_db()
        if db is None:
            raise ConnectionError("[QuickPrint] MongoDB not available")
        return getattr(db, name)


# Singleton proxy — safe to import at module level
db_main = _DbProxy()
