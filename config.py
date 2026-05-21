"""
Centralized database configuration.

Loads credentials from the .env file at the project root.
Every module in this project should import DB_CONFIG or DATABASE_URL
from here instead of hardcoding credentials.
"""

import os
from pathlib import Path


def _load_env():
    """Parse the .env file at the project root into os.environ."""
    env_path = Path(__file__).resolve().parent / ".env"
    if not env_path.exists():
        return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            # Don't overwrite values already set in the real environment
            if key not in os.environ:
                os.environ[key] = value


_load_env()

DB_USER = os.environ.get("DB_USER", "threatuser")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "threatpass")
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = os.environ.get("DB_PORT", "5432")
DB_NAME = os.environ.get("DB_NAME", "threat_intel")

# psycopg2-style dict
DB_CONFIG = {
    "host": DB_HOST,
    "port": int(DB_PORT),
    "database": DB_NAME,
    "user": DB_USER,
    "password": DB_PASSWORD,
}

# SQLAlchemy-style URL
DATABASE_URL = (
    f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)
    