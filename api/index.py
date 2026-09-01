import os
import sys

# Add the repository root directory to Python module search path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set SQLite database path to writable /tmp directory on Vercel Serverless
if "DATABASE_URL" not in os.environ:
    os.environ["DATABASE_URL"] = "sqlite:////tmp/campaignx.db"

# Force offline mode on Vercel if no API keys provided
if "MODE" not in os.environ:
    os.environ["MODE"] = "offline"

from backend.app.main import app
from backend.app.database.init_db import init_db

# Initialize database schema and baseline seed data on serverless startup
try:
    init_db()
except Exception as e:
    print(f"Vercel Serverless DB Initialization Notice: {e}")
