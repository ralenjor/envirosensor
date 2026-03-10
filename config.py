import os
from datetime import timedelta

# Load environment variables from .env file if present
from dotenv import load_dotenv
load_dotenv()


class Config:
    # Secret key for session signing - MUST be set via environment variable
    # Generate with: python -c "import os; print(os.urandom(32).hex())"
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY environment variable must be set")

    # Session configuration
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

    # Account lockout settings (AC-7)
    MAX_LOGIN_ATTEMPTS = 4
    LOCKOUT_DURATION_MINUTES = 15

    # Data file paths
    DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
    USERS_FILE = os.path.join(DATA_DIR, 'users.json')
    SENSOR_DATA_FILE = os.path.join(DATA_DIR, 'sensor_data.json')
    ACCESS_LOG_FILE = os.path.join(DATA_DIR, 'access_log.json')

    # Password hashing settings
    PASSWORD_HASH_METHOD = 'pbkdf2:sha256'
    PASSWORD_HASH_ITERATIONS = 600000  # Werkzeug default for PBKDF2
