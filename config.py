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
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'  # VULN-004 fix
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

    # Account lockout settings (AC-7)
    MAX_LOGIN_ATTEMPTS = 4
    LOCKOUT_DURATION_MINUTES = 15

    # IP-based rate limiting settings (VULN-003 fix)
    RATELIMIT_STORAGE_URI = "memory://"
    RATELIMIT_DEFAULT = "200 per day"
    RATELIMIT_HEADERS_ENABLED = True
    LOGIN_RATE_LIMIT = "5 per minute"

    # Data file paths
    DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
    USERS_FILE = os.path.join(DATA_DIR, 'users.json')
    SENSOR_DATA_FILE = os.path.join(DATA_DIR, 'sensor_data.json')
    ACCESS_LOG_FILE = os.path.join(DATA_DIR, 'access_log.json')

    # Password hashing settings (VULN-006 fix - use bcrypt per CLAUDE.md)
    PASSWORD_HASH_METHOD = 'pbkdf2:sha256:600000'  # Keep for backward compatibility
    PASSWORD_HASH_METHOD_NEW = 'scrypt'  # Werkzeug's secure default (bcrypt requires extra dep)

    # File upload settings (VULN-001 fix)
    ALLOWED_UPLOAD_EXTENSIONS = {'json', 'csv'}
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB max upload size

    # Trusted proxies for X-Forwarded-For (VULN-008 fix)
    TRUSTED_PROXIES = os.environ.get('TRUSTED_PROXIES', '127.0.0.1').split(',')

    # Valid sensor ID pattern (VULN-009 fix)
    VALID_SENSOR_IDS = {'SENSOR-001', 'SENSOR-002', 'SENSOR-003'}

    # Password complexity requirements (VULN-011 fix)
    PASSWORD_MIN_LENGTH = 12
    PASSWORD_REQUIRE_UPPERCASE = True
    PASSWORD_REQUIRE_LOWERCASE = True
    PASSWORD_REQUIRE_DIGIT = True
    PASSWORD_REQUIRE_SPECIAL = True
