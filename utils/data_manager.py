"""
Data manager module for JSON file operations.
Handles CRUD operations for users, sensor data, and access logs.
"""

import json
import os
import re
import uuid
from datetime import datetime, timedelta
from typing import Optional, Tuple
from filelock import FileLock
from werkzeug.security import generate_password_hash, check_password_hash


class PasswordValidationError(Exception):
    """Raised when password does not meet complexity requirements."""
    pass


class DataManager:
    """Manages JSON file operations with file locking for thread safety."""

    def __init__(self, config):
        self.config = config
        self._ensure_data_dir()

    def validate_password(self, password: str) -> Tuple[bool, str]:
        """
        Validate password meets complexity requirements (VULN-011 fix).
        Returns (is_valid, error_message).
        """
        if len(password) < self.config.PASSWORD_MIN_LENGTH:
            return False, f"Password must be at least {self.config.PASSWORD_MIN_LENGTH} characters"

        if self.config.PASSWORD_REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"

        if self.config.PASSWORD_REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"

        if self.config.PASSWORD_REQUIRE_DIGIT and not re.search(r'\d', password):
            return False, "Password must contain at least one digit"

        if self.config.PASSWORD_REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>\-_=+\[\]\\;\'`~]', password):
            return False, "Password must contain at least one special character"

        return True, ""

    def _ensure_data_dir(self):
        """Ensure data directory exists."""
        os.makedirs(self.config.DATA_DIR, exist_ok=True)

    def _read_json(self, filepath: str) -> dict:
        """Read JSON file with locking."""
        lock = FileLock(f"{filepath}.lock")
        with lock:
            if not os.path.exists(filepath):
                return {}
            with open(filepath, 'r') as f:
                return json.load(f)

    def _write_json(self, filepath: str, data: dict):
        """Write JSON file with locking."""
        lock = FileLock(f"{filepath}.lock")
        with lock:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, default=str)

    # ==================== USER OPERATIONS ====================

    def get_user(self, username: str) -> Optional[dict]:
        """Get user by username."""
        data = self._read_json(self.config.USERS_FILE)
        users = data.get('users', [])
        for user in users:
            if user['username'] == username:
                return user
        return None

    def get_all_users(self) -> list:
        """Get all users (excluding password hashes for display)."""
        data = self._read_json(self.config.USERS_FILE)
        users = data.get('users', [])
        return [{k: v for k, v in u.items() if k != 'password_hash'} for u in users]

    def create_user(self, username: str, password: str, role: str,
                    skip_password_validation: bool = False) -> Tuple[bool, str]:
        """
        Create a new user with hashed password.
        Returns (success, error_message).
        """
        if self.get_user(username):
            return False, "Username already exists"

        # VULN-011 fix: Validate password complexity
        if not skip_password_validation:
            is_valid, error_msg = self.validate_password(password)
            if not is_valid:
                return False, error_msg

        data = self._read_json(self.config.USERS_FILE)
        if 'users' not in data:
            data['users'] = []

        # VULN-006 fix: Use more secure hashing method
        # Using scrypt which is Werkzeug's modern secure default
        hash_method = getattr(self.config, 'PASSWORD_HASH_METHOD_NEW',
                              self.config.PASSWORD_HASH_METHOD)
        password_hash = generate_password_hash(
            password,
            method=hash_method
        )

        new_user = {
            'username': username,
            'password_hash': password_hash,
            'role': role,
            'failed_attempts': 0,
            'locked': False,
            'locked_until': None,
            'last_login': None
        }

        data['users'].append(new_user)
        self._write_json(self.config.USERS_FILE, data)
        return True, ""

    def verify_password(self, username: str, password: str) -> bool:
        """Verify user password."""
        user = self.get_user(username)
        if not user:
            return False
        return check_password_hash(user['password_hash'], password)

    def update_user(self, username: str, updates: dict) -> bool:
        """Update user fields."""
        data = self._read_json(self.config.USERS_FILE)
        users = data.get('users', [])

        for i, user in enumerate(users):
            if user['username'] == username:
                # Don't allow updating username or password_hash directly
                safe_updates = {k: v for k, v in updates.items()
                               if k not in ['username', 'password_hash']}
                users[i].update(safe_updates)
                self._write_json(self.config.USERS_FILE, data)
                return True
        return False

    def increment_failed_attempts(self, username: str) -> int:
        """Increment failed login attempts, return new count."""
        user = self.get_user(username)
        if not user:
            return 0

        new_count = user.get('failed_attempts', 0) + 1
        updates = {'failed_attempts': new_count}

        # Lock account if max attempts reached
        if new_count >= self.config.MAX_LOGIN_ATTEMPTS:
            locked_until = datetime.utcnow() + timedelta(
                minutes=self.config.LOCKOUT_DURATION_MINUTES
            )
            updates['locked'] = True
            updates['locked_until'] = locked_until.isoformat()

        self.update_user(username, updates)
        return new_count

    def reset_failed_attempts(self, username: str):
        """Reset failed login attempts after successful login."""
        self.update_user(username, {
            'failed_attempts': 0,
            'locked': False,
            'locked_until': None
        })

    def is_account_locked(self, username: str) -> bool:
        """Check if account is locked."""
        user = self.get_user(username)
        if not user or not user.get('locked'):
            return False

        locked_until = user.get('locked_until')
        if locked_until:
            locked_until_dt = datetime.fromisoformat(locked_until)
            if datetime.utcnow() > locked_until_dt:
                # Auto-unlock after duration
                self.unlock_user(username)
                return False
        return True

    def unlock_user(self, username: str) -> bool:
        """Manually unlock a user account."""
        return self.update_user(username, {
            'failed_attempts': 0,
            'locked': False,
            'locked_until': None
        })

    def record_login(self, username: str):
        """Record successful login timestamp."""
        self.update_user(username, {
            'last_login': datetime.utcnow().isoformat()
        })

    # ==================== SENSOR DATA OPERATIONS ====================

    def get_sensor_readings(self, hours: int = 24) -> list:
        """Get sensor readings from the last N hours."""
        data = self._read_json(self.config.SENSOR_DATA_FILE)
        readings = data.get('readings', [])

        cutoff = datetime.utcnow() - timedelta(hours=hours)

        filtered = []
        for reading in readings:
            timestamp = datetime.fromisoformat(reading['timestamp'])
            if timestamp >= cutoff:
                filtered.append(reading)

        # Sort by timestamp descending (newest first)
        filtered.sort(key=lambda x: x['timestamp'], reverse=True)
        return filtered

    def get_sensor_reading(self, reading_id: str) -> Optional[dict]:
        """Get a single sensor reading by ID."""
        data = self._read_json(self.config.SENSOR_DATA_FILE)
        readings = data.get('readings', [])
        for reading in readings:
            if reading['id'] == reading_id:
                return reading
        return None

    def create_sensor_reading(self, temperature: float, humidity: float,
                               sensor_id: str = "SENSOR-001") -> dict:
        """Create a new sensor reading."""
        data = self._read_json(self.config.SENSOR_DATA_FILE)
        if 'readings' not in data:
            data['readings'] = []

        new_reading = {
            'id': str(uuid.uuid4()),
            'timestamp': datetime.utcnow().isoformat(),
            'temperature_f': round(temperature, 2),
            'humidity_percent': round(humidity, 2),
            'sensor_id': sensor_id
        }

        data['readings'].append(new_reading)
        self._write_json(self.config.SENSOR_DATA_FILE, data)
        return new_reading

    def update_sensor_reading(self, reading_id: str, temperature: float,
                               humidity: float) -> bool:
        """Update an existing sensor reading."""
        data = self._read_json(self.config.SENSOR_DATA_FILE)
        readings = data.get('readings', [])

        for i, reading in enumerate(readings):
            if reading['id'] == reading_id:
                readings[i]['temperature_f'] = round(temperature, 2)
                readings[i]['humidity_percent'] = round(humidity, 2)
                self._write_json(self.config.SENSOR_DATA_FILE, data)
                return True
        return False

    def delete_sensor_reading(self, reading_id: str) -> bool:
        """Delete a sensor reading."""
        data = self._read_json(self.config.SENSOR_DATA_FILE)
        readings = data.get('readings', [])

        for i, reading in enumerate(readings):
            if reading['id'] == reading_id:
                del readings[i]
                self._write_json(self.config.SENSOR_DATA_FILE, data)
                return True
        return False

    # ==================== ACCESS LOG OPERATIONS ====================

    def log_access(self, ip_address: str, url: str, http_code: int,
                   username: Optional[str] = None,
                   event_type: str = "page_access",
                   details: str = ""):
        """Log an access event."""
        data = self._read_json(self.config.ACCESS_LOG_FILE)
        if 'entries' not in data:
            data['entries'] = []

        entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'ip_address': ip_address,
            'url': url,
            'http_code': http_code,
            'username': username,
            'event_type': event_type,
            'details': details
        }

        data['entries'].append(entry)
        self._write_json(self.config.ACCESS_LOG_FILE, data)

    def get_access_logs(self, limit: int = 100) -> list:
        """Get recent access log entries."""
        data = self._read_json(self.config.ACCESS_LOG_FILE)
        entries = data.get('entries', [])
        # Return most recent entries first
        entries.sort(key=lambda x: x['timestamp'], reverse=True)
        return entries[:limit]
