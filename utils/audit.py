"""
Audit logging utilities for NIST SP 800-53 AU-2 compliance.

Logs the following events:
- Page access (date/time, IP, URL, HTTP code)
- Login attempts (success/failure)
- Logout events
- Account lockout events
- Admin CRUD operations (AC-6 privileged function logging)
"""

from flask import request, session
from functools import wraps


class AuditLogger:
    """Handles audit logging to the access log file."""

    def __init__(self, data_manager):
        self.dm = data_manager

    def _get_client_ip(self):
        """Get client IP address, handling proxies."""
        # Check for forwarded header (behind proxy)
        if request.headers.get('X-Forwarded-For'):
            return request.headers.get('X-Forwarded-For').split(',')[0].strip()
        return request.remote_addr or 'unknown'

    def _get_username(self):
        """Get current username from session."""
        return session.get('username')

    def log_page_access(self, http_code: int = 200):
        """Log a page access event."""
        self.dm.log_access(
            ip_address=self._get_client_ip(),
            url=request.path,
            http_code=http_code,
            username=self._get_username(),
            event_type='page_access',
            details=f"Method: {request.method}"
        )

    def log_login_success(self, username: str):
        """Log a successful login."""
        self.dm.log_access(
            ip_address=self._get_client_ip(),
            url=request.path,
            http_code=200,
            username=username,
            event_type='login',
            details='Login successful'
        )

    def log_login_failure(self, username: str, reason: str = 'Invalid credentials'):
        """Log a failed login attempt."""
        self.dm.log_access(
            ip_address=self._get_client_ip(),
            url=request.path,
            http_code=401,
            username=username,
            event_type='login',
            details=f'Login failed: {reason}'
        )

    def log_logout(self, username: str):
        """Log a logout event."""
        self.dm.log_access(
            ip_address=self._get_client_ip(),
            url=request.path,
            http_code=200,
            username=username,
            event_type='logout',
            details='User logged out'
        )

    def log_lockout(self, username: str):
        """Log an account lockout event."""
        self.dm.log_access(
            ip_address=self._get_client_ip(),
            url=request.path,
            http_code=403,
            username=username,
            event_type='lockout',
            details='Account locked due to excessive failed login attempts'
        )

    def log_admin_action(self, action: str, target: str, details: str = ''):
        """
        Log an administrative action (AC-6 compliance).

        Args:
            action: The action performed (create, update, delete, unlock)
            target: What was acted upon (sensor_reading, user_account, etc.)
            details: Additional details about the action
        """
        self.dm.log_access(
            ip_address=self._get_client_ip(),
            url=request.path,
            http_code=200,
            username=self._get_username(),
            event_type='admin_action',
            details=f'Action: {action}, Target: {target}, {details}'
        )

    def log_error(self, http_code: int, error_message: str):
        """Log an error event."""
        self.dm.log_access(
            ip_address=self._get_client_ip(),
            url=request.path,
            http_code=http_code,
            username=self._get_username(),
            event_type='error',
            details=error_message
        )


def log_access(audit_logger):
    """
    Decorator to automatically log page access for a route.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            result = f(*args, **kwargs)
            # Log after request to capture actual status code
            http_code = 200
            if hasattr(result, 'status_code'):
                http_code = result.status_code
            audit_logger.log_page_access(http_code)
            return result
        return decorated_function
    return decorator
