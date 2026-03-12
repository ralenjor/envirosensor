"""
Authentication and authorization utilities.

Provides:
- Login/logout session management
- @login_required decorator
- @admin_required decorator
- CSRF token generation and validation
"""

import secrets
from datetime import datetime
from functools import wraps
from flask import session, redirect, url_for, request, abort, g


def generate_csrf_token():
    """Generate a new CSRF token and store in session."""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']


def validate_csrf_token():
    """
    Validate CSRF token from form submission.
    Returns True if valid, False otherwise.
    """
    token = session.get('_csrf_token')
    form_token = request.form.get('_csrf_token')

    if not token or not form_token:
        return False

    return secrets.compare_digest(token, form_token)


def csrf_protect(f):
    """
    Decorator to require CSRF token validation on POST requests.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            if not validate_csrf_token():
                abort(400, description="Invalid CSRF token")
        return f(*args, **kwargs)
    return decorated_function


def login_required(f):
    """
    Decorator to require authentication for a route.
    Redirects to login page if not authenticated.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('notice'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """
    Decorator to require administrator role for a route.
    Redirects to login if not authenticated.
    Returns 403 Forbidden if authenticated but not admin.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('notice'))
        if session.get('role') != 'administrator':
            abort(403, description="Administrator access required")
        return f(*args, **kwargs)
    return decorated_function


def login_user(username: str, role: str, last_login: str = None):
    """
    Log in a user by setting session variables.
    Regenerates session to prevent session fixation attacks (VULN-010 fix).
    """
    # Store previous login for display
    previous_login = last_login

    # VULN-010 fix: Complete session regeneration
    # Clear all existing session data first
    session.clear()

    # Force session modification to trigger new session ID generation
    # by setting a new session identifier timestamp
    session['_session_regenerated_at'] = secrets.token_hex(16)

    # Set new session data
    session['username'] = username
    session['role'] = role
    session['previous_login'] = previous_login
    session['_login_time'] = datetime.utcnow().isoformat()
    session.permanent = True
    session.modified = True  # Ensure session is marked as modified

    # Generate new CSRF token
    generate_csrf_token()


def logout_user():
    """Log out the current user by clearing the session."""
    session.clear()


def get_current_user():
    """Get current user info from session."""
    if 'username' not in session:
        return None
    return {
        'username': session.get('username'),
        'role': session.get('role'),
        'previous_login': session.get('previous_login')
    }


def is_admin():
    """Check if current user is an administrator."""
    return session.get('role') == 'administrator'
