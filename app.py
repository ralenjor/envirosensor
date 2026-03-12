"""
Environmental Sensor Web Application

A Flask-based web application for authenticated access to ICS environmental
sensor data, compliant with FIPS 200 and NIST SP 800-53 security controls.
"""

import os
import re
import json
import math
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, abort, Response
)
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Load environment variables before importing config
load_dotenv()

from config import Config
from utils.data_manager import DataManager
from utils.auth import (
    login_required, admin_required, csrf_protect,
    login_user, logout_user, get_current_user,
    generate_csrf_token, validate_csrf_token
)
from utils.audit import AuditLogger

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Set max content length for file uploads (VULN-001 fix)
app.config['MAX_CONTENT_LENGTH'] = Config.MAX_CONTENT_LENGTH

# Initialize rate limiter (VULN-003 fix)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=Config.RATELIMIT_STORAGE_URI,
    default_limits=[Config.RATELIMIT_DEFAULT]
)

# Initialize data manager and audit logger
data_manager = DataManager(Config)
audit_logger = AuditLogger(data_manager, Config)


# ==================== TEMPLATE CONTEXT ====================

@app.context_processor
def inject_csrf_token():
    """Make CSRF token available in all templates."""
    return {'csrf_token': generate_csrf_token}


# ==================== SECURITY HEADERS ====================

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' https://cdn.jsdelivr.net;"
    )
    # VULN-005 fix: Add HSTS header for HTTPS enforcement
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


# ==================== ERROR HANDLERS ====================

@app.errorhandler(400)
def bad_request(e):
    audit_logger.log_error(400, str(e))
    return render_template('errors/400.html', error=e), 400


@app.errorhandler(401)
def unauthorized(e):
    audit_logger.log_error(401, str(e))
    return render_template('errors/401.html', error=e), 401


@app.errorhandler(403)
def forbidden(e):
    audit_logger.log_error(403, str(e))
    return render_template('errors/403.html', error=e), 403


@app.errorhandler(404)
def not_found(e):
    audit_logger.log_error(404, str(e))
    return render_template('errors/404.html', error=e), 404


@app.errorhandler(500)
def internal_error(e):
    audit_logger.log_error(500, str(e))
    return render_template('errors/500.html', error=e), 500


@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded errors (VULN-003 fix)."""
    audit_logger.log_error(429, "Rate limit exceeded")
    return render_template('errors/429.html', error=e), 429


# ==================== PUBLIC ROUTES ====================

@app.route('/')
def index():
    """Root route - redirect based on authentication status."""
    if 'username' in session:
        return redirect(url_for('home'))
    return redirect(url_for('notice'))


@app.route('/notice')
def notice():
    """Display system use notification (AC-8)."""
    if 'username' in session:
        return redirect(url_for('home'))
    if session.get('notice_acknowledged'):
        return redirect(url_for('login'))
    audit_logger.log_page_access(200)
    return render_template('system_notice.html')


@app.route('/notice', methods=['POST'])
@csrf_protect
def acknowledge_notice():
    """Process system use notification acknowledgment."""
    session['notice_acknowledged'] = True
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit(Config.LOGIN_RATE_LIMIT, methods=['POST'])  # VULN-003 fix: IP rate limiting
def login():
    """Handle user login."""
    # Redirect if already logged in
    if 'username' in session:
        return redirect(url_for('home'))

    # Require notice acknowledgment
    if not session.get('notice_acknowledged'):
        return redirect(url_for('notice'))

    error = None

    if request.method == 'POST':
        # Validate CSRF
        if not validate_csrf_token():
            abort(400, description="Invalid CSRF token")

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            error = "Username and password are required"
        else:
            # VULN-007 fix: Use generic error message to prevent username enumeration
            generic_error = "Invalid username or password"

            # Check if account is locked
            if data_manager.is_account_locked(username):
                # Log the actual reason but show generic message
                audit_logger.log_login_failure(username, "Account locked")
                error = generic_error
            else:
                # Verify credentials
                if data_manager.verify_password(username, password):
                    # Get user info
                    user = data_manager.get_user(username)

                    # Record login and reset failed attempts
                    previous_login = user.get('last_login')
                    data_manager.reset_failed_attempts(username)
                    data_manager.record_login(username)

                    # Set up session
                    login_user(username, user['role'], previous_login)

                    audit_logger.log_login_success(username)
                    flash('Login successful', 'success')
                    return redirect(url_for('welcome'))
                else:
                    # Increment failed attempts
                    attempts = data_manager.increment_failed_attempts(username)

                    if attempts >= Config.MAX_LOGIN_ATTEMPTS:
                        audit_logger.log_lockout(username)
                    else:
                        audit_logger.log_login_failure(username, "Invalid credentials")

                    # VULN-007 fix: Always show generic error
                    error = generic_error

    audit_logger.log_page_access(200 if not error else 401)
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    """Log out the current user."""
    username = session.get('username')
    if username:
        audit_logger.log_logout(username)
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('notice'))


# ==================== AUTHENTICATED ROUTES ====================

@app.route('/welcome')
@login_required
def welcome():
    """Display welcome page after login."""
    audit_logger.log_page_access(200)
    return render_template('welcome.html', user=get_current_user())


@app.route('/home')
@login_required
def home():
    """Display home page with last login info and menu descriptions."""
    audit_logger.log_page_access(200)
    return render_template('home.html', user=get_current_user())


@app.route('/sensor-data')
@login_required
def sensor_data():
    """Display environmental sensor data for the last 24 hours."""
    readings = data_manager.get_sensor_readings(hours=24)
    audit_logger.log_page_access(200)
    return render_template('sensor_data.html', readings=readings, user=get_current_user())


@app.route('/cloud')
@login_required
def cloud_status():
    """Display cloud archival and backup synchronization status."""
    # Simulated cloud status data
    now = datetime.now()

    cloud_data = {
        'last_sync_primary': (now - timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S'),
        'next_sync_primary': (now + timedelta(minutes=45)).strftime('%Y-%m-%d %H:%M:%S'),
        'data_transferred_primary': 12.4,
        'last_sync_secondary': (now - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S'),
        'next_sync_secondary': (now + timedelta(hours=5)).strftime('%Y-%m-%d %H:%M:%S'),
        'data_transferred_secondary': 48.7,
        'total_archived': 2.3,
        'sync_success_rate': 99.7,
        'days_since_failure': 42,
        'sync_history': [
            {'timestamp': (now - timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M'),
             'service': 'AWS S3', 'operation': 'Incremental Backup',
             'files': 12, 'size': 0.8, 'status': 'Success'},
            {'timestamp': (now - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M'),
             'service': 'Azure Blob', 'operation': 'Full Sync',
             'files': 96, 'size': 4.2, 'status': 'Success'},
            {'timestamp': (now - timedelta(hours=2)).strftime('%Y-%m-%d %H:%M'),
             'service': 'AWS S3', 'operation': 'Incremental Backup',
             'files': 8, 'size': 0.5, 'status': 'Success'},
            {'timestamp': (now - timedelta(hours=3)).strftime('%Y-%m-%d %H:%M'),
             'service': 'AWS S3', 'operation': 'Incremental Backup',
             'files': 15, 'size': 1.1, 'status': 'Success'},
            {'timestamp': (now - timedelta(hours=6)).strftime('%Y-%m-%d %H:%M'),
             'service': 'Azure Blob', 'operation': 'Full Sync',
             'files': 96, 'size': 4.1, 'status': 'Success'},
        ]
    }

    audit_logger.log_page_access(200)
    return render_template('cloud.html', user=get_current_user(), **cloud_data)


@app.route('/ics')
@admin_required
def ics_import_page():
    """Display ICS data import page."""
    # Simulated import history
    import_history = [
        {'timestamp': '2026-03-09 10:30:00', 'filename': 'sensor_export_0309.json',
         'sensor_id': 'SENSOR-001', 'records': 96, 'status': 'Success', 'imported_by': 'admin'},
        {'timestamp': '2026-03-08 14:15:00', 'filename': 'readings_backup.csv',
         'sensor_id': 'SENSOR-001', 'records': 48, 'status': 'Success', 'imported_by': 'admin'},
        {'timestamp': '2026-03-07 09:00:00', 'filename': 'weekly_data.json',
         'sensor_id': 'SENSOR-002', 'records': 672, 'status': 'Success', 'imported_by': 'admin'},
    ]

    audit_logger.log_page_access(200)
    return render_template('ics.html', user=get_current_user(), import_history=import_history)


def allowed_file(filename):
    """Check if file extension is allowed (VULN-001 fix)."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_UPLOAD_EXTENSIONS


def validate_file_content(file, extension):
    """Validate file content matches expected format (VULN-001 fix)."""
    try:
        content = file.read()
        file.seek(0)  # Reset file pointer for later use

        if extension == 'json':
            data = json.loads(content.decode('utf-8'))
            # Verify expected structure
            if not isinstance(data, dict) or 'readings' not in data:
                return False, "JSON must contain 'readings' array"
            if not isinstance(data['readings'], list):
                return False, "'readings' must be an array"
            return True, None
        elif extension == 'csv':
            lines = content.decode('utf-8').strip().split('\n')
            if len(lines) < 2:
                return False, "CSV must have header and at least one data row"
            header = lines[0].lower()
            if 'timestamp' not in header or 'temperature' not in header:
                return False, "CSV must contain timestamp and temperature columns"
            return True, None
        return False, "Unsupported file type"
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return False, f"Invalid file format: {str(e)}"


@app.route('/ics/import', methods=['POST'])
@admin_required
@csrf_protect
def ics_import():
    """Handle ICS data file import."""
    # Check if file was uploaded
    if 'datafile' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('ics_import_page'))

    file = request.files['datafile']
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('ics_import_page'))

    # VULN-001 fix: Validate file extension
    if not allowed_file(file.filename):
        flash(f'Invalid file type. Allowed types: {", ".join(Config.ALLOWED_UPLOAD_EXTENSIONS)}', 'danger')
        audit_logger.log_admin_action('import_failed', 'sensor_data',
                                       f'Rejected file: {file.filename} (invalid extension)')
        return redirect(url_for('ics_import_page'))

    # Secure the filename
    filename = secure_filename(file.filename)
    extension = filename.rsplit('.', 1)[1].lower()

    # VULN-001 fix: Validate file content
    is_valid, error_msg = validate_file_content(file, extension)
    if not is_valid:
        flash(f'Invalid file content: {error_msg}', 'danger')
        audit_logger.log_admin_action('import_failed', 'sensor_data',
                                       f'Rejected file: {filename} ({error_msg})')
        return redirect(url_for('ics_import_page'))

    # VULN-009 fix: Validate sensor_id
    sensor_id = request.form.get('sensor_id', 'SENSOR-001')
    if sensor_id not in Config.VALID_SENSOR_IDS:
        flash('Invalid sensor ID', 'danger')
        return redirect(url_for('ics_import_page'))

    # For now, just simulate a successful import
    audit_logger.log_admin_action('import', 'sensor_data',
                                   f'File: {filename}, Sensor: {sensor_id}')
    flash(f'File "{filename}" imported successfully', 'success')
    return redirect(url_for('ics_import_page'))


@app.route('/ics/generate', methods=['POST'])
@admin_required
@csrf_protect
def ics_generate():
    """Generate sample sensor data."""
    hours = int(request.form.get('hours', 24))
    hours = max(1, min(168, hours))  # Clamp between 1 and 168 hours

    # Import and run the data generator
    from utils.data_generator import generate_sensor_data, save_sensor_data
    readings = generate_sensor_data(hours)
    save_sensor_data(readings, Config.SENSOR_DATA_FILE)

    audit_logger.log_admin_action('generate', 'sensor_data',
                                   f'Generated {len(readings)} readings for {hours} hours')
    flash(f'Generated {len(readings)} sensor readings for the past {hours} hours', 'success')
    return redirect(url_for('ics_import_page'))


@app.route('/about')
@login_required
def about():
    """Display about page."""
    audit_logger.log_page_access(200)
    return render_template('about.html', user=get_current_user())


@app.route('/reports')
@login_required
def reports():
    """Display reports and analytics page."""
    # Get time range from query param (default 24 hours)
    time_range = request.args.get('range', 24, type=int)
    time_range = max(24, min(720, time_range))  # Clamp between 24 and 720 hours

    # Get readings for the time range
    readings = data_manager.get_sensor_readings(hours=time_range)

    # Calculate statistics
    if readings:
        temps = [r['temperature_f'] for r in readings]
        humids = [r['humidity_percent'] for r in readings]

        # Standard deviation calculation
        temp_avg = sum(temps) / len(temps)
        humidity_avg = sum(humids) / len(humids)
        temp_variance = sum((t - temp_avg) ** 2 for t in temps) / len(temps)
        humidity_variance = sum((h - humidity_avg) ** 2 for h in humids) / len(humids)

        # Count out-of-range alerts (temp outside 65-80°F)
        alerts = sum(1 for t in temps if t < 65 or t > 80)

        # Get previous period for trend comparison
        prev_readings = data_manager.get_sensor_readings(hours=time_range * 2)
        prev_temps = [r['temperature_f'] for r in prev_readings[len(readings):]]
        prev_humids = [r['humidity_percent'] for r in prev_readings[len(readings):]]

        prev_temp_avg = sum(prev_temps) / len(prev_temps) if prev_temps else temp_avg
        prev_humidity_avg = sum(prev_humids) / len(prev_humids) if prev_humids else humidity_avg

        stats = {
            'reading_count': len(readings),
            'temp_min': min(temps),
            'temp_max': max(temps),
            'temp_avg': temp_avg,
            'temp_std': math.sqrt(temp_variance),
            'temp_trend': temp_avg - prev_temp_avg,
            'humidity_min': min(humids),
            'humidity_max': max(humids),
            'humidity_avg': humidity_avg,
            'humidity_std': math.sqrt(humidity_variance),
            'humidity_trend': humidity_avg - prev_humidity_avg,
            'alerts': alerts
        }

        # Prepare chart data (sample every N points to keep chart readable)
        max_points = 50
        step = max(1, len(readings) // max_points)
        sampled = readings[::step]

        chart_labels = [r['timestamp'][11:16] for r in sampled]  # HH:MM format
        chart_temp_data = [r['temperature_f'] for r in sampled]
        chart_humidity_data = [r['humidity_percent'] for r in sampled]

        # Hourly breakdown (last 24 hours only)
        hourly_data = []
        readings_24h = data_manager.get_sensor_readings(hours=24)
        hours_seen = {}
        for r in readings_24h:
            hour = r['timestamp'][11:13] + ':00'
            if hour not in hours_seen:
                hours_seen[hour] = {'temps': [], 'humids': []}
            hours_seen[hour]['temps'].append(r['temperature_f'])
            hours_seen[hour]['humids'].append(r['humidity_percent'])

        for hour in sorted(hours_seen.keys()):
            data = hours_seen[hour]
            hourly_data.append({
                'hour': hour,
                'count': len(data['temps']),
                'temp_avg': sum(data['temps']) / len(data['temps']),
                'humidity_avg': sum(data['humids']) / len(data['humids'])
            })
    else:
        stats = {
            'reading_count': 0, 'temp_min': 0, 'temp_max': 0, 'temp_avg': 0,
            'temp_std': 0, 'temp_trend': 0, 'humidity_min': 0, 'humidity_max': 0,
            'humidity_avg': 0, 'humidity_std': 0, 'humidity_trend': 0, 'alerts': 0
        }
        chart_labels = []
        chart_temp_data = []
        chart_humidity_data = []
        hourly_data = []

    audit_logger.log_page_access(200)
    return render_template('reports.html',
                           user=get_current_user(),
                           time_range=time_range,
                           stats=stats,
                           chart_labels=json.dumps(chart_labels),
                           chart_temp_data=json.dumps(chart_temp_data),
                           chart_humidity_data=json.dumps(chart_humidity_data),
                           hourly_data=hourly_data)


def sanitize_csv_value(value):
    """
    Sanitize CSV value to prevent formula injection (VULN-002 fix).
    Prefixes dangerous characters with a single quote to prevent
    Excel/LibreOffice from interpreting them as formulas.
    """
    str_value = str(value)
    # Characters that can trigger formula execution in spreadsheets
    dangerous_chars = ('=', '@', '+', '-', '\t', '\r', '\n')
    if str_value.startswith(dangerous_chars):
        return "'" + str_value
    return str_value


@app.route('/reports/export')
@login_required
def reports_export():
    """Export sensor data as CSV."""
    time_range = request.args.get('range', 24, type=int)
    time_range = max(24, min(720, time_range))

    readings = data_manager.get_sensor_readings(hours=time_range)

    # Build CSV content with sanitization (VULN-002 fix)
    csv_lines = ['timestamp,sensor_id,temperature_f,humidity_percent']
    for r in readings:
        timestamp = sanitize_csv_value(r["timestamp"])
        sensor_id = sanitize_csv_value(r["sensor_id"])
        temp = sanitize_csv_value(r["temperature_f"])
        humidity = sanitize_csv_value(r["humidity_percent"])
        csv_lines.append(f'{timestamp},{sensor_id},{temp},{humidity}')

    csv_content = '\n'.join(csv_lines)

    audit_logger.log_admin_action('export', 'sensor_data',
                                   f'Exported {len(readings)} readings ({time_range}h)')

    return Response(
        csv_content,
        mimetype='text/csv; charset=utf-8',
        headers={'Content-Disposition': f'attachment; filename=sensor_data_{time_range}h.csv'}
    )


# ==================== ADMIN ROUTES ====================

@app.route('/admin/sensor')
@admin_required
def admin_sensor():
    """Admin page to manage sensor data."""
    readings = data_manager.get_sensor_readings(hours=24)
    audit_logger.log_page_access(200)
    return render_template('admin_form.html', readings=readings, user=get_current_user())


@app.route('/admin/sensor', methods=['POST'])
@admin_required
@csrf_protect
def admin_sensor_create():
    """Create a new sensor reading."""
    try:
        temperature = float(request.form.get('temperature', 0))
        humidity = float(request.form.get('humidity', 0))
        sensor_id = request.form.get('sensor_id', 'SENSOR-001').strip()

        # Validate ranges
        if not (0 <= temperature <= 150):
            flash('Temperature must be between 0 and 150°F', 'danger')
            return redirect(url_for('admin_sensor'))

        if not (0 <= humidity <= 100):
            flash('Humidity must be between 0 and 100%', 'danger')
            return redirect(url_for('admin_sensor'))

        # VULN-009 fix: Validate sensor_id against whitelist
        if sensor_id not in Config.VALID_SENSOR_IDS:
            flash(f'Invalid sensor ID. Must be one of: {", ".join(Config.VALID_SENSOR_IDS)}', 'danger')
            return redirect(url_for('admin_sensor'))

        reading = data_manager.create_sensor_reading(temperature, humidity, sensor_id)
        audit_logger.log_admin_action(
            'create', 'sensor_reading',
            f'ID: {reading["id"]}, Temp: {temperature}°F, Humidity: {humidity}%'
        )
        flash('Sensor reading created successfully', 'success')

    except ValueError:
        flash('Invalid temperature or humidity value', 'danger')

    return redirect(url_for('admin_sensor'))


@app.route('/admin/sensor/<reading_id>/update', methods=['POST'])
@admin_required
@csrf_protect
def admin_sensor_update(reading_id):
    """Update an existing sensor reading."""
    try:
        temperature = float(request.form.get('temperature', 0))
        humidity = float(request.form.get('humidity', 0))

        # Validate ranges
        if not (0 <= temperature <= 150):
            flash('Temperature must be between 0 and 150°F', 'danger')
            return redirect(url_for('admin_sensor'))

        if not (0 <= humidity <= 100):
            flash('Humidity must be between 0 and 100%', 'danger')
            return redirect(url_for('admin_sensor'))

        if data_manager.update_sensor_reading(reading_id, temperature, humidity):
            audit_logger.log_admin_action(
                'update', 'sensor_reading',
                f'ID: {reading_id}, Temp: {temperature}°F, Humidity: {humidity}%'
            )
            flash('Sensor reading updated successfully', 'success')
        else:
            flash('Sensor reading not found', 'danger')

    except ValueError:
        flash('Invalid temperature or humidity value', 'danger')

    return redirect(url_for('admin_sensor'))


@app.route('/admin/sensor/<reading_id>/delete', methods=['POST'])
@admin_required
@csrf_protect
def admin_sensor_delete(reading_id):
    """Delete a sensor reading."""
    if data_manager.delete_sensor_reading(reading_id):
        audit_logger.log_admin_action('delete', 'sensor_reading', f'ID: {reading_id}')
        flash('Sensor reading deleted successfully', 'success')
    else:
        flash('Sensor reading not found', 'danger')

    return redirect(url_for('admin_sensor'))


@app.route('/admin/users')
@admin_required
def admin_users():
    """Admin page to manage user accounts."""
    users = data_manager.get_all_users()
    audit_logger.log_page_access(200)
    return render_template('admin_users.html', users=users, user=get_current_user())


@app.route('/admin/users/<username>/unlock', methods=['POST'])
@admin_required
@csrf_protect
def admin_user_unlock(username):
    """Manually unlock a user account."""
    if data_manager.unlock_user(username):
        audit_logger.log_admin_action('unlock', 'user_account', f'Username: {username}')
        flash(f'User "{username}" has been unlocked', 'success')
    else:
        flash(f'User "{username}" not found', 'danger')

    return redirect(url_for('admin_users'))


# ==================== MAIN ====================

if __name__ == '__main__':
    # Development server only - use gunicorn for production
    app.run(host='127.0.0.1', port=5000, debug=False)
