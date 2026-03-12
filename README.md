# Environmental Sensor Monitoring System

A Flask-based web application demonstrating secure, authenticated access to ICS environmental sensor data, built to comply with **FIPS 200** and **NIST SP 800-53** security controls.

## Security Features

This project demonstrates implementation of federal security standards:

| NIST Control | Implementation |
|--------------|----------------|
| **AC-2** Account Management | Role-based access (user/administrator), failed attempt tracking, last login notification |
| **AC-7** Unsuccessful Logon Attempts | Account lockout after 4 failed attempts, IP-based rate limiting (5/min) |
| **AC-8** System Use Notification | Mandatory acknowledgment banner before login |
| **AC-9** Previous Logon Notification | Displays last successful login timestamp |
| **AU-2/AU-3** Event Logging | Comprehensive audit trail with validated IP logging via trusted proxy configuration |
| **IA-2** Identification & Authentication | Username/password with scrypt hashing (backward compatible with PBKDF2) |
| **IA-5** Authenticator Management | Password complexity requirements (12+ chars, mixed case, digits, special chars) |
| **SA-11** Developer Security Testing | Static analysis with Bandit, security review (see `securityreview.txt`) |
| **SC-5** Denial of Service Protection | Rate limiting via Flask-Limiter, file upload size limits |
| **SC-8/SC-23** Session Security | HSTS headers, secure cookies in production, session regeneration |
| **SI-10** Input Validation | File upload validation, sensor ID whitelist, CSV injection prevention |
| **SI-11** Error Handling | Generic authentication error messages to prevent username enumeration |

### Security Implementation Details

- **CSRF Protection**: Per-session tokens with constant-time comparison
- **Session Security**: HttpOnly cookies, SameSite=Lax, Secure flag in production, session regeneration on login with fixation protection
- **Password Storage**: Werkzeug's scrypt with per-user salt (backward compatible with existing PBKDF2 hashes)
- **Password Policy**: Minimum 12 characters with uppercase, lowercase, digit, and special character requirements
- **Security Headers**: CSP, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, HSTS
- **Rate Limiting**: Flask-Limiter enforces 5 login attempts per minute per IP (prevents password spraying)
- **Input Validation**: Server-side validation on all form inputs, sensor ID whitelist, CSV output sanitization
- **File Upload Security**: Extension whitelist (.json, .csv), 10MB size limit, content structure validation
- **IP Logging**: Trusted proxy validation prevents X-Forwarded-For spoofing
- **Error Handling**: Generic authentication errors prevent username enumeration
- **File Locking**: Thread-safe JSON operations using `filelock`

## Quick Start

```bash
# Clone and setup
git clone https://github.com/ralenjor/envirosensor.git
cd envirosensor
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and set a secure SECRET_KEY:
# python -c "import os; print(os.urandom(32).hex())"

# Initialize demo users
python utils/setup_users.py

# Generate sample sensor data
python -c "from utils.data_generator import generate_sensor_data, save_sensor_data; from config import Config; save_sensor_data(generate_sensor_data(24), Config.SENSOR_DATA_FILE)"

# Run the application
python app.py
```

Access at `http://127.0.0.1:5000`

### Demo Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | AdminPass123! | Administrator |
| user1 | UserPass123! | User |

## Project Structure

```
envirosensor/
├── app.py                 # Main Flask application with routes
├── config.py              # Configuration and security settings
├── requirements.txt       # Python dependencies
├── .env.example           # Environment template (copy to .env)
├── securityreview.txt     # Security audit findings and remediation status
│
├── utils/
│   ├── auth.py            # Authentication decorators and session management
│   ├── audit.py           # NIST AU-2 compliant audit logging with trusted proxy support
│   ├── data_manager.py    # Thread-safe JSON CRUD with password validation
│   ├── data_generator.py  # Simulated sensor data generation
│   └── setup_users.py     # Demo user initialization script
│
├── templates/             # Jinja2 templates with Bootstrap 5
│   └── errors/
│       └── 429.html       # Rate limit exceeded error page
├── static/                # CSS and JavaScript assets
└── data/                  # JSON data storage
    ├── users.json         # User accounts (hashed passwords)
    ├── sensor_data.json   # Environmental readings
    └── access_log.json    # Audit trail
```

## Portfolio Notes: Production vs. Demo

This project is configured for **demonstration and portfolio purposes**. The following decisions prioritize showcasing code and architecture over production deployment:

### Included for Review (Would Exclude in Production)

| Item | Why Included | Production Approach |
|------|--------------|---------------------|
| `data/users.json` | Shows user schema and password hashing | Store in database, never in version control |
| `data/access_log.json` | Demonstrates audit logging format | Use centralized logging (SIEM, CloudWatch) |
| `data/sensor_data.json` | Shows data structure | Database or time-series DB |
| `utils/setup_users.py` | Shows user provisioning logic | Secure onboarding workflow, no hardcoded credentials |
| `banditresults.txt` | Demonstrates security testing | Run in CI/CD, don't commit results |
| `securityreview.txt` | Documents vulnerability assessment and remediation | Internal security documentation |

### Production Hardening Checklist

Security controls implemented following security review (see `securityreview.txt`):

- [x] **HTTPS/TLS**: `SESSION_COOKIE_SECURE = True` when `FLASK_ENV=production`
- [x] **HSTS Header**: `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- [x] **Rate Limiting**: Flask-Limiter (5 requests/minute on login endpoint)
- [x] **Password Policy**: 12+ characters with complexity requirements enforced
- [x] **File Upload Validation**: Extension whitelist, 10MB limit, content validation
- [x] **Trusted Proxy Validation**: Configurable `TRUSTED_PROXIES` for accurate IP logging
- [x] **Input Sanitization**: CSV injection prevention, sensor ID whitelist
- [x] **Session Fixation Protection**: Session regeneration with token binding
- [x] **Generic Error Messages**: Prevents username enumeration attacks
- [ ] **Database**: Replace JSON files with PostgreSQL/MySQL
- [ ] **Secrets Management**: Use AWS Secrets Manager, HashiCorp Vault, or similar
- [ ] **Log Integrity**: Cryptographic chaining or external log server
- [ ] **Monitoring**: Application performance monitoring and alerting
- [ ] **WAF**: Web Application Firewall for additional protection

### Security Review

A comprehensive security review identified and remediated 11 vulnerabilities (see `securityreview.txt`):
- **Critical**: Unvalidated file upload - now validates extension, size, and content
- **High**: CSV injection, missing rate limiting, insecure session cookies - all remediated
- **Medium**: Missing HSTS, username enumeration, IP spoofing, input validation - all remediated
- **Low**: Session fixation, password complexity - all remediated

### Known Bandit Findings

Static analysis with Bandit reports low-severity findings that are **intentional for this demo**:

- `B105` (hardcoded passwords): Demo credentials in `setup_users.py` - would use secure provisioning in production
- `B311` (random): Used in `data_generator.py` for sensor simulation - not security-sensitive

### Post-Deployment Checklist

After deploying security updates:
```bash
pip install -r requirements.txt  # Install Flask-Limiter
export FLASK_ENV=production      # Enable SESSION_COOKIE_SECURE
export TRUSTED_PROXIES=10.0.0.0/8  # Configure if behind load balancer
```

## API Routes

### Public
- `GET /` - Redirect based on auth status
- `GET /notice` - System use notification (AC-8)
- `GET /login` - Login form
- `POST /login` - Authenticate user

### Authenticated (User + Admin)
- `GET /home` - Dashboard with last login info
- `GET /sensor-data` - View 24-hour sensor readings
- `GET /reports` - Analytics and visualizations
- `GET /reports/export` - Download CSV export
- `GET /cloud` - Cloud sync status (simulated)
- `GET /about` - System information

### Admin Only
- `GET /admin/sensor` - Manage sensor readings
- `POST /admin/sensor` - Create reading
- `POST /admin/sensor/<id>/update` - Update reading
- `POST /admin/sensor/<id>/delete` - Delete reading
- `GET /admin/users` - User management
- `POST /admin/users/<username>/unlock` - Unlock account
- `GET /ics` - ICS data import interface
- `POST /ics/import` - Import data file
- `POST /ics/generate` - Generate test data

## Technologies

- **Backend**: Python 3.13, Flask 3.0
- **Security**: Werkzeug (password hashing), secrets (CSRF tokens), Flask-Limiter (rate limiting)
- **Frontend**: Bootstrap 5.3, Chart.js
- **Data**: JSON with filelock for thread safety

## License

MIT License - See LICENSE file for details.
