# Environmental Sensor Monitoring System

A Flask-based web application demonstrating secure, authenticated access to ICS environmental sensor data, built to comply with **FIPS 200** and **NIST SP 800-53** security controls.

## Security Features

This project demonstrates implementation of federal security standards:

| NIST Control | Implementation |
|--------------|----------------|
| **AC-2** Account Management | Role-based access (user/administrator), failed attempt tracking, last login notification |
| **AC-7** Unsuccessful Logon Attempts | Account lockout after 4 failed attempts for 15 minutes |
| **AC-8** System Use Notification | Mandatory acknowledgment banner before login |
| **AC-9** Previous Logon Notification | Displays last successful login timestamp |
| **AU-2** Event Logging | Comprehensive audit trail of all access and admin actions |
| **IA-2** Identification & Authentication | Username/password with PBKDF2-SHA256 hashing (600k iterations) |
| **SA-11** Developer Security Testing | Static analysis with Bandit (see `banditresults.txt`) |

### Security Implementation Details

- **CSRF Protection**: Per-session tokens with constant-time comparison
- **Session Security**: HttpOnly cookies, SameSite=Lax, session regeneration on login
- **Password Storage**: Werkzeug's PBKDF2-SHA256 with per-user salt
- **Security Headers**: CSP, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection
- **Input Validation**: Server-side validation on all form inputs
- **File Locking**: Thread-safe JSON operations using `filelock`

## Quick Start

```bash
# Clone and setup
git clone <repository-url>
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
│
├── utils/
│   ├── auth.py            # Authentication decorators and session management
│   ├── audit.py           # NIST AU-2 compliant audit logging
│   ├── data_manager.py    # Thread-safe JSON CRUD operations
│   ├── data_generator.py  # Simulated sensor data generation
│   └── setup_users.py     # Demo user initialization script
│
├── templates/             # Jinja2 templates with Bootstrap 5
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

### Production Hardening Checklist

For actual deployment, implement the following:

- [ ] **HTTPS/TLS**: Set `SESSION_COOKIE_SECURE = True`
- [ ] **HSTS Header**: `Strict-Transport-Security: max-age=31536000`
- [ ] **Rate Limiting**: Add Flask-Limiter for brute-force protection
- [ ] **Database**: Replace JSON files with PostgreSQL/MySQL
- [ ] **Secrets Management**: Use AWS Secrets Manager, HashiCorp Vault, or similar
- [ ] **Password Policy**: Enforce complexity requirements on user creation
- [ ] **File Upload Validation**: Validate type, size, and content on ICS import
- [ ] **Log Integrity**: Cryptographic chaining or external log server
- [ ] **Monitoring**: Application performance monitoring and alerting
- [ ] **WAF**: Web Application Firewall for additional protection

### Known Bandit Findings

Static analysis with Bandit reports low-severity findings that are **intentional for this demo**:

- `B105` (hardcoded passwords): Demo credentials in `setup_users.py` - would use secure provisioning in production
- `B311` (random): Used in `data_generator.py` for sensor simulation - not security-sensitive

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
- **Security**: Werkzeug (password hashing), secrets (CSRF tokens)
- **Frontend**: Bootstrap 5.3, Chart.js
- **Data**: JSON with filelock for thread safety

## License

MIT License - See LICENSE file for details.
