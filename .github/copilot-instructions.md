# Copilot Instructions for SecureLogin

## Project Overview

SecureLogin is a Flask-based authentication system with user registration and login. It uses SQLite for persistence, implements password hashing with PBKDF2-SHA256, and renders HTML templates with Flask's Jinja2 templating engine.

**Architecture:**
- **Flask App** (`SecureLogin.py`): Single-file entry point with database initialization, routing, and authentication logic
- **Database** (`SecureLogin.db`): SQLite with single `users` table storing username, salted password hash, and salt
- **Templates** (`templates/`): Jinja2 HTML templates for login (index.html), registration (register.html), and dashboard (dashboard.html)
- **Configuration**: Environment variables via `.env` file (SECRET_KEY is required)

## Running and Testing

### Start the Application
```bash
python SecureLogin.py
```
The app runs on `http://localhost:5000` (default Flask port). Debug mode is controlled by `FLASK_DEBUG` env var (default: false).

### Database
- **Initialize**: Automatically happens on app startup via `init_db()`
- **Reset**: Delete `SecureLogin.db` and restart the app

### Manual Testing Endpoints
- `GET /` - Login page
- `POST /` - Submit login credentials
- `GET /register` - Registration page
- `POST /register` - Submit registration
- `GET /dashboard` - Protected user dashboard (redirects to login if not authenticated)
- `GET /logout` - Clear session and return to login

## Key Conventions

### Input Validation
- Character whitelist in `valid_chars` tuple: alphanumeric, underscore, hyphen, period, exclamation, asterisk, dollar sign
- Both username and password are validated via `check_chars()` (returns `True` if invalid characters found, `False` if valid)
- Validation happens before password hashing to reject invalid input early

### Password Security
- Generated with `os.urandom(16)` for per-user salt (16 bytes = 128 bits)
- Hashed using PBKDF2 with SHA-256, 100,000 iterations
- Stored in database as hex strings (`salt.hex()`, `salted_hash.hex()`)
- Comparison is constant-time via `.hex()` string equality

### Session Management
- Flask session stores username under `session["user"]`
- Session is cleared on logout and at login start to prevent replay
- Dashboard and other protected routes check `if "user" not in session` and redirect to login

### Database Patterns
- All queries use parameterized statements with `?` placeholders to prevent SQL injection
- `sqlite3.IntegrityError` is caught on user creation (handles duplicate username constraint)
- Connections are short-lived: `get_db()` creates connection, used immediately, closed after query

### Template Rendering
- Flash messages for errors: use `flash()` in routes, iterate with `get_flashed_messages()` in templates
- Login page uses inline CSS; registration page is minimal HTML; dashboard shows logged-in username
- Registration and index templates have inconsistent styling (registration is barebones, index is modern)
