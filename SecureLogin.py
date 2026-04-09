from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import hashlib
import os
from dotenv import load_dotenv
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)

limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day"])

talisman = Talisman(
    app,
    force_https=False,
    session_cookie_secure=False,
    session_cookie_samesite='Lax',
    content_security_policy={
        'default-src': "'self'",
        'style-src': "'self' 'unsafe-inline'",
        'script-src': "'self'",
        'form-action': "'self'",
    }
)

csrf = CSRFProtect(app)


load_dotenv()

secret = os.getenv("SECRET_KEY")
if not secret:
    raise RuntimeError("SECRET_KEY is not set!")
app.secret_key = secret

# Whitelist of chars
valid_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-.,!*$')

# initializes database
def init_db():
    db = sqlite3.connect("SecureLogin.db")
    cursor = db.cursor()
    cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                pass_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            )
        """)
    db.commit()
    db.close()

    pass

def get_db():
    return sqlite3.connect("SecureLogin.db")

# makes new row in db with username, hashed and salted password, and the salt
def create_user(username, pass_hash):
    db = get_db()
    cursor = db.cursor()
    salt = os.urandom(16)

    salted_hash = hashlib.pbkdf2_hmac('sha256', pass_hash.encode('utf-8'), salt, 100000)

    cursor.execute(
        "INSERT INTO users (username, pass_hash, salt) VALUES (?, ?, ?)",
        (username, salted_hash.hex(), salt.hex())
    )
    db.commit()
    user_id = cursor.lastrowid
    db.close()
    return user_id

def check_chars(word):
    for char in word:
        if char not in valid_chars:
            return True
    return False

# registers new user
@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():
    if request.method == "POST":
        name = request.form.get("username")
        user_check = check_chars(name)

        password = request.form.get("password")
        pass_check = check_chars(password)

        if len(name) < 3 or len(name) > 32:
            flash("Username must be between 3 and 32 characters.")
            return redirect(url_for("register"))

        if len(password) < 8 or len(password) > 64:
            flash("Password must be between 8 and 64 characters.")
            return redirect(url_for("register"))

        if user_check or pass_check:
            flash("Invalid characters used")
            return render_template("register.html")
        try:
            create_user(name, password)
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already taken!")

    return render_template("register.html")

@app.route("/", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    # gets input of username and password
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        db = get_db()
        cursor = db.cursor()

        user_check = check_chars(username)
        pass_check = check_chars(password)

        if user_check or pass_check:
            flash("Invalid characters used")
            db.close()
            return redirect(url_for("login"))


        # gets the row in the db that matches the input username
        row = cursor.execute(
            "SELECT pass_hash, salt FROM users WHERE username = ?", (username,)
        ).fetchone()

        # if there is no such row, it does not log in
        if row is None:
            flash("Invalid username or password.")

        # if this row exists, the password is then hashed and salted then compared to
        # the one stored in the database
        else:
            stored_hash, stored_salt = row
            salt = bytes.fromhex(stored_salt)
            attempt_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

            if attempt_hash.hex() == stored_hash:
                session.clear()
                session["user"] = username
                return redirect(url_for("dashboard"))
            else:
                flash("Invalid username or password.")

        db.close()

    return render_template("index.html")

# shows the user they logged in if successful, otherwise brings back to home
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html")

# takes username out of session and returns user to home
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")