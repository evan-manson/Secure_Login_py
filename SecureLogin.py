from click import pass_obj
from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import hashlib
import os
from dotenv import load_dotenv
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day"])

talisman = Talisman(
    app,
    force_https=False,
    content_security_policy={
        'default-src': "'self'",
        'style-src': "'self' 'unsafe-inline'",
        'script-src': "'self'"
    }
)

load_dotenv()

secret = os.getenv("SECRET_KEY")
if not secret:
    raise RuntimeError("SECRET_KEY is not set!")
app.secret_key = secret

# Whitelist of chars
valid_chars = ('A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Z,a,b,c,d,e,f,g,h,'
               'i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,0,1,2,3,4,5,6,7,8,9,_,-,.,!,*,$')

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
def register():
    message = ""

    if request.method == "POST":
        name = request.form.get("username")
        user_check = check_chars(name)

        password = request.form.get("password")
        pass_check = check_chars(password)

        if len(password) < 8 or len(password) > 64:
            flash("Password must be between 8 and 64 characters.")
            return redirect(url_for("register"))

        if user_check or pass_check:
            flash("Invalid characters used")
            return render_template("register.html", message=message)
        try:
            create_user(name, password)
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already taken!")

    return render_template("register.html", message=message)

@app.route("/", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    #makes sure there is no user loaded in session
    session.pop("user", None)

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
    return render_template("index.html")


if __name__ == "__main__":
    init_db()
    app.run(debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")