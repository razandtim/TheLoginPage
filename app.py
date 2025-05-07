import sqlite3
from flask import Flask, render_template, request, redirect, make_response
from flask_bcrypt import Bcrypt
import jwt
import datetime
import re

app = Flask(__name__)
bcrypt = Bcrypt(app)

PRIVATE_KEY = "your_super_secret_private_key"  # Replace this with a secure key or load from a file
DATABASE = 'users.db'

# --- Initialize database ---
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        first_name TEXT,
                        last_name TEXT,
                        email TEXT UNIQUE,
                        password TEXT,
                        gender TEXT,
                        youtube_link TEXT
                    )''')
        conn.commit()

init_db()

# --- Home page (dashboard if logged in, welcome page otherwise) ---
@app.route("/")
def home():
    token = request.cookies.get("token")
    if token:
        try:
            payload = jwt.decode(token, PRIVATE_KEY, algorithms=["HS256"])
            return redirect("/dashboard")
        except jwt.ExpiredSignatureError:
            pass
        except jwt.InvalidTokenError:
            pass
    return render_template("dashboard.html", first_name=None, youtube_link=None)

# --- Registration ---
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data = request.form
        email = data.get("email")

        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE email = ?", (email,))
            if c.fetchone():
                return render_template("register.html", error="Email is already used.")

            hashed_pw = bcrypt.generate_password_hash(data.get("password")).decode('utf-8')
            youtube_link = data.get("youtube_link") if data.get("add_video") == "yes" else ""
            c.execute("""
                INSERT INTO users (first_name, last_name, email, password, gender, youtube_link)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (data.get("first_name"), data.get("last_name"), email,
                 hashed_pw, data.get("gender"), youtube_link))
            conn.commit()
            user_id = c.lastrowid
            token = generate_token(user_id)
            resp = make_response(redirect("/dashboard"))
            resp.set_cookie("token", token)
            return resp

    return render_template("register.html")

# --- Login ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        # Basic email format check
        if not re.match(r"^[^@]+@[^@]+\.[a-zA-Z]{2,}$", email):
            return render_template("login.html", error="Please enter a valid email address.")

        # Basic password length check
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute("SELECT id, password FROM users WHERE email = ?", (email,))
            user = c.fetchone()
            if user:
                user_id, hashed_pw = user
                if bcrypt.check_password_hash(hashed_pw, password):
                    token = generate_token(user_id)
                    resp = make_response(redirect("/dashboard"))
                    resp.set_cookie("token", token)
                    return resp
                else:
                    return render_template("login.html", error="Wrong password.")
            else:
                return render_template("login.html", error="User does not exist.")

    return render_template("login.html")

# --- Dashboard (after login) ---
@app.route("/dashboard")
def dashboard():
    token = request.cookies.get("token")
    if not token:
        return redirect("/")
    try:
        payload = jwt.decode(token, PRIVATE_KEY, algorithms=["HS256"])
        user_id = payload["user_id"]
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute("SELECT first_name, youtube_link FROM users WHERE id = ?", (user_id,))
            row = c.fetchone()
            if row:
                return render_template("dashboard.html", first_name=row[0], youtube_link=row[1])
    except jwt.ExpiredSignatureError:
        return redirect("/")
    except jwt.InvalidTokenError:
        return redirect("/")
    return redirect("/")

@app.route("/update_video", methods=["POST"])
def update_video():
    token = request.cookies.get("token")
    if not token:
        return redirect("/login")

    try:
        payload = jwt.decode(token, PRIVATE_KEY, algorithms=["HS256"])
        user_id = payload["user_id"]
        new_link = request.form.get("youtube_link")

        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute("UPDATE users SET youtube_link = ? WHERE id = ?", (new_link, user_id))
            conn.commit()

        return redirect("/dashboard")

    except jwt.ExpiredSignatureError:
        return redirect("/login")
    except jwt.InvalidTokenError:
        return redirect("/login")


# --- Logout ---
@app.route("/logout")
def logout():
    resp = make_response(redirect("/"))
    resp.set_cookie("token", '', expires=0)
    return resp

# --- Token Generator ---
def generate_token(user_id):
    payload = {
        "user_id": user_id,
        "login_time": str(datetime.datetime.utcnow()),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, PRIVATE_KEY, algorithm="HS256")

# --- Run App ---
if __name__ == "__main__":
    app.run(debug=True)
