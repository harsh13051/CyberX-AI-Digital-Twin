from flask import Flask, request, render_template, redirect, url_for
import mysql.connector
import bcrypt
import os

app = Flask(__name__)

# DATABASE CONFIG
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'harsh7264867686',
    'database': 'SecureX'
}

MAX_ATTEMPTS = 3

# ---------------- HOME ----------------
@app.route('/')
def index():
    return render_template('index.html')

# ---------------- REGISTER ----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        db = mysql.connector.connect(**db_config)
        cursor = db.cursor()

        cursor.execute(
            "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
            (username, email, hashed_password)
        )

        db.commit()
        db.close()

        return "<h2>Registration Successful!</h2><a href='/login'>Go to Login</a>"

    return render_template('register.html')

# ---------------- LOGIN ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip = request.remote_addr

        db = mysql.connector.connect(**db_config)
        cursor = db.cursor()

        # Check if IP blocked
        cursor.execute("SELECT * FROM blocked_ips WHERE ip_address=%s", (ip,))
        if cursor.fetchone():
            return "🚫 Your IP is blocked!"

        # Fetch user
        cursor.execute("SELECT password FROM users WHERE username=%s", (username,))
        result = cursor.fetchone()

        if result and bcrypt.checkpw(password.encode('utf-8'), result[0]):
            cursor.execute(
                "INSERT INTO login_attempts (username, ip_address, status) VALUES (%s, %s, %s)",
                (username, ip, "SUCCESS")
            )
            db.commit()
            db.close()
            return redirect(url_for('home'))

        # Failed login
        cursor.execute(
            "INSERT INTO login_attempts (username, ip_address, status) VALUES (%s, %s, %s)",
            (username, ip, "FAILED")
        )

        cursor.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE ip_address=%s AND status='FAILED'",
            (ip,)
        )
        attempts = cursor.fetchone()[0]

        if attempts >= MAX_ATTEMPTS:
            cursor.execute("INSERT INTO blocked_ips (ip_address) VALUES (%s)", (ip,))
            db.commit()
            db.close()
            return "🚫 Too many attempts! IP blocked."

        db.commit()
        db.close()

        return f"❌ Login Failed! Attempts: {attempts}"

    return render_template('login.html')

# ---------------- HOME ----------------
@app.route('/home')
def home():
    return render_template('home.html')

# ---------------- DASHBOARD ----------------
@app.route('/dashboard')
def dashboard():
    db = mysql.connector.connect(**db_config)
    cursor = db.cursor()

    cursor.execute("SELECT username, ip_address, status, timestamp FROM login_attempts ORDER BY timestamp DESC")
    logs = cursor.fetchall()

    db.close()

    return render_template('dashboard.html', logs=logs)

# ---------------- NMAP SCAN ----------------
@app.route('/scan')
def scan():
    result = os.popen("nmap 127.0.0.1").read()
    return f"<pre>{result}</pre>"

# ---------------- RUN ----------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)