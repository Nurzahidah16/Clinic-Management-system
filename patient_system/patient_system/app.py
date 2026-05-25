from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import timedelta, datetime
import pyodbc
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = "your_secret_key_here"
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
LOCKOUT_MINUTES = 10
MAX_LOGIN_ATTEMPTS = 5

SERVER = os.getenv('DB_SERVER', r'.\SQLEXPRESS')
DATABASE = os.getenv('DB_NAME', 'clinic_db')
USERNAME = os.getenv('DB_USER', '')
PASSWORD = os.getenv('DB_PASSWORD', '')
DRIVER = os.getenv('DB_DRIVER', 'ODBC Driver 17 for SQL Server')


def get_db_connection():
    try:
        if USERNAME and PASSWORD:
            conn_str = (
                f'DRIVER={{{DRIVER}}};'
                f'SERVER={SERVER};'
                f'DATABASE={DATABASE};'
                f'UID={USERNAME};'
                f'PWD={PASSWORD};'
                'TrustServerCertificate=yes;'
            )
        else:
            conn_str = (
                f'DRIVER={{{DRIVER}}};'
                f'SERVER={SERVER};'
                f'DATABASE={DATABASE};'
                'Trusted_Connection=yes;'
                'TrustServerCertificate=yes;'
            )
        return pyodbc.connect(conn_str)
    except Exception as e:
        print('DB connection error:', e)
        return None


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in') or 'patient_name' not in session:
            return redirect(url_for('login'))
        last_seen = session.get('last_seen')
        if last_seen:
            try:
                if (datetime.utcnow() - datetime.fromisoformat(last_seen)).total_seconds() > 900:
                    session.clear()
                    return redirect(url_for('login'))
            except Exception:
                session.clear()
                return redirect(url_for('login'))
        session['last_seen'] = datetime.utcnow().isoformat()
        return f(*args, **kwargs)
    return decorated


def init_db():
    conn = get_db_connection()
    if not conn:
        return
    cursor = conn.cursor()
    cursor.execute("""
    IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'patients')
    CREATE TABLE patients (
        id INT IDENTITY(1,1) PRIMARY KEY,
        full_name NVARCHAR(100) NOT NULL,
        email NVARCHAR(150) NOT NULL UNIQUE,
        password NVARCHAR(255) NOT NULL
    )
    """)
    cursor.execute("""
    IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'appointments')
    CREATE TABLE appointments (
        appointment_id INT IDENTITY(1,1) PRIMARY KEY,
        patient_name VARCHAR(100) NOT NULL,
        doctor_id INT NOT NULL,
        appointment_date DATE NOT NULL,
        appointment_time TIME NOT NULL,
        status VARCHAR(20) DEFAULT 'Pending'
    )
    """)
    cursor.execute("""
    IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'audit_log')
    CREATE TABLE audit_log (
        log_id INT IDENTITY(1,1) PRIMARY KEY,
        user_name NVARCHAR(100) NOT NULL,
        action_type NVARCHAR(50) NOT NULL,
        details NVARCHAR(500) NOT NULL,
        created_at DATETIME DEFAULT GETDATE()
    )
    """)
    conn.commit()
    conn.close()


def write_log(user_name, action_type, details):
    conn = get_db_connection()
    if not conn:
        return
    try:
        conn.cursor().execute(
            'INSERT INTO audit_log (user_name, action_type, details) VALUES (?, ?, ?)',
            (user_name, action_type, details)
        )
        conn.commit()
    finally:
        conn.close()


@app.route('/')
def home():
    return redirect(url_for('dashboard')) if session.get('logged_in') and 'patient_name' in session else redirect(url_for('login'))

def password_ok(password):
    if len(password) < 8:
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    return has_upper and has_lower and has_digit


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        if not full_name or not email or not password:
            flash('Please fill in all fields.', 'login_error')
            return render_template('register.html')

        if not password_ok(password):
            flash('Password must be 8+ chars and include upper, lower, and number.', 'login_error')
            return render_template('register.html')

        conn = get_db_connection()
        if not conn:
            flash('Database connection failed.', 'login_error')
            return render_template('register.html')

        try:
            conn.cursor().execute(
                'INSERT INTO patients (full_name, email, password) VALUES (?, ?, ?)',
                (full_name, email, generate_password_hash(password))
            )
            conn.commit()
            write_log(full_name, 'REGISTER', f'Patient registered: {email}')
            flash('Registered successfully. Please login.', 'success')
            return redirect(url_for('login'))
        except Exception:
            flash('Email already exists or database error.', 'login_error')
        finally:
            conn.close()

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        if not email or not password:
            flash('Please fill in all fields.', 'login_error')
            return render_template('login.html')
        attempts = session.get('login_attempts', 0)
        locked_until = session.get('locked_until')
        if locked_until:
            try:
                if datetime.utcnow() < datetime.fromisoformat(locked_until):
                    flash('Too many attempts. Try again later.', 'login_error')
                    return render_template('login.html')
            except Exception:
                session.pop('locked_until', None)

        conn = get_db_connection()
        if not conn:
            flash('Database connection failed.', 'login_error')
            return render_template('login.html')

        try:
            patient = conn.cursor().execute(
                'SELECT full_name, password FROM patients WHERE email = ?',
                (email,)
            ).fetchone()
        finally:
            conn.close()

        if patient and check_password_hash(patient.password, password):
            session.clear()
            session.permanent = True
            session['logged_in'] = True
            session['patient_name'] = patient.full_name
            session['full_name'] = patient.full_name
            session['last_seen'] = datetime.utcnow().isoformat()
            write_log(patient.full_name, 'LOGIN', f'Patient login success: {email}')
            return redirect(url_for('dashboard'))

        if patient is None:
            flash('Email is not registered.', 'login_error')
            write_log(email, 'LOGIN_FAIL', 'Unregistered email')
        else:
            flash('Wrong password.', 'login_error')
            write_log(email, 'LOGIN_FAIL', 'Wrong password')

    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/book_appointment', methods=['GET', 'POST'])
@login_required
def book_appointment():
    if request.method == 'POST':
        appointment_date = request.form.get('appointment_date', '').strip()
        appointment_time = request.form.get('appointment_time', '').strip()

        if not appointment_date or not appointment_time:
            flash('Please fill in all fields.', 'login_error')
            return render_template('book_appointment.html')

        conn = get_db_connection()
        if not conn:
            flash('Database connection failed.', 'login_error')
            return render_template('book_appointment.html')

        try:
            conn.cursor().execute(
                'INSERT INTO appointments (patient_name, doctor_id, appointment_date, appointment_time, status) VALUES (?, ?, ?, ?, ?)',
                (session['full_name'], 1, appointment_date, appointment_time, 'Scheduled')
            )
            conn.commit()
            write_log(session['full_name'], 'BOOK_APPOINTMENT', f'Appointment on {appointment_date} {appointment_time}')
            flash('Appointment booked successfully.', 'success')
            return redirect(url_for('my_appointments'))
        except Exception:
            flash('Unable to save appointment.', 'login_error')
        finally:
            conn.close()

    return render_template('book_appointment.html')


@app.route('/my_appointments')
@login_required
def my_appointments():
    conn = get_db_connection()
    if not conn:
        flash('Database connection failed.', 'login_error')
        return render_template('my_appointments.html', appointments=[])
    try:
        rows = conn.cursor().execute(
            'SELECT appointment_id, patient_name, doctor_id, appointment_date, appointment_time, status FROM appointments WHERE patient_name = ? ORDER BY appointment_date DESC, appointment_time DESC',
            (session['patient_name'],)
        ).fetchall()
    finally:
        conn.close()
    return render_template('my_appointments.html', appointments=rows)


@app.route('/logout')
def logout():
    user = session.get('full_name', 'unknown')
    write_log(user, 'LOGOUT', 'Patient logged out')
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True)