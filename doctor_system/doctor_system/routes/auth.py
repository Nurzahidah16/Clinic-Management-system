from flask import Blueprint, render_template, request, redirect, session, flash
from database.db import get_connection
from werkzeug.security import generate_password_hash, check_password_hash

auth = Blueprint('auth', __name__)

# ==========================
# LOGIN
# ==========================
@auth.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        email = request.form['email'].strip()
        password = request.form['password']

        conn = get_connection()
        cursor = conn.cursor()

        # ==========================
        # BRUTE FORCE CHECK
        # ==========================
        cursor.execute("""
            SELECT COUNT(*)
            FROM login_attempts
            WHERE username = ?
            AND status = 'FAILED'
            AND attempt_time >= DATEADD(MINUTE, -5, GETDATE())
        """, (email,))

        failed_attempts = cursor.fetchone()[0]

        if failed_attempts >= 3:

            flash(
                "Too many failed login attempts. Try again later.",
                "error"
            )

            return redirect('/login')

        # ==========================
        # CHECK USER
        # ==========================
        cursor.execute("""
            SELECT doctor_id, name, password_hash
            FROM doctors
            WHERE email = ?
        """, (email,))

        user = cursor.fetchone()

        # ==========================
        # INVALID USER
        # ==========================
        if not user:

            cursor.execute("""
                INSERT INTO login_attempts (username, status)
                VALUES (?, ?)
            """, (email, 'FAILED'))

            conn.commit()

            flash("Invalid credentials", "error")

            return redirect('/login')

        # ==========================
        # PASSWORD CHECK
        # ==========================
        if not check_password_hash(user[2], password):

            cursor.execute("""
                INSERT INTO login_attempts (username, status)
                VALUES (?, ?)
            """, (email, 'FAILED'))

            conn.commit()

            flash("Invalid credentials", "error")

            return redirect('/login')

        # ==========================
        # SUCCESSFUL LOGIN
        # ==========================
        cursor.execute("""
            INSERT INTO login_attempts (username, status)
            VALUES (?, ?)
        """, (email, 'SUCCESS'))

        cursor.execute("""
            INSERT INTO audit_logs (user_role, action_performed)
            VALUES (?, ?)
        """, (
            "Doctor",
            f"Dr. {user[1]} logged into the system"
        ))

        conn.commit()

        session.permanent = True
        session['doctor_id'] = user[0]
        session['doctor_name'] = user[1]
        session['role'] = 'doctor'

        flash("Login successful", "success")

        return redirect('/dashboard')

    return render_template('login.html')


# ==========================
# LOGOUT
# ==========================
@auth.route('/logout')
def logout():

    if 'doctor_name' in session:

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO audit_logs (user_role, action_performed)
            VALUES (?, ?)
        """, (
            "Doctor",
            f"Dr. {session['doctor_name']} logged out"
        ))

        conn.commit()

    session.clear()

    flash("Logged out successfully", "success")

    return redirect('/login')