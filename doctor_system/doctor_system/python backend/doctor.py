from flask import Blueprint, render_template, session, redirect, request, flash
from functools import wraps
from database.db import get_connection
import re
import secrets
from datetime import datetime
from urllib.parse import unquote

doctor = Blueprint('doctor', __name__)

# ==========================
# CSRF TOKEN SETUP 
# ==========================
def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


def validate_csrf():
    token_form = request.form.get("csrf_token")
    token_session = session.get("csrf_token")
    return token_form and token_session and token_form == token_session


# ==========================
# RBAC SECURITY
# ==========================
def role_required(role):
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):

            if 'doctor_id' not in session:
                flash("Session expired or unauthorized access", "error")
                return redirect('/login')

            user_role = session.get('role')

            if user_role != role:

                conn = get_connection()
                cursor = conn.cursor()

                cursor.execute("""
                    INSERT INTO audit_logs (user_role, action_performed)
                    VALUES (?, ?)
                """, (
                    user_role,
                    f"ROLE ESCALATION ATTEMPT: tried accessing {role} route"
                ))

                conn.commit()

                return "Unauthorized Access (Security Event Logged)", 403

            return f(*args, **kwargs)

        return decorated
    return wrapper
# ==========================
# INPUT VALIDATION 
# ==========================
def validate_text(field):
    if not field:
        return False

    field = field.strip()

    # block injection patterns
    if re.search(r"[<>;{}'\"--]", field):
        return False

    return 3 <= len(field) <= 100


def validate_notes(field):
    if field is None:
        return True
    if re.search(r"[<>;{}]", field):
        return False
    return len(field) <= 500


# ==========================
# SECURE AUDIT LOGGING
# ==========================
def log_action(role, action):
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO audit_logs (user_role, action_performed)
            VALUES (?, ?)
        """, (role, action))

        conn.commit()

    except Exception as e:
        print("Audit log error:", e)


# ==========================
# DASHBOARD
# ==========================
@doctor.route('/dashboard')
@role_required('doctor')
def dashboard():
    generate_csrf_token()
    return render_template('dashboard.html', doctor_name=session['doctor_name'])


# ==========================
# APPOINTMENTS
# ==========================
@doctor.route('/appointments')
@role_required('doctor')
def appointments():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT appointment_id, patient_name, appointment_date, appointment_time, status
        FROM appointments
        WHERE doctor_id = ?
    """, (session['doctor_id'],))

    return render_template('appointments.html', appointments=cursor.fetchall())


# ==========================
# ADD APPOINTMENT
# ==========================
@doctor.route('/add_appointment', methods=['GET', 'POST'])
@role_required('doctor')
def add_appointment():

    if request.method == 'POST':

        if not validate_csrf():
            return "CSRF validation failed", 403

        name = request.form['patient_name'].strip()
        date = request.form['appointment_date']
        time = request.form['appointment_time']

        if not validate_text(name):
            flash("Invalid patient name. Only valid letters allowed.", "error")
            return redirect('/add_appointment')

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO appointments (patient_name, doctor_id, appointment_date, appointment_time, status)
            VALUES (?, ?, ?, ?, ?)
        """, (name, session['doctor_id'], date, time, "Scheduled"))

        log_action("Doctor", f"{session['doctor_name']} created appointment for {name}")
        conn.commit()

        flash("Appointment created successfully.", "success")
        return redirect('/appointments')

    return render_template('add_appointment.html', csrf_token=generate_csrf_token())


# ==========================
# UPDATE STATUS
# ==========================
@doctor.route('/update_appointment_status/<int:id>')
@role_required('doctor')
def update_status(id):

    status = request.args.get('status')
    allowed = ["Scheduled", "In Progress", "Completed", "Cancelled"]

    if status not in allowed:
        return redirect('/appointments')

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE appointments
        SET status = ?
        WHERE appointment_id = ? AND doctor_id = ?
    """, (status, id, session['doctor_id']))

    log_action("Doctor", f"{session['doctor_name']} updated appointment {id} to {status}")
    conn.commit()

    flash(f"Appointment updated to {status}", "success")
    return redirect('/appointments')


# ==========================
# DELETE APPOINTMENT
# ==========================
@doctor.route('/delete_appointment/<int:id>')
@role_required('doctor')
def delete_appointment(id):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM appointments
        WHERE appointment_id = ? AND doctor_id = ?
    """, (id, session['doctor_id']))

    log_action("Doctor", f"{session['doctor_name']} deleted appointment {id}")
    conn.commit()

    flash("Appointment deleted successfully.", "success")
    return redirect('/appointments')


# ==========================
# MEDICAL RECORDS
# ==========================
@doctor.route('/medical_records')
@role_required('doctor')
def medical_records():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT record_id, patient_name, diagnosis, prescription, notes, updated_at
        FROM medical_records
        WHERE doctor_id = ?
    """, (session['doctor_id'],))

    return render_template('medical_records.html', records=cursor.fetchall())


# ==========================
# ADD MEDICAL RECORD
# ==========================
@doctor.route('/add_medical_record', methods=['GET', 'POST'])
@role_required('doctor')
def add_medical_record():

    if request.method == 'POST':

        if not validate_csrf():
            return "CSRF validation failed", 403

        name = request.form.get('patient_name')

        diagnosis = request.form.get('diagnosis_select')
        if diagnosis == "Other":
            diagnosis = request.form.get('diagnosis_other')

        prescription = request.form.get('prescription_select')
        if prescription == "Other":
            prescription = request.form.get('prescription_other')

        notes = request.form.get('notes')

        # CLEAN INPUT CHECK (PREVENT NULL ERROR)
        if not name or not diagnosis or not prescription:
            flash("Diagnosis and Prescription are required", "error")
            return redirect('/add_medical_record')

        if not validate_text(name):
            flash("Invalid patient name", "error")
            return redirect('/add_medical_record')

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO medical_records (patient_name, doctor_id, diagnosis, prescription, notes)
            VALUES (?, ?, ?, ?, ?)
        """, (name, session['doctor_id'], diagnosis, prescription, notes))

        conn.commit()

        log_action(
            "Doctor",
            f"{session['doctor_name']} added medical record for {name}"
        )

        flash("Medical record added successfully.", "success")
        return redirect('/medical_records')

    return render_template('add_medical_record.html', csrf_token=generate_csrf_token())

# ==========================
# SEARCH PATIENT
# ==========================
@doctor.route('/search_patient', methods=['GET', 'POST'])
@role_required('doctor')
def search_patient():

    results = []

    if request.method == 'POST':

        keyword = request.form.get('keyword', '')

        if not validate_text(keyword):
            flash("Invalid search input", "error")
            return redirect('/search_patient')

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT DISTINCT patient_name
            FROM medical_records
            WHERE doctor_id = ? AND patient_name LIKE ?
        """, (session['doctor_id'], '%' + keyword + '%'))

        results = [{"patient_name": r[0]} for r in cursor.fetchall()]

    return render_template('search_patient.html', results=results)

# ==========================
# PATIENT HISTORY
# ==========================
@doctor.route('/patient_history/<patient_name>')
@role_required('doctor')
def patient_history(patient_name):

    patient_name = unquote(patient_name)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT record_id, diagnosis, prescription, notes, updated_at
        FROM medical_records
        WHERE patient_name = ? AND doctor_id = ?
        ORDER BY updated_at DESC
    """, (patient_name, session['doctor_id']))

    return render_template(
        'patient_history.html',
        history=cursor.fetchall(),
        patient_name=patient_name
    )

# ==========================
# LOGIN ANALYTICS
# ==========================
@doctor.route('/login_analytics')
@role_required('doctor')
def login_analytics():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            username,
            status,
            attempt_time
        FROM login_attempts
        ORDER BY attempt_time DESC
    """)

    rows = cursor.fetchall()

    logs = [
        {
            "username": r[0],
            "status": r[1],
            "attempt_time": r[2]
        }
        for r in rows
    ]

    return render_template('login_analytics.html', logs=logs)

@doctor.route('/audit_logs')
@role_required('doctor')
def audit_logs():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT log_id, user_role, action_performed, log_time
        FROM audit_logs
        ORDER BY log_time DESC
    """)

    rows = cursor.fetchall()

    logs = [
        {
            "log_id": r[0],
            "user_role": r[1],
            "action_performed": r[2],
            "log_time": r[3]
        }
        for r in rows
    ]

    return render_template('audit_logs.html', logs=logs)

# ==========================
# ANALYTICS
# ==========================
@doctor.route('/analytics')
@role_required('doctor')
def analytics():

    conn = get_connection()
    cursor = conn.cursor()

    # Total appointments
    cursor.execute("""
        SELECT COUNT(*)
        FROM appointments
        WHERE doctor_id = ?
    """, (session['doctor_id'],))
    total_appointments = cursor.fetchone()[0]

    # Total medical records
    cursor.execute("""
        SELECT COUNT(*)
        FROM medical_records
        WHERE doctor_id = ?
    """, (session['doctor_id'],))
    total_records = cursor.fetchone()[0]

    # Total patients
    cursor.execute("""
        SELECT COUNT(DISTINCT patient_name)
        FROM medical_records
        WHERE doctor_id = ?
    """, (session['doctor_id'],))
    total_patients = cursor.fetchone()[0]

    # Today Appointments
    cursor.execute("""
        SELECT COUNT(*)
        FROM appointments
        WHERE doctor_id = ?
        AND CONVERT(date, appointment_date) = CONVERT(date, GETDATE())
    """, (session['doctor_id'],))
    today_appointments = cursor.fetchone()[0]

    return render_template(
        'analytics.html',
        total_appointments=total_appointments,
        total_records=total_records,
        total_patients=total_patients,
        today_appointments=today_appointments  
    )

# ==========================
# LOGOUT
# ==========================
@doctor.route('/logout')
def logout():
    session.clear()
    return redirect('/login')