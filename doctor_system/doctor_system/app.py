from flask import Flask, session, redirect, render_template
from routes.auth import auth
from routes.doctor import doctor
from datetime import timedelta

app = Flask(__name__)

# ==========================
# SECURITY CONFIG
# ==========================
app.secret_key = "super_secure_clinic_key"
app.permanent_session_lifetime = timedelta(minutes=15)

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'LAX'

# ==========================
# BLUEPRINTS
# ==========================
app.register_blueprint(auth)
app.register_blueprint(doctor)

# ==========================
# HOME
# ==========================
@app.route('/')
def home():
    return redirect('/login')

# ==========================
# DASHBOARD
# ==========================
@app.route('/dashboard')
def dashboard():

    if 'doctor_id' not in session:
        return redirect('/login')

    return render_template(
        'dashboard.html',
        doctor_name=session.get('doctor_name')
    )

# ==========================
# LOGOUT
# ==========================
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)