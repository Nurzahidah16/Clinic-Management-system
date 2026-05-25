from flask import Flask, render_template, request, redirect, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import pyodbc
from datetime import timedelta

app = Flask(__name__)


app.secret_key = "super_secure_clinic_key"
app.permanent_session_lifetime = timedelta(minutes=15)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'LAX'

def get_db():
    return pyodbc.connect(
        'DRIVER={ODBC Driver 18 for SQL Server};'
        'SERVER=localhost;'
        'DATABASE=SecureClinicDB;'
        'Trusted_Connection=yes;'
        'TrustServerCertificate=yes;' 
    )

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("SELECT UserID, PasswordHash, Role FROM Users WHERE Username=?", (username,))
        user = cursor.fetchone()
        
        if user and check_password_hash(user[1], password):
            session.permanent = True
            session['admin'] = username
            session['role'] = user[2]
            session['user_id'] = user[0] 
            
            cursor.execute("INSERT INTO AuditLogs (UserID, ActionUser, ActionPerformed) VALUES (?, ?, ?)", 
                           (user[0], username, 'Successful Admin Login'))
            conn.commit()
            conn.close() 
            flash('Login successful!', 'success')
            return redirect('/dashboard')
        else:
            flash('Invalid credentials.', 'error')
            conn.close()
            
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'admin' not in session or session.get('role') != 'Admin': 
        return redirect('/')
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM vw_UserSummary")
    users = cursor.fetchall()
    
    cursor.execute("SELECT TOP 15 * FROM AuditLogs ORDER BY LogTime DESC")
    logs = cursor.fetchall()
    
    cursor.execute("SELECT COUNT(*) FROM Users")
    user_count = cursor.fetchone()[0]
    
    conn.close()
    return render_template('dashboard.html', users=users, logs=logs, user_count=user_count)

@app.route('/add_user', methods=['POST'])
@app.route('/add_user', methods=['POST'])
def add_user():
    if 'admin' in session and session.get('role') == 'Admin':
        username = request.form['username']
        role = request.form['role']
        hashed_pw = generate_password_hash('default123') 
        
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO Users (Username, PasswordHash, Role) 
                OUTPUT INSERTED.UserID 
                VALUES (?, ?, ?)
            """, (username, hashed_pw, role))
            
            new_id = cursor.fetchone()[0]
            
            cursor.execute("INSERT INTO AuditLogs (UserID, ActionUser, ActionPerformed) VALUES (?, ?, ?)", 
                           (new_id, session['admin'], f'Created {role} user: {username}'))
            conn.commit()
            flash(f'User {username} added successfully!', 'success')
            
        except pyodbc.IntegrityError:
            conn.rollback()
            flash(f'Error: The username "{username}" already exists. Please choose another.', 'error')
            
        except Exception as e:
            conn.rollback()
            flash(f'An unexpected error occurred: {str(e)}', 'error')
            
        finally:
            conn.close()
            
    return redirect('/dashboard')

@app.route('/delete_user/<int:id>')
def delete_user(id):
    if 'admin' not in session or session.get('role') != 'Admin':
        return redirect('/')
        
    if id == session.get('user_id'):
        flash("SECURITY ALERT: Cannot delete active Admin account.", 'error')
        return redirect('/dashboard')

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("EXEC sp_DeleteUser @DeleteID=?, @AdminName=?", (id, session['admin']))
    conn.commit()
    conn.close()
    flash('User securely deleted via Stored Procedure.', 'success')
    return redirect('/dashboard')

@app.route('/logout')
def logout():

    if 'admin' in session:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO AuditLogs (UserID, ActionUser, ActionPerformed) VALUES (?, ?, ?)", 
                       (session.get('user_id'), session['admin'], 'Admin Logged Out'))
        conn.commit()
        conn.close()
        
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)