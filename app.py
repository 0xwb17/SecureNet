from flask import Flask, render_template, request, redirect, url_for, session
import pymysql
import html
import time
import re
from functools import wraps
import threading
import subprocess

app = Flask(__name__)

app.secret_key = 'super_secret_random_key_change_in_production_123!'

DB_CONFIG = {
    'host': 'localhost',
    'user': 'portal_user',
    'password': 'StrongDbP@ss123',
    'database': 'captive_portal'
}

failed_logins = {} 
MAX_ATTEMPTS = 5
MAX_DEVICES_PER_USER = 2
LOCKOUT_TIME = 15 * 60

active_users = {} 
HEARTBEAT_TIMEOUT = 15 

def get_client_ip():
    return request.remote_addr

def is_ip_locked(ip):
    if ip not in failed_logins:
        return False, 0
    attempt_data = failed_logins[ip]
    time_since_first_fail = time.time() - attempt_data['first_fail_time']
    if time_since_first_fail > LOCKOUT_TIME:
        del failed_logins[ip]
        return False, 0
    if attempt_data['count'] >= MAX_ATTEMPTS:
        remaining_time = int(LOCKOUT_TIME - time_since_first_fail)
        minutes_left = remaining_time // 60
        return True, minutes_left
    return False, 0

def record_failed_login(ip):
    if ip not in failed_logins:
        failed_logins[ip] = {"count": 1, "first_fail_time": time.time()}
    else:
        failed_logins[ip]["count"] += 1

def reset_failed_logins(ip):
    if ip in failed_logins:
        del failed_logins[ip]

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'role' not in session or session['role'] != 'admin':
            return "Unauthorized: Admins only.", 403
        return f(*args, **kwargs)
    return decorated_function

def get_db_connection():
    return pymysql.connect(**DB_CONFIG, cursorclass=pymysql.cursors.DictCursor)

def network_monitor():
    while True:
        time.sleep(60) 
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT id, ip_address FROM connection_logs WHERE logout_time IS NULL")
            active_sessions = cursor.fetchall()
            
            for session_log in active_sessions:
                log_id = session_log['id']
                user_ip = session_log['ip_address']
                
                # Skip checking localhost
                if user_ip in ['127.0.0.1', '10.0.0.1']:
                    continue
                

                result = subprocess.run(
                    ['arping', '-c', '1', '-w', '2', user_ip], 
                    stdout=subprocess.DEVNULL, 
                    stderr=subprocess.DEVNULL
                )
                
                
                if result.returncode != 0:
                    print(f"[NETWORK MONITOR] Device {user_ip} LEFT THE NETWORK (ARP failed). Ending Log ID {log_id}.")
                    cursor.execute(
                        "UPDATE connection_logs SET logout_time = NOW(), data_downloaded_mb = 0.00, data_uploaded_mb = 0.00 WHERE id = %s", 
                        (log_id,)
                    )
                    conn.commit()
                    
            conn.close()
        except Exception as e:
            print(f"[NETWORK MONITOR] Error: {e}")

@app.route('/', methods=['GET'], defaults={'path': ''}, endpoint='index')
@app.route('/<path:path>', endpoint='index')
def catch_all(path):
    if 'logged_in' in session:
        if session['role'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        
        
        active_users[get_client_ip()] = time.time()
        return render_template('user_dashboard.html', username=session['username'])
    
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ""
    client_ip = get_client_ip()
    
    locked, minutes_left = is_ip_locked(client_ip)
    if locked:
        error = f"Too many failed attempts. IP locked for {minutes_left} more minutes."
        return render_template('login.html', error=error)
    
    if request.method == 'POST':
        raw_username = request.form.get('username', '')
        raw_password = request.form.get('password', '')
        username = html.escape(raw_username)
        password = html.escape(raw_password)

        if not re.match(r"^[a-zA-Z0-9_]{3,20}$", raw_username):
            record_failed_login(client_ip) 
            error = "Invalid username format. Only letters, numbers, and underscores allowed."
            return render_template('login.html', error=error)

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            sql = "SELECT * FROM users WHERE username = %s LIMIT 1"
            cursor.execute(sql, (username,))
            user = cursor.fetchone()

            from werkzeug.security import check_password_hash
            
            if user and check_password_hash(user['password_hash'], raw_password):
                reset_failed_logins(client_ip)
                session['logged_in'] = True
                session['username'] = user['username']
                session['role'] = user['role']
                session['user_id'] = user['id']
                
                if user['role'] == 'admin':
                    return redirect(url_for('admin_dashboard'))
                
                cursor.execute(
                    "SELECT id, ip_address FROM connection_logs WHERE user_id = %s AND logout_time IS NULL", 
                    (user['id'],)
                )
                active_sessions = cursor.fetchall()
                
                if len(active_sessions) >= MAX_DEVICES_PER_USER:
                    is_known_ip = any(session['ip_address'] == client_ip for session in active_sessions)
                    if not is_known_ip:
                        error = f"Max device limit reached ({MAX_DEVICES_PER_USER}). Log out of another device first."
                        return render_template('login.html', error=error)
                    else:
                        cursor.execute(
                            "UPDATE connection_logs SET logout_time = NOW(), data_downloaded_mb = 0.00, data_uploaded_mb = 0.00 WHERE user_id = %s AND ip_address = %s AND logout_time IS NULL", 
                            (user['id'], client_ip)
                        )
                        conn.commit()
                
                cursor.execute(
                    "INSERT INTO connection_logs (user_id, ip_address, login_time) VALUES (%s, %s, NOW())", 
                    (user['id'], client_ip)
                )
                conn.commit()
                session['log_id'] = cursor.lastrowid
                
                return redirect(url_for('index'))
            else:
                record_failed_login(client_ip)
                locked_now, mins = is_ip_locked(client_ip)
                if locked_now:
                    error = f"Too many failed attempts. IP locked for {mins} more minutes."
                else:
                    attempts_left = MAX_ATTEMPTS - failed_logins[client_ip]['count']
                    error = f"Invalid username or password. {attempts_left} attempts remaining."

        except Exception as e:
            error = f"System error: {str(e)}"
        finally:
            if 'conn' in locals() and conn.open:
                conn.close()

    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    if 'log_id' in session:
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            simulated_download_mb = 15.45
            simulated_upload_mb = 2.10
            cursor.execute(
                "UPDATE connection_logs SET logout_time = NOW(), data_downloaded_mb = %s, data_uploaded_mb = %s WHERE id = %s", 
                (simulated_download_mb, simulated_upload_mb, session['log_id'])
            )
            conn.commit()
            conn.close()
        except Exception as e:
            pass
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin')
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role, password_hash FROM users")
    users = cursor.fetchall()
    cursor.execute("""
        SELECT c.id, u.username, c.ip_address, c.login_time, c.logout_time, c.data_downloaded_mb, c.data_uploaded_mb 
        FROM connection_logs c 
        JOIN users u ON c.user_id = u.id 
        ORDER BY c.login_time DESC 
        LIMIT 20
    """)
    logs = cursor.fetchall()
    msg = session.pop('msg', None)
    msg_type = session.pop('msg_type', None)    
    conn.close()
    return render_template('admin.html', users=users, logs=logs)

@app.route('/admin/add_user', methods=['POST'])
@admin_required
def add_user():
    raw_user = request.form.get('username', '')
    raw_pass = request.form.get('password', '')
    raw_role = request.form.get('role', 'user') 

    if not re.match(r"^[a-zA-Z0-9_]{3,20}$", raw_user):
        session['msg'] = "Invalid username format."
        session['msg_type'] = "error"
    elif raw_role not in ['user', 'admin']: 
        session['msg'] = "Invalid role specified."
        session['msg_type'] = "error"                        
    elif len(raw_pass) < 6:
        session['msg'] = "Password must be at least 6 characters."
        session['msg_type'] = "error"
    else:
        try:
            from werkzeug.security import generate_password_hash
            hashed_pw = generate_password_hash(raw_pass, method='pbkdf2:sha256', salt_length=16)
            
            
            role = raw_role 
            safe_user = html.escape(raw_user)
            
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)", (safe_user, hashed_pw, role))
            conn.commit()
            conn.close()
            
            session['msg'] = f"User '{raw_user}' created successfully!"
            session['msg_type'] = "success"
        except pymysql.err.IntegrityError:
            session['msg'] = "Error: Username already exists."
            session['msg_type'] = "error"

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    if user_id == 1:
        return "Cannot delete primary admin.", 400
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/library')
def library():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    return render_template('library.html')

@app.route('/cafeteria')
def cafeteria():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    return render_template('cafeteria.html')

if __name__ == '__main__':
    print("[*] Starting SecureNet Backend...")
    
    # Layer 2 ARP Monitor Active
    monitor_thread = threading.Thread(target=network_monitor, daemon=True)
    monitor_thread.start()
    print("[+] Network Monitor active (Using ARP to detect physical disconnects)...")
    
    app.run(host='0.0.0.0', port=80, debug=False)
