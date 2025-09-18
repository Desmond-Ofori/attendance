import sys
import os
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)
from datetime import datetime, timedelta
import os
import logging
from flask import Flask, jsonify, request, render_template, session, redirect, url_for, flash, send_from_directory, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_mail import Mail, Message
from flask_cors import CORS
from dotenv import load_dotenv
from flask_socketio import SocketIO, join_room, emit
import jwt
import re

# Local imports
from tapin_backend.models import db, User, Course, Enrollment, migrate_db
from tapin_backend.auth import auth_bp
from tapin_backend.routes_classes import classes_bp
from tapin_backend.routes_attendance import attendance_bp
from tapin_backend.routes_announcements import announcements_bp
from tapin_backend.routes_student_profile import student_profile_bp
from tapin_backend.routes_profile import profile_bp
from tapin_backend.routes_analytics import analytics_bp
from tapin_backend.routes_reports import reports_bp
from tapin_backend.routes_notifications import notifications_bp
from tapin_backend.routes_qr_attendance import qr_attendance_bp
from tapin_backend.routes_student_analytics import student_analytics_bp
from tapin_backend.routes_bulk_enrollment import bulk_enrollment_bp
from tapin_backend.routes_schedule import schedule_bp
from tapin_backend.routes_reminders import reminders_bp
from tapin_backend.routes_backup import backup_bp
from tapin_backend.routes_visualization import visualization_bp
from tapin_backend.utils import hash_password, verify_password, create_token, broadcast_check_in, verify_verification_token

logging.basicConfig(level=logging.DEBUG)
load_dotenv()


app = Flask(
    __name__,
    static_folder=os.path.join(BASE_DIR, 'static'),
    template_folder=os.path.join(BASE_DIR, 'templates')
)

# Config
instance_dir = os.path.join(BASE_DIR, 'instance')
os.makedirs(instance_dir, exist_ok=True)
default_db_path = f"sqlite:///{os.path.join(instance_dir, 'tapin.db')}"

# Get the database URL from environment - CRITICAL FIX
database_url = os.getenv('DATABASE_URL')
print(f"[DEBUG] DATABASE_URL from env: {database_url}")  # Debug logging

# FIX FOR RENDER: Handle PostgreSQL URL format
if database_url and database_url.strip():
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
        print(f"[DEBUG] Fixed DATABASE_URL: {database_url}")  # Debug logging
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = default_db_path
    print(f"[DEBUG] Using default SQLite database: {default_db_path}")  # Debug logging

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'devkey-change-me')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['JWT_TOKEN_LOCATION'] = ["cookies", "headers"]
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['DEBUG'] = os.getenv('DEBUG', 'False').lower() == 'true'
app.config['TESTING'] = False

# Enable CORS
origins = os.getenv('CORS_ORIGINS', '').split(',') if os.getenv('CORS_ORIGINS') else ['*', 'https://tapin-attendance-app.onrender.com', 'http://localhost:3000', 'http://localhost:5000', 'http://127.0.0.1:5000']
CORS(app, supports_credentials=True, origins=origins)

# -------------------------------
# DEBUG ROUTES (TEMPORARY - REMOVE AFTER FIXING)
# -------------------------------
@app.route('/api/debug/db-check')
def debug_db_check():
    try:
        # Try a simple database query - FIXED SQL expression
        from sqlalchemy import text
        result = db.session.execute(text('SELECT 1')).scalar()
        return jsonify({
            'database_accessible': True,
            'result': result,
            'db_uri': app.config['SQLALCHEMY_DATABASE_URI'],
            'env': os.getenv('FLASK_ENV'),
            'database_type': 'PostgreSQL' if 'postgresql' in str(app.config['SQLALCHEMY_DATABASE_URI']) else 'SQLite'
        })
    except Exception as e:
        return jsonify({
            'database_accessible': False,
            'error': str(e),
            'db_uri': app.config['SQLALCHEMY_DATABASE_URI'],
            'env': os.getenv('FLASK_ENV'),
            'database_type': 'PostgreSQL' if 'postgresql' in str(app.config['SQLALCHEMY_DATABASE_URI']) else 'SQLite'
        }), 500

@app.route('/api/debug/config')
def debug_config():
    return jsonify({
        'flask_env': os.getenv('FLASK_ENV'),
        'debug': app.config.get('DEBUG'),
        'has_secret_key': bool(app.config.get('SECRET_KEY')),
        'database_uri': app.config.get('SQLALCHEMY_DATABASE_URI'),
        'mail_configured': bool(app.config.get('MAIL_PASSWORD'))
    })

@app.route('/api/health-simple')
@app.route('/api/debug/users')
def debug_users():
    users = User.query.all()
    result = []
    for user in users:
        result.append({
            'id': user.id,
            'email': user.email,
            'role': user.role,
            'is_verified': user.is_verified,
            'fullname': user.fullname
        })
    return jsonify({'users': result, 'count': len(result)})
def health_simple():
    return jsonify({'status': 'ok', 'message': 'Server is running'})

@app.route('/api/debug/login-query')
def debug_login_query():
    try:
        from tapin_backend.models import User
        email = 'ey49590568@gmail.com'
        role = 'lecturer'
        user = User.query.filter(User.email == email, User.role == role).first()
        if user:
            return jsonify({
                'found': True,
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'role': str(user.role),
                    'role_type': type(user.role).__name__
                }
            })
        else:
            return jsonify({'found': False, 'message': 'No matching user found with email and role'})
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        logging.error(f"[DEBUG LOGIN QUERY] Exception during query: {str(e)}\nTraceback:\n{tb}")
        return jsonify({
            'error': str(e),
            'exception_type': type(e).__name__,
            'traceback': tb
        }), 500

# Initialize extensions
# Initialize extensions
db.init_app(app)

from flask_migrate import Migrate
migrate = Migrate(app, db)

# Auto-apply migrations on startup for production DB
if 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI']:
    with app.app_context():
        try:
            migrate.upgrade()
            print("[AUTO-MIGRATE] Database migrations applied successfully")
        except Exception as e:
            print(f"[AUTO-MIGRATE] Warning: Failed to apply migrations: {str(e)}")
            # Don't fail startup, log and continue
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', 'myapp@gmail.com')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'myapp@gmail.com')
mail = Mail(app)
if not app.config['MAIL_PASSWORD']:
    logging.warning("[APP START] MAIL_PASSWORD not set in .env. Verification and reset emails will fail unless using dev bypass. Please set MAIL_PASSWORD=your_gmail_app_password in .env")


from flask_jwt_extended import JWTManager
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# -------------------------------
# SOCKET.IO EVENTS
# -------------------------------
@socketio.on('connect')
def handle_connect():
    print('Client connected')

    @socketio.on('disconnect')
    def handle_disconnect():
        print('Client disconnected')

@socketio.on('join_class')
def handle_join_class(data):
    try:
        token = data.get('token')
        class_id = data.get('classId')
        
        if not token or not class_id:
            emit('error', {'message': 'Missing token or class ID'})
            return False
        
        # Verify token (you'll need to implement this)
        # For now, we'll just join the room
        join_room(f"class_{class_id}")
        emit('joined', {'classId': class_id})
        
    except Exception as e:
        emit('error', {'message': f'Connection error: {str(e)}'})


# -------------------------------
# BLUEPRINTS
# -------------------------------
blueprints = [
    (auth_bp, '/api/auth'), (profile_bp, '/api/profile'), (classes_bp, '/api/classes'), (attendance_bp, '/api'),
    (announcements_bp, '/api/announcements'), (student_profile_bp, '/api/student'),
    (analytics_bp, '/api/analytics'), (reports_bp, '/api/reports'),
    (notifications_bp, '/api/notifications'), (qr_attendance_bp, '/api/qr'),
    (student_analytics_bp, '/api/student-analytics'), (bulk_enrollment_bp, '/api/bulk'),
    (schedule_bp, '/api/schedule'), (reminders_bp, '/api/reminders'), (backup_bp, '/api/backup'),
    (visualization_bp, '/api/visualization')
]
for bp, prefix in blueprints:
    app.register_blueprint(bp, url_prefix=prefix)

# -------------------------------
# AUTH DECORATORS
# -------------------------------
def login_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this resource', 'error')
            return redirect(url_for('account'))
        return f(*args, **kwargs)
    return wrapper

def lecturer_required(f):
    from functools import wraps
    import logging
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'lecturer':
            flash('Please login as a lecturer to access this page', 'error')
            return redirect(url_for('lecturer_login_page'))
        
        is_verified = session.get('is_verified', False)
        current_path = request.path
        
        if not is_verified:
            if current_path not in ['/lecturer/initial-home', '/lecturer/dashboard']:
                logging.warning(f"[LECTURER_REQUIRED] Unverified lecturer {session['user_id']} on {current_path}, redirecting to initial_home")
                flash('Please verify your email before accessing full features', 'warning')
                return redirect(url_for('lecturer_initial_home'))
            else:
                logging.info(f"[LECTURER_REQUIRED] Allowing limited access for unverified lecturer on {current_path}")
        else:
            logging.info(f"[LECTURER_REQUIRED] Access granted for verified lecturer on {current_path}")
        
        return f(*args, **kwargs)
    return wrapper

def student_required(f):
    from functools import wraps
    import logging
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'student':
            flash('Please login as a student to access this page', 'error')
            return redirect(url_for('student_login_page'))
        
        is_verified = session.get('is_verified', False)
        current_path = request.path
        
        if not is_verified and current_path != '/student/initial-home':
            logging.warning(f"[STUDENT_REQUIRED] Unverified student {session['user_id']} on {current_path}, redirecting to initial_home")
            flash('Please verify your email to access full features', 'warning')
            return redirect(url_for('student_initial_home'))
        else:
            if not is_verified:
                logging.info(f"[STUDENT_REQUIRED] Allowing limited access for unverified student on initial_home")
            else:
                logging.info(f"[STUDENT_REQUIRED] Access granted for verified student on {current_path}")
        
        return f(*args, **kwargs)
    return wrapper

# -------------------------------
# FRONTEND ROUTES
# -------------------------------
@app.route('/')
def home():
    return render_template('welcome_page/index.html')

@app.route('/account')
def account():
    return render_template('welcome_page/account.html')

@app.route('/lecturer_login')
def lecturer_login_page():
    return render_template('welcome_page/lecturer_login.html')

@app.route('/student_login')
def student_login_page():
    return render_template('welcome_page/student_login.html')

@app.route('/lecturer_create_account')
def lecturer_create_account_page():
    return render_template('welcome_page/lecturer_create_account.html')

@app.route('/student_create_account')
def student_create_account_page():
    return render_template('welcome_page/student_create_account.html')

@app.route('/lecturer_forgot_password')
def lecturer_forgot_password_page():
    return render_template('welcome_page/lecturer_forgot_password.html')

@app.route('/student_forgot_password')
def student_forgot_password_page():
    return render_template('welcome_page/student_forgot_password.html')

@app.route('/reset_password')
def reset_password_page():
    token = request.args.get('token')
    role = request.args.get('role')
    if not token or not role:
        flash('Invalid reset link', 'error')
        return redirect(url_for('account'))
    return render_template('welcome_page/reset_password.html', token=token, role=role)

@app.route('/api/send-reset-link', methods=['POST'])
def send_reset_link():
    logging.info("[SEND_RESET_LINK] Request received")
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    email = (data.get('email') or '').strip().lower()
    role = data.get('role')

    logging.info(f"[SEND_RESET_LINK] Parsed data: email={email}, role={role}")

    if not email or not role:
        logging.warning(f"[SEND_RESET_LINK] Missing email or role: email={bool(email)}, role={role}")
        return jsonify({'error': 'Email and role are required'}), 400

    # Email validation
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        logging.warning(f"[SEND_RESET_LINK] Invalid email format: {email}")
        return jsonify({'error': 'Invalid email format'}), 400

    user = User.query.filter_by(email=email, role=role).first()
    if not user:
        logging.info(f"[SEND_RESET_LINK] No user found for {email}, {role} - security response")
        # Don't reveal if user exists for security
        return jsonify({'message': 'If an account with this email exists, a reset link has been sent.'}), 200

    try:
        token = make_reset_token(email, role)
        logging.info(f"[SEND_RESET_LINK] Reset token created for {email}")
    except Exception as e:
        logging.error(f"[SEND_RESET_LINK] Failed to create reset token for {email}: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to generate reset link'}), 500

    if send_reset_email(email, role, token):
        logging.info(f"[SEND_RESET_LINK] Reset email sent successfully to {email}")
        return jsonify({'message': 'Password reset link sent to your email.'}), 200
    else:
        logging.error(f"[SEND_RESET_LINK] Failed to send reset email to {email}")
        return jsonify({'error': 'Failed to send reset email. Please try again.'}), 500

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    logging.info("[RESET_PASSWORD] Request received")
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    token = data.get('token')
    role = data.get('role')
    password = data.get('password')
    confirm_password = data.get('confirm_password', data.get('confirmPassword', ''))

    logging.info(f"[RESET_PASSWORD] Parsed data: token_len={len(token) if token else 0}, role={role}, password_len={len(password) if password else 0}, confirm_len={len(confirm_password) if confirm_password else 0}")

    if not all([token, role, password]):
        logging.warning(f"[RESET_PASSWORD] Missing required fields: token={bool(token)}, role={bool(role)}, password={bool(password)}")
        return jsonify({'success': False, 'error': 'Token, role, and password are required'}), 400

    if password != confirm_password:
        logging.warning(f"[RESET_PASSWORD] Passwords do not match for role={role}")
        return jsonify({'success': False, 'error': 'Passwords do not match'}), 400

    # Password strength validation (same as registration)
    errors = []
    if len(password) < 8:
        errors.append('Password must be at least 8 characters long')
        logging.warning(f"[RESET_PASSWORD] Password too short: length={len(password)}")
    if not re.search(r'[A-Z]', password):
        errors.append('Password must contain at least one uppercase letter')
        logging.warning("[RESET_PASSWORD] No uppercase in password")
    if not re.search(r'[a-z]', password):
        errors.append('Password must contain at least one lowercase letter')
        logging.warning("[RESET_PASSWORD] No lowercase in password")
    if not re.search(r'\d', password):
        errors.append('Password must contain at least one digit')
        logging.warning("[RESET_PASSWORD] No digit in password")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append('Password must contain at least one special character')
        logging.warning("[RESET_PASSWORD] No special char in password")

    if errors:
        error_msg = ', '.join(errors)
        logging.warning(f"[RESET_PASSWORD] Password validation errors: {error_msg}")
        return jsonify({'success': False, 'error': error_msg}), 400

    try:
        valid, payload = verify_reset_token(token, max_age=3600)
        logging.info(f"[RESET_PASSWORD] Token verification: valid={valid}, payload_role={payload.get('role') if valid else 'N/A'}")
    except Exception as e:
        logging.error(f"[RESET_PASSWORD] Token verification failed: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'message': 'Invalid token'}), 400

    if not valid:
        logging.warning("[RESET_PASSWORD] Invalid or expired token")
        return jsonify({'success': False, 'message': 'Invalid or expired token'}), 400

    email = payload.get('email')
    if payload.get('role') != role:
        logging.warning(f"[RESET_PASSWORD] Token role mismatch: expected={role}, got={payload.get('role')}")
        return jsonify({'success': False, 'message': 'Token does not match role'}), 400

    user = User.query.filter_by(email=email, role=role).first()
    if not user:
        logging.warning(f"[RESET_PASSWORD] User not found: email={email}, role={role}")
        return jsonify({'success': False, 'message': 'User not found'}), 404

    try:
        user.password_hash = hash_password(password)
        db.session.commit()
        logging.info(f"[RESET_PASSWORD] Password updated and committed for user {user.id} (email={email})")

        # Auto-login after successful password reset
        session['user_id'] = user.id
        session['role'] = user.role
        session['user_email'] = user.email
        session['user_name'] = user.fullname
        session['is_verified'] = user.is_verified
        if user.role == 'student':
            session['student_id'] = user.student_id
        session.permanent = True
        logging.info(f"[RESET_PASSWORD] Auto-login session set for user {user.id} (email={email}, role={role})")

        # Generate token and response like login
        token = create_token(user.id, user.role)
        if role == 'lecturer':
            next_url = url_for('lecturer_initial_home') if not user.is_verified else url_for('lecturer_dashboard')
        else:
            next_url = url_for('student_initial_home') if not user.is_verified else url_for('student_dashboard')
        response_data = {
            'token': token,
            'user': {
                'id': user.id,
                'fullname': user.fullname,
                'email': user.email,
                'role': user.role,
                'student_id': user.student_id,
                'is_verified': user.is_verified
            },
            'redirect_url': next_url,
            'success': True,
            'message': 'Password reset successful. You are now logged in.'
        }
        logging.info(f"[RESET_PASSWORD] Auto-login response prepared for {email}")
        return jsonify(response_data)

    except Exception as e:
        db.session.rollback()
        logging.error(f"[RESET_PASSWORD] Failed to update password for {email}: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'message': 'Failed to update password'}), 500

@app.route('/api/validate-token')
def validate_token():
    token = request.args.get('token')
    role = request.args.get('role')
    if not token or not role:
        return jsonify({'valid': False, 'message': 'Missing token or role'}), 400

    valid, payload = verify_reset_token(token, max_age=3600)
    if valid and payload.get('email') and payload.get('role') == role:
        return jsonify({'valid': True})
    else:
        return jsonify({'valid': False, 'message': 'Invalid or expired token'})


# -------------------------------
# DASHBOARD ROUTES
# -------------------------------
@app.route('/lecturer/dashboard')
@lecturer_required
def lecturer_dashboard():
    logging.info(f"[LECTURER_DASHBOARD] Rendering lecturer_home.html for user_id={session.get('user_id')}, is_verified={session.get('is_verified')}, full_session={dict(session)}")
    return render_template('lecturer_page/lecturer_home.html')

@app.route('/lecturer/initial-home')
@lecturer_required
def lecturer_initial_home():
    return render_template('lecturer_page/lecturer_verify_notice.html')

@app.route('/lecturer/class/<int:class_id>')
@lecturer_required
def lecturer_class_page(class_id):
    session['current_class_id'] = class_id
    return render_template('lecturer_page/class_page.html', class_id=class_id)

@app.route('/lecturer/take-attendance')
@app.route('/lecturer/take-attendance/<int:class_id>')
@lecturer_required
def lecturer_take_attendance(class_id=None):
    if class_id is None:
        class_id = session.get('current_class_id')
    if class_id is None:
        flash('No class selected please select a class first.', 'error')
        return redirect(url_for('lecturer_dashboard'))
    return render_template('lecturer_page/take_attendance.html', class_id=class_id)

@app.route('/lecturer/home')
@lecturer_required
def lecturer_home():
    return render_template('lecturer_page/lecturer_initial_home.html')

@app.route('/lecturer/announcements')
@lecturer_required
def lecturer_announcements():
    return render_template('lecturer_page/lecturer_announcement.html')

@app.route('/lecturer/profile')
@lecturer_required
def lecturer_profile():
    return render_template('lecturer_page/lecturer_profile.html')

@app.route('/lecturer/settings')
@lecturer_required
def lecturer_settings():
    return render_template('lecturer_page/lecturer_settings.html')

@app.route('/lecturer/about')
@lecturer_required
def lecturer_about():
    return render_template('lecturer_page/lecturer_about.html')

@app.route('/lecturer/notification')
@lecturer_required
def lecturer_notification():
    return render_template('lecturer_page/lecturer_notification.html')

@app.route('/lecturer/attendance-history/<int:class_id>')
@app.route('/lecturer/attendance-history')
@lecturer_required
def lecturer_attendance_history(class_id=None):
    if class_id is None:
        class_id = request.args.get('id')
    if class_id is None:
        class_id = session.get('current_class_id')
    if class_id is None:
        flash('Please select a class first to view attendance history.', 'error')
        return redirect(url_for('lecturer_dashboard'))
    
    try:
        class_id = int(class_id)
    except ValueError:
        flash('Invalid class ID.', 'error')
        return redirect(url_for('lecturer_dashboard'))
    
    session['current_class_id'] = class_id
    return render_template('lecturer_page/attendance_history.html', class_id=class_id)

@app.route('/student/initial-home')
@student_required
def student_initial_home():
    logging.info(f"[STUDENT_INITIAL_HOME] Rendering initial home for unverified student user_id={session.get('user_id')}, session={dict(session)}")
    return render_template('student_page/student_initial_home.html')

@app.route('/student/dashboard')
@student_required
def student_dashboard():
    logging.info(f"[STUDENT_DASHBOARD] Rendering dashboard for user_id={session.get('user_id')}, session={dict(session)}")
    return render_template('student_page/student_home.html')


@app.route('/student/home')
@student_required
def student_home():
    """Redirect to student dashboard - fix for missing student_home route"""
    return redirect(url_for('student_dashboard'))

@app.route('/student/classes')
@student_required
def student_classes():
    return render_template('student_page/student_class.html')

@app.route('/student/attendance')
@student_required
def student_attendance():
    return render_template('student_page/student_attendance.html')

@app.route('/student/profile')
@student_required
def student_profile():
    return render_template('student_page/student_profile.html')

@app.route('/student/about')
@student_required
def student_about():
    return render_template('student_page/student_about.html')

@app.route('/student/settings')
@student_required
def student_settings():
    return render_template('student_page/student_settings.html')

@app.route('/student/notification')
@student_required
def student_notification():
    return render_template('student_page/student_notification.html')

@app.route('/student/attendance-history')
@student_required
def student_attendance_history():
    return render_template('student_page/student_attendance_history.html')

@app.route('/student/class-detail/<int:class_id>')
@student_required
def student_class_detail(class_id):
    return render_template('student_page/student_class_detail.html', class_id=class_id)

# -------------------------------
# AUTHENTICATION
# -------------------------------
def get_serializer():
    from itsdangerous import URLSafeTimedSerializer
    return URLSafeTimedSerializer(app.config['SECRET_KEY'], salt='tapin-reset')

def make_reset_token(email, role):
    s = get_serializer()
    return s.dumps({'email': email, 'role': role})

def verify_reset_token(token, max_age=3600):
    s = get_serializer()
    try:
        return True, s.loads(token, max_age=max_age)
    except Exception as e:  # Catch both SignatureExpired and BadSignature
        import logging
        logging.error(f"[RESET/VERIFY] Token error: {str(e)}")
        return False, {'error': 'invalid'}

def send_reset_email(email, role, token):
    logging.info(f"[EMAIL SEND RESET] Starting for {email}, role={role}")
    try:
        reset_url = url_for('reset_password_page', token=token, role=role, _external=True)
        logging.info(f"[EMAIL SEND RESET] Generated URL for {email}: {reset_url}")
    except Exception as e:
        logging.error(f"[EMAIL SEND RESET] Failed to generate URL for {email}: {str(e)}", exc_info=True)
        return False

    # Check if mail is configured for development bypass
    if not current_app.config.get('MAIL_SERVER'):
        print(f"[EMAIL DEV BYPASS] Reset URL for {email} ({role}): {reset_url}")
        logging.info(f"[EMAIL DEV BYPASS] Logged reset URL to console for {email} -> {reset_url}")
        return True  # Treat as success for testing

    try:
        msg = Message(
            subject="TapIn password reset",
            recipients=[email],
            body=f"Click the link to reset your password:\n{reset_url}\nValid for 1 hour."
        )
        mail.send(msg)
        logging.info(f"[EMAIL] Sent reset link to {email} -> {reset_url}")
        return True
    except Exception as e:
        logging.error(f"[EMAIL] Failed to send reset email to {email}: {str(e)}", exc_info=True)
        print(f"[EMAIL ERROR] Failed to send to {email}: {str(e)}. Manual reset URL: {reset_url}")
        return False


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'success')
    return redirect(url_for('account'))


# Get fresh token from session for client-side use
@app.route('/api/get_token', methods=['GET'])
@login_required
def get_token():
    user_id = session['user_id']
    role = session['role']
    token = create_token(user_id, role)
    return jsonify({'token': token})

# -------------------------------
# HEALTH CHECK
# -------------------------------
@app.route('/api/health')
def health_check():
    session_info = {'has_user_id': 'user_id' in session, 'role': session.get('role'), 'user_id': session.get('user_id')}
    logging.info(f"[HEALTH] Check hit - session info: {session_info}, full session: {dict(session)}")
    return jsonify({'status': 'ok', 'authenticated': 'user_id' in session, 'session': session_info, 'time': datetime.utcnow().isoformat()})

# -------------------------------
# SERVE FRONTEND CATCH-ALL
# -------------------------------
@app.route('/<path:path>')
def serve_app(path):
    return send_from_directory('../templates', path)

# -------------------------------
# GLOBAL ERROR HANDLER
# -------------------------------
@app.errorhandler(Exception)
def handle_exception(e):
    logging.error(f"[GLOBAL ERROR] Unhandled exception: {str(e)}", exc_info=True)
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500
    else:
        flash('An unexpected error occurred', 'error')
        return render_template('welcome_page/error.html'), 500  # Assume a generic error template exists or redirect

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Not found'}), 404
    else:
        flash('Page not found', 'error')
        return redirect(url_for('home')), 404

@app.errorhandler(403)
def forbidden(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Forbidden'}), 403
    else:
        flash('Access denied', 'error')
        return redirect(url_for('account')), 403

@app.errorhandler(401)
def unauthorized(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Unauthorized'}), 401
    else:
        flash('Please log in', 'error')
        return redirect(url_for('account')), 401

# -------------------------------
# SERVE FRONTEND
# -------------------------------
# def seed():
#     """Seed the database with test data."""
#     from tapin_backend.utils import hash_password
#     from .models import User
#     if User.query.count() == 0:
#         # Test Lecturer
#         lecturer = User(
#             fullname='Test Lecturer',
#             email='lecturer@test.com',
#             role='lecturer',
#             password_hash=hash_password('TestPass123!'),
#             is_verified=True
#         )
#         db.session.add(lecturer)
#
#         # Test Student
#         student = User(
#             fullname='Test Student',
#             email='student@test.com',
#             student_id='STU001',
#             role='student',
#             password_hash=hash_password('TestPass123!'),
#             is_verified=True
#         )
#         db.session.add(student)
#
#         db.session.commit()
#         print("Test users seeded: lecturer@test.com and student@test.com (password: TestPass123!)")
#     else:
#         print("Database already has users; skipping seed.")


# -------------------------------
# SERVER ENTRY
# -------------------------------
@app.route('/join_class/<token>')
def join_via_link(token):
    from tapin_backend.models import db, Course, Enrollment, User
    cls = Course.query.filter_by(join_code=token).first()
    if not cls:
        flash('Invalid join link.', 'error')
        return redirect(url_for('account'))
    
    if 'user_id' not in session or session.get('role') != 'student':
        # Redirect to login with return_url
        return_url = f"{request.url}"
        return redirect(url_for('student_login_page', return_url=return_url))
    
    # Check if already enrolled
    existing = Enrollment.query.filter_by(class_id=cls.id, student_id=session['user_id']).first()
    if existing:
        flash('You are already enrolled in this class.', 'success')
        return redirect(url_for('student_classes'))
    
    # Enroll
    enr = Enrollment(class_id=cls.id, student_id=session['user_id'])
    db.session.add(enr)
    db.session.commit()
    flash('Successfully joined the class!', 'success')
    return redirect(url_for('student_classes'))
if __name__ == '__main__':
    port = 5001
    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)
