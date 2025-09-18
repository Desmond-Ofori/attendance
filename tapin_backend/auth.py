import logging
import re
from flask import Blueprint, request, jsonify, make_response, session, url_for, flash, redirect, render_template, current_app
from .models import db, User
from sqlalchemy.exc import StatementError, SQLAlchemyError
from .utils import hash_password, verify_password, create_token, send_verification_email, create_verification_token, send_password_reset_email, create_reset_token, verify_reset_token, auth_required

import jwt
import datetime

auth_bp = Blueprint('auth', __name__)

def make_json_response(data, status=200):
    response = make_response(jsonify(data), status)
    response.headers['Content-Type'] = 'application/json'
    return response
@auth_bp.route('/register/<role>', methods=['POST'])
def register(role):
    logging.info(f"[REGISTER] Request received for role {role}")
    logging.info(f"[REGISTER] Is JSON: {request.is_json}, Content-Type: {request.content_type}")
    try:
        # Force JSON response for API routes
        if not request.is_json:
            # If it's a form submission, still return JSON
            return jsonify({'error': 'Please use JSON format'}), 400
        
        data = request.get_json()
        fullname = (data.get('fullname') or data.get('name') or '').strip()
        email = (data.get('email') or '').strip().lower()
        password = data.get('password', '')
        confirm = data.get('confirm-password', '') or data.get('confirm_password', '')
        student_id = (data.get('student_id') or '').strip()

        logging.info(f"[REGISTER] Parsed data: fullname={fullname}, email={email}, role={role}, student_id={student_id}")

        errors = []

        # Validations
        if not fullname or not email or not password:
            errors.append('Missing required fields')
            logging.warning(f"[REGISTER] Missing required fields: fullname={bool(fullname)}, email={bool(email)}, password={bool(password)}")

        if password != confirm:
            errors.append('Passwords do not match')
            logging.warning(f"[REGISTER] Passwords do not match for email={email}")

        # Email validation
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if email and not re.match(email_regex, email):
            errors.append('Invalid email format')
            logging.warning(f"[REGISTER] Invalid email format: {email}")

        # Password strength validation
        if len(password) < 8:
            errors.append('Password must be at least 8 characters long')
            logging.warning(f"[REGISTER] Password too short: length={len(password)} for email={email}")
        if not re.search(r'[A-Z]', password):
            errors.append('Password must contain at least one uppercase letter')
            logging.warning(f"[REGISTER] No uppercase in password for email={email}")
        if not re.search(r'[a-z]', password):
            errors.append('Password must contain at least one lowercase letter')
            logging.warning(f"[REGISTER] No lowercase in password for email={email}")
        if not re.search(r'\d', password):
            errors.append('Password must contain at least one digit')
            logging.warning(f"[REGISTER] No digit in password for email={email}")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append('Password must contain at least one special character')
            logging.warning(f"[REGISTER] No special char in password for email={email}")

        if errors:
            error_msg = ', '.join(errors)
            logging.warning(f"[REGISTER] Validation errors for email={email}: {error_msg}")
            return {"success": False, "error": error_msg}, 400

        existing = User.query.filter_by(email=email).first()
        if existing:
            logging.warning(f"[REGISTER] Email already registered: {email}")
            return {"success": False, "error": "Email already registered"}, 400

        # For students, validate student_id if role is student
        if role == 'student' and not student_id:
            logging.warning(f"[REGISTER] Missing student_id for student role: email={email}")
            return {"success": False, "error": "Student ID is required for student accounts"}, 400

        student_id_value = None if role == 'lecturer' else student_id
        u = User(fullname=fullname, email=email, phone=None, student_id=student_id_value, role=role, is_verified=False, password_hash=hash_password(password))
        db.session.add(u)
        try:
            db.session.commit()
            logging.info(f"[REGISTER] User committed: id={u.id}, email={u.email}, role={role}, verified=False")

            try:
                client_token = create_token(u.id, u.role)
                logging.info(f"[REGISTER] Token created for user {u.id}")
            except Exception as e:
                logging.error(f"[REGISTER] Failed to create token for user {u.id}: {str(e)}", exc_info=True)
                db.session.rollback()
                return {"success": False, "error": "Failed to generate session token"}, 500

        except SQLAlchemyError as e:
            db.session.rollback()
            logging.exception(f"[REGISTER] SQLAlchemyError during commit for email {email}")
            return {"success": False, "error": "Registration failed due to database error"}, 500
        except Exception as e:
            db.session.rollback()
            logging.error(f"[REGISTER] Commit failed: {str(e)}", exc_info=True)
            return {"success": False, "error": "Registration failed due to unexpected error"}, 500
        
        # Set session for unverified access
        session.clear()  # Clear any old session
        session['user_id'] = u.id
        session['role'] = u.role
        session['user_email'] = u.email
        session['user_name'] = u.fullname
        session['is_verified'] = u.is_verified
        if u.role == 'student':
            session['student_id'] = u.student_id
        session.permanent = True
        logging.info(f"[REGISTER] Session set for user {u.id}, role {u.role}, verified={u.is_verified}")

        # Send verification email
        try:
            verification_token = create_verification_token(u.id, u.role)
            logging.info(f"[REGISTER] Verification token created for {u.email}")
        except Exception as e:
            logging.error(f"[REGISTER] Failed to create verification token for {u.email}: {str(e)}", exc_info=True)
            verification_token = None

        if verification_token and send_verification_email(u.email, u.role, verification_token):
            logging.info(f"[REGISTER] Verification email sent to {u.email}")
            message = 'Registration successful. Please check your email to verify your account.'
        else:
            logging.warning(f"[REGISTER] Failed to send verification email to {u.email}")
            message = 'Registration successful but verification email failed to send. Please contact support to verify your account.'

        # Determine redirect based on verification status
        if u.role == 'lecturer':
            next_url = url_for('lecturer_initial_home', _external=True) if not u.is_verified else url_for('lecturer_dashboard', _external=True)
        else:
            next_url = url_for('student_initial_home', _external=True) if not u.is_verified else url_for('student_dashboard', _external=True)

        response_data = {
            'success': True,
            'token': client_token,
            'access_token': client_token,  # For frontend compatibility
            'user': {
                'id': u.id,
                'fullname': u.fullname,
                'email': u.email,
                'role': u.role,
                'student_id': u.student_id if u.role == 'student' else None,
                'is_verified': u.is_verified
            },
            'redirect_url': next_url,
            'message': message
        }
        logging.info(f"[REGISTER] Returning JSON response: {response_data}")
        response = make_json_response(response_data)
        return response
    except Exception as e:
        logging.error(f"[REGISTER] Unexpected error: {str(e)}", exc_info=True)
        return {"success": False, "error": "Internal server error during registration"}, 500

@auth_bp.route('/login/<role>', methods=['POST'])
def login(role):
    logging.info(f"[LOGIN] Request received for role {role}")
    try:
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form
        email = (data.get('email') or '').strip().lower()
        password = data.get('password', '')

        logging.info(f"[LOGIN] Attempting login with email='{email}'")

        if not email:
            logging.warning("[LOGIN] No email provided")
            if request.is_json:
                return {"success": False, "error": "Email required"}, 400
            else:
                flash('Email required', 'error')
                return redirect(url_for('account'))

        # Query user by email
        u = None
        role = None
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, email):
            logging.warning(f"[LOGIN] Invalid email format: {email}")
            if request.is_json:
                return {"success": False, "error": "Invalid email format"}, 400
            else:
                flash('Invalid email format', 'error')
                return redirect(url_for('account'))
        try:
            # Use the route parameter role for the query
            u = User.query.filter_by(email=email, role=role).first()
            if not u:
                logging.warning(f"[LOGIN] User lookup by email='{email}' and role='{role}' returned None")
            else:
                logging.info(f"[LOGIN] User lookup successful for email='{email}', role='{role}'")
        except (StatementError, SQLAlchemyError) as e:
            logging.error(f"[LOGIN] Database query error for email {email}, role {role}: {str(e)}", exc_info=True)
            if request.is_json:
                return {"success": False, "error": "Database error occurred"}, 500
            else:
                flash('Database error. Please try again.', 'error')
                return redirect(url_for('account'))
        if u:
            role = u.role
            logging.info(f"[LOGIN] Found user by email: id={u.id}, role={role}, verified={u.is_verified}")

        if not u:
            logging.warning(f"[LOGIN] No user found for email='{email}', role='{role}'")
            if request.is_json:
                return {"success": False, "error": "Invalid credentials"}, 401  # Generic for security
            else:
                flash('Invalid credentials', 'error')
                return redirect(url_for('account'))

        if not verify_password(password, u.password_hash):
            logging.warning(f"[LOGIN] check_password_hash failed for user {u.id} (email={u.email})")
            if request.is_json:
                return {"success": False, "error": "Invalid credentials"}, 401  # Generic
            else:
                flash('Invalid credentials', 'error')
                return redirect(url_for('account'))

        logging.info(f"[LOGIN] Successful authentication for user {u.id} ({u.email}), role={role}, verified={u.is_verified}")

        try:
            client_token = create_token(u.id, u.role)
            logging.info(f"[LOGIN] Token created for user {u.id}")
        except Exception as e:
            logging.error(f"[LOGIN] Failed to create token for user {u.id}: {str(e)}", exc_info=True)
            if request.is_json:
                return {"success": False, "error": "Failed to generate session token"}, 500
            else:
                flash('Login failed due to internal error', 'error')
                return redirect(url_for('account'))

        # Set session
        session.clear()  # Clear any old session
        session['user_id'] = u.id
        session['role'] = u.role
        session['user_email'] = u.email
        session['user_name'] = u.fullname
        session['is_verified'] = u.is_verified
        if u.role == 'student':
            session['student_id'] = u.student_id
        session.permanent = True
        logging.info(f"[LOGIN] Session set for user {u.id}, role {u.role}, verified={u.is_verified}")

        # Determine redirect based on verification status
        if u.is_verified:
            if u.role == 'lecturer':
                next_url = url_for('lecturer_dashboard', _external=True)
                flash_msg = 'Logged in successfully'
            else:
                next_url = url_for('student_dashboard', _external=True)
                flash_msg = 'Logged in successfully'
        else:
            if u.role == 'lecturer':
                next_url = url_for('lecturer_initial_home', _external=True)
                flash_msg = 'Logged in successfully. Please verify your email to access full features.'
            else:
                next_url = url_for('student_initial_home', _external=True)
                flash_msg = 'Logged in successfully. Please verify your email to access full features.'

        logging.info(f"[LOGIN] Redirecting to {next_url} for role {u.role}, verified={u.is_verified}")

        if request.is_json:
            response_data = {
                'access_token': client_token,
                'user': {
                    'id': u.id,
                    'fullname': u.fullname,
                    'email': u.email,
                    'role': u.role,
                    'student_id': u.student_id if u.role == 'student' else None,
                    'is_verified': u.is_verified
                },
                'redirect_url': next_url,
                'success': True,
                'message': flash_msg
            }
            logging.info(f"[LOGIN] JSON response prepared")
            response = make_json_response(response_data)
            return response
        else:
            flash(flash_msg, 'success')
            return redirect(next_url)
    except Exception as e:
        logging.error(f"[LOGIN] Unexpected error: {str(e)}", exc_info=True)
        if request.is_json:
            return {"success": False, "error": "Internal server error during login"}, 500
        else:
            flash('Login failed due to server error. Please try again.', 'error')
            return redirect(url_for('account'))


@auth_bp.route('/verify', methods=['POST'])
def verify_email_post():
    logging.info("[VERIFY] Request received")
    try:
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form
        token = data.get('token')
        
        if not token:
            logging.warning("[VERIFY] No token provided")
            return {"success": False, "error": "Verification token required"}, 400
        
        # Verify token
        valid, payload = verify_verification_token(token)
        if not valid:
            logging.warning("[VERIFY] Invalid or expired token")
            return {"success": False, "error": "Invalid or expired verification token"}, 400
        
        user_id = payload.get('sub')
        role = payload.get('role')
        user = User.query.get(user_id)
        if not user:
            return {"success": False, "error": "User not found"}, 404
        email = user.email
        
        user = User.query.filter_by(email=email).first()
        if not user:
            logging.error(f"[VERIFY] User not found for email: {email}")
            return {"success": False, "error": "User not found"}, 404
        
        was_already_verified = user.is_verified
        
        if not user.is_verified:
            user.is_verified = True
            db.session.commit()
            logging.info(f"[VERIFY] User {user.id} verified successfully")
        
        # Set session for verified access
        session.clear()
        session['user_id'] = user.id
        session['role'] = user.role
        session['user_email'] = user.email
        session['user_name'] = user.fullname
        session['is_verified'] = True
        if user.role == 'student':
            session['student_id'] = user.student_id
        session.permanent = True
        logging.info(f"[VERIFY] Session set for verified user {user.id}, role {user.role}")
        
        # Create token for login
        try:
            client_token = create_token(user.id, user.role)
            logging.info(f"[VERIFY] Token created for user {user.id}")
        except Exception as e:
            logging.error(f"[VERIFY] Failed to create token for user {user.id}: {str(e)}", exc_info=True)
            return {"success": False, "error": "Failed to generate session token"}, 500
        
        # Determine redirect
        if user.role == 'lecturer':
            next_url = url_for('lecturer_dashboard', _external=True)
        else:
            next_url = url_for('student_dashboard', _external=True)
        
        response_data = {
            'access_token': client_token,
            'user': {
                'id': user.id,
                'fullname': user.fullname,
                'email': user.email,
                'role': user.role,
                'student_id': user.student_id if user.role == 'student' else None,
                'is_verified': True
            },
            'redirect_url': next_url,
            'message': 'Verification successful. Logging you in.' if not was_already_verified else 'Account already verified. Logging you in.'
        }
        logging.info(f"[VERIFY] Returning success response for user {user.id}")
        response = make_json_response(response_data)
        return response
    except Exception as e:
        logging.error(f"[VERIFY] Unexpected error: {str(e)}", exc_info=True)
        return {"success": False, "error": "Internal server error during verification"}, 500


@auth_bp.route('/verify/<token>', methods=['GET'], endpoint='verify_email_route')
def verify_email_get(token):
    try:
        # Use current_app instead of app
        data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
        user = User.query.get(data["sub"])
        
        if not user:
            return redirect("/account?error=notfound")
        
        user.is_verified = True
        db.session.commit()
        
        # Create a proper token for the frontend
        access_token = create_token(user.id, user.role)
        
        # Set session
        session['user_id'] = user.id
        session['role'] = user.role
        session['user_email'] = user.email
        session['user_name'] = user.fullname
        session['is_verified'] = True
        if user.role == 'student':
            session['student_id'] = user.student_id
        session.permanent = True
        
        # Redirect to success page
        return redirect(f"/static/verify_success.html?token={access_token}&amp;role={user.role}")
    
    except jwt.ExpiredSignatureError:
        return redirect("/account?error=expired")
    except Exception as e:
        current_app.logger.exception("Verification error")
        return redirect("/account?error=invalid")
@auth_bp.post('/resend')
def resend_verification():
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    email = (data.get('email') or '').strip().lower()
    role = data.get('role', 'lecturer')

    if not email or not role:
        return {"success": False, "error": "Email and role are required"}, 400

    # Email validation
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        return {"success": False, "error": "Invalid email format"}, 400

    user = User.query.filter_by(email=email, role=role).first()
    if not user:
        return {"success": False, "error": "User not found"}, 404

    if user.is_verified:
        return {"success": False, "error": "Account already verified"}, 400

    verification_token = create_verification_token(user.id, role)
    if send_verification_email(email, role, verification_token):
        logging.info(f"[RESEND] Verification email resent to {email}")
        return {"success": true, "message": "Verification email resent successfully"}, 200
    else:
        return {"success": False, "error": "Failed to send verification email"}, 500
    

@auth_bp.post('/forgot_password')
def forgot_password():
    logging.info("[FORGOT_PASSWORD] Request received")
    try:
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form
        email = (data.get('email') or '').strip().lower()

        if not email:
            logging.warning("[FORGOT_PASSWORD] No email provided")
            if request.is_json:
                return {"success": False, "error": "Email is required"}, 400
            else:
                flash('Email is required to reset password.', 'error')
                return redirect(url_for('account'))

        # Email validation
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, email):
            logging.warning(f"[FORGOT_PASSWORD] Invalid email format: {email}")
            if request.is_json:
                return {"success": False, "error": "Invalid email format"}, 400
            else:
                flash('Invalid email format. Please check and try again.', 'error')
                return redirect(url_for('account'))

        role_from_request = data.get('role')
        try:
            if role_from_request:
                user = User.query.filter_by(email=email, role=role_from_request).first()
                if not user:
                    logging.warning(f"[FORGOT_PASSWORD] User lookup by email='{email}' and role='{role_from_request}' returned None")
            else:
                user = User.query.filter_by(email=email).first()
                if not user:
                    logging.warning(f"[FORGOT_PASSWORD] User lookup by email='{email}' returned None")
        except (StatementError, SQLAlchemyError) as e:
            logging.error(f"[FORGOT_PASSWORD] Database query error for email {email}: {str(e)}", exc_info=True)
            if request.is_json:
                return {"success": False, "error": "Database error occurred"}, 500
            else:
                flash('Database error. Please try again.', 'error')
                return redirect(url_for('account'))

        if not user:
            logging.info(f"[FORGOT_PASSWORD] User not found for email: {email} - sending generic response for security")
            # Generic response for security - don't reveal if user exists
            if request.is_json:
                return {"success": true, "message": "If an account with this email exists, a reset link has been sent. Check your inbox."}, 200
            else:
                flash('If an account with this email exists, a reset link has been sent. Check your inbox.', 'success')
                return redirect(url_for('account'))

        try:
            reset_token = create_reset_token(user.email, user.role)
            logging.info(f"[FORGOT_PASSWORD] Reset token created for {user.email}")
        except Exception as e:
            logging.error(f"[FORGOT_PASSWORD] Failed to create reset token for {user.email}: {str(e)}", exc_info=True)
            if request.is_json:
                return {"success": False, "error": "Failed to generate reset token"}, 500
            else:
                flash('Failed to generate reset link. Please try again or contact support.', 'error')
                return redirect(url_for('account'))

        if send_password_reset_email(user.email, user.role, reset_token):
            logging.info(f"[FORGOT_PASSWORD] Password reset email sent successfully to {user.email}")
            if request.is_json:
                return {"success": true, "message": "Password reset email sent. Check your email for the link (valid for 1 hour)."}, 200
            else:
                flash('Password reset email sent. Check your email for the link (valid for 1 hour).', 'success')
                return redirect(url_for('account'))
        else:
            logging.error(f"[FORGOT_PASSWORD] Failed to send password reset email to {user.email}")
            if request.is_json:
                return {"success": False, "error": "Failed to send reset email"}, 500
            else:
                flash('Failed to send reset email. Please try again later or contact support.', 'error')
                return redirect(url_for('account'))
    except Exception as e:
        logging.error(f"[FORGOT_PASSWORD] Unexpected error: {str(e)}", exc_info=True)
        if request.is_json:
            return {"success": False, "error": "Internal server error"}, 500
        else:
            flash('An error occurred. Please try again or contact support.', 'error')
            return redirect(url_for('account'))


@auth_bp.get('/validate_reset_token')
def validate_reset_token():
    token = request.args.get('token')
    if not token:
        return {"success": False, "error": "Missing token"}, 400
    valid, payload = verify_reset_token(token)
    if valid:
        return {"success": true, "role": payload.get('role')}
    else:
        return {"success": False, "error": "Invalid or expired token"}, 400


@auth_bp.route('/me', methods=['GET', 'PUT'])
@auth_required()
def me():
    try:
        logging.debug(f"Me request method: {request.method}")
        logging.debug(f"Me request headers: {dict(request.headers)}")
        if request.method == 'GET':
            u = User.query.get(request.user_id)
            if not u:
                logging.error(f"[ME/GET] User not found: {request.user_id}")
                return {"success": False, "error": "User not found"}, 404
            logging.info(f"[ME/GET] Returning profile for user {request.user_id}")
            return jsonify({'id': u.id, 'fullname': u.fullname, 'email': u.email, 'phone': u.phone, 'role': u.role, 'student_id': u.student_id, 'is_verified': u.is_verified})
        else:
            data = request.get_json(force=True)
            if not data:
                logging.warning(f"[ME/PUT] No JSON data provided for user {request.user_id}")
                return {"success": False, "error": "No data provided"}, 400
            u = User.query.get(request.user_id)
            if not u:
                logging.error(f"[ME/PUT] User not found: {request.user_id}")
                return {"success": False, "error": "User not found"}, 404
            updated = False
            if 'fullname' in data or 'name' in data:
                new_name = data.get('fullname') or data.get('name')
                if new_name and new_name.strip() != u.fullname:
                    u.fullname = new_name.strip()
                    updated = True
                    logging.info(f"[ME/PUT] Updated fullname to '{u.fullname}' for user {request.user_id}")
            if 'phone' in data:
                new_phone = data.strip() if data['phone'] else None
                if new_phone != u.phone:
                    u.phone = new_phone
                    updated = True
                    logging.info(f"[ME/PUT] Updated phone to '{u.phone}' for user {request.user_id}")
            if 'student_id' in data and u.role == 'student':
                new_student_id = data['student_id'].strip() if data['student_id'] else None
                if new_student_id != u.student_id:
                    u.student_id = new_student_id
                    updated = True
                    logging.info(f"[ME/PUT] Updated student_id to '{u.student_id}' for user {request.user_id}")
            if not updated:
                logging.info(f"[ME/PUT] No changes detected for user {request.user_id}")
                return {"success": true, "message": "No updates applied"}
            db.session.commit()
            logging.info(f"[ME/PUT] Profile updated for user {request.user_id}")
            return {"success": true, "message": "Profile updated successfully"}
    except Exception as e:
        db.session.rollback()
        logging.error(f"[ME] Unexpected error for user {request.user_id}: {str(e)}", exc_info=True)
        return {"success": False, "error": "Failed to update profile"}, 500

@auth_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('account'))
