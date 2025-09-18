import os
import logging
from datetime import datetime, timedelta
from functools import wraps
import math
import jwt
from flask import request, jsonify, current_app, url_for
from passlib.hash import bcrypt
from flask_socketio import emit
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Message

JWT_EXPIRES_MIN = int(os.getenv('JWT_EXPIRES_MIN', '43200'))  # 30 days by default

# Password helpers

# Verification token helpers
def create_verification_token(user_id, role):
    payload = {
        'sub': user_id,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')

def verify_verification_token(token):
    try:
        return True, jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        current_app.logger.error("[VERIFY] Token expired")
        return False, {'error': 'expired'}
    except jwt.InvalidTokenError as e:
        current_app.logger.error(f"[VERIFY] Invalid token: {str(e)}")
        return False, {'error': 'invalid'}

def send_verification_email(email, role, token):
    try:
        verify_url = url_for('auth.verify_email_route', token=token, _external=True)
        current_app.logger.info(f"[EMAIL DEBUG] Attempting send to {email} ({role})")
        
        # Get sender email safely
        sender = current_app.config.get('MAIL_DEFAULT_SENDER') or current_app.config.get('MAIL_USERNAME')
        if not sender:
            current_app.logger.warning(f"[EMAIL] No sender configured for {email}")
            return False
            
        current_app.logger.info(f"[EMAIL DEBUG] Config - Server: {current_app.config.get('MAIL_SERVER')}, Port: {current_app.config.get('MAIL_PORT')}, Use TLS: {current_app.config.get('MAIL_USE_TLS')}, Username: {current_app.config.get('MAIL_USERNAME') or 'NOT SET'}, Sender: {sender or 'NOT SET'}")
        print(f"[EMAIL DEBUG] Verification URL for {email} ({role}): {verify_url}")
        
        msg = Message(
            subject="TapIn Email Verification",
            sender=sender,
            recipients=[email],
            body=f"Click the link to verify your email:\n{verify_url}\nValid for 24 hours."
        )
        mail = current_app.extensions['mail']
        try:
            mail.send(msg)
            current_app.logger.info(f"[EMAIL] Successfully sent verification link to {email} -> {verify_url}")
            return True
        except Exception as send_e:
            current_app.logger.error(f"[EMAIL SEND ERROR] Specific send failure for {email}: {str(send_e)}")
            raise
    except Exception as e:
        # Define variables for error logging
        sender = current_app.config.get('MAIL_DEFAULT_SENDER') or current_app.config.get('MAIL_USERNAME')
        verify_url = f"https://tapin-attendance-app.onrender.com/verify/{token}"  # Manual URL construction - corrected path
        current_app.logger.error(f"[EMAIL] Failed to send verification email to {email}: {str(e)}")
        current_app.logger.error(f"[EMAIL DEBUG] Config - Server: {current_app.config.get('MAIL_SERVER')}, Port: {current_app.config.get('MAIL_PORT')}, Use TLS: {current_app.config.get('MAIL_USE_TLS')}, Username: {current_app.config.get('MAIL_USERNAME') or 'NOT SET'}, Sender: {sender or 'NOT SET'}")
        print(f"[EMAIL ERROR] Failed to send to {email}: {str(e)}. Manual URL: {verify_url}. Check logs for config.")
        return False

# Password reset token helpers
def get_reset_serializer():
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'], salt='tapin-reset')

def create_reset_token(email, role):
    s = get_reset_serializer()
    return s.dumps({'email': email, 'role': role})

def verify_reset_token(token, max_age=3600):  # 1 hour
    s = get_reset_serializer()
    try:
        return True, s.loads(token, max_age=max_age)
    except Exception as e:
        current_app.logger.error(f"[RESET] Token error: {str(e)}")
        return False, {'error': 'invalid'}

def send_password_reset_email(email, role, token):
    try:
        reset_url = url_for('reset_password_page', token=token, role=role, _external=True)
        current_app.logger.info(f"[RESET EMAIL DEBUG] Attempting send to {email} ({role})")
        current_app.logger.info(f"[RESET EMAIL DEBUG] Config - Server: {current_app.config.get('MAIL_SERVER')}, Port: {current_app.config.get('MAIL_PORT')}, Use TLS: {current_app.config.get('MAIL_USE_TLS')}, Username: {current_app.config.get('MAIL_USERNAME') or 'NOT SET'}, Sender: {current_app.config.get('MAIL_DEFAULT_SENDER') or 'NOT SET'}")
        print(f"[RESET EMAIL DEBUG] Reset URL for {email} ({role}): {reset_url}")
        sender = current_app.config.get('MAIL_DEFAULT_SENDER', current_app.config.get('MAIL_USERNAME'))
        if not sender:
            current_app.logger.warning(f"[RESET EMAIL] No sender configured for {email}")
            return False
        msg = Message(
            subject="TapIn Password Reset",
            sender=sender,
            recipients=[email],
            body=f"Click the link to reset your password:\n{reset_url}\nThis link is valid for 1 hour."
        )
        mail = current_app.extensions['mail']
        try:
            mail.send(msg)
            current_app.logger.info(f"[RESET EMAIL] Successfully sent reset link to {email} -> {reset_url}")
            return True
        except Exception as send_e:
            current_app.logger.error(f"[RESET EMAIL SEND ERROR] Specific send failure for {email}: {str(send_e)}")
            raise
    except Exception as e:
        reset_url = f"https://tapin-attendance-app.onrender.com/reset_password?token={token}&role={role}"  # Manual URL construction
        current_app.logger.error(f"[RESET EMAIL] Failed to send reset email to {email}: {str(e)}")
        current_app.logger.error(f"[RESET EMAIL DEBUG] Config - Server: {current_app.config.get('MAIL_SERVER')}, Port: {current_app.config.get('MAIL_PORT')}, Use TLS: {current_app.config.get('MAIL_USE_TLS')}, Username: {current_app.config.get('MAIL_USERNAME') or 'NOT SET'}, Sender: {current_app.config.get('MAIL_DEFAULT_SENDER') or 'NOT SET'}")
        print(f"[RESET EMAIL ERROR] Failed to send to {email}: {str(e)}. Manual URL: {reset_url}. Check logs for config and ensure MAIL_PASSWORD is set in .env.")
        return False

def hash_password(pw: str) -> str:
    return bcrypt.hash(pw)

def verify_password(pw: str, hashed: str) -> bool:
    return bcrypt.verify(pw, hashed)

# JWT helpers

def create_token(user_id: int, role: str):
    payload = {
        'sub': user_id,
        'role': role,
        'exp': datetime.utcnow() + timedelta(days=30)  # Fixed expiration
    }
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')

def decode_token(token: str):
    return jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])


def auth_required(roles=None):
    from functools import wraps
    from flask_jwt_extended import jwt_required, get_jwt_identity

    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            try:
                user_id = get_jwt_identity()
                from .models import User
                user = User.query.get(user_id)
                
                if not user:
                    return jsonify({'error': 'User not found'}), 401
                
                if not user.is_verified:
                    logging.warning(f"[AUTH_REQUIRED] Unverified user {user_id} ({user.email}) attempted access to {request.path}")
                    return jsonify({'error': 'Please verify your email before accessing this feature'}), 403
                
                request.user_id = user_id
                request.user_role = user.role
                request.user_verified = user.is_verified
                
                logging.info(f"[AUTH_REQUIRED] Access granted for user {user_id} ({user.email}), role={user.role}, verified={user.is_verified} on {request.path}")
                
                if roles and request.user_role not in roles:
                    logging.warning(f"[AUTH_REQUIRED] Role {user.role} not in required {roles} for {request.path}")
                    return jsonify({'error': 'Insufficient permissions'}), 403
                
                return fn(*args, **kwargs)
            except Exception as e:
                logging.error(f"[AUTH_REQUIRED] Error: {str(e)}")
                return jsonify({'error': 'Authentication failed'}), 401
        return wrapper
    return decorator

# Haversine distance in meters

def distance_m(lat1, lon1, lat2, lon2):
    R = 6371000.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c

def broadcast_check_in(class_id, student):
    emit('student_checked_in', {
        'name': student['name'],
        'student_id': student['student_id'],
        'check_in_time': student['check_in_time']
    }, room=str(class_id))
