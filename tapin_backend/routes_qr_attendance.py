from flask import Blueprint, request, jsonify, send_file
from .models import db, Course, AttendanceSession, AttendanceRecord, Enrollment, User
from tapin_backend.utils import auth_required, broadcast_check_in
from datetime import datetime, timedelta
import qrcode
import io
import base64
import json
import uuid
import jwt
from flask import current_app

qr_attendance_bp = Blueprint('qr_attendance', __name__)

@qr_attendance_bp.post('/classes/<int:class_id>/qr-session')
@auth_required(roles=['lecturer'])
def create_qr_attendance_session(class_id):
    """Create a QR code-based attendance session"""
    try:
        data = request.get_json(force=True)
        duration_sec = int(data.get('duration_sec', 300))  # Default 5 minutes
        
        # Verify lecturer owns this class
        course = Course.query.get_or_404(class_id)
        if course.lecturer_id != request.user_id:
            return jsonify({'error': 'Forbidden'}), 403
        
        # Create attendance session
        session = AttendanceSession(
            class_id=class_id,
            method='qr',
            expires_at=datetime.utcnow() + timedelta(seconds=duration_sec),
            is_open=True
        )
        db.session.add(session)
        db.session.flush()  # Get the session ID
        
        # Generate unique QR token
        qr_token = str(uuid.uuid4())
        
        # Create QR payload with session info and security token
        qr_payload = {
            'session_id': session.id,
            'class_id': class_id,
            'token': qr_token,
            'expires_at': session.expires_at.isoformat(),
            'created_at': datetime.utcnow().isoformat()
        }
        
        # Sign the payload to prevent tampering
        signed_payload = jwt.encode(qr_payload, current_app.config['SECRET_KEY'], algorithm='HS256')
        
        # Store the QR token in the session (we'll use pin_code field for this)
        session.pin_code = qr_token
        db.session.commit()
        
        # Generate QR code
        qr_data = {
            'type': 'tapin_attendance',
            'payload': signed_payload,
            'course_name': course.course_name,
            'expires_at': session.expires_at.isoformat()
        }
        
        qr_code_data = json.dumps(qr_data)
        
        # Create QR code image
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_code_data)
        qr.make(fit=True)
        
        # Create QR code image
        qr_img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64 for easy transmission
        img_buffer = io.BytesIO()
        qr_img.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        qr_base64 = base64.b64encode(img_buffer.getvalue()).decode()
        
        return jsonify({
            'session_id': session.id,
            'qr_token': qr_token,
            'qr_code_base64': f"data:image/png;base64,{qr_base64}",
            'expires_at': session.expires_at.isoformat() + 'Z',
            'duration_sec': duration_sec,
            'class_info': {
                'name': course.course_name,
                'code': course.course_code
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to create QR attendance session', 'details': str(e)}), 500

@qr_attendance_bp.post('/qr-attendance/scan')
@auth_required(roles=['student'])
def scan_qr_attendance():
    """Process QR code scan for attendance"""
    try:
        data = request.get_json(force=True)
        qr_data = data.get('qr_data')
        student_location = data.get('location', {})  # Optional location data
        
        if not qr_data:
            return jsonify({'error': 'QR data is required'}), 400
        
        # Parse QR data
        try:
            qr_info = json.loads(qr_data)
            if qr_info.get('type') != 'tapin_attendance':
                return jsonify({'error': 'Invalid QR code type'}), 400
            
            # Verify and decode the signed payload
            signed_payload = qr_info.get('payload')
            payload = jwt.decode(signed_payload, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            
        except (json.JSONDecodeError, jwt.InvalidTokenError, jwt.ExpiredSignatureError) as e:
            return jsonify({'error': 'Invalid or expired QR code'}), 400
        
        # Extract session information
        session_id = payload.get('session_id')
        class_id = payload.get('class_id')
        qr_token = payload.get('token')
        
        # Verify session exists and is valid
        session = AttendanceSession.query.get_or_404(session_id)
        
        if not session.is_open or datetime.utcnow() > session.expires_at:
            return jsonify({'error': 'Attendance session has expired'}), 400
        
        if session.pin_code != qr_token:
            return jsonify({'error': 'Invalid QR code token'}), 400
        
        # Verify student is enrolled in the class
        enrollment = Enrollment.query.filter_by(
            class_id=class_id, student_id=request.user_id
        ).first()
        
        if not enrollment:
            return jsonify({'error': 'You are not enrolled in this class'}), 403
        
        # Check if student has already marked attendance
        existing_record = AttendanceRecord.query.filter_by(
            session_id=session_id, student_id=request.user_id
        ).first()
        
        if existing_record:
            return jsonify({
                'message': 'Attendance already marked',
                'status': existing_record.status,
                'timestamp': existing_record.timestamp.isoformat() + 'Z'
            }), 200
        
        # Create attendance record
        attendance_record = AttendanceRecord(
            session_id=session_id,
            student_id=request.user_id,
            status='Present'
        )
        db.session.add(attendance_record)
        db.session.commit()
        
        # Get class info for response
        course = Course.query.get(class_id)
        
        return jsonify({
            'message': 'Attendance marked successfully',
            'status': 'Present',
            'timestamp': attendance_record.timestamp.isoformat() + 'Z',
            'class_info': {
                'name': course.course_name,
                'code': course.course_code
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to process QR attendance', 'details': str(e)}), 500

@qr_attendance_bp.get('/classes/<int:class_id>/qr-session/active')
@auth_required(roles=['lecturer'])
def get_active_qr_session(class_id):
    """Get active QR attendance session for a class"""
    try:
        # Verify lecturer owns this class
        course = Course.query.get_or_404(class_id)
        if course.lecturer_id != request.user_id:
            return jsonify({'error': 'Forbidden'}), 403
        
        # Find active QR session
        now = datetime.utcnow()
        session = AttendanceSession.query.filter(
            AttendanceSession.class_id == class_id,
            AttendanceSession.method == 'qr',
            AttendanceSession.is_open == True,
            AttendanceSession.expires_at > now
        ).order_by(AttendanceSession.id.desc()).first()
        
        if not session:
            return jsonify({'active': False}), 200
        
        # Get attendance count for this session
        attendance_count = AttendanceRecord.query.filter_by(
            session_id=session.id, status='Present'
        ).count()
        
        # Get total enrolled students
        total_students = Enrollment.query.filter_by(class_id=class_id).count()
        
        return jsonify({
            'active': True,
            'session_id': session.id,
            'expires_at': session.expires_at.isoformat() + 'Z',
            'attendance_count': attendance_count,
            'total_students': total_students,
            'time_remaining': int((session.expires_at - now).total_seconds())
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get QR session info', 'details': str(e)}), 500

@qr_attendance_bp.get('/classes/<int:class_id>/qr-session/<int:session_id>/attendees')
@auth_required(roles=['lecturer'])
def get_qr_session_attendees(class_id, session_id):
    """Get real-time list of students who have marked attendance via QR"""
    try:
        # Verify lecturer owns this class
        course = Course.query.get_or_404(class_id)
        if course.lecturer_id != request.user_id:
            return jsonify({'error': 'Forbidden'}), 403
        
        # Verify session belongs to this class
        session = AttendanceSession.query.filter_by(
            id=session_id, class_id=class_id
        ).first_or_404()
        
        # Get attendance records with student info
        attendees = db.session.query(AttendanceRecord, User).join(
            User, AttendanceRecord.student_id == User.id
        ).filter(
            AttendanceRecord.session_id == session_id,
            AttendanceRecord.status == 'Present'
        ).order_by(AttendanceRecord.timestamp.desc()).all()
        
        attendee_list = []
        for record, user in attendees:
            attendee_list.append({
                'id': user.id,
                'name': user.fullname,
                'student_id': user.student_id,
                'email': user.email,
                'timestamp': record.timestamp.isoformat() + 'Z'
            })
        
        return jsonify({
            'session_id': session_id,
            'class_name': course.course_name,
            'attendees': attendee_list,
            'count': len(attendee_list)
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get attendees', 'details': str(e)}), 500

@qr_attendance_bp.get('/classes/<int:class_id>/qr-session/<int:session_id>/qr-code')
@auth_required(roles=['lecturer'])
def regenerate_qr_code(class_id, session_id):
    """Regenerate QR code for an active session"""
    try:
        # Verify lecturer owns this class
        course = Course.query.get_or_404(class_id)
        if course.lecturer_id != request.user_id:
            return jsonify({'error': 'Forbidden'}), 403
        
        # Get session
        session = AttendanceSession.query.filter_by(
            id=session_id, class_id=class_id
        ).first_or_404()
        
        if not session.is_open or datetime.utcnow() > session.expires_at:
            return jsonify({'error': 'Session is not active'}), 400
        
        # Create QR payload
        qr_payload = {
            'session_id': session.id,
            'class_id': class_id,
            'token': session.pin_code,  # QR token stored in pin_code field
            'expires_at': session.expires_at.isoformat(),
            'created_at': datetime.utcnow().isoformat()
        }
        
        # Sign the payload
        signed_payload = jwt.encode(qr_payload, current_app.config['SECRET_KEY'], algorithm='HS256')
        
        # Generate QR code
        qr_data = {
            'type': 'tapin_attendance',
            'payload': signed_payload,
            'course_name': course.course_name,
            'expires_at': session.expires_at.isoformat()
        }
        
        qr_code_data = json.dumps(qr_data)
        
        # Create QR code image
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_code_data)
        qr.make(fit=True)
        
        qr_img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        img_buffer = io.BytesIO()
        qr_img.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        qr_base64 = base64.b64encode(img_buffer.getvalue()).decode()
        
        return jsonify({
            'qr_code_base64': f"data:image/png;base64,{qr_base64}",
            'expires_at': session.expires_at.isoformat() + 'Z'
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to regenerate QR code', 'details': str(e)}), 500
