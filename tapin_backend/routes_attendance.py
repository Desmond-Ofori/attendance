from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify
from tapin_backend.models import db, Course, AttendanceSession, AttendanceRecord, Enrollment, User
from tapin_backend.utils import auth_required
import logging
import random
from math import radians, sin, cos, sqrt, atan2

# Setup logging
logging.basicConfig(level=logging.INFO)

attendance_bp = Blueprint('attendance', __name__)

def calculate_distance(lat1, lon1, lat2, lon2):
    # Convert degrees to radians
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    
    # Haversine formula
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1-a))
    radius = 6371000  # Earth radius in meters
    return radius * c

# -------------------------
# Lecturer opens attendance session
# -------------------------
@attendance_bp.post('/classes/<int:class_id>/sessions')
@auth_required(roles=['lecturer'])
def open_session(class_id):
    try:
        data = request.get_json(force=True)
        method = data.get('method')  # 'geo' or 'pin'
        duration_sec = int(data.get('duration_sec', 300))

        if method not in ('geo', 'pin', 'qr'):
            return jsonify({'error': 'Invalid method'}), 400
            
        # Verify the lecturer owns this class
        course = Course.query.get_or_404(class_id)
        if course.lecturer_id != request.user_id:
            return jsonify({'error': 'Forbidden'}), 403

        # Create session data
        session_data = {
            'class_id': class_id,
            'lecturer_id': request.user_id,  # Add lecturer_id
            'method': method,
            'expires_at': datetime.utcnow() + timedelta(seconds=duration_sec),
            'is_open': True
        }
        
        # Method-specific setup
        if method == 'pin':
            pin_code = data.get('pin_code') or str(random.randint(100000, 999999))
            session_data['pin_code'] = pin_code
        
        elif method == 'geo':
            lecturer_lat = data.get('lecturer_lat')
            lecturer_lng = data.get('lecturer_lng')
            radius_m = data.get('radius_m', 100)
            
            if not lecturer_lat or not lecturer_lng:
                return jsonify({'error': 'Location coordinates required for geofencing'}), 400
            
            session_data['lecturer_lat'] = lecturer_lat
            session_data['lecturer_lng'] = lecturer_lng
            session_data['radius_m'] = radius_m

        sess = AttendanceSession(**session_data)
        db.session.add(sess)
        db.session.commit()

        logging.info(f"Attendance session {sess.id} opened by lecturer {request.user_id}")
        return jsonify({
            'session_id': sess.id,
            'pin_code': sess.pin_code,
            'expires_at': sess.expires_at.isoformat() + 'Z'
        }), 201

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error opening attendance session: {e}")
        return jsonify({'error': 'Failed to open session', 'details': str(e)}), 500


# -------------------------
# Get active session for a class
# -------------------------
@attendance_bp.get('/classes/<int:class_id>/sessions/active')
@auth_required()
def get_active_session(class_id):
    try:
        now = datetime.utcnow()
        sess = AttendanceSession.query.filter(
            AttendanceSession.class_id == class_id,
            AttendanceSession.is_open == True,
            AttendanceSession.expires_at > now
        ).order_by(AttendanceSession.id.desc()).first()

        if not sess:
            return jsonify({'active': False, 'message': 'No active session found'}), 200

        # Calculate time left in seconds
        time_left = max(0, int((sess.expires_at - now).total_seconds()))

        payload = {
            'active': True,
            'id': sess.id,
            'session_id': sess.id,
            'method': sess.method,
            'expires_at': sess.expires_at.isoformat() + 'Z',
            'time_left': time_left,
            'radius_m': sess.radius_m,
            'lecturerLocation': {
                'lat': sess.lecturer_lat,
                'lng': sess.lecturer_lng
            } if sess.method == 'geo' else None,
            'needs_pin': bool(sess.pin_code),
            'method': sess.method,
            'message': 'Active session retrieved successfully'
        }
        return jsonify(payload), 200
    except Exception as e:
        logging.error(f"Error fetching active session for class {class_id}: {e}")
        return jsonify({'error': 'Failed to fetch active session', 'details': 'Internal server error'}), 500


# -------------------------
# Student marks attendance
# -------------------------
@attendance_bp.post('/attendance/mark')
@auth_required(roles=['student'])
def mark_attendance():
    try:
        data = request.get_json(force=True)
        session_id = int(data.get('session_id'))
        sess = AttendanceSession.query.get_or_404(session_id)

        # Ensure student is enrolled in the class
        enrolled = Enrollment.query.filter_by(class_id=sess.class_id, student_id=request.user_id).first()
        if not enrolled:
            return jsonify({'error': 'Not enrolled in this class'}), 403

        # Check if session is still open
        if not sess.is_open or datetime.utcnow() > sess.expires_at:
            return jsonify({'error': 'Session is closed'}), 400

        # Validate attendance method
        if sess.method == 'pin':
            pin = str(data.get('pin') or '')
            if pin != (sess.pin_code or ''):
                return jsonify({'error': 'Invalid PIN'}), 400
                
        elif sess.method == 'geo':
            lat = data.get('lat')
            lng = data.get('lng')
            if lat is None or lng is None or sess.lecturer_lat is None or sess.lecturer_lng is None:
                return jsonify({'error': 'Location required'}), 400
                
            # Use proper distance calculation
            distance = calculate_distance(float(lat), float(lng), float(sess.lecturer_lat), float(sess.lecturer_lng))
            if distance > (sess.radius_m or 120):
                return jsonify({'error': f'Out of allowed radius. Distance: {distance:.2f}m, Allowed: {sess.radius_m}m'}), 400

        # Record attendance (prevent duplicates)
        existing_record = AttendanceRecord.query.filter_by(session_id=session_id, student_id=request.user_id).first()
        if existing_record:
            return jsonify({'message': 'Already marked', 'status': existing_record.status}), 200

        rec = AttendanceRecord(session_id=session_id, student_id=request.user_id, status='Present')
        db.session.add(rec)
        db.session.commit()

        # Broadcast real-time update to lecturer
        student_user = User.query.get(request.user_id)
        student_info = {
            'student_id': request.user_id,
            'name': student_user.fullname if student_user else f'Student {request.user_id}',
            'check_in_time': rec.timestamp.isoformat() + 'Z'
        }
        
        # Use Socket.IO for real-time updates
        try:
            from flask_socketio import emit
            emit('student_checked_in', student_info, room=f"class_{sess.class_id}")
        except Exception as e:
            logging.error(f"Failed to send socket notification: {e}")

        logging.info(f"Attendance marked for student {request.user_id} in session {session_id}")
        return jsonify({'message': 'Attendance marked', 'status': 'Present'}), 201

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error marking attendance: {e}")
        return jsonify({'error': 'Failed to mark attendance', 'details': str(e)}), 500


# -------------------------
# Get attendance history
# -------------------------
@attendance_bp.get('/classes/<int:class_id>/attendance/history')
@auth_required(roles=['lecturer'])
def history(class_id):
    try:
        course = Course.query.get_or_404(class_id)
        if course.lecturer_id != request.user_id:
            return jsonify({'error': 'Forbidden', 'details': 'You do not own this class'}), 403

        # Get all enrollments for the class
        enrollments = db.session.query(Enrollment.student_id).filter_by(class_id=class_id).all()
        student_ids = [e.student_id for e in enrollments]

        if not student_ids:
            return jsonify({'sessions': [], 'message': 'No students enrolled in this class'}), 200

        # Get all sessions for the class
        sessions = AttendanceSession.query.filter_by(class_id=class_id).order_by(AttendanceSession.created_at.desc()).all()

        result = []
        for sess in sessions:
            # Get records for this session
            records = db.session.query(AttendanceRecord.student_id).filter_by(session_id=sess.id).all()
            present_student_ids = [r.student_id for r in records]

            # Get students
            present_students = []
            absent_students = []
            for sid in student_ids:
                user = User.query.get(sid)
                if user:
                    fullname = user.fullname or f"Unknown Student ({sid})"
                    if sid in present_student_ids:
                        present_students.append(fullname)
                    else:
                        absent_students.append(fullname)

            if present_students or absent_students:  # Only include if there's data
                created_at = sess.created_at or datetime.utcnow()
                result.append({
                    'date': created_at.date().isoformat(),
                    'timestamp': created_at.isoformat() + 'Z',
                    'method': sess.method,
                    'present': present_students,
                    'absent': absent_students,
                    'total_students': len(student_ids),
                    'attendance_rate': f"{len(present_students)/len(student_ids)*100:.1f}%"
                })

        return jsonify({
            'sessions': result,
            'total_sessions': len(result),
            'message': f'Attendance history retrieved for {len(student_ids)} students'
        }), 200

    except Exception as e:
        logging.error(f"Error fetching attendance history for class {class_id}: {e}", exc_info=True)
        return jsonify({'error': 'Failed to fetch attendance history', 'details': 'Internal server error. Please try again'}), 500


# -------------------------
# Lecturer closes attendance session
# -------------------------
@attendance_bp.patch('/sessions/<int:session_id>/close')
@auth_required(roles=['lecturer'])
def close_session(session_id):
    try:
        sess = AttendanceSession.query.get_or_404(session_id)
        course = Course.query.get(sess.class_id)

        if course.lecturer_id != request.user_id:
            return jsonify({'error': 'Forbidden', 'details': 'You do not own this class'}), 403

        if not sess.is_open:
            return jsonify({'error': 'Session already closed', 'details': 'This session is not active'}), 400

        sess.is_open = False
        closed_at = datetime.utcnow()
        db.session.commit()

        logging.info(f"Attendance session {session_id} closed by lecturer {request.user_id} at {closed_at}")
        return jsonify({
            'message': 'Session closed successfully',
            'session_id': sess.id,
            'closed_at': closed_at.isoformat() + 'Z',
            'final_count': len(sess.records)
        }), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error closing session {session_id}: {e}", exc_info=True)
        return jsonify({'error': 'Failed to close session', 'details': 'Internal server error. Please try again'}), 500
