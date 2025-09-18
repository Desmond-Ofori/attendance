from flask import Blueprint, request, jsonify, make_response
from .models import db, Course, AttendanceSession, AttendanceRecord, Enrollment, User, Announcement, Notification, Schedule
from .utils import auth_required
from datetime import datetime, timedelta
import json
import csv
import io
import zipfile
import os
import tempfile

backup_bp = Blueprint('backup', __name__)

@backup_bp.get('/lecturer/data/export')
@auth_required(roles=['lecturer'])
def export_lecturer_data():
    """Export all lecturer's data"""
    try:
        export_format = request.args.get('format', 'json')  # json, csv, or zip
        
        # Get lecturer's courses
        courses = Course.query.filter_by(lecturer_id=request.user_id).all()
        course_ids = [c.id for c in courses]
        
        if not course_ids:
            return jsonify({'error': 'No courses found'}), 404
        
        # Collect all data
        export_data = {
            'export_info': {
                'exported_at': datetime.utcnow().isoformat() + 'Z',
                'lecturer_id': request.user_id,
                'export_format': export_format
            },
            'courses': [],
            'attendance_sessions': [],
            'attendance_records': [],
            'enrollments': [],
            'announcements': [],
            'schedules': []
        }
        
        # Export courses
        for crs in courses:
            export_data['courses'].append({
                'id': crs.id,
                'programme': crs.programme,
                'faculty': crs.faculty,
                'department': crs.department,
                'course_name': crs.course_name,
                'course_code': crs.course_code,
                'level': crs.level,
                'section': crs.section,
                'join_pin': crs.join_pin,
                'created_at': crs.created_at.isoformat() + 'Z'
            })
        
        # Export attendance sessions
        sessions = AttendanceSession.query.filter(AttendanceSession.course_id.in_(course_ids)).all()
        for session in sessions:
            export_data['attendance_sessions'].append({
                'id': session.id,
                'course_id': session.course_id,
                'method': session.method,
                'pin_code': session.pin_code,
                'lecturer_lat': session.lecturer_lat,
                'lecturer_lng': session.lecturer_lng,
                'radius_m': session.radius_m,
                'expires_at': session.expires_at.isoformat() + 'Z',
                'is_open': session.is_open,
                'created_at': session.created_at.isoformat() + 'Z'
            })
        
        # Export attendance records
        session_ids = [s.id for s in sessions]
        if session_ids:
            records = AttendanceRecord.query.filter(AttendanceRecord.session_id.in_(session_ids)).all()
            for record in records:
                export_data['attendance_records'].append({
                    'id': record.id,
                    'session_id': record.session_id,
                    'student_id': record.student_id,
                    'status': record.status,
                    'timestamp': record.timestamp.isoformat() + 'Z'
                })
        
        # Export enrollments
        enrollments = Enrollment.query.filter(Enrollment.course_id.in_(course_ids)).all()
        for enrollment in enrollments:
            export_data['enrollments'].append({
                'id': enrollment.id,
                'course_id': enrollment.course_id,
                'student_id': enrollment.student_id,
                'joined_at': enrollment.joined_at.isoformat() + 'Z'
            })
        
        # Export announcements
        announcements = Announcement.query.filter(
            (Announcement.course_id.in_(course_ids)) | (Announcement.course_id == None)
        ).all()
        for announcement in announcements:
            export_data['announcements'].append({
                'id': announcement.id,
                'course_id': announcement.course_id,
                'title': announcement.title,
                'message': announcement.message,
                'created_at': announcement.created_at.isoformat() + 'Z'
            })
        
        # Export schedules
        schedules = Schedule.query.filter(Schedule.course_id.in_(course_ids)).all()
        for schedule in schedules:
            export_data['schedules'].append({
                'id': schedule.id,
                'course_id': schedule.course_id,
                'day_of_week': schedule.day_of_week,
                'start_time': schedule.start_time.strftime('%H:%M'),
                'end_time': schedule.end_time.strftime('%H:%M'),
                'location': schedule.location,
                'is_active': schedule.is_active,
                'created_at': schedule.created_at.isoformat() + 'Z'
            })
        
        # Return based on format
        if export_format == 'json':
            response = make_response(json.dumps(export_data, indent=2))
            response.headers['Content-Type'] = 'application/json'
            response.headers['Content-Disposition'] = f'attachment; filename=lecturer_data_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
            return response
        
        elif export_format == 'zip':
            return create_zip_export(export_data)
        
        else:
            return jsonify({'error': 'Unsupported export format'}), 400
            
    except Exception as e:
        return jsonify({'error': 'Failed to export data', 'details': str(e)}), 500

def create_zip_export(export_data):
    """Create a ZIP file with multiple CSV files"""
    try:
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
        
        with zipfile.ZipFile(temp_file.name, 'w', zipfile.ZIP_DEFLATED) as zipf:
            info_content = json.dumps(export_data['export_info'], indent=2)
            zipf.writestr('export_info.json', info_content)
            
            if export_data['courses']:
                courses_csv = create_csv_from_data(export_data['courses'])
                zipf.writestr('courses.csv', courses_csv)
            if export_data['attendance_sessions']:
                zipf.writestr('attendance_sessions.csv', create_csv_from_data(export_data['attendance_sessions']))
            if export_data['attendance_records']:
                zipf.writestr('attendance_records.csv', create_csv_from_data(export_data['attendance_records']))
            if export_data['enrollments']:
                zipf.writestr('enrollments.csv', create_csv_from_data(export_data['enrollments']))
            if export_data['announcements']:
                zipf.writestr('announcements.csv', create_csv_from_data(export_data['announcements']))
            if export_data['schedules']:
                zipf.writestr('schedules.csv', create_csv_from_data(export_data['schedules']))
        
        with open(temp_file.name, 'rb') as f:
            zip_content = f.read()
        
        os.unlink(temp_file.name)
        
        response = make_response(zip_content)
        response.headers['Content-Type'] = 'application/zip'
        response.headers['Content-Disposition'] = f'attachment; filename=lecturer_data_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.zip'
        
        return response
        
    except Exception as e:
        if 'temp_file' in locals() and os.path.exists(temp_file.name):
            os.unlink(temp_file.name)
        raise e

def create_csv_from_data(data_list):
    """Convert list of dictionaries to CSV string"""
    if not data_list:
        return ""
    
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=data_list[0].keys())
    writer.writeheader()
    writer.writerows(data_list)
    return output.getvalue()

@backup_bp.get('/student/data/export')
@auth_required(roles=['student'])
def export_student_data():
    """Export student's attendance data"""
    try:
        export_format = request.args.get('format', 'json')
        
        enrollments = db.session.query(Enrollment, Course).join(
            Course, Enrollment.course_id == Course.id
        ).filter(Enrollment.student_id == request.user_id).all()
        
        attendance_records = db.session.query(AttendanceRecord, AttendanceSession, Course).join(
            AttendanceSession, AttendanceRecord.session_id == AttendanceSession.id
        ).join(
            Course, AttendanceSession.course_id == Course.id
        ).filter(AttendanceRecord.student_id == request.user_id).all()
        
        student = User.query.get(request.user_id)
        
        export_data = {
            'export_info': {
                'exported_at': datetime.utcnow().isoformat() + 'Z',
                'student_id': request.user_id,
                'student_name': student.fullname,
                'student_email': student.email,
                'student_number': student.student_id,
                'export_format': export_format
            },
            'enrolled_courses': [],
            'attendance_history': []
        }
        
        for enrollment, crs in enrollments:
            export_data['enrolled_courses'].append({
                'course_id': crs.id,
                'course_name': crs.course_name,
                'course_code': crs.course_code,
                'programme': crs.programme,
                'faculty': crs.faculty,
                'department': crs.department,
                'level': crs.level,
                'section': crs.section,
                'enrolled_at': enrollment.joined_at.isoformat() + 'Z'
            })
        
        for record, session, crs in attendance_records:
            export_data['attendance_history'].append({
                'course_name': crs.course_name,
                'course_code': crs.course_code,
                'date': record.timestamp.date().isoformat(),
                'time': record.timestamp.time().strftime('%H:%M:%S'),
                'status': record.status,
                'method': session.method,
                'session_duration': int((session.expires_at - session.created_at).total_seconds() / 60)
            })
        
        export_data['attendance_history'].sort(key=lambda x: x['date'], reverse=True)
        
        if export_format == 'json':
            response = make_response(json.dumps(export_data, indent=2))
            response.headers['Content-Type'] = 'application/json'
            response.headers['Content-Disposition'] = f'attachment; filename=student_attendance_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
            return response
        
        elif export_format == 'csv':
            output = io.StringIO()
            if export_data['attendance_history']:
                writer = csv.DictWriter(output, fieldnames=export_data['attendance_history'][0].keys())
                writer.writeheader()
                writer.writerows(export_data['attendance_history'])
            
            response = make_response(output.getvalue())
            response.headers['Content-Type'] = 'text/csv'
            response.headers['Content-Disposition'] = f'attachment; filename=student_attendance_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            return response
        
        else:
            return jsonify({'error': 'Unsupported export format'}), 400
            
    except Exception as e:
        return jsonify({'error': 'Failed to export student data', 'details': str(e)}), 500

@backup_bp.post('/system/backup')
@auth_required(roles=['lecturer'])  # could be admin-only
def create_system_backup():
    """Create a backup of the entire system (for admin/lecturer use)"""
    try:
        backup_data = {
            'backup_info': {
                'created_at': datetime.utcnow().isoformat() + 'Z',
                'created_by': request.user_id,
                'version': '1.0'
            },
            'statistics': {
                'total_users': User.query.count(),
                'total_courses': Course.query.count(),
                'total_sessions': AttendanceSession.query.count(),
                'total_records': AttendanceRecord.query.count()
            }
        }
        
        return jsonify({
            'message': 'System backup created successfully',
            'backup_info': backup_data['backup_info'],
            'statistics': backup_data['statistics']
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to create system backup', 'details': str(e)}), 500

@backup_bp.get('/data/summary')
@auth_required()
def get_data_summary():
    """Get summary of user's data for export preview"""
    try:
        if request.user_role == 'lecturer':
            courses = Course.query.filter_by(lecturer_id=request.user_id).all()
            course_ids = [c.id for c in courses]
            
            sessions_count = AttendanceSession.query.filter(
                AttendanceSession.course_id.in_(course_ids)
            ).count() if course_ids else 0
            
            enrollments_count = Enrollment.query.filter(
                Enrollment.course_id.in_(course_ids)
            ).count() if course_ids else 0
            
            records_count = db.session.query(AttendanceRecord).join(
                AttendanceSession, AttendanceRecord.session_id == AttendanceSession.id
            ).filter(AttendanceSession.course_id.in_(course_ids)).count() if course_ids else 0
            
            return jsonify({
                'user_type': 'lecturer',
                'data_summary': {
                    'courses': len(courses),
                    'attendance_sessions': sessions_count,
                    'enrollments': enrollments_count,
                    'attendance_records': records_count,
                    'announcements': Announcement.query.filter(
                        (Announcement.course_id.in_(course_ids)) | (Announcement.course_id == None)
                    ).count() if course_ids else 0,
                    'schedules': Schedule.query.filter(
                        Schedule.course_id.in_(course_ids)
                    ).count() if course_ids else 0
                }
            }), 200
        
        else:  # student
            enrollments = Enrollment.query.filter_by(student_id=request.user_id).all()
            records_count = db.session.query(AttendanceRecord).join(
                AttendanceSession, AttendanceRecord.session_id == AttendanceSession.id
            ).filter(AttendanceRecord.student_id == request.user_id).count()
            
            return jsonify({
                'user_type': 'student',
                'data_summary': {
                    'enrolled_courses': len(enrollments),
                    'attendance_records': records_count,
                    'notifications': Notification.query.filter_by(user_id=request.user_id).count()
                }
            }), 200
            
    except Exception as e:
        return jsonify({'error': 'Failed to get data summary', 'details': str(e)}), 500

@backup_bp.delete('/data/cleanup')
@auth_required(roles=['lecturer'])
def cleanup_old_data():
    """Clean up old data (sessions older than specified days)"""
    try:
        data = request.get_json(force=True)
        days_old = int(data.get('days_old', 90))  # Default 90 days
        
        if days_old < 30:
            return jsonify({'error': 'Cannot delete data newer than 30 days'}), 400
        
        cutoff_date = datetime.utcnow() - timedelta(days=days_old)
        
        courses = Course.query.filter_by(lecturer_id=request.user_id).all()
        course_ids = [c.id for c in courses]
        
        if not course_ids:
            return jsonify({'message': 'No data to clean up'}), 200
        
        old_sessions = AttendanceSession.query.filter(
            AttendanceSession.course_id.in_(course_ids),
            AttendanceSession.created_at < cutoff_date,
            AttendanceSession.is_open == False
        ).all()
        
        old_session_ids = [s.id for s in old_sessions]
        
        records_to_delete = AttendanceRecord.query.filter(
            AttendanceRecord.session_id.in_(old_session_ids)
        ).count() if old_session_ids else 0
        
        if old_session_ids:
            AttendanceRecord.query.filter(
                AttendanceRecord.session_id.in_(old_session_ids)
            ).delete(synchronize_session=False)
        
        sessions_deleted = len(old_sessions)
        for session in old_sessions:
            db.session.delete(session)
        
        db.session.commit()
        
        return jsonify({
            'message': 'Data cleanup completed',
            'deleted': {
                'sessions': sessions_deleted,
                'attendance_records': records_to_delete
            },
            'cutoff_date': cutoff_date.isoformat() + 'Z'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to cleanup data', 'details': str(e)}), 500
