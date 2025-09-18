from flask import Blueprint, request, jsonify
from .models import db, Course, AttendanceSession, AttendanceRecord, Enrollment, User
from .utils import auth_required
from datetime import datetime, timedelta
from sqlalchemy import func, and_

analytics_bp = Blueprint('analytics', __name__)

@analytics_bp.get('/classes/<int:class_id>/analytics')
@auth_required(roles=['lecturer'])
def get_class_analytics(class_id):
    """Get comprehensive analytics for a specific class"""
    try:
        # Verify lecturer owns this class
        cls = Course.query.get_or_404(class_id)
        if cls.lecturer_id != request.user_id:
            return jsonify({'error': 'Forbidden'}), 403

        # Get total enrolled students
        total_students = Enrollment.query.filter_by(class_id=class_id).count()
        
        # Get total sessions conducted
        total_sessions = AttendanceSession.query.filter_by(class_id=class_id).count()
        
        # Get attendance records for this class
        attendance_records = db.session.query(
            AttendanceRecord, AttendanceSession
        ).join(
            AttendanceSession, AttendanceRecord.session_id == AttendanceSession.id
        ).filter(
            AttendanceSession.class_id == class_id
        ).all()
        
        # Calculate attendance statistics
        total_records = len(attendance_records)
        present_records = len([r for r in attendance_records if r.AttendanceRecord.status == 'Present'])
        attendance_rate = (present_records / total_records * 100) if total_records > 0 else 0
        
        # Get recent attendance trends (last 7 sessions)
        recent_sessions = AttendanceSession.query.filter_by(
            class_id=class_id
        ).order_by(AttendanceSession.created_at.desc()).limit(7).all()
        
        trends = []
        for session in reversed(recent_sessions):
            session_records = AttendanceRecord.query.filter_by(session_id=session.id).all()
            present_count = len([r for r in session_records if r.status == 'Present'])
            trends.append({
                'date': session.created_at.date().isoformat(),
                'present': present_count,
                'total': len(session_records),
                'rate': (present_count / len(session_records) * 100) if session_records else 0
            })
        
        # Get student attendance summary
        student_stats = []
        enrolled_students = db.session.query(User).join(
            Enrollment, Enrollment.student_id == User.id
        ).filter(Enrollment.class_id == class_id).all()
        
        for student in enrolled_students:
            student_records = db.session.query(AttendanceRecord).join(
                AttendanceSession, AttendanceRecord.session_id == AttendanceSession.id
            ).filter(
                AttendanceSession.class_id == class_id,
                AttendanceRecord.student_id == student.id
            ).all()
            
            present_count = len([r for r in student_records if r.status == 'Present'])
            total_count = len(student_records)
            
            student_stats.append({
                'id': student.id,
                'name': student.fullname,
                'student_id': student.student_id,
                'present': present_count,
                'total': total_count,
                'rate': (present_count / total_count * 100) if total_count > 0 else 0
            })
        
        # Sort students by attendance rate
        student_stats.sort(key=lambda x: x['rate'], reverse=True)
        
        return jsonify({
            'class_info': {
                'id': cls.id,
                'course_name': cls.course_name,
                'course_code': cls.course_code
            },
            'summary': {
                'total_students': total_students,
                'total_sessions': total_sessions,
                'overall_attendance_rate': round(attendance_rate, 2)
            },
            'trends': trends,
            'student_stats': student_stats[:10],  # Top 10 students
            'low_attendance_students': [s for s in student_stats if s['rate'] < 75 and s['total'] > 0]
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch analytics', 'details': str(e)}), 500

@analytics_bp.get('/dashboard/summary')
@auth_required(roles=['lecturer'])
def get_dashboard_summary():
    """Get overall dashboard summary for lecturer"""
    try:
        # Get all classes for this lecturer
        classes = Course.query.filter_by(lecturer_id=request.user_id).all()
        class_ids = [c.id for c in classes]
        
        if not class_ids:
            return jsonify({
                'total_classes': 0,
                'total_students': 0,
                'total_sessions': 0,
                'average_attendance': 0,
                'recent_activity': []
            }), 200
        
        # Get total enrolled students across all classes
        total_students = db.session.query(func.count(Enrollment.id)).filter(
            Enrollment.class_id.in_(class_ids)
        ).scalar()
        
        # Get total sessions
        total_sessions = AttendanceSession.query.filter(
            AttendanceSession.class_id.in_(class_ids)
        ).count()
        
        # Calculate average attendance rate
        all_records = db.session.query(AttendanceRecord).join(
            AttendanceSession, AttendanceRecord.session_id == AttendanceSession.id
        ).filter(AttendanceSession.class_id.in_(class_ids)).all()
        
        if all_records:
            present_count = len([r for r in all_records if r.status == 'Present'])
            average_attendance = (present_count / len(all_records)) * 100
        else:
            average_attendance = 0
        
        # Get recent activity (last 5 sessions)
        recent_sessions = db.session.query(AttendanceSession, Course).join(
            Course, AttendanceSession.class_id == Course.id
        ).filter(
            AttendanceSession.class_id.in_(class_ids)
        ).order_by(AttendanceSession.created_at.desc()).limit(5).all()
        
        recent_activity = []
        for session, cls in recent_sessions:
            session_records = AttendanceRecord.query.filter_by(session_id=session.id).all()
            present_count = len([r for r in session_records if r.status == 'Present'])
            
            recent_activity.append({
                'class_name': cls.course_name,
                'class_code': cls.course_code,
                'date': session.created_at.isoformat() + 'Z',
                'method': session.method,
                'present': present_count,
                'total': len(session_records)
            })
        
        return jsonify({
            'total_classes': len(classes),
            'total_students': total_students,
            'total_sessions': total_sessions,
            'average_attendance': round(average_attendance, 2),
            'recent_activity': recent_activity
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch dashboard summary', 'details': str(e)}), 500

@analytics_bp.get('/classes/<int:class_id>/attendance-patterns')
@auth_required(roles=['lecturer'])
def get_attendance_patterns(class_id):
    """Get detailed attendance patterns for visualization"""
    try:
        # Verify lecturer owns this class
        cls = Class.query.get_or_404(class_id)
        if cls.lecturer_id != request.user_id:
            return jsonify({'error': 'Forbidden'}), 403
        
        # Get attendance data grouped by date
        sessions = AttendanceSession.query.filter_by(class_id=class_id).order_by(
            AttendanceSession.created_at.asc()
        ).all()
        
        daily_data = []
        for session in sessions:
            records = AttendanceRecord.query.filter_by(session_id=session.id).all()
            present_count = len([r for r in records if r.status == 'Present'])
            
            daily_data.append({
                'date': session.created_at.date().isoformat(),
                'present': present_count,
                'absent': len(records) - present_count,
                'total': len(records),
                'method': session.method
            })
        
        # Get attendance by day of week
        day_patterns = {}
        for session in sessions:
            day_name = session.created_at.strftime('%A')
            if day_name not in day_patterns:
                day_patterns[day_name] = {'sessions': 0, 'total_present': 0, 'total_records': 0}
            
            records = AttendanceRecord.query.filter_by(session_id=session.id).all()
            present_count = len([r for r in records if r.status == 'Present'])
            
            day_patterns[day_name]['sessions'] += 1
            day_patterns[day_name]['total_present'] += present_count
            day_patterns[day_name]['total_records'] += len(records)
        
        # Calculate average attendance by day
        day_averages = []
        for day, data in day_patterns.items():
            avg_rate = (data['total_present'] / data['total_records'] * 100) if data['total_records'] > 0 else 0
            day_averages.append({
                'day': day,
                'average_attendance': round(avg_rate, 2),
                'sessions_count': data['sessions']
            })
        
        return jsonify({
            'daily_attendance': daily_data,
            'day_patterns': day_averages
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch attendance patterns', 'details': str(e)}), 500
