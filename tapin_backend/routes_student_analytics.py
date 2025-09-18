from flask import Blueprint, request, jsonify
from .models import db, Course, AttendanceSession, AttendanceRecord, Enrollment, User
from .utils import auth_required
from datetime import datetime, timedelta
from sqlalchemy import func, and_

student_analytics_bp = Blueprint('student_analytics', __name__)

@student_analytics_bp.get('/student/dashboard')
@auth_required(roles=['student'])
def get_student_dashboard():
    """Get comprehensive dashboard data for student"""
    try:
        # Get all enrolled courses
        enrolled_courses = db.session.query(Course).join(
            Enrollment, Enrollment.course_id == Course.id
        ).filter(Enrollment.student_id == request.user_id).all()
        
        course_ids = [c.id for c in enrolled_courses]
        
        if not course_ids:
            return jsonify({
                'total_courses': 0,
                'overall_attendance_rate': 0,
                'courses_summary': [],
                'recent_sessions': [],
                'attendance_trends': []
            }), 200
        
        # Get all attendance records for this student
        all_records = db.session.query(AttendanceRecord, AttendanceSession, Course).join(
            AttendanceSession, AttendanceRecord.session_id == AttendanceSession.id
        ).join(
            Course, AttendanceSession.course_id == Course.id
        ).filter(
            AttendanceRecord.student_id == request.user_id,
            AttendanceSession.course_id.in_(course_ids)
        ).all()
        
        # Calculate overall statistics
        total_records = len(all_records)
        present_records = len([r for r in all_records if r.AttendanceRecord.status == 'Present'])
        overall_attendance_rate = (present_records / total_records * 100) if total_records > 0 else 0
        
        # Get course-wise summary
        courses_summary = []
        for course in enrolled_courses:
            course_records = [r for r in all_records if r.Course.id == course.id]
            course_present = len([r for r in course_records if r.AttendanceRecord.status == 'Present'])
            course_rate = (course_present / len(course_records) * 100) if course_records else 0
            
            # Get total sessions for this course
            total_sessions = AttendanceSession.query.filter_by(course_id=course.id).count()
            
            courses_summary.append({
                'id': course.id,
                'course_name': course.course_name,
                'course_code': course.course_code,
                'programme': course.programme,
                'attendance_rate': round(course_rate, 2),
                'sessions_attended': course_present,
                'total_sessions': len(course_records),
                'all_sessions': total_sessions,
                'status': 'excellent' if course_rate >= 90 else 'good' if course_rate >= 75 else 'warning' if course_rate >= 60 else 'critical'
            })
        
        # Get recent attendance sessions (last 10)
        recent_sessions = []
        recent_records = sorted(all_records, key=lambda x: x.AttendanceRecord.timestamp, reverse=True)[:10]
        
        for record, session, course in recent_records:
            recent_sessions.append({
                'course_name': course.course_name,
                'course_code': course.course_code,
                'date': record.timestamp.date().isoformat(),
                'time': record.timestamp.time().strftime('%H:%M'),
                'status': record.status,
                'method': session.method
            })
        
        # Get attendance trends (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_records_30d = [r for r in all_records if r.AttendanceRecord.timestamp >= thirty_days_ago]
        
        # Group by date
        daily_attendance = {}
        for record, session, course in recent_records_30d:
            date_str = record.timestamp.date().isoformat()
            if date_str not in daily_attendance:
                daily_attendance[date_str] = {'present': 0, 'total': 0}
            
            daily_attendance[date_str]['total'] += 1
            if record.status == 'Present':
                daily_attendance[date_str]['present'] += 1
        
        attendance_trends = []
        for date_str, data in sorted(daily_attendance.items()):
            rate = (data['present'] / data['total'] * 100) if data['total'] > 0 else 0
            attendance_trends.append({
                'date': date_str,
                'rate': round(rate, 2),
                'present': data['present'],
                'total': data['total']
            })
        
        return jsonify({
            'total_courses': len(enrolled_courses),
            'overall_attendance_rate': round(overall_attendance_rate, 2),
            'total_sessions_attended': present_records,
            'total_sessions': total_records,
            'courses_summary': courses_summary,
            'recent_sessions': recent_sessions,
            'attendance_trends': attendance_trends
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch student dashboard', 'details': str(e)}), 500


@student_analytics_bp.get('/student/course/<int:course_id>/analytics')
@auth_required(roles=['student'])
def get_student_course_analytics(course_id):
    """Get detailed analytics for a specific course"""
    try:
        # Verify student is enrolled in this course
        enrollment = Enrollment.query.filter_by(
            course_id=course_id, student_id=request.user_id
        ).first()
        
        if not enrollment:
            return jsonify({'error': 'Not enrolled in this course'}), 403
        
        # Get course info
        course = Course.query.get_or_404(course_id)
        
        # Get all attendance records for this student in this course
        records = db.session.query(AttendanceRecord, AttendanceSession).join(
            AttendanceSession, AttendanceRecord.session_id == AttendanceSession.id
        ).filter(
            AttendanceSession.course_id == course_id,
            AttendanceRecord.student_id == request.user_id
        ).order_by(AttendanceRecord.timestamp.desc()).all()
        
        # Calculate statistics
        total_attended = len(records)
        present_count = len([r for r in records if r.AttendanceRecord.status == 'Present'])
        attendance_rate = (present_count / total_attended * 100) if total_attended > 0 else 0
        
        # Get total sessions conducted (including ones student didn't attend)
        total_sessions = AttendanceSession.query.filter_by(course_id=course_id).count()
        missed_sessions = total_sessions - total_attended
        
        # Get attendance history
        attendance_history = []
        for record, session in records:
            attendance_history.append({
                'date': record.timestamp.date().isoformat(),
                'time': record.timestamp.time().strftime('%H:%M'),
                'status': record.status,
                'method': session.method,
                'session_duration': int((session.expires_at - session.created_at).total_seconds() / 60)
            })
        
        # Get attendance by method
        method_stats = {}
        for record, session in records:
            method = session.method
            if method not in method_stats:
                method_stats[method] = {'total': 0, 'present': 0}
            
            method_stats[method]['total'] += 1
            if record.status == 'Present':
                method_stats[method]['present'] += 1
        
        method_breakdown = []
        for method, stats in method_stats.items():
            rate = (stats['present'] / stats['total'] * 100) if stats['total'] > 0 else 0
            method_breakdown.append({
                'method': method,
                'total': stats['total'],
                'present': stats['present'],
                'rate': round(rate, 2)
            })
        
        # Get weekly attendance pattern
        weekly_pattern = {}
        for record, session in records:
            day_name = record.timestamp.strftime('%A')
            if day_name not in weekly_pattern:
                weekly_pattern[day_name] = {'total': 0, 'present': 0}
            
            weekly_pattern[day_name]['total'] += 1
            if record.status == 'Present':
                weekly_pattern[day_name]['present'] += 1
        
        weekly_stats = []
        for day in ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']:
            if day in weekly_pattern:
                stats = weekly_pattern[day]
                rate = (stats['present'] / stats['total'] * 100) if stats['total'] > 0 else 0
                weekly_stats.append({
                    'day': day,
                    'rate': round(rate, 2),
                    'sessions': stats['total']
                })
        
        # Calculate performance insights
        insights = []
        
        if attendance_rate >= 90:
            insights.append({'type': 'success','message': 'Excellent attendance! Keep up the great work.','icon': '🎉'})
        elif attendance_rate >= 75:
            insights.append({'type': 'info','message': 'Good attendance rate. Try to maintain consistency.','icon': '👍'})
        elif attendance_rate >= 60:
            insights.append({'type': 'warning','message': 'Your attendance needs improvement. Consider setting reminders.','icon': '⚠️'})
        else:
            insights.append({'type': 'danger','message': 'Critical: Your attendance is very low. Please speak with your lecturer.','icon': '🚨'})
        
        if missed_sessions > 0:
            insights.append({'type': 'info','message': f'You have missed {missed_sessions} session(s).','icon': '📝'})
        
        return jsonify({
            'course_info': {
                'id': course.id,
                'course_name': course.course_name,
                'course_code': course.course_code,
                'programme': course.programme,
                'department': course.department
            },
            'statistics': {
                'attendance_rate': round(attendance_rate, 2),
                'sessions_attended': present_count,
                'total_sessions_marked': total_attended,
                'total_sessions_conducted': total_sessions,
                'missed_sessions': missed_sessions
            },
            'attendance_history': attendance_history,
            'method_breakdown': method_breakdown,
            'weekly_pattern': weekly_stats,
            'insights': insights
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch course analytics', 'details': str(e)}), 500
