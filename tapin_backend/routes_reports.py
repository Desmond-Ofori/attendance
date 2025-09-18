from flask import Blueprint, request, jsonify, make_response
from .models import db, Course, AttendanceSession, AttendanceRecord, Enrollment, User
from .utils import auth_required
from datetime import datetime, timedelta
import csv
import io
from sqlalchemy import and_

reports_bp = Blueprint('reports', __name__)

@reports_bp.get('/courses/<int:course_id>/reports/attendance')
@auth_required(roles=['lecturer'])
def generate_attendance_report(course_id):
    """Generate detailed attendance report for a course"""
    try:
        # Verify lecturer owns this course
        course = Course.query.get_or_404(course_id)
        if course.lecturer_id != request.user_id:
            return jsonify({'error': 'Forbidden'}), 403

        # Get query parameters
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        format_type = request.args.get('format', 'json')  # json or csv

        # Build query filters
        query_filters = [AttendanceSession.course_id == course_id]
        
        if start_date:
            try:
                start_dt = datetime.fromisoformat(start_date)
                query_filters.append(AttendanceSession.created_at >= start_dt)
            except ValueError:
                return jsonify({'error': 'Invalid start_date format'}), 400
                
        if end_date:
            try:
                end_dt = datetime.fromisoformat(end_date)
                query_filters.append(AttendanceSession.created_at <= end_dt)
            except ValueError:
                return jsonify({'error': 'Invalid end_date format'}), 400

        # Get all sessions in the date range
        sessions = AttendanceSession.query.filter(and_(*query_filters)).order_by(
            AttendanceSession.created_at.asc()
        ).all()

        # Get all enrolled students
        students = db.session.query(User).join(
            Enrollment, Enrollment.student_id == User.id
        ).filter(Enrollment.course_id == course_id).order_by(User.fullname).all()

        # Build attendance matrix
        report_data = []
        for student in students:
            student_data = {
                'student_id': student.student_id or f"ID{student.id}",
                'name': student.fullname,
                'email': student.email,
                'sessions': [],
                'total_present': 0,
                'total_sessions': len(sessions),
                'attendance_rate': 0
            }
            
            for session in sessions:
                record = AttendanceRecord.query.filter_by(
                    session_id=session.id,
                    student_id=student.id
                ).first()
                
                status = record.status if record else 'Absent'
                student_data['sessions'].append({
                    'date': session.created_at.date().isoformat(),
                    'time': session.created_at.time().strftime('%H:%M'),
                    'method': session.method,
                    'status': status
                })
                
                if status == 'Present':
                    student_data['total_present'] += 1
            
            # Calculate attendance rate
            if student_data['total_sessions'] > 0:
                student_data['attendance_rate'] = round(
                    (student_data['total_present'] / student_data['total_sessions']) * 100, 2
                )
            
            report_data.append(student_data)

        # Return CSV format if requested
        if format_type == 'csv':
            return generate_csv_report(report_data, course, sessions)

        # Return JSON format
        return jsonify({
            'course_info': {
                'id': course.id,
                'course_name': course.course_name,
                'course_code': course.course_code,
                'programme': course.programme,
                'faculty': course.faculty,
                'department': course.department
            },
            'report_period': {
                'start_date': start_date,
                'end_date': end_date,
                'total_sessions': len(sessions)
            },
            'students': report_data,
            'summary': {
                'total_students': len(students),
                'average_attendance': round(
                    sum(s['attendance_rate'] for s in report_data) / len(report_data), 2
                ) if report_data else 0
            }
        }), 200

    except Exception as e:
        return jsonify({'error': 'Failed to generate report', 'details': str(e)}), 500

def generate_csv_report(report_data, course, sessions):
    """Generate CSV format attendance report"""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header information
    writer.writerow(['Attendance Report'])
    writer.writerow(['Course:', f"{course.course_name} ({course.course_code})"])
    writer.writerow(['Programme:', course.programme])
    writer.writerow(['Faculty:', course.faculty])
    writer.writerow(['Department:', course.department])
    writer.writerow(['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
    writer.writerow([])  # Empty row
    
    # Write column headers
    headers = ['Student ID', 'Name', 'Email']
    for session in sessions:
        headers.append(f"{session.created_at.date()} ({session.method})")
    headers.extend(['Total Present', 'Total Sessions', 'Attendance Rate (%)'])
    writer.writerow(headers)
    
    # Write student data
    for student in report_data:
        row = [
            student['student_id'],
            student['name'],
            student['email']
        ]
        
        # Add session attendance
        for session_data in student['sessions']:
            row.append(session_data['status'])
        
        # Add summary data
        row.extend([
            student['total_present'],
            student['total_sessions'],
            student['attendance_rate']
        ])
        
        writer.writerow(row)
    
    # Create response
    output.seek(0)
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename=attendance_report_{course.course_code}_{datetime.now().strftime("%Y%m%d")}.csv'
    
    return response

@reports_bp.get('/courses/<int:course_id>/reports/summary')
@auth_required(roles=['lecturer'])
def get_course_summary_report(course_id):
    """Get summary statistics for a course"""
    try:
        # Verify lecturer owns this course
        course = Course.query.get_or_404(course_id)
        if course.lecturer_id != request.user_id:
            return jsonify({'error': 'Forbidden'}), 403

        # Get basic statistics
        total_students = Enrollment.query.filter_by(course_id=course_id).count()
        total_sessions = AttendanceSession.query.filter_by(course_id=course_id).count()
        
        # Get attendance records
        attendance_records = db.session.query(AttendanceRecord).join(
            AttendanceSession, AttendanceRecord.session_id == AttendanceSession.id
        ).filter(AttendanceSession.course_id == course_id).all()
        
        total_records = len(attendance_records)
        present_records = len([r for r in attendance_records if r.status == 'Present'])
        
        # Calculate rates
        overall_attendance_rate = (present_records / total_records * 100) if total_records > 0 else 0
        
        # Get students with low attendance (< 75%)
        low_attendance_students = []
        students = db.session.query(User).join(
            Enrollment, Enrollment.student_id == User.id
        ).filter(Enrollment.course_id == course_id).all()
        
        for student in students:
            student_records = db.session.query(AttendanceRecord).join(
                AttendanceSession, AttendanceRecord.session_id == AttendanceSession.id
            ).filter(
                AttendanceSession.course_id == course_id,
                AttendanceRecord.student_id == student.id
            ).all()
            
            if student_records:
                present_count = len([r for r in student_records if r.status == 'Present'])
                attendance_rate = (present_count / len(student_records)) * 100
                
                if attendance_rate < 75:
                    low_attendance_students.append({
                        'id': student.id,
                        'name': student.fullname,
                        'student_id': student.student_id,
                        'attendance_rate': round(attendance_rate, 2),
                        'sessions_attended': present_count,
                        'total_sessions': len(student_records)
                    })
        
        # Get recent session statistics
        recent_sessions = AttendanceSession.query.filter_by(
            course_id=course_id
        ).order_by(AttendanceSession.created_at.desc()).limit(5).all()
        
        recent_stats = []
        for session in recent_sessions:
            session_records = AttendanceRecord.query.filter_by(session_id=session.id).all()
            present_count = len([r for r in session_records if r.status == 'Present'])
            
            recent_stats.append({
                'date': session.created_at.date().isoformat(),
                'method': session.method,
                'present': present_count,
                'total': len(session_records),
                'rate': (present_count / len(session_records) * 100) if session_records else 0
            })

        return jsonify({
            'course_info': {
                'id': course.id,
                'course_name': course.course_name,
                'course_code': course.course_code
            },
            'statistics': {
                'total_students': total_students,
                'total_sessions': total_sessions,
                'overall_attendance_rate': round(overall_attendance_rate, 2),
                'total_attendance_records': total_records
            },
            'low_attendance_students': low_attendance_students,
            'recent_sessions': recent_stats
        }), 200

    except Exception as e:
        return jsonify({'error': 'Failed to generate summary report', 'details': str(e)}), 500

@reports_bp.get('/lecturer/reports/overview')
@auth_required(roles=['lecturer'])
def get_lecturer_overview_report():
    """Get overview report for all lecturer's courses"""
    try:
        # Get all courses for this lecturer
        courses = Course.query.filter_by(lecturer_id=request.user_id).all()
        
        overview_data = []
        total_students = 0
        total_sessions = 0
        total_attendance_records = 0
        total_present_records = 0
        
        for course in courses:
            # Get course statistics
            course_students = Enrollment.query.filter_by(course_id=course.id).count()
            course_sessions = AttendanceSession.query.filter_by(course_id=course.id).count()
            
            # Get attendance records for this course
            course_records = db.session.query(AttendanceRecord).join(
                AttendanceSession, AttendanceRecord.session_id == AttendanceSession.id
            ).filter(AttendanceSession.course_id == course.id).all()
            
            course_present = len([r for r in course_records if r.status == 'Present'])
            course_attendance_rate = (course_present / len(course_records) * 100) if course_records else 0
            
            overview_data.append({
                'id': course.id,
                'course_name': course.course_name,
                'course_code': course.course_code,
                'programme': course.programme,
                'students': course_students,
                'sessions': course_sessions,
                'attendance_rate': round(course_attendance_rate, 2),
                'total_records': len(course_records)
            })
            
            # Add to totals
            total_students += course_students
            total_sessions += course_sessions
            total_attendance_records += len(course_records)
            total_present_records += course_present
        
        # Calculate overall statistics
        overall_attendance_rate = (total_present_records / total_attendance_records * 100) if total_attendance_records > 0 else 0
        
        return jsonify({
            'summary': {
                'total_courses': len(courses),
                'total_students': total_students,
                'total_sessions': total_sessions,
                'overall_attendance_rate': round(overall_attendance_rate, 2)
            },
            'courses': overview_data
        }), 200

    except Exception as e:
        return jsonify({'error': 'Failed to generate overview report', 'details': str(e)}), 500
