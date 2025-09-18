from flask import Blueprint, request, jsonify
from .models import db, Course, AttendanceSession, AttendanceRecord, Enrollment, User
from .utils import auth_required
from datetime import datetime, timedelta
from sqlalchemy import func, and_, extract
import calendar

visualization_bp = Blueprint('visualization', __name__)

@visualization_bp.get('/courses/<int:course_id>/trends/attendance')
@auth_required(roles=['lecturer'])
def get_attendance_trends(course_id):
    """Get attendance trends for visualization"""
    try:
        # Verify lecturer owns this course
        course = Course.query.get_or_404(course_id)
        if course.lecturer_id != request.user_id:
            return jsonify({'error': 'Forbidden'}), 403
        
        # Get query parameters
        period = request.args.get('period', '30')  # days, weeks, months
        chart_type = request.args.get('chart_type', 'line')  # line, bar, pie
        
        try:
            days = int(period)
        except ValueError:
            days = 30
        
        # Get data for the specified period
        start_date = datetime.utcnow() - timedelta(days=days)
        
        # Get attendance sessions and records
        sessions_data = db.session.query(
            AttendanceSession,
            func.count(AttendanceRecord.id).label('total_records'),
            func.sum(func.case([(AttendanceRecord.status == 'Present', 1)], else_=0)).label('present_count')
        ).outerjoin(
            AttendanceRecord, AttendanceSession.id == AttendanceRecord.session_id
        ).filter(
            AttendanceSession.course_id == course_id,
            AttendanceSession.created_at >= start_date
        ).group_by(AttendanceSession.id).order_by(AttendanceSession.created_at).all()
        
        # Prepare data for different chart types
        if chart_type == 'line':
            # Daily attendance trend
            daily_data = {}
            for session, total, present in sessions_data:
                date_key = session.created_at.date().isoformat()
                if date_key not in daily_data:
                    daily_data[date_key] = {'total': 0, 'present': 0, 'sessions': 0}
                
                daily_data[date_key]['total'] += total or 0
                daily_data[date_key]['present'] += present or 0
                daily_data[date_key]['sessions'] += 1
            
            # Fill missing dates with zeros
            current_date = start_date.date()
            end_date = datetime.utcnow().date()
            
            trend_data = []
            while current_date <= end_date:
                date_key = current_date.isoformat()
                data = daily_data.get(date_key, {'total': 0, 'present': 0, 'sessions': 0})
                
                attendance_rate = (data['present'] / data['total'] * 100) if data['total'] > 0 else 0
                
                trend_data.append({
                    'date': date_key,
                    'attendance_rate': round(attendance_rate, 2),
                    'present': data['present'],
                    'total': data['total'],
                    'sessions': data['sessions']
                })
                
                current_date += timedelta(days=1)
            
            return jsonify({
                'chart_type': 'line',
                'period_days': days,
                'data': trend_data,
                'summary': {
                    'total_sessions': len(sessions_data),
                    'avg_attendance_rate': round(
                        sum(d['attendance_rate'] for d in trend_data if d['total'] > 0) / 
                        len([d for d in trend_data if d['total'] > 0]), 2
                    ) if any(d['total'] > 0 for d in trend_data) else 0
                }
            }), 200
        
        elif chart_type == 'bar':
            # Weekly attendance comparison
            weekly_data = {}
            for session, total, present in sessions_data:
                week_start = session.created_at.date() - timedelta(days=session.created_at.weekday())
                week_key = week_start.isoformat()
                
                if week_key not in weekly_data:
                    weekly_data[week_key] = {'total': 0, 'present': 0, 'sessions': 0}
                
                weekly_data[week_key]['total'] += total or 0
                weekly_data[week_key]['present'] += present or 0
                weekly_data[week_key]['sessions'] += 1
            
            bar_data = []
            for week_start, data in sorted(weekly_data.items()):
                attendance_rate = (data['present'] / data['total'] * 100) if data['total'] > 0 else 0
                
                bar_data.append({
                    'week_start': week_start,
                    'week_label': f"Week of {week_start}",
                    'attendance_rate': round(attendance_rate, 2),
                    'present': data['present'],
                    'total': data['total'],
                    'sessions': data['sessions']
                })
            
            return jsonify({
                'chart_type': 'bar',
                'period_days': days,
                'data': bar_data
            }), 200
        
        elif chart_type == 'pie':
            # Attendance status distribution
            total_present = sum(present or 0 for _, _, present in sessions_data)
            total_records = sum(total or 0 for _, total, _ in sessions_data)
            total_absent = total_records - total_present
            
            pie_data = [
                {
                    'label': 'Present',
                    'value': total_present,
                    'percentage': round((total_present / total_records * 100), 2) if total_records > 0 else 0,
                    'color': '#28a745'
                },
                {
                    'label': 'Absent',
                    'value': total_absent,
                    'percentage': round((total_absent / total_records * 100), 2) if total_records > 0 else 0,
                    'color': '#dc3545'
                }
            ]
            
            return jsonify({
                'chart_type': 'pie',
                'period_days': days,
                'data': pie_data,
                'total_records': total_records
            }), 200
        
        else:
            return jsonify({'error': 'Invalid chart_type'}), 400
            
    except Exception as e:
        return jsonify({'error': 'Failed to get attendance trends', 'details': str(e)}), 500

@visualization_bp.get('/courses/<int:course_id>/trends/methods')
@auth_required(roles=['lecturer'])
def get_method_trends(course_id):
    """Get attendance method usage trends"""
    try:
        # Verify lecturer owns this course
        course = Course.query.get_or_404(course_id)
        if course.lecturer_id != request.user_id:
            return jsonify({'error': 'Forbidden'}), 403
        
        # Get method usage data
        method_data = db.session.query(
            AttendanceSession.method,
            func.count(AttendanceSession.id).label('session_count'),
            func.count(AttendanceRecord.id).label('total_records'),
            func.sum(func.case([(AttendanceRecord.status == 'Present', 1)], else_=0)).label('present_count')
        ).outerjoin(
            AttendanceRecord, AttendanceSession.id == AttendanceRecord.session_id
        ).filter(
            AttendanceSession.course_id == course_id
        ).group_by(AttendanceSession.method).all()
        
        method_trends = []
        for method, sessions, total, present in method_data:
            success_rate = (present / total * 100) if total and total > 0 else 0
            
            method_trends.append({
                'method': method,
                'sessions': sessions,
                'total_records': total or 0,
                'present_records': present or 0,
                'success_rate': round(success_rate, 2),
                'avg_attendance_per_session': round((total or 0) / sessions, 2) if sessions > 0 else 0
            })
        
        return jsonify({
            'method_trends': method_trends,
            'total_sessions': sum(m['sessions'] for m in method_trends)
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get method trends', 'details': str(e)}), 500

@visualization_bp.get('/courses/<int:course_id>/trends/hourly')
@auth_required(roles=['lecturer'])
def get_hourly_trends(course_id):
    """Get attendance trends by hour of day"""
    try:
        # Verify lecturer owns this course
        course = Course.query.get_or_404(course_id)
        if course.lecturer_id != request.user_id:
            return jsonify({'error': 'Forbidden'}), 403
        
        # Get hourly data
        hourly_data = db.session.query(
            extract('hour', AttendanceSession.created_at).label('hour'),
            func.count(AttendanceSession.id).label('session_count'),
            func.count(AttendanceRecord.id).label('total_records'),
            func.sum(func.case([(AttendanceRecord.status == 'Present', 1)], else_=0)).label('present_count')
        ).outerjoin(
            AttendanceRecord, AttendanceSession.id == AttendanceRecord.session_id
        ).filter(
            AttendanceSession.course_id == course_id
        ).group_by(extract('hour', AttendanceSession.created_at)).order_by('hour').all()
        
        hourly_trends = []
        for hour, sessions, total, present in hourly_data:
            attendance_rate = (present / total * 100) if total and total > 0 else 0
            
            hourly_trends.append({
                'hour': int(hour),
                'hour_label': f"{int(hour):02d}:00",
                'sessions': sessions,
                'attendance_rate': round(attendance_rate, 2),
                'total_records': total or 0,
                'present_records': present or 0
            })
        
        return jsonify({
            'hourly_trends': hourly_trends,
            'peak_hour': max(hourly_trends, key=lambda x: x['sessions'])['hour'] if hourly_trends else None
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get hourly trends', 'details': str(e)}), 500

@visualization_bp.get('/courses/<int:course_id>/trends/monthly')
@auth_required(roles=['lecturer'])
def get_monthly_trends(course_id):
    """Get monthly attendance trends"""
    try:
        # Verify lecturer owns this course
        course = Course.query.get_or_404(course_id)
        if course.lecturer_id != request.user_id:
            return jsonify({'error': 'Forbidden'}), 403
        
        # Get monthly data for the past year
        one_year_ago = datetime.utcnow() - timedelta(days=365)
        
        monthly_data = db.session.query(
            extract('year', AttendanceSession.created_at).label('year'),
            extract('month', AttendanceSession.created_at).label('month'),
            func.count(AttendanceSession.id).label('session_count'),
            func.count(AttendanceRecord.id).label('total_records'),
            func.sum(func.case([(AttendanceRecord.status == 'Present', 1)], else_=0)).label('present_count')
        ).outerjoin(
            AttendanceRecord, AttendanceSession.id == AttendanceRecord.session_id
        ).filter(
            AttendanceSession.course_id == course_id,
            AttendanceSession.created_at >= one_year_ago
        ).group_by(
            extract('year', AttendanceSession.created_at),
            extract('month', AttendanceSession.created_at)
        ).order_by('year', 'month').all()
        
        monthly_trends = []
        for year, month, sessions, total, present in monthly_data:
            attendance_rate = (present / total * 100) if total and total > 0 else 0
            
            monthly_trends.append({
                'year': int(year),
                'month': int(month),
                'month_name': calendar.month_name[int(month)],
                'month_label': f"{calendar.month_name[int(month)]} {int(year)}",
                'sessions': sessions,
                'attendance_rate': round(attendance_rate, 2),
                'total_records': total or 0,
                'present_records': present or 0
            })
        
        return jsonify({
            'monthly_trends': monthly_trends,
            'period': 'past_year'
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get monthly trends', 'details': str(e)}), 500

@visualization_bp.get('/lecturer/trends/overview')
@auth_required(roles=['lecturer'])
def get_lecturer_trends_overview():
    """Get overall trends across all lecturer's courses"""
    try:
        # Get lecturer's courses
        courses = Course.query.filter_by(lecturer_id=request.user_id).all()
        course_ids = [c.id for c in courses]
        
        if not course_ids:
            return jsonify({'error': 'No courses found'}), 404
        
        # Get overall statistics
        period_days = int(request.args.get('days', 30))
        start_date = datetime.utcnow() - timedelta(days=period_days)
        
        # Daily trends across all courses
        daily_trends = db.session.query(
            func.date(AttendanceSession.created_at).label('date'),
            func.count(AttendanceSession.id).label('sessions'),
            func.count(AttendanceRecord.id).label('total_records'),
            func.sum(func.case([(AttendanceRecord.status == 'Present', 1)], else_=0)).label('present_count')
        ).outerjoin(
            AttendanceRecord, AttendanceSession.id == AttendanceRecord.session_id
        ).filter(
            AttendanceSession.course_id.in_(course_ids),
            AttendanceSession.created_at >= start_date
        ).group_by(func.date(AttendanceSession.created_at)).order_by('date').all()
        
        trend_data = []
        for date, sessions, total, present in daily_trends:
            attendance_rate = (present / total * 100) if total and total > 0 else 0
            
            trend_data.append({
                'date': date.isoformat(),
                'sessions': sessions,
                'attendance_rate': round(attendance_rate, 2),
                'total_records': total or 0,
                'present_records': present or 0
            })
        
        # Course comparison
        course_comparison = []
        for course in courses:
            course_data = db.session.query(
                func.count(AttendanceSession.id).label('sessions'),
                func.count(AttendanceRecord.id).label('total_records'),
                func.sum(func.case([(AttendanceRecord.status == 'Present', 1)], else_=0)).label('present_count')
            ).outerjoin(
                AttendanceRecord, AttendanceSession.id == AttendanceRecord.session_id
            ).filter(
                AttendanceSession.course_id == course.id,
                AttendanceSession.created_at >= start_date
            ).first()
            
            sessions, total, present = course_data
            attendance_rate = (present / total * 100) if total and total > 0 else 0
            
            course_comparison.append({
                'course_id': course.id,
                'course_name': course.course_name,
                'course_code': course.course_code,
                'sessions': sessions or 0,
                'attendance_rate': round(attendance_rate, 2),
                'total_records': total or 0,
                'present_records': present or 0
            })
        
        # Sort by attendance rate
        course_comparison.sort(key=lambda x: x['attendance_rate'], reverse=True)
        
        return jsonify({
            'period_days': period_days,
            'daily_trends': trend_data,
            'course_comparison': course_comparison,
            'summary': {
                'total_courses': len(courses),
                'total_sessions': sum(c['sessions'] for c in course_comparison),
                'overall_attendance_rate': round(
                    sum(c['present_records'] for c in course_comparison) / 
                    sum(c['total_records'] for c in course_comparison) * 100, 2
                ) if sum(c['total_records'] for c in course_comparison) > 0 else 0
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get lecturer trends overview', 'details': str(e)}), 500

@visualization_bp.get('/student/trends/personal')
@auth_required(roles=['student'])
def get_student_personal_trends():
    """Get student's personal attendance trends"""
    try:
        period_days = int(request.args.get('days', 30))
        start_date = datetime.utcnow() - timedelta(days=period_days)
        
        # Get student's attendance records
        attendance_data = db.session.query(
            AttendanceRecord,
            AttendanceSession,
            Course
        ).join(
            AttendanceSession, AttendanceRecord.session_id == AttendanceSession.id
        ).join(
            Course, AttendanceSession.course_id == Course.id
        ).filter(
            AttendanceRecord.student_id == request.user_id,
            AttendanceRecord.timestamp >= start_date
        ).order_by(AttendanceRecord.timestamp).all()
        
        # Daily attendance trend
        daily_data = {}
        for record, session, course in attendance_data:
            date_key = record.timestamp.date().isoformat()
            if date_key not in daily_data:
                daily_data[date_key] = {'total': 0, 'present': 0}
            
            daily_data[date_key]['total'] += 1
            if record.status == 'Present':
                daily_data[date_key]['present'] += 1
        
        # Fill missing dates
        current_date = start_date.date()
        end_date = datetime.utcnow().date()
        
        trend_data = []
        while current_date <= end_date:
            date_key = current_date.isoformat()
            data = daily_data.get(date_key, {'total': 0, 'present': 0})
            
            attendance_rate = (data['present'] / data['total'] * 100) if data['total'] > 0 else None
            
            trend_data.append({
                'date': date_key,
                'attendance_rate': round(attendance_rate, 2) if attendance_rate is not None else None,
                'present': data['present'],
                'total': data['total'],
                'has_data': data['total'] > 0
            })
            
            current_date += timedelta(days=1)
        
        # Course-wise breakdown
        course_breakdown = {}
        for record, session, course in attendance_data:
            course_key = f"{course.course_code}"
            if course_key not in course_breakdown:
                course_breakdown[course_key] = {
                    'course_name': course.course_name,
                    'total': 0,
                    'present': 0
                }
            
            course_breakdown[course_key]['total'] += 1
            if record.status == 'Present':
                course_breakdown[course_key]['present'] += 1
        
        course_stats = []
        for course_code, data in course_breakdown.items():
            attendance_rate = (data['present'] / data['total'] * 100) if data['total'] > 0 else 0
            course_stats.append({
                'course_code': course_code,
                'course_name': data['course_name'],
                'attendance_rate': round(attendance_rate, 2),
                'present': data['present'],
                'total': data['total']
            })
        
        return jsonify({
            'period_days': period_days,
            'daily_trends': trend_data,
            'course_breakdown': course_stats,
            'summary': {
                'total_sessions': len(attendance_data),
                'present_sessions': len([r for r, _, _ in attendance_data if r.status == 'Present']),
                'overall_attendance_rate': round(
                    len([r for r, _, _ in attendance_data if r.status == 'Present']) / 
                    len(attendance_data) * 100, 2
                ) if attendance_data else 0
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get student trends', 'details': str(e)}), 500
