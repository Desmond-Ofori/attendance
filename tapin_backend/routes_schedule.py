from flask import Blueprint, request, jsonify
from .models import db, Course, Schedule, Enrollment, User
from .utils import auth_required
from datetime import datetime, time, timedelta
from sqlalchemy import and_

schedule_bp = Blueprint('schedule', __name__)

# Day mapping for better readability
DAYS_OF_WEEK = {
    0: 'Monday',
    1: 'Tuesday', 
    2: 'Wednesday',
    3: 'Thursday',
    4: 'Friday',
    5: 'Saturday',
    6: 'Sunday'
}

def time_to_string(time_obj):
    """Convert time object to string"""
    return time_obj.strftime('%H:%M') if time_obj else None

def string_to_time(time_str):
    """Convert time string to time object"""
    try:
        return datetime.strptime(time_str, '%H:%M').time()
    except ValueError:
        return None

@schedule_bp.post('/courses/<int:course_id>/schedule')
@auth_required(roles=['lecturer'])
def create_course_schedule(course_id):
    """Create or update course schedule"""
    try:
        # Verify lecturer owns this course
        course = Course.query.get_or_404(course_id)
        if course.lecturer_id != request.user_id:
            return jsonify({'error': 'Forbidden'}), 403
        
        data = request.get_json(force=True)
        schedules_data = data.get('schedules', [])
        
        if not schedules_data:
            return jsonify({'error': 'Schedule data is required'}), 400
        
        # Delete existing schedules for this course
        Schedule.query.filter_by(course_id=course_id).delete()
        
        created_schedules = []
        
        for schedule_item in schedules_data:
            day_of_week = schedule_item.get('day_of_week')
            start_time_str = schedule_item.get('start_time')
            end_time_str = schedule_item.get('end_time')
            location = schedule_item.get('location', '')
            
            # Validation
            if day_of_week is None or day_of_week < 0 or day_of_week > 6:
                return jsonify({'error': 'Invalid day_of_week. Must be 0-6 (Monday-Sunday)'}), 400
            
            start_time = string_to_time(start_time_str)
            end_time = string_to_time(end_time_str)
            
            if not start_time or not end_time:
                return jsonify({'error': 'Invalid time format. Use HH:MM format'}), 400
            
            if start_time >= end_time:
                return jsonify({'error': 'Start time must be before end time'}), 400
            
            # Create schedule entry
            schedule = Schedule(
                course_id=course_id,
                day_of_week=day_of_week,
                start_time=start_time,
                end_time=end_time,
                location=location,
                is_active=True
            )
            db.session.add(schedule)
            created_schedules.append({
                'day_of_week': day_of_week,
                'day_name': DAYS_OF_WEEK[day_of_week],
                'start_time': start_time_str,
                'end_time': end_time_str,
                'location': location
            })
        
        db.session.commit()
        
        return jsonify({
            'message': 'Course schedule created successfully',
            'schedules': created_schedules
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to create schedule', 'details': str(e)}), 500

@schedule_bp.get('/courses/<int:course_id>/schedule')
@auth_required()
def get_course_schedule(course_id):
    """Get course schedule"""
    try:
        # Verify access to this course
        course = Course.query.get_or_404(course_id)
        
        if request.user_role == 'lecturer':
            if course.lecturer_id != request.user_id:
                return jsonify({'error': 'Forbidden'}), 403
        else:  # student
            enrollment = Enrollment.query.filter_by(
                course_id=course_id, student_id=request.user_id
            ).first()
            if not enrollment:
                return jsonify({'error': 'Not enrolled in this course'}), 403
        
        # Get schedules
        schedules = Schedule.query.filter_by(
            course_id=course_id, is_active=True
        ).order_by(Schedule.day_of_week, Schedule.start_time).all()
        
        schedule_list = []
        for schedule in schedules:
            schedule_list.append({
                'id': schedule.id,
                'day_of_week': schedule.day_of_week,
                'day_name': DAYS_OF_WEEK[schedule.day_of_week],
                'start_time': time_to_string(schedule.start_time),
                'end_time': time_to_string(schedule.end_time),
                'location': schedule.location,
                'duration_minutes': int((datetime.combine(datetime.today(), schedule.end_time) - 
                                       datetime.combine(datetime.today(), schedule.start_time)).total_seconds() / 60)
            })
        
        return jsonify({
            'course_info': {
                'id': course.id,
                'course_name': course.course_name,
                'course_code': course.course_code
            },
            'schedules': schedule_list
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch schedule', 'details': str(e)}), 500
