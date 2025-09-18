from flask import Blueprint, request, jsonify, current_app
from .models import db, Course, AttendanceSession, Enrollment, User, Notification
from .utils import auth_required
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from threading import Thread

notifications_bp = Blueprint('notifications', __name__)

def send_email_async(app, to_email, subject, body_html, body_text=None):
    """Send email asynchronously"""
    with app.app_context():
        try:
            # Email configuration
            smtp_server = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
            smtp_port = int(os.getenv('MAIL_PORT', 587))
            smtp_username = os.getenv('MAIL_USERNAME')
            smtp_password = os.getenv('MAIL_PASSWORD')
            from_email = os.getenv('MAIL_DEFAULT_SENDER', 'TapIn <no-reply@tapin.edu>')
            
            if not smtp_username or not smtp_password:
                current_app.logger.error("Email credentials not configured")
                return False
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = from_email
            msg['To'] = to_email
            
            # Add text and HTML parts
            if body_text:
                text_part = MIMEText(body_text, 'plain')
                msg.attach(text_part)
            
            html_part = MIMEText(body_html, 'html')
            msg.attach(html_part)
            
            # Send email
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)
            server.quit()
            
            current_app.logger.info(f"Email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            current_app.logger.error(f"Failed to send email to {to_email}: {str(e)}")
            return False

def send_attendance_session_notification(course_id, session_id, session_type='opened'):
    """Send notification to all enrolled students about attendance session"""
    try:
        # Get course and session info
        course = Course.query.get(course_id)
        session = AttendanceSession.query.get(session_id)
        
        if not course or not session:
            return False
        
        # Get all enrolled students
        students = db.session.query(User).join(
            Enrollment, Enrollment.student_id == User.id
        ).filter(Enrollment.course_id == course_id).all()
        
        # Prepare email content
        if session_type == 'opened':
            subject = f"Attendance Session Started - {course.course_name}"
            
            # Calculate time remaining
            time_remaining = session.expires_at - datetime.utcnow()
            minutes_remaining = int(time_remaining.total_seconds() / 60)
            
            body_html = f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;">
                        📚 Attendance Session Started
                    </h2>
                    
                    <div style="background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
                        <h3 style="margin-top: 0; color: #2c3e50;">Course Information</h3>
                        <p><strong>Course:</strong> {course.course_name} ({course.course_code})</p>
                        <p><strong>Programme:</strong> {course.programme}</p>
                        <p><strong>Department:</strong> {course.department}</p>
                    </div>
                    
                    <div style="background-color: #e8f5e8; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #27ae60;">
                        <h3 style="margin-top: 0; color: #27ae60;">⏰ Action Required</h3>
                        <p><strong>Attendance Method:</strong> {session.method.upper()}</p>
                        <p><strong>Time Remaining:</strong> {minutes_remaining} minutes</p>
                        <p><strong>Expires At:</strong> {session.expires_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="#" style="background-color: #3498db; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
                            Mark Attendance Now
                        </a>
                    </div>
                    
                    <div style="background-color: #fff3cd; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #ffc107;">
                        <p style="margin: 0;"><strong>⚠️ Important:</strong> Please mark your attendance before the session expires to avoid being marked absent.</p>
                    </div>
                    
                    <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
                    <p style="font-size: 12px; color: #666; text-align: center;">
                        This is an automated message from TapIn Attendance System.<br>
                        Please do not reply to this email.
                    </p>
                </div>
            </body>
            </html>
            """
            
            body_text = f"""
            Attendance Session Started - {course.course_name}
            
            Course: {course.course_name} ({course.course_code})
            Programme: {course.programme}
            Department: {course.department}
            
            Attendance Method: {session.method.upper()}
            Time Remaining: {minutes_remaining} minutes
            Expires At: {session.expires_at.strftime('%Y-%m-%d %H:%M:%S')}
            
            Please mark your attendance before the session expires.
            
            ---
            TapIn Attendance System
            """
        
        elif session_type == 'reminder':
            subject = f"Attendance Reminder - {course.course_name}"
            
            time_remaining = session.expires_at - datetime.utcnow()
            minutes_remaining = int(time_remaining.total_seconds() / 60)
            
            body_html = f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #e74c3c; border-bottom: 2px solid #e74c3c; padding-bottom: 10px;">
                        ⏰ Attendance Reminder
                    </h2>
                    
                    <div style="background-color: #fdf2f2; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #e74c3c;">
                        <h3 style="margin-top: 0; color: #e74c3c;">Urgent: Only {minutes_remaining} minutes left!</h3>
                        <p>The attendance session for <strong>{course.course_name}</strong> is about to expire.</p>
                        <p><strong>Expires At:</strong> {session.expires_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="#" style="background-color: #e74c3c; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
                            Mark Attendance Now
                        </a>
                    </div>
                    
                    <p style="font-size: 12px; color: #666; text-align: center;">
                        This is an automated reminder from TapIn Attendance System.
                    </p>
                </div>
            </body>
            </html>
            """
            
            body_text = f"""
            Attendance Reminder - {course.course_name}
            
            Urgent: Only {minutes_remaining} minutes left!
            
            The attendance session for {course.course_name} is about to expire.
            Expires At: {session.expires_at.strftime('%Y-%m-%d %H:%M:%S')}
            
            Please mark your attendance immediately.
            
            ---
            TapIn Attendance System
            """
        
        # Send emails to all students
        app = current_app._get_current_object()
        for student in students:
            if student.email:
                # Create in-app notification
                notification = Notification(
                    user_id=student.id,
                    text=f"Attendance session {'started' if session_type == 'opened' else 'reminder'} for {course.course_name}",
                    read=False
                )
                db.session.add(notification)
                
                # Send email asynchronously
                thread = Thread(
                    target=send_email_async,
                    args=(app, student.email, subject, body_html, body_text)
                )
                thread.start()
        
        db.session.commit()
        return True
        
    except Exception as e:
        current_app.logger.error(f"Failed to send attendance notifications: {str(e)}")
        return False

@notifications_bp.post('/send-attendance-notification')
@auth_required(roles=['lecturer'])
def send_attendance_notification():
    """Manually send attendance session notification"""
    try:
        data = request.get_json(force=True)
        course_id = data.get('course_id')
        session_id = data.get('session_id')
        notification_type = data.get('type', 'opened')  # 'opened' or 'reminder'
        
        if not course_id or not session_id:
            return jsonify({'error': 'course_id and session_id are required'}), 400
        
        # Verify lecturer owns this course
        course = Course.query.get_or_404(course_id)
        if course.lecturer_id != request.user_id:
            return jsonify({'error': 'Forbidden'}), 403
        
        # Send notifications
        success = send_attendance_session_notification(course_id, session_id, notification_type)
        
        if success:
            return jsonify({'message': 'Notifications sent successfully'}), 200
        else:
            return jsonify({'error': 'Failed to send notifications'}), 500
            
    except Exception as e:
        return jsonify({'error': 'Failed to send notifications', 'details': str(e)}), 500

@notifications_bp.get('/user/notifications')
@auth_required()
def get_user_notifications():
    """Get notifications for the current user"""
    try:
        # Get query parameters
        limit = min(int(request.args.get('limit', 20)), 100)
        offset = int(request.args.get('offset', 0))
        unread_only = request.args.get('unread_only', 'false').lower() == 'true'
        
        # Build query
        query = Notification.query.filter_by(user_id=request.user_id)
        
        if unread_only:
            query = query.filter_by(read=False)
        
        notifications = query.order_by(
            Notification.timestamp.desc()
        ).offset(offset).limit(limit).all()
        
        # Get unread count
        unread_count = Notification.query.filter_by(
            user_id=request.user_id, read=False
        ).count()
        
        return jsonify({
            'notifications': [
                {
                    'id': n.id,
                    'text': n.text,
                    'read': n.read,
                    'timestamp': n.timestamp.isoformat() + 'Z'
                }
                for n in notifications
            ],
            'unread_count': unread_count,
            'total': len(notifications)
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch notifications', 'details': str(e)}), 500

@notifications_bp.patch('/user/notifications/<int:notification_id>/read')
@auth_required()
def mark_notification_read(notification_id):
    """Mark a notification as read"""
    try:
        notification = Notification.query.filter_by(
            id=notification_id, user_id=request.user_id
        ).first_or_404()
        
        notification.read = True
        db.session.commit()
        
        return jsonify({'message': 'Notification marked as read'}), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to mark notification as read', 'details': str(e)}), 500

@notifications_bp.patch('/user/notifications/mark-all-read')
@auth_required()
def mark_all_notifications_read():
    """Mark all notifications as read for the current user"""
    try:
        Notification.query.filter_by(
            user_id=request.user_id, read=False
        ).update({'read': True})
        
        db.session.commit()
        
        return jsonify({'message': 'All notifications marked as read'}), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to mark notifications as read', 'details': str(e)}), 500

@notifications_bp.delete('/user/notifications/<int:notification_id>')
@auth_required()
def delete_notification(notification_id):
    """Delete a notification"""
    try:
        notification = Notification.query.filter_by(
            id=notification_id, user_id=request.user_id
        ).first_or_404()
        
        db.session.delete(notification)
        db.session.commit()
        
        return jsonify({'message': 'Notification deleted'}), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to delete notification', 'details': str(e)}), 500
