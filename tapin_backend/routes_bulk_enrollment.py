from flask import Blueprint, request, jsonify
from .models import db, Course, Enrollment, User
from .utils import auth_required
import csv
import io
from werkzeug.security import generate_password_hash
import re

bulk_enrollment_bp = Blueprint('bulk_enrollment', __name__)

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_student_id(student_id):
    """Validate student ID format (basic validation)"""
    return len(student_id.strip()) > 0

@bulk_enrollment_bp.post('/courses/<int:class_id>/bulk-enroll')
@auth_required(roles=['lecturer'])
def bulk_enroll_students(class_id):
    """Bulk enroll students from CSV data"""
    try:
        # Verify lecturer owns this course
        cls = Course.query.get_or_404(class_id)
        if cls.lecturer_id != request.user_id:
            return jsonify({'error': 'Forbidden'}), 403
        
        # Get CSV data from request
        data = request.get_json(force=True)
        csv_data = data.get('csv_data')
        create_accounts = data.get('create_accounts', False)  # Whether to create user accounts
        
        if not csv_data:
            return jsonify({'error': 'CSV data is required'}), 400
        
        # Parse CSV data
        csv_reader = csv.DictReader(io.StringIO(csv_data))
        
        # Expected columns: name, email, student_id
        required_columns = ['name', 'email', 'student_id']
        
        # Validate CSV headers
        if not all(col in csv_reader.fieldnames for col in required_columns):
            return jsonify({
                'error': 'CSV must contain columns: name, email, student_id',
                'found_columns': csv_reader.fieldnames
            }), 400
        
        results = {
            'total_processed': 0,
            'successful_enrollments': 0,
            'created_accounts': 0,
            'errors': [],
            'enrolled_students': []
        }
        
        for row_num, row in enumerate(csv_reader, start=2):  # Start at 2 because row 1 is headers
            results['total_processed'] += 1
            
            # Extract and validate data
            name = row['name'].strip()
            email = row['email'].strip().lower()
            student_id = row['student_id'].strip()
            
            # Validation
            errors = []
            if not name:
                errors.append('Name is required')
            if not email or not validate_email(email):
                errors.append('Valid email is required')
            if not student_id or not validate_student_id(student_id):
                errors.append('Valid student ID is required')
            
            if errors:
                results['errors'].append({
                    'row': row_num,
                    'data': row,
                    'errors': errors
                })
                continue
            
            try:
                # Check if user exists
                user = User.query.filter_by(email=email).first()
                
                if not user and create_accounts:
                    # Create new user account
                    default_password = f"student{student_id}"  # You might want to generate random passwords
                    user = User(
                        fullname=name,
                        email=email,
                        student_id=student_id,
                        role='student',
                        password_hash=generate_password_hash(default_password)
                    )
                    db.session.add(user)
                    db.session.flush()  # Get the user ID
                    results['created_accounts'] += 1
                    
                elif not user:
                    results['errors'].append({
                        'row': row_num,
                        'data': row,
                        'errors': ['User account does not exist. Enable "create_accounts" to create new accounts.']
                    })
                    continue
                
                # Check if already enrolled
                existing_enrollment = Enrollment.query.filter_by(
                    class_id=class_id, student_id=user.id
                ).first()
                
                if existing_enrollment:
                    results['errors'].append({
                        'row': row_num,
                        'data': row,
                        'errors': ['Student is already enrolled in this course']
                    })
                    continue
                
                # Create enrollment
                enrollment = Enrollment(
                    class_id=class_id,
                    student_id=user.id
                )
                db.session.add(enrollment)
                
                results['successful_enrollments'] += 1
                results['enrolled_students'].append({
                    'name': name,
                    'email': email,
                    'student_id': student_id,
                    'user_id': user.id
                })
                
            except Exception as e:
                results['errors'].append({
                    'row': row_num,
                    'data': row,
                    'errors': [f'Database error: {str(e)}']
                })
        
        # Commit all changes
        db.session.commit()
        
        return jsonify({
            'message': f'Bulk enrollment completed. {results["successful_enrollments"]} students enrolled.',
            'results': results
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to process bulk enrollment', 'details': str(e)}), 500

@bulk_enrollment_bp.get('/courses/<int:class_id>/enrollment-template')
@auth_required(roles=['lecturer'])
def get_enrollment_template(class_id):
    """Get CSV template for bulk enrollment"""
    try:
        # Verify lecturer owns this course
        cls = Course.query.get_or_404(class_id)
        if cls.lecturer_id != request.user_id:
            return jsonify({'error': 'Forbidden'}), 403
        
        # Create CSV template
        template_data = [
            ['name', 'email', 'student_id'],
            ['John Doe', 'john.doe@university.edu', 'STU001'],
            ['Jane Smith', 'jane.smith@university.edu', 'STU002'],
            ['Bob Johnson', 'bob.johnson@university.edu', 'STU003']
        ]
        
        # Convert to CSV string
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerows(template_data)
        csv_content = output.getvalue()
        
        return jsonify({
            'template_csv': csv_content,
            'instructions': [
                'Fill in the CSV with student information',
                'Required columns: name, email, student_id',
                'Email addresses must be unique',
                'Student IDs should be unique within your institution',
                'Remove the example rows before uploading'
            ]
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to generate template', 'details': str(e)}), 500

@bulk_enrollment_bp.post('/courses/<int:class_id>/validate-csv')
@auth_required(roles=['lecturer'])
def validate_enrollment_csv(class_id):
    """Validate CSV data before actual enrollment"""
    try:
        # Verify lecturer owns this course
        cls = Course.query.get_or_404(class_id)
        if cls.lecturer_id != request.user_id:
            return jsonify({'error': 'Forbidden'}), 403
        
        data = request.get_json(force=True)
        csv_data = data.get('csv_data')
        
        if not csv_data:
            return jsonify({'error': 'CSV data is required'}), 400
        
        # Parse CSV data
        csv_reader = csv.DictReader(io.StringIO(csv_data))
        
        # Validate headers
        required_columns = ['name', 'email', 'student_id']
        if not all(col in csv_reader.fieldnames for col in required_columns):
            return jsonify({
                'valid': False,
                'error': 'CSV must contain columns: name, email, student_id',
                'found_columns': csv_reader.fieldnames
            }), 400
        
        validation_results = {
            'valid': True,
            'total_rows': 0,
            'valid_rows': 0,
            'errors': [],
            'warnings': [],
            'preview': []
        }
        
        seen_emails = set()
        seen_student_ids = set()
        
        for row_num, row in enumerate(csv_reader, start=2):
            validation_results['total_rows'] += 1
            
            name = row['name'].strip()
            email = row['email'].strip().lower()
            student_id = row['student_id'].strip()
            
            row_errors = []
            row_warnings = []
            
            # Validate required fields
            if not name:
                row_errors.append('Name is required')
            if not email:
                row_errors.append('Email is required')
            elif not validate_email(email):
                row_errors.append('Invalid email format')
            if not student_id:
                row_errors.append('Student ID is required')
            
            # Check for duplicates within CSV
            if email in seen_emails:
                row_errors.append('Duplicate email in CSV')
            else:
                seen_emails.add(email)
            
            if student_id in seen_student_ids:
                row_errors.append('Duplicate student ID in CSV')
            else:
                seen_student_ids.add(student_id)
            
            # Check if user exists in database
            if email and validate_email(email):
                existing_user = User.query.filter_by(email=email).first()
                if existing_user:
                    # Check if already enrolled
                    existing_enrollment = Enrollment.query.filter_by(
                        class_id=class_id, student_id=existing_user.id
                    ).first()
                    if existing_enrollment:
                        row_warnings.append('Student is already enrolled in this course')
                else:
                    row_warnings.append('User account does not exist - will need to be created')
            
            if row_errors:
                validation_results['errors'].append({
                    'row': row_num,
                    'data': row,
                    'errors': row_errors
                })
                validation_results['valid'] = False
            else:
                validation_results['valid_rows'] += 1
            
            if row_warnings:
                validation_results['warnings'].append({
                    'row': row_num,
                    'data': row,
                    'warnings': row_warnings
                })
            
            # Add to preview (first 5 rows)
            if len(validation_results['preview']) < 5:
                validation_results['preview'].append({
                    'row': row_num,
                    'name': name,
                    'email': email,
                    'student_id': student_id,
                    'has_errors': len(row_errors) > 0,
                    'has_warnings': len(row_warnings) > 0
                })
        
        return jsonify(validation_results), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to validate CSV', 'details': str(e)}), 500

@bulk_enrollment_bp.get('/courses/<int:class_id>/enrolled-students')
@auth_required(roles=['lecturer'])
def get_enrolled_students(class_id):
    """Get list of enrolled students with export option"""
    try:
        # Verify lecturer owns this course
        cls = Course.query.get_or_404(class_id)
        if cls.lecturer_id != request.user_id:
            return jsonify({'error': 'Forbidden'}), 403
        
        # Get enrolled students
        students = db.session.query(User).join(
            Enrollment, Enrollment.student_id == User.id
        ).filter(Enrollment.class_id == class_id).order_by(User.fullname).all()
        
        student_list = []
        for student in students:
            enrollment = Enrollment.query.filter_by(
                class_id=class_id, student_id=student.id
            ).first()
            
            student_list.append({
                'id': student.id,
                'name': student.fullname,
                'email': student.email,
                'student_id': student.student_id,
                'enrolled_at': enrollment.joined_at.isoformat() + 'Z' if enrollment else None
            })
        
        # Check if CSV export is requested
        export_format = request.args.get('format')
        if export_format == 'csv':
            # Generate CSV
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write headers
            writer.writerow(['Name', 'Email', 'Student ID', 'Enrolled At'])
            
            # Write data
            for student in student_list:
                writer.writerow([
                    student['name'],
                    student['email'],
                    student['student_id'],
                    student['enrolled_at']
                ])
            
            csv_content = output.getvalue()
            
            return jsonify({
                'csv_data': csv_content,
                'filename': f"{cls.course_code}_enrolled_students.csv"
            }), 200
        
        return jsonify({
            'course_info': {
                'id': cls.id,
                'course_name': cls.course_name,
                'course_code': cls.course_code
            },
            'students': student_list,
            'total_enrolled': len(student_list)
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch enrolled students', 'details': str(e)}), 500

@bulk_enrollment_bp.delete('/courses/<int:class_id>/students/<int:student_id>')
@auth_required(roles=['lecturer'])
def remove_student_from_course(class_id, student_id):
    """Remove a student from the course"""
    try:
        # Verify lecturer owns this course
        cls = Course.query.get_or_404(class_id)
        if cls.lecturer_id != request.user_id:
            return jsonify({'error': 'Forbidden'}), 403
        
        # Find enrollment
        enrollment = Enrollment.query.filter_by(
            class_id=class_id, student_id=student_id
        ).first_or_404()
        
        # Get student info for response
        student = User.query.get(student_id)
        
        # Remove enrollment
        db.session.delete(enrollment)
        db.session.commit()
        
        return jsonify({
            'message': f'Student {student.fullname} removed from course',
            'student': {
                'id': student.id,
                'name': student.fullname,
                'email': student.email,
                'student_id': student.student_id
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to remove student', 'details': str(e)}), 500
