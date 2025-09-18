from flask import Blueprint, request, jsonify
from tapin_backend.models import db, User, Course, Enrollment
from sqlalchemy.exc import IntegrityError
from .utils import auth_required
import random
import logging

classes_bp = Blueprint('classes', __name__)

@classes_bp.post('/')
@auth_required(roles=['lecturer'])
def create_class():
    import logging
    logging.basicConfig(level=logging.DEBUG)
    logging.info(f"[CLASSES] Create class POST attempt for user_id: {getattr(request, 'user_id', 'Unknown')}, role: {getattr(request, 'user_role', 'Unknown')}")
    try:
        data = request.get_json(force=True)
        logging.info(f"[CLASSES] Received data: {data}")
        if not data:
            logging.warning("[CLASSES] No JSON data received")
            return jsonify({'error': 'No JSON data received'}), 400
        
        # Validate required fields
        required = ['programme', 'faculty', 'department', 'course_name', 'course_code', 'level', 'section']
        missing = [field for field in required if field not in data or not data[field]]
        if missing:
            logging.warning(f"[CLASSES] Missing fields: {missing}")
            return jsonify({'error': f'Missing required fields: {", ".join(missing)}'}), 400
        
        import uuid
        
        # Check if class_name exists in database schema by inspecting the table
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        columns = [col['name'] for col in inspector.get_columns('classes')]
        has_class_name_column = 'class_name' in columns
        
        # Create class data without class_name if column doesn't exist
        class_data = {
            'lecturer_id': request.user_id,
            'programme': data['programme'],
            'faculty': data['faculty'],
            'department': data['department'],
            'course_name': data['course_name'],
            'course_code': data['course_code'],
            'level': data['level'],
            'section': data['section'],
            'join_pin': data.get('join_pin') or str(random.randint(100000, 999999)),
            'join_code': str(uuid.uuid4().hex)
        }
        
        # Only include class_name if the column exists
        if has_class_name_column:
            class_data['class_name'] = data.get('class_name', data['course_name'])
        
        cls = Course(**class_data)
        db.session.add(cls)
        db.session.commit()
        logging.info(f"[CLASSES] Class created successfully, id: {cls.id}")
        link = f"{request.host_url.rstrip('/')}/join_class/{cls.join_code}"
        return jsonify({
            'id': cls.id,
            'join_pin': cls.join_pin,
            'join_link': link,
            'message': 'Class created successfully',
            'class_name': data.get('class_name', data['course_name'])
        }), 201
    except IntegrityError as ie:
        db.session.rollback()
        logging.error(f"[CLASSES] Integrity error creating class: {str(ie)}")
        error_msg = "Class could not be created due to a conflict (e.g., duplicate course code or PIN). Please try different values."
        return jsonify({'error': error_msg}), 409
    except Exception as e:
        db.session.rollback()
        logging.error(f"[CLASSES] Error creating class: {str(e)}")
        # More specific error message for database schema issues
        if "class_name" in str(e) and "does not exist" in str(e):
            return jsonify({
                'error': 'Database configuration issue. Please contact support.',
                'details': 'The class_name column is missing from the database.'
            }), 500
        return jsonify({'error': 'Failed to create class', 'details': str(e)}), 500

@classes_bp.get('/')
@auth_required()
def list_classes():
    try:
        print(f"[CLASSES] List classes GET for role: {request.user_role}, user_id: {request.user_id}")
        role = request.user_role
        if role == 'lecturer':
            rows = Course.query.filter_by(lecturer_id=request.user_id).all()
        else:
            rows = db.session.query(Course).join(Enrollment, Enrollment.class_id == Course.id)\
                .filter(Enrollment.student_id == request.user_id).all()
        print(f"[CLASSES] Found {len(rows)} classes")
        
        # Check if class_name column exists in database
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        columns = [col['name'] for col in inspector.get_columns('classes')]
        has_class_name_column = 'class_name' in columns
        
        classes_list = []
        for c in rows:
            class_data = {
                'id': c.id,
                'programme': c.programme,
                'faculty': c.faculty,
                'department': c.department,
                'course_name': c.course_name,
                'course_code': c.course_code,
                'level': c.level,
                'section': c.section,
                'join_pin': c.join_pin if role=='lecturer' else None
            }
            
            # Add class_name if the column exists, otherwise use course_name
            if has_class_name_column and hasattr(c, 'class_name') and c.class_name:
                class_data['class_name'] = c.class_name
            else:
                class_data['class_name'] = c.course_name
                
            classes_list.append(class_data)
            
        return jsonify(classes_list)
    except Exception as e:
        print(f"[CLASSES] Error listing classes: {str(e)}")
        return jsonify({'error': 'Failed to load classes', 'details': str(e)}), 500

@classes_bp.get('/<int:class_id>')
@auth_required(roles=['lecturer'])
def get_class(class_id):
    try:
        cls = Course.query.filter_by(id=class_id, lecturer_id=request.user_id).first()
        if not cls:
            return jsonify({'error': 'Class not found or access denied'}), 404
        return jsonify({
            'id': cls.id,
            'course_name': cls.course_name,
            'programme': cls.programme,
            'faculty': cls.faculty,
            'department': cls.department,
            'course_code': cls.course_code,
            'level': cls.level,
            'section': cls.section,
            'join_pin': cls.join_pin,
            'join_code': cls.join_code
        })
    except Exception as e:
        print(f"[CLASSES] Error getting class {class_id}: {str(e)}")
        return jsonify({'error': 'Failed to load class details', 'details': str(e)}), 500

@classes_bp.post('/join')
@auth_required(roles=['student'])
def join_class():
    data = request.get_json(force=True)
    pin = data.get('join_pin')
    if not pin:
        return jsonify({'error': 'join_pin is required'}), 400
    cls = Course.query.filter_by(join_pin=pin).first()
    if not cls:
        return jsonify({'error': 'Invalid PIN'}), 404
    existing = Enrollment.query.filter_by(class_id=cls.id, student_id=request.user_id).first()
    if existing:
        return jsonify({'message': 'Already enrolled', 'class_id': cls.id})
    enr = Enrollment(class_id=cls.id, student_id=request.user_id)
    db.session.add(enr)
    db.session.commit()
    return jsonify({'message': 'Joined class', 'class_id': cls.id})

@classes_bp.get('/<int:class_id>/students')
@auth_required(roles=['lecturer'])
def list_students(class_id):
    rows = db.session.query(User).join(Enrollment).filter(
        Enrollment.class_id == class_id,
        User.role == 'student'
    ).all()
    return jsonify([{
        'id': u.id,
        'fullname': u.fullname,
        'email': u.email,
        'student_id': u.student_id or 'N/A'
    } for u in rows])

@classes_bp.delete('/<int:class_id>')
@auth_required(roles=['lecturer'])
def delete_class(class_id):
    cls = Course.query.filter_by(id=class_id, lecturer_id=request.user_id).first_or_404()
    db.session.delete(cls)
    db.session.commit()
    return jsonify({'message': 'Class deleted successfully'})

@classes_bp.delete('/<int:class_id>/enrollment')
@auth_required(roles=['student'])
def leave_class(class_id):
    enrollment = Enrollment.query.filter_by(class_id=class_id, student_id=request.user_id).first()
    if not enrollment:
        return jsonify({'error': 'Not enrolled in this class'}), 404
    db.session.delete(enrollment)
    db.session.commit()
    return jsonify({'message': 'Successfully left the class'})

@classes_bp.post('/<int:class_id>/api/autocomplete')
@auth_required(roles=['lecturer'])
def autocomplete_students(class_id):
    try:
        data = request.get_json(force=True)
        query = data.get('q', '') if data else ''
        logging.info(f"[CLASSES] Autocomplete called for class {class_id} with query '{query}' by user {request.user_id}")
        
        course = Course.query.get_or_404(class_id)
        if course.lecturer_id != request.user_id:
            return jsonify({'error': 'Forbidden'}), 403
        
        students = db.session.query(User).join(Enrollment).filter(
            Enrollment.class_id == class_id,
            db.or_(
                User.fullname.ilike(f'%{query}%'),
                User.email.ilike(f'%{query}%')
            )
        ).limit(10).all()
        
        result = [{'id': u.id, 'name': u.fullname, 'email': u.email} for u in students]
        logging.info(f"[CLASSES] Autocomplete returned {len(result)} students")
        return jsonify(result)
        
    except Exception as e:
        logging.error(f"[CLASSES] Autocomplete error: {str(e)}")
        return jsonify({'error': 'Failed to fetch students', 'details': str(e)}), 500

import uuid

@classes_bp.post('/<int:class_id>/generate_link')
@auth_required(roles=['lecturer'])
def generate_join_link(class_id):
    cls = Course.query.filter_by(id=class_id, lecturer_id=request.user_id).first_or_404()
    if not cls.join_code:
        cls.join_code = str(uuid.uuid4().hex)
        db.session.commit()
    link = f"{request.host_url.rstrip('/')}/join_class/{cls.join_code}"
    return jsonify({'link': link, 'code': cls.join_code})
