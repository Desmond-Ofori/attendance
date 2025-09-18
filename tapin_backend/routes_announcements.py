from flask import Blueprint, request, jsonify
from .models import db, Announcement, Enrollment
from .utils import auth_required

announcements_bp = Blueprint('announcements', __name__)

@announcements_bp.post('')
@auth_required(roles=['lecturer'])
def create_announcement():
    data = request.get_json(force=True)
    ann = Announcement(
        class_id=data.get('class_id'),
        title=data['title'],
        message=data['message']
    )
    db.session.add(ann)
    db.session.commit()
    return jsonify({'id': ann.id}), 201

@announcements_bp.get('')
@auth_required()
def list_my_announcements():
    # Global announcements + class announcements for classes the user belongs to
    if request.user_role == 'student':
        class_ids = [r.class_id for r in Enrollment.query.filter_by(student_id=request.user_id).all()]
    else:
        class_ids = []
    rows = Announcement.query.filter(
        (Announcement.class_id == None) | (Announcement.class_id.in_(class_ids))
    ).order_by(Announcement.created_at.desc()).limit(50).all()

    return jsonify([
        {
            'id': a.id,
            'class_id': a.class_id,
            'title': a.title,
            'message': a.message,
            'date': a.created_at.date().isoformat()
        } for a in rows
    ])
