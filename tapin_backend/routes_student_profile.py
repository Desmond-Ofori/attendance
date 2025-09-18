import os
import logging
from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename
from .models import db, User
from .utils import auth_required, hash_password

student_profile_bp = Blueprint("student_profile", __name__)
logging.basicConfig(level=logging.INFO)

# Avatar storage
AVATAR_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", "uploads", "avatars")
os.makedirs(AVATAR_DIR, exist_ok=True)
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# -----------------------
# Get student profile
# -----------------------
@student_profile_bp.route("/me", methods=["GET"])
@auth_required()
def get_profile():
    try:
        user = User.query.get_or_404(request.user_id)
        avatar_url = f"/static/uploads/avatars/{user.avatar_url}" if user.avatar_url else None
        return jsonify({
            "id": user.id,
            "fullname": user.fullname,
            "email": user.email,
            "phone": user.phone,
            "role": user.role,
            "avatar": avatar_url
        })
    except Exception as e:
        logging.error(f"Error in get_profile: {str(e)}")
        return jsonify({"error": "Failed to get profile"}), 500

# -----------------------
# Upload avatar
# -----------------------
@student_profile_bp.route("/avatar", methods=["POST"])
@auth_required(roles=['student'])
def upload_avatar():
    try:
        user = User.query.get_or_404(request.user_id)

        if "avatar" not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files["avatar"]
        if file.filename == "" or not allowed_file(file.filename):
            return jsonify({"error": "Invalid file type"}), 400

        filename = secure_filename(f"student_{user.id}_{file.filename}")
        filepath = os.path.join(AVATAR_DIR, filename)
        file.save(filepath)

        # Delete old avatar
        if user.avatar_url and user.avatar_url != filename:
            old_path = os.path.join(AVATAR_DIR, user.avatar_url)
            if os.path.exists(old_path):
                os.remove(old_path)

        user.avatar_url = filename
        db.session.commit()

        logging.info(f"Avatar uploaded for student {request.user_id}")
        return jsonify({"success": True, "avatar": f"/static/uploads/avatars/{filename}"})
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error in upload_avatar: {str(e)}")
        return jsonify({"error": "Failed to upload avatar"}), 500

# -----------------------
# Remove avatar
# -----------------------
@student_profile_bp.route("/avatar", methods=["DELETE"])
@auth_required(roles=['student'])
def remove_avatar():
    try:
        user = User.query.get_or_404(request.user_id)

        if user.avatar_url:
            path = os.path.join(AVATAR_DIR, user.avatar_url)
            if os.path.exists(path):
                os.remove(path)
            user.avatar_url = None
            db.session.commit()

        logging.info(f"Avatar removed for student {request.user_id}")
        return jsonify({"success": True})
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error in remove_avatar: {str(e)}")
        return jsonify({"error": "Failed to remove avatar"}), 500

# -----------------------
# Update student settings
# -----------------------
@student_profile_bp.route("/settings", methods=["PATCH"])
@auth_required(roles=['student'])
def update_settings():
    user = User.query.get_or_404(request.user_id)
    data = request.get_json()

    try:
        # Update basic info
        if "fullname" in data:
            user.fullname = data["fullname"]
            logging.info(f"[STUDENT/UPDATE] Updated fullname for user {request.user_id}")
        if "phone" in data:
            user.phone = data["phone"]

        # Update password if provided
        if "password" in data and data["password"]:
            user.password_hash = hash_password(data["password"])
            logging.info(f"[STUDENT/UPDATE] Updated password for user {request.user_id}")

        db.session.commit()
        return jsonify({"success": True, "message": "Settings updated successfully"})
    except Exception as e:
        db.session.rollback()
        logging.error(f"[STUDENT/UPDATE] Error for user {request.user_id}: {str(e)}")
        return jsonify({"error": "Update failed"}), 500
