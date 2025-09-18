# routes_profile.py
import os
from flask import Blueprint, request, jsonify, current_app, send_from_directory
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
from .models import db, User

profile_bp = Blueprint("profile", __name__, url_prefix="/api/profile")

# Directory to store avatars
AVATAR_DIR = os.path.join(os.getcwd(), "static", "uploads", "avatars")
os.makedirs(AVATAR_DIR, exist_ok=True)
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# -----------------------
# Get profile
# -----------------------
print("Adding route: /me to profile_bp")
@profile_bp.route("/me", methods=["GET"])
@jwt_required()
def get_profile():
    import logging
    logging.basicConfig(level=logging.DEBUG)
    try:
        user_id_str = get_jwt_identity()
        user_id = int(user_id_str)
        logging.info(f"[PROFILE/GET] JWT identity: {type(user_id_str)} {user_id_str} -> converted to int {user_id}")
        logging.info(f"[PROFILE/GET] Querying DB for user_id {user_id}")
        user = User.query.get(user_id)
        if not user:
            logging.error(f"[PROFILE/GET] User not found for id {user_id}. Available users: {[u.id for u in User.query.all()]}")
            return jsonify({"error": "User not found"}), 404
        avatar_url = user.avatar_url or ""
        fullname = user.fullname or "Unknown"
        logging.info(f"[PROFILE/GET] User {user_id} profile: fullname={fullname}, avatar_url={avatar_url}")
        return jsonify({
            "id": user.id,
            "fullname": fullname,
            "email": user.email,
            "phone": user.phone,
            "role": user.role,
            "avatar_url": avatar_url
        })
    except Exception as e:
        logging.error(f"[PROFILE/GET] Error for user_id {user_id or 'unknown'}: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to fetch profile", "details": str(e)}), 500

# -----------------------
# Upload avatar
# -----------------------
print("Adding route: /avatar POST to profile_bp")
@profile_bp.route("/avatar", methods=["POST"])
@jwt_required()
def upload_avatar():
    import logging
    logging.basicConfig(level=logging.DEBUG)
    user_id = get_jwt_identity()
    user = User.query.get_or_404(user_id)

    if "avatar" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["avatar"]
    if file.filename == "" or not allowed_file(file.filename):
        return jsonify({"error": "Invalid file type"}), 400

    filename = secure_filename(f"user_{user_id}_{file.filename}")
    filepath = os.path.join(AVATAR_DIR, filename)
    file.save(filepath)

    # Delete old avatar if exists
    if user.avatar_url:
        old_path = os.path.join(AVATAR_DIR, os.path.basename(user.avatar_url))
        if os.path.exists(old_path):
            os.remove(old_path)

    user.avatar_url = f"/static/uploads/avatars/{filename}"
    db.session.commit()
    logging.info(f"[PROFILE/AVATAR] Uploaded avatar for user {user_id}: {user.avatar_url}")

    return jsonify({"success": True, "avatar_url": user.avatar_url})

# -----------------------
# Remove avatar
# -----------------------
print("Adding route: /avatar DELETE to profile_bp")
@profile_bp.route("/avatar", methods=["DELETE"])
@jwt_required()
def remove_avatar():
    import logging
    logging.basicConfig(level=logging.DEBUG)
    user_id = get_jwt_identity()
    user = User.query.get_or_404(user_id)

    if user.avatar_url:
        path = os.path.join(AVATAR_DIR, os.path.basename(user.avatar_url))
        if os.path.exists(path):
            os.remove(path)
        user.avatar_url = None
        db.session.commit()
        logging.info(f"[PROFILE/AVATAR] Removed avatar for user {user_id}")

    return jsonify({"success": True})


# -----------------------
# Update profile
# -----------------------
print("Adding route: /update-profile PUT to profile_bp")
@profile_bp.route("/update-profile", methods=["PUT"])
@jwt_required()
def update_profile():
    import logging
    logging.basicConfig(level=logging.DEBUG)
    user_id = get_jwt_identity()
    user = User.query.get_or_404(user_id)
    data = request.get_json()

    try:
        # Update basic info
        if "fullname" in data:
            user.fullname = data["fullname"]
            logging.info(f"[PROFILE/UPDATE] Updated fullname for user {user_id}")
        if "email" in data:
            user.email = data["email"]
        if "phone" in data:
            user.phone = data["phone"]

        # Update password if provided
        if "password" in data and data["password"]:
            from .utils import hash_password
            user.password_hash = hash_password(data["password"])
            logging.info(f"[PROFILE/UPDATE] Updated password for user {user_id}")
    except Exception as e:
        logging.error(f"[PROFILE/UPDATE] Error for user {user_id}: {str(e)}")
        return jsonify({"error": "Update failed"}), 500

    db.session.commit()

    return jsonify({"success": True, "message": "Profile updated successfully"})
