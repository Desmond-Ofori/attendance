# TapIn Attendance System - Consolidated Edition

## 📋 Overview

This is the **consolidated version** of the TapIn Attendance System where both frontend and backend functionality have been merged into a single Flask application. This simplifies deployment and maintenance while maintaining all the original features.

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip package manager

### Installation & Setup

1. **Navigate to the consolidated backend folder:**
   ```bash
   cd tapin_backend
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Initialize database:**
   ```bash
   python -c "from app import app; from models import db; app.app_context().push(); db.create_all()"
   ```

5. **Start the application:**
   ```bash
   python start_app.py
   ```

6. **Access the application:**
   - **Frontend:** http://localhost:8000/
   - **API:** http://localhost:8000/api/
   - **Health Check:** http://localhost:8000/api/health

## 🏗️ Architecture

### Consolidated Structure
```
tapin_backend/
├── app.py                 # Main Flask application (frontend + backend)
├── models.py              # Database models
├── auth.py                # Authentication utilities
├── routes/                # API route modules
│   ├── routes_analytics.py
│   ├── routes_attendance.py
│   ├── routes_classes.py
│   ├── routes_notifications.py
│   ├── routes_qr_attendance.py
│   ├── routes_reports.py
│   ├── routes_schedule.py
│   └── ...
├── static/                # Static files (CSS, JS, images)
├── templates/             # HTML templates
├── requirements.txt       # Python dependencies
├── .env                   # Environment configuration
└── start_app.py          # Application startup script
```

### Key Features
- ✅ **Unified Application:** Single Flask app serving both frontend and API
- ✅ **Session-based Auth:** Traditional Flask sessions for user authentication
- ✅ **JWT API Bridge:** JWT tokens for API authentication
- ✅ **Real-time Features:** Socket.IO for live attendance updates
- ✅ **QR Code System:** Mobile-responsive QR attendance
- ✅ **Email Notifications:** Automated attendance notifications
- ✅ **Analytics Dashboard:** Comprehensive attendance analytics
- ✅ **Bulk Operations:** CSV import/export functionality
- ✅ **Schedule Management:** Class scheduling system

## 🔐 Authentication Flow

### User Registration
1. Visit `/account` to select user type
2. Choose "Lecturer" or "Student"
3. Fill registration form
4. Auto-login and redirect to dashboard

### Login Process
**Lecturer Login:**
- URL: `/lecturer_login`
- Method: POST with email/password
- Success: Redirect to `/lecturer/dashboard`

**Student Login:**
- URL: `/student_login`
- Method: POST with Student ID/Email/Password
- Success: Redirect to `/student/dashboard`

### Session Management
- Sessions maintained across page loads
- Automatic logout on invalid sessions
- Role-based access control
- Secure session handling

## 📡 API Endpoints

### Core Endpoints
- `GET /api/health` - Health check
- `POST /register` - User registration
- `POST /login` - Lecturer login
- `POST /login_student` - Student login
- `GET /logout` - Session logout

### Attendance Management
- `GET /api/classes/<class_id>/sessions/active` - Get active session
- `POST /api/attendance/mark` - Mark attendance
- `GET /api/classes/<class_id>/attendance/history` - Attendance history

### Analytics & Reports
- `GET /api/analytics/dashboard/summary` - Dashboard analytics
- `GET /api/classes/<class_id>/analytics` - Class analytics
- `GET /api/reports/attendance` - Attendance reports
- `GET /api/student/dashboard` - Student dashboard

### QR Attendance
- `POST /api/qr/classes/<class_id>/qr-session` - Create QR session
- `POST /api/qr/attendance/scan` - Scan QR code
- `GET /api/qr/classes/<class_id>/qr-session/active` - Get active QR session

## 🎯 User Roles & Permissions

### Lecturer Features
- Create and manage classes
- Start attendance sessions
- View attendance analytics
- Generate reports
- Send notifications
- Manage schedules

### Student Features
- Join classes via PIN
- Mark attendance
- View personal attendance history
- Access attendance analytics
- Receive notifications

## 🔧 Configuration

### Environment Variables
```bash
# Flask Configuration
SECRET_KEY=your-secret-key-here
FLASK_ENV=production
DEBUG=False

# Database
DATABASE_URL=sqlite:///tapin.db

# Email Configuration
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password

# CORS
CORS_ORIGINS=*
```

### Production Deployment
1. Set environment variables in Render dashboard
2. Deploy using the provided `render.yaml` blueprint
3. Database will be automatically created on first run
4. Static files served automatically

## 🚀 Deployment

### Render Deployment
1. Connect GitHub repository to Render
2. Use the provided `render.yaml` configuration
3. Set environment variables in Render dashboard
4. Deploy and access your application

### Local Development
```bash
# Development mode
export FLASK_ENV=development
python start_app.py

# Production mode
export FLASK_ENV=production
python start_app.py
```

## 📊 Features Overview

### ✅ Completed Features
- [x] User registration and authentication
- [x] Role-based dashboards (Lecturer/Student)
- [x] Real-time attendance tracking
- [x] QR code attendance system
- [x] Email notifications
- [x] Attendance analytics and reports
- [x] Bulk student enrollment
- [x] Class schedule management
- [x] Data export functionality
- [x] Mobile-responsive design

### 🎯 Key Benefits
- **Simplified Architecture:** Single application to manage
- **Easy Deployment:** One-click deployment to Render
- **Unified Codebase:** No frontend/backend separation complexity
- **Session Security:** Traditional Flask session management
- **API Compatibility:** JWT bridge for modern API access
- **Production Ready:** Optimized for cloud deployment

## 🐛 Troubleshooting

### Common Issues
1. **Database Connection:** Check DATABASE_URL environment variable
2. **Email Notifications:** Verify MAIL_* environment variables
3. **Static Files:** Ensure correct file paths in templates
4. **Session Issues:** Check SECRET_KEY configuration

### Debug Mode
```bash
export FLASK_ENV=development
export DEBUG=True
python start_app.py
```

## 📞 Support

For issues or questions:
1. Check the deployment logs in Render
2. Verify environment variable configuration
3. Test API endpoints individually
4. Review browser console for JavaScript errors

---

**🎉 Your TapIn Attendance System is now consolidated and ready for deployment!**