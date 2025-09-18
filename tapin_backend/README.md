# 🎓 TapIn Attendance Application

A comprehensive attendance management system with real-time features, built with Flask and Socket.IO.

## 🏗️ Architecture

- **Frontend Web App** (`app.py/`) - Flask web interface for lecturers and students
- **Backend API** (`tapin_backend/`) - RESTful API with Socket.IO for real-time updates
- **Database** - SQLite (development) / PostgreSQL (production)
- **Authentication** - Session-based (frontend) + JWT tokens (backend)

## ✨ Features

### For Lecturers
- 👨‍🏫 Create and manage classes
- 📊 Take attendance (PIN or GPS-based)
- 📈 View attendance reports and history
- 📢 Send announcements to students
- 🔔 Real-time attendance notifications

### For Students
- 👨‍🎓 Join classes with PIN codes
- ✅ Mark attendance (PIN entry or location-based)
- 📱 View attendance history
- 📬 Receive class announcements
- 🔔 Get notifications

### System Features
- 🔐 Secure authentication with password reset
- 📧 Email notifications
- 🌐 Real-time updates with Socket.IO
- 📱 Responsive web interface
- 🐳 Docker support

## 🚀 Quick Start

### Option 1: Automated Setup (Recommended)

```bash
# Clone the repository
git clone <your-repo-url>
cd attendance_app

# Run the complete setup and launch script
python run_app.py
```

This will:
- Install all dependencies
- Initialize databases
- Start both frontend and backend
- Open the application at http://localhost:5000

### Option 2: Manual Setup

1. **Install Dependencies**
```bash
# Frontend dependencies
cd app.py
pip install -r requirements.txt
cd ..

# Backend dependencies
cd tapin_backend
pip install -r requirements.txt
cd ..
```

2. **Start Backend API**
```bash
python start_backend.py
# Backend runs at http://localhost:8000
```

3. **Start Frontend (in another terminal)**
```bash
python start_frontend.py
# Frontend runs at http://localhost:5000
```

### Option 3: Docker

```bash
# Build and run with Docker
docker build -t tapin-app .
docker run -p 5000:5000 -p 8000:8000 tapin-app
```

## 🌐 Application URLs

- **Main Application**: http://localhost:5000
- **Lecturer Login**: http://localhost:5000/lecturer_login
- **Student Login**: http://localhost:5000/student_login
- **Backend API**: http://localhost:8000
- **API Health Check**: http://localhost:8000/api/health

## 📚 API Documentation

### Authentication Endpoints
```
POST /api/auth/register - Register new user
POST /api/auth/login    - Login user
GET  /api/auth/me       - Get user profile
PUT  /api/auth/me       - Update user profile
```

### Class Management
```
GET    /api/classes           - Get user's classes
POST   /api/classes           - Create new class (lecturer)
POST   /api/classes/join      - Join class with PIN (student)
GET    /api/classes/{id}      - Get class details
```

### Attendance
```
GET  /api/classes/{id}/sessions/active     - Get active attendance session
POST /api/attendance/mark                  - Mark attendance
GET  /api/classes/{id}/attendance/history  - Get attendance history
```

### Announcements
```
GET  /api/announcements - Get announcements
POST /api/announcements - Create announcement (lecturer)
```

## 🔧 Configuration

### Environment Variables

**Frontend** (`.env` in `app.py/`):
```env
SECRET_KEY=your-secret-key
DEBUG=False
DATABASE_URL=sqlite:///tapin.db
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
```

**Backend** (`.env` in `tapin_backend/`):
```env
SECRET_KEY=your-backend-secret-key
DATABASE_URL=sqlite:///tapin.db
JWT_EXPIRES_MIN=43200
CORS_ORIGINS=http://localhost:5500,http://127.0.0.1:5500
```

## 🗄️ Database Schema

### Users
- `id`, `fullname`, `email`, `student_id`, `phone`, `role`, `password_hash`, `created_at`

### Classes
- `id`, `lecturer_id`, `programme`, `faculty`, `department`, `course_name`, `course_code`, `level`, `section`, `join_pin`, `created_at`

### Attendance Sessions
- `id`, `class_id`, `method` (geo/pin), `pin_code`, `lecturer_lat`, `lecturer_lng`, `radius_m`, `expires_at`, `is_open`, `created_at`

### Attendance Records
- `id`, `session_id`, `student_id`, `status`, `timestamp`

## 🔒 Security Features

- Password hashing with bcrypt
- JWT token authentication
- CORS protection
- SQL injection prevention with SQLAlchemy ORM
- Secure session management
- Email verification for password reset

## 🚀 Deployment

### Production Deployment

1. **Set Environment Variables**
```bash
export SECRET_KEY="your-production-secret-key"
export DATABASE_URL="postgresql://user:pass@host:5432/dbname"
export MAIL_USERNAME="your-production-email"
export MAIL_PASSWORD="your-production-password"
```

2. **Use Production WSGI Server**
```bash
# Frontend
cd app.py
gunicorn -w 4 -b 0.0.0.0:5000 app:app

# Backend
cd tapin_backend
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

### Docker Production
```bash
docker build -t tapin-app .
docker run -d -p 5000:5000 -p 8000:8000 \
  -e SECRET_KEY="your-secret" \
  -e DATABASE_URL="your-db-url" \
  tapin-app
```

## 🧪 Testing

```bash
# Test backend API
curl http://localhost:8000/api/health

# Test frontend
curl http://localhost:5000

# Register a test user
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"fullname":"Test User","email":"test@example.com","password":"testpass123","role":"student"}'
```

## 🐛 Troubleshooting

### Common Issues

1. **Port Already in Use**
```bash
# Kill processes on ports 5000 and 8000
lsof -ti:5000 | xargs kill -9
lsof -ti:8000 | xargs kill -9
```

2. **Database Issues**
```bash
# Delete and recreate database
rm instance/tapin.db
python run_app.py
```

3. **Import Errors**
```bash
# Ensure you're in the correct directory
pwd  # Should show attendance_app directory
python -c "import flask; print('Flask installed')"
```

4. **Email Not Working**
- Check Gmail app password settings
- Verify MAIL_USERNAME and MAIL_PASSWORD in .env
- Enable 2-factor authentication and use app password

## 📝 Development

### Adding New Features

1. **Backend API**: Add routes in `tapin_backend/routes_*.py`
2. **Frontend**: Add templates in `templates/` and routes in `app.py/app.py`
3. **Database**: Update models in `tapin_backend/models.py`
4. **Real-time**: Add Socket.IO events in `tapin_backend/app.py`

### Code Structure
```
attendance_app/
├── app.py/                 # Frontend Flask app
│   ├── app.py             # Main frontend application
│   ├── requirements.txt   # Frontend dependencies
│   └── .env              # Frontend configuration
├── tapin_backend/         # Backend API
│   ├── app.py            # Main backend application
│   ├── models.py         # Database models
│   ├── auth.py           # Authentication routes
│   ├── routes_*.py       # Feature-specific routes
│   ├── utils.py          # Utility functions
│   ├── requirements.txt  # Backend dependencies
│   └── .env             # Backend configuration
├── templates/            # HTML templates
├── static/              # CSS, JS, images
├── instance/            # Database files
├── run_app.py          # Complete setup script
├── start_backend.py    # Backend startup script
├── start_frontend.py   # Frontend startup script
└── Dockerfile          # Docker configuration
```

## 📄 License

This project is licensed under the MIT License.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

---

**Made with ❤️ for educational institutions**