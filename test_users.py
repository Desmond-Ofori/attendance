import requests
import json

base_url = 'http://127.0.0.1:54112/api/auth/register'

# Register lecturer
lecturer_data = {
    'fullname': 'Test Lecturer',
    'email': 'lecturer@test.com',
    'password': 'Password123!',
    'confirm-password': 'Password123!',
    'role': 'lecturer'
}

response = requests.post(base_url, json=lecturer_data)
print(f"Lecturer registration: {response.status_code}, {response.text}")

# Register student
student_data = {
    'fullname': 'Test Student',
    'email': 'student@test.com',
    'password': 'Password123!',
    'confirm-password': 'Password123!',
    'student_id': 'STU001',
    'role': 'student'
}

response = requests.post(base_url, json=student_data)
print(f"Student registration: {response.status_code}, {response.text}")