import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest
from tapin_backend.app import app
from tapin_backend.models import db, User
from tapin_backend.utils import create_verification_token, hash_password

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for tests
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.drop_all()

@pytest.fixture
def user_factory():
    def _factory(role='student', is_verified=False, email='test@example.com', fullname='Test User', password='TestPass123!', **kwargs):
        u = User(
            fullname=fullname,
            email=email,
            role=role.lower(),
            password_hash=hash_password(password),
            is_verified=is_verified,
            **kwargs
        )
        db.session.add(u)
        db.session.commit()
        return u
    return _factory

def test_verify_sets_session_and_redirects(client, user_factory):
    user = user_factory(role='lecturer', is_verified=False)
    token = create_verification_token(user.email, user.role)
    resp = client.get(f'/verify-email/{token}')
    assert resp.status_code == 302
    assert '/lecturer/dashboard' in resp.location
    with client.session_transaction() as sess:
        assert sess['user_id'] == user.id
        assert sess['role'] == 'lecturer'
        assert sess['is_verified'] is True

def test_verify_invalid_token(client):
    resp = client.get('/verify-email/invalidtoken')
    assert resp.status_code == 302
    assert '/account' in resp.location

def test_already_verified_redirects_to_account(client, user_factory):
    user = user_factory(role='student', is_verified=True)
    token = create_verification_token(user.email, user.role)
    resp = client.get(f'/verify-email/{token}')
    assert resp.status_code == 302
    assert '/account' in resp.location

def test_login_sets_session(client, user_factory):
    user = user_factory(role='lecturer', is_verified=True)
    data = {'email': user.email, 'password': 'TestPass123!'}
    resp = client.post('/api/auth/login', json=data)
    assert resp.status_code == 200
    response_data = resp.get_json()
    assert response_data['success'] is True
    assert 'token' in response_data
    with client.session_transaction() as sess:
        assert sess['user_id'] == user.id
        assert sess['role'] == 'lecturer'
        assert sess['is_verified'] is True