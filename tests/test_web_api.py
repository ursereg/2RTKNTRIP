import pytest
import json
from ntrip_caster.web import WebManager
from ntrip_caster.database import DatabaseManager
from ntrip_caster import config
from unittest.mock import MagicMock

@pytest.fixture
def app(temp_db):
    db_manager = DatabaseManager()
    # Mock data_forwarder and start_time
    web_manager = WebManager(db_manager, MagicMock(), 0)
    app = web_manager.app
    app.config.update({
        "TESTING": True,
    })
    return app

@pytest.fixture
def client(app):
    return app.test_client()

def test_api_login(client):
    # Test successful login
    response = client.post('/api/login',
                           json={'username': config.DEFAULT_ADMIN['username'],
                                 'password': config.DEFAULT_ADMIN['password']})
    assert response.status_code == 200
    assert response.get_json()['success'] is True

    # Test failed login (wrong password but valid length)
    response = client.post('/api/login',
                           json={'username': 'admin', 'password': 'wrongpassword'})
    assert response.status_code == 401

def test_api_add_user(client):
    # Login first
    client.post('/api/login',
                json={'username': config.DEFAULT_ADMIN['username'],
                      'password': config.DEFAULT_ADMIN['password']})

    # Add user
    response = client.post('/api/users',
                           json={'username': 'newuser', 'password': 'newpassword'})
    assert response.status_code == 201
    assert "added successfully" in response.get_json()['message']

    # Verify user added
    response = client.get('/api/users')
    assert response.status_code == 200
    users = response.get_json()
    assert any(u['username'] == 'newuser' for u in users)

def test_api_add_mount(client):
    # Login first
    client.post('/api/login',
                json={'username': config.DEFAULT_ADMIN['username'],
                      'password': config.DEFAULT_ADMIN['password']})

    # Add mount
    response = client.post('/api/mounts',
                           json={'mount': 'NEWMONT', 'password': 'mountpass'})
    assert response.status_code == 201
    assert "added successfully" in response.get_json()['message']

    # Verify mount added
    response = client.get('/api/mounts')
    assert response.status_code == 200
    mounts = response.get_json()
    assert any(m['mount'] == 'NEWMONT' for m in mounts)
