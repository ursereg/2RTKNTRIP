import pytest
from ntrip_caster.database import DatabaseManager
from ntrip_caster.web import WebManager
from ntrip_caster import config
from unittest.mock import MagicMock

@pytest.fixture
def client(temp_db):
    db_manager = DatabaseManager()
    web_manager = WebManager(db_manager, MagicMock(), 0)
    app = web_manager.app
    app.config['TESTING'] = True
    return app.test_client()

def test_batch_add_users(client):
    """Refactored batch user addition test"""
    # Admin login
    login_response = client.post('/api/login', json={
        "username": config.DEFAULT_ADMIN['username'],
        "password": config.DEFAULT_ADMIN['password']
    })
    assert login_response.status_code == 200
    
    total_users = 5
    for i in range(1, total_users + 1):
        username = f"testuser{i:03d}"
        password = f"pass{i:03d}"
        
        response = client.post('/api/users', json={
            "username": username,
            "password": password
        })
        assert response.status_code == 201
    
    # Verify users were added
    response = client.get('/api/users')
    assert response.status_code == 200
    users = response.get_json()
    assert len([u for u in users if u['username'].startswith('testuser')]) == total_users
