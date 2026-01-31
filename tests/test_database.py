import pytest
from ntrip_caster import database

def test_hash_and_verify_password():
    password = "test_password"
    hashed = database.hash_password(password)
    assert hashed != password
    assert database.verify_password(hashed, password)
    assert not database.verify_password(hashed, "wrong_password")

def test_user_management(temp_db):
    username = "testuser"
    password = "testpassword"

    # Add user
    success, message = database.add_user(username, password)
    assert success
    assert message == "User added successfully"

    # Add duplicate user
    success, message = database.add_user(username, password)
    assert not success
    assert message == "Username already exists"

    # Get all users
    users = database.get_all_users()
    assert any(u[1] == username for u in users)

    # Update user password
    new_password = "newpassword"
    success, message = database.update_user_password(username, new_password)
    assert success

    # Verify new password
    db_manager = database.DatabaseManager()
    stored_hashed = db_manager.get_user_password(username)
    assert database.verify_password(stored_hashed, new_password)

    # Delete user
    db_manager = database.DatabaseManager()
    success, deleted_username = db_manager.delete_user(username)
    assert success
    assert deleted_username == username

    # Verify deletion
    users = database.get_all_users()
    assert not any(u[1] == username for u in users)

def test_mount_management(temp_db):
    mount_name = "TESTMOUNT"
    mount_password = "mountpassword"

    # Add mount
    success, message = database.add_mount(mount_name, mount_password)
    assert success
    assert message == "Mount point added successfully"

    # Add duplicate mount
    success, message = database.add_mount(mount_name, mount_password)
    assert not success
    assert message == "Mount point name already exists"

    # Check mount existence
    db_manager = database.DatabaseManager()
    assert db_manager.check_mount_exists_in_db(mount_name)
    assert not db_manager.check_mount_exists_in_db("NONEXISTENT")

    # Get all mounts
    mounts = database.get_all_mounts()
    assert any(m[1] == mount_name for m in mounts)

    # Update mount password
    new_mount_password = "newmountpassword"
    success, message = db_manager.update_mount_password(mount_name, new_mount_password)
    assert success

    # Delete mount
    success, deleted_mount = db_manager.delete_mount(mount_name)
    assert success
    assert deleted_mount == mount_name

    # Verify deletion
    assert not db_manager.check_mount_exists_in_db(mount_name)

def test_authentication_verification(temp_db):
    username = "authuser"
    password = "authpassword"
    mount_name = "AUTHMOUNT"
    mount_password = "mountpassword"

    database.add_user(username, password)
    # Get user_id
    users = database.get_all_users()
    user_id = next(u[0] for u in users if u[1] == username)

    database.add_mount(mount_name, mount_password, user_id=user_id)

    db_manager = database.DatabaseManager()

    # NTRIP 1.0 success (mount password)
    success, message = db_manager.verify_mount_and_user(mount_name, mount_password=mount_password, protocol_version="1.0")
    assert success

    # NTRIP 1.0 failure (wrong mount password)
    success, message = db_manager.verify_mount_and_user(mount_name, mount_password="wrong", protocol_version="1.0")
    assert not success

    # NTRIP 2.0 success (user credentials)
    success, message = db_manager.verify_mount_and_user(mount_name, username=username, password=password, protocol_version="2.0")
    assert success

    # NTRIP 2.0 failure (wrong user password)
    success, message = db_manager.verify_mount_and_user(mount_name, username=username, password="wrong", protocol_version="2.0")
    assert not success

    # NTRIP 2.0 failure (unbound user - if we had another user)
    other_user = "otheruser"
    database.add_user(other_user, "otherpass")
    success, message = db_manager.verify_mount_and_user(mount_name, username=other_user, password="otherpass", protocol_version="2.0")
    assert not success
    assert "User does not have access" in message

    # Download verification
    success, message = db_manager.verify_download_user(mount_name, username, password)
    assert success

    success, message = db_manager.verify_download_user(mount_name, other_user, "otherpass")
    assert success # Download usually allows any valid user if mount exists

def test_admin_verification(temp_db):
    # Default admin from config
    from ntrip_caster import config
    assert database.verify_admin(config.DEFAULT_ADMIN['username'], config.DEFAULT_ADMIN['password'])

    # Update admin password
    new_admin_pass = "newadmin123"
    assert database.update_admin_password(config.DEFAULT_ADMIN['username'], new_admin_pass)
    assert database.verify_admin(config.DEFAULT_ADMIN['username'], new_admin_pass)
    assert not database.verify_admin(config.DEFAULT_ADMIN['username'], config.DEFAULT_ADMIN['password'])
