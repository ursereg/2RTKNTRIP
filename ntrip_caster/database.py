#!/usr/bin/env python3

import sqlite3
import hashlib
import secrets
import logging
from threading import Lock
from . import config
from . import logger
from .logger import log_debug, log_info, log_warning, log_error, log_critical, log_database_operation, log_authentication

db_lock = Lock()

def hash_password(password, salt=None):
    """Hash password using PBKDF2 and SHA256"""
    if salt is None:
        salt = secrets.token_hex(16)  
    
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 10000)
    return f"{salt}${key.hex()}"

def verify_password(stored_password, provided_password):
    """Verify if password matches"""
    if '$' not in stored_password:
        return stored_password == provided_password
        
    salt, hash_value = stored_password.split('$', 1)
    key = hashlib.pbkdf2_hmac('sha256', provided_password.encode(), salt.encode(), 10000)
    return key.hex() == hash_value

def init_db():
    """Initialize SQLite database schema"""
    with db_lock:
        conn = sqlite3.connect(config.DATABASE_PATH)
        c = conn.cursor()

        # Admins table
        c.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
        ''')
        
        # Users table (NTRIP client users)
        c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
        ''')
        
        # Mount points table
        c.execute('''
        CREATE TABLE IF NOT EXISTS mounts (
            id INTEGER PRIMARY KEY,
            mount TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            user_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id)
                ON DELETE SET NULL
                ON UPDATE CASCADE
        )
        ''')
        
        c.execute("SELECT * FROM admins")
        if not c.fetchone():
            # Store default admin password with hash
            admin_username = config.DEFAULT_ADMIN['username']
            admin_password = config.DEFAULT_ADMIN['password']
            hashed_password = hash_password(admin_password)
            c.execute("INSERT INTO admins (username, password) VALUES (?, ?)", (admin_username, hashed_password))
            print(f"Default admin created: {admin_username}/{admin_password} (Please change after first login)")
        
        conn.commit()
        conn.close()
        log_info('Database initialization complete')

def verify_mount_and_user(mount, username=None, password=None, mount_password=None, protocol_version="1.0"):
    """Verify mount point and user information
    
    Args:
        mount: Mount point name
        username: Username (optional)
        password: Password (optional)
        mount_password: Mount point password (optional)
        protocol_version: NTRIP protocol version
    """
    with db_lock:
        conn = sqlite3.connect(config.DATABASE_PATH)
        c = conn.cursor()
        
        try:
            # Check if mount point exists and get info
            c.execute("SELECT id, password, user_id FROM mounts WHERE mount = ?", (mount,))
            mount_result = c.fetchone()
            
            if not mount_result:
                log_authentication(username or 'unknown', mount, False, 'database', 'Mount point does not exist')
                return False, "Mount point does not exist"
            
            mount_id, stored_mount_password, bound_user_id = mount_result
            
            # Validation logic based on protocol version
            if protocol_version == "2.0":
                if not username or not password:
                    log_authentication(username or 'unknown', mount, False, 'database', 'NTRIP 2.0 requires username and password')
                    return False, "NTRIP 2.0 requires username and password"
                
                # Verify user exists
                c.execute("SELECT id, password FROM users WHERE username = ?", (username,))
                user_result = c.fetchone()
                if not user_result:
                    log_authentication(username, mount, False, 'database', 'User does not exist')
                    return False, "User does not exist"
                
                user_id, stored_user_password = user_result
                
                # Verify user password
                if not verify_password(stored_user_password, password):
                    log_authentication(username, mount, False, 'database', 'Incorrect password')
                    return False, "Incorrect password"
                
                # Verify if mount point is bound to this user
                if bound_user_id is not None and bound_user_id != user_id:
                    log_authentication(username, mount, False, 'database', 'User does not have access to this mount point')
                    return False, "User does not have access to this mount point"
                
                log_authentication(username, mount, True, 'database', 'NTRIP 2.0 authentication successful')
                return True, "NTRIP 2.0 authentication successful"
            
            else:
                # NTRIP 1.0 validation logic
                if not mount_password:
                    log_authentication(username or 'unknown', mount, False, 'database', 'NTRIP 1.0 requires mount point password')
                    return False, "NTRIP 1.0 requires mount point password"
                
                # Verify mount point password
                if stored_mount_password != mount_password:
                    log_authentication(username or 'unknown', mount, False, 'database', 'Incorrect mount point password')
                    return False, "Incorrect mount point password"
                
                log_authentication(username or 'unknown', mount, True, 'database', 'NTRIP 1.0 authentication successful')
                return True, "NTRIP 1.0 authentication successful"
            
        except Exception as e:
            log_error(f"User authentication exception: {e}", exc_info=True)
            return False, f"Authentication exception: {e}"
        finally:
            conn.close()

def add_user(username, password):
    """Add new user to database"""
    with db_lock:
        conn = sqlite3.connect(config.DATABASE_PATH)
        c = conn.cursor()
        try:
            # Check if user already exists
            c.execute("SELECT * FROM users WHERE username = ?", (username,))
            if c.fetchone():
                return False, "Username already exists"
            
            # Hash password and add user
            hashed_password = hash_password(password)
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            log_database_operation('add_user', 'users', True, f'User: {username}')
            return True, "User added successfully"
        except Exception as e:
            log_database_operation('add_user', 'users', False, str(e))
            return False, f"Failed to add user: {e}"
        finally:
            conn.close()

def update_user(user_id, username, password):
    """Update user information"""
    with db_lock:
        conn = sqlite3.connect(config.DATABASE_PATH)
        c = conn.cursor()
        try:
            # Check for username conflict
            c.execute("SELECT * FROM users WHERE username = ? AND id != ?", (username, user_id))
            if c.fetchone():
                return False, "Username already exists"
            
            c.execute("SELECT password FROM users WHERE id = ?", (user_id,))
            old_password = c.fetchone()[0]
            
            if '$' in old_password and verify_password(old_password, password):
                new_password = old_password
            else:
                new_password = hash_password(password)
            
            c.execute("UPDATE users SET username = ?, password = ? WHERE id = ?", (username, new_password, user_id))
            conn.commit()
            log_database_operation('update_user', 'users', True, f'User: {username}')
            return True, "User updated successfully"
        except Exception as e:
            log_database_operation('update_user', 'users', False, str(e))
            return False, f"Failed to update user: {e}"
        finally:
            conn.close()

def delete_user(user_id):
    """Delete user"""
    with db_lock:
        conn = sqlite3.connect(config.DATABASE_PATH)
        c = conn.cursor()
        try:
            c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
            result = c.fetchone()
            if not result:
                return False, "User does not exist"
            
            username = result[0]
            
            # Clear user_id for mount points bound to this user
            c.execute("UPDATE mounts SET user_id = NULL WHERE user_id = ?", (user_id,))
            affected_mounts = c.rowcount
            
            # Delete user
            c.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
            
            log_message = f'User: {username}'
            if affected_mounts > 0:
                log_message += f', cleared user binding for {affected_mounts} mount points'
            
            log_database_operation('delete_user', 'users', True, log_message)
            return True, username
        except Exception as e:
            log_database_operation('delete_user', 'users', False, str(e))
            return False, f"Failed to delete user: {e}"
        finally:
            conn.close()

def get_all_users():
    """Get all users list"""
    with db_lock:
        conn = sqlite3.connect(config.DATABASE_PATH)
        c = conn.cursor()
        try:
            c.execute("SELECT id, username, password FROM users")
            return c.fetchall()
        finally:
            conn.close()

def update_user_password(username, new_password):
    """Update user password"""
    with db_lock:
        conn = sqlite3.connect(config.DATABASE_PATH)
        c = conn.cursor()
        try:
            c.execute("SELECT id FROM users WHERE username = ?", (username,))
            result = c.fetchone()
            if not result:
                return False, "User does not exist"
            
            hashed_password = hash_password(new_password)
            c.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, username))
            conn.commit()
            log_info(f"Password updated successfully for user {username}")
            return True, "Password updated successfully"
        except Exception as e:
            log_error(f"Failed to update user password: {e}")
            return False, f"Failed to update password: {e}"
        finally:
            conn.close()

def add_mount(mount, password, user_id=None):
    """Add new mount point"""
    with db_lock:
        conn = sqlite3.connect(config.DATABASE_PATH)
        c = conn.cursor()
        try:
            c.execute("SELECT * FROM mounts WHERE mount = ?", (mount,))
            if c.fetchone():
                return False, "Mount point name already exists"
            
            # Verify user exists if user_id is specified
            if user_id is not None:
                c.execute("SELECT id FROM users WHERE id = ?", (user_id,))
                if not c.fetchone():
                    return False, "Specified user does not exist"
            
            c.execute("INSERT INTO mounts (mount, password, user_id) VALUES (?, ?, ?)", (mount, password, user_id))
            conn.commit()
            log_database_operation('add_mount', 'mounts', True, f'Mount: {mount}, User ID: {user_id}')
            return True, "Mount point added successfully"
        except Exception as e:
            log_database_operation('add_mount', 'mounts', False, str(e))
            return False, f"Failed to add mount point: {e}"
        finally:
            conn.close()

def update_mount(mount_id, mount=None, password=None, user_id=None):
    """Update mount point information"""
    with db_lock:
        conn = sqlite3.connect(config.DATABASE_PATH)
        c = conn.cursor()
        try:
            c.execute("SELECT mount, password, user_id FROM mounts WHERE id = ?", (mount_id,))
            result = c.fetchone()
            if not result:
                return False, "Mount point does not exist"
            
            old_mount, old_password, old_user_id = result
            new_mount = mount if mount is not None else old_mount
            new_password = password if password is not None else old_password
            new_user_id = user_id if user_id != 'keep_current' else old_user_id
            
            # Check for name conflict
            if mount is not None and mount != old_mount:
                c.execute("SELECT * FROM mounts WHERE mount = ? AND id != ?", (mount, mount_id))
                if c.fetchone():
                    return False, "Mount point name already exists"
            
            # Verify user exists
            if new_user_id is not None:
                c.execute("SELECT id FROM users WHERE id = ?", (new_user_id,))
                if not c.fetchone():
                    return False, "Specified user does not exist"
            
            c.execute("UPDATE mounts SET mount = ?, password = ?, user_id = ? WHERE id = ?", (new_mount, new_password, new_user_id, mount_id))
            conn.commit()
            log_database_operation('update_mount', 'mounts', True, f'Mount: {old_mount} -> {new_mount}')
            return True, old_mount
        except Exception as e:
            log_database_operation('update_mount', 'mounts', False, str(e))
            return False, f"Failed to update mount point: {e}"
        finally:
            conn.close()

def delete_mount(mount_id):
    """Delete mount point"""
    with db_lock:
        conn = sqlite3.connect(config.DATABASE_PATH)
        c = conn.cursor()
        try:
            c.execute("SELECT mount FROM mounts WHERE id = ?", (mount_id,))
            result = c.fetchone()
            if not result:
                return False, "Mount point does not exist"
            
            mount = result[0]
            c.execute("DELETE FROM mounts WHERE id = ?", (mount_id,))
            conn.commit()
            log_database_operation('delete_mount', 'mounts', True, f'Mount: {mount}')
            return True, mount
        except Exception as e:
            log_database_operation('delete_mount', 'mounts', False, str(e))
            return False, f"Failed to delete mount point: {e}"
        finally:
            conn.close()

def get_all_mounts():
    """Get all mount points list"""
    with db_lock:
        conn = sqlite3.connect(config.DATABASE_PATH)
        c = conn.cursor()
        try:
            c.execute("PRAGMA table_info(mounts)")
            columns = [column[1] for column in c.fetchall()]
            
            if 'lat' in columns and 'lon' in columns:
                c.execute("""SELECT m.id, m.mount, m.password, m.user_id, u.username, m.lat, m.lon
                             FROM mounts m 
                             LEFT JOIN users u ON m.user_id = u.id""")
            else:
                c.execute("""SELECT m.id, m.mount, m.password, m.user_id, u.username, NULL as lat, NULL as lon
                             FROM mounts m 
                             LEFT JOIN users u ON m.user_id = u.id""")
            return c.fetchall()
        finally:
            conn.close()

def verify_admin(username, password):
    """Verify admin credentials"""
    with db_lock:
        conn = sqlite3.connect(config.DATABASE_PATH)
        c = conn.cursor()
        try:
            c.execute("SELECT password FROM admins WHERE username = ?", (username,))
            result = c.fetchone()
            if result and verify_password(result[0], password):
                return True
            return False
        finally:
            conn.close()

def update_admin_password(username, new_password):
    """Update admin password"""
    with db_lock:
        conn = sqlite3.connect(config.DATABASE_PATH)
        c = conn.cursor()
        try:
            hashed_password = hash_password(new_password)
            c.execute("UPDATE admins SET password = ? WHERE username = ?", (hashed_password, username))
            conn.commit()
            log_database_operation('update_admin_password', 'admins', True, f'Admin: {username}')
            return True
        except Exception as e:
            log_database_operation('update_admin_password', 'admins', False, str(e))
            return False
        finally:
            conn.close()

class DatabaseManager:
    """Database Manager class, wraps database operation functions"""
    
    def __init__(self):
        pass
    
    def init_database(self):
        """Initialize database"""
        return init_db()
    
    def verify_mount_and_user(self, mount, username=None, password=None, mount_password=None, protocol_version="1.0"):
        """Verify mount point and user"""
        return verify_mount_and_user(mount, username, password, mount_password, protocol_version)
    
    def add_user(self, username, password):
        """Add user"""
        return add_user(username, password)
    
    def update_user_password(self, username, new_password):
        """Update user password"""
        return update_user_password(username, new_password)
    
    def delete_user(self, username):
        """Delete user"""
        users = get_all_users()
        user_id = None
        for user in users:
            if user[1] == username:
                user_id = user[0]
                break
        
        if user_id is None:
            return False, "User does not exist"
        
        return delete_user(user_id)
    
    def get_all_users(self):
        """Get all users"""
        return get_all_users()
    
    def get_user_password(self, username):
        """Get user password, used for Digest authentication"""
        with sqlite3.connect(config.DATABASE_PATH) as conn:
            c = conn.cursor()
            c.execute("SELECT password FROM users WHERE username = ?", (username,))
            result = c.fetchone()
            return result[0] if result else None
    
    def check_mount_exists_in_db(self, mount):
        """Check if mount point exists in database"""
        with sqlite3.connect(config.DATABASE_PATH) as conn:
            c = conn.cursor()
            c.execute("SELECT id FROM mounts WHERE mount = ?", (mount,))
            return c.fetchone() is not None
    
    def verify_download_user(self, mount, username, password):
        """Verify download user, checks username/password, ignores mount binding"""
        with sqlite3.connect(config.DATABASE_PATH) as conn:
            c = conn.cursor()
            
            c.execute("SELECT id FROM mounts WHERE mount = ?", (mount,))
            mount_result = c.fetchone()
            if not mount_result:
                log_authentication(username, mount, False, 'database', 'Mount point does not exist')
                return False, "Mount point does not exist"
            
            c.execute("SELECT id, password FROM users WHERE username = ?", (username,))
            user_result = c.fetchone()
            if not user_result:
                log_authentication(username, mount, False, 'database', 'User does not exist')
                return False, "User does not exist"
            
            user_id, stored_password = user_result
            
            if not verify_password(stored_password, password):
                log_authentication(username, mount, False, 'database', 'Incorrect password')
                return False, "Incorrect password"
            
            log_authentication(username, mount, True, 'database', 'Download authentication successful')
            return True, "Download authentication successful"
    
    def add_mount(self, mount, password=None, user_id=None):
        """Add mount point"""
        return add_mount(mount, password, user_id)
    
    def update_mount_password(self, mount, new_password):
        """Update mount point password"""
        with db_lock:
            conn = sqlite3.connect(config.DATABASE_PATH)
            c = conn.cursor()
            try:
                c.execute("UPDATE mounts SET password = ? WHERE mount = ?", (new_password, mount))
                if c.rowcount > 0:
                    conn.commit()
                    return True, "Mount point password updated successfully"
                else:
                    return False, "Mount point does not exist"
            except Exception as e:
                return False, f"Failed to update mount point password: {str(e)}"
            finally:
                conn.close()
    
    def update_user(self, user_id, username, password):
        """Update user info"""
        return update_user(user_id, username, password)
    
    def update_mount(self, mount_id, mount=None, password=None, user_id=None):
        """Update mount point info"""
        return update_mount(mount_id, mount, password, user_id)
    
    def delete_mount(self, mount):
        """Delete mount point"""
        mounts = self.get_all_mounts()
        mount_id = None
        for m in mounts:
            if m[1] == mount:
                mount_id = m[0]
                break
        
        if mount_id is None:
            return False, "Mount point does not exist"
        
        return delete_mount(mount_id)
    
    def get_all_mounts(self):
        """Get all mount points"""
        return get_all_mounts()
       
    def verify_admin(self, username, password):
        """Verify admin"""
        return verify_admin(username, password)
    
    def update_admin_password(self, username, new_password):
        """Update admin password"""
        return update_admin_password(username, new_password)
