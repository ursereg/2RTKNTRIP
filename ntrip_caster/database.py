#!/usr/bin/env python3

import hashlib
import secrets
import threading
from typing import Any, Optional, Generator
from contextlib import contextmanager

from sqlalchemy import create_engine, select, update, delete, or_
from sqlalchemy.orm import sessionmaker, Session, scoped_session
from sqlalchemy.engine import Engine

from . import config
from .logger import (
    log_authentication,
    log_database_operation,
    log_error,
    log_info,
)
from .models import Base, Admin, User, Mount

class Database:
    _instance: Optional['Database'] = None
    _lock = threading.Lock()

    def __init__(self) -> None:
        self.engine: Optional[Engine] = None
        self.session_factory = None
        self.db_session = None
        self._current_url = None

    @classmethod
    def get_instance(cls) -> 'Database':
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def _get_engine(self) -> Engine:
        url = config.settings.database.connection_url
        if self.engine is None or self._current_url != url:
            with self._lock:
                # Double check after lock
                if self.engine is None or self._current_url != url:
                    self.engine = create_engine(
                        url,
                        pool_size=config.settings.database.pool_size,
                        pool_pre_ping=True
                    )
                    self.session_factory = sessionmaker(bind=self.engine)
                    self.db_session = scoped_session(self.session_factory)
                    self._current_url = url
        return self.engine

    @contextmanager
    def session_scope(self) -> Generator[Session, None, None]:
        self._get_engine()
        session = self.db_session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

def db_session():
    return Database.get_instance().session_scope()

def hash_password(password: str, salt: str | None = None) -> str:
    """Hash password using PBKDF2 and SHA256"""
    if salt is None:
        salt = secrets.token_hex(16)

    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 10000)
    return f"{salt}${key.hex()}"


def verify_password(stored_password: str, provided_password: str) -> bool:
    """Verify if password matches"""
    if "$" not in stored_password:
        return stored_password == provided_password

    salt, hash_value = stored_password.split("$", 1)
    key = hashlib.pbkdf2_hmac("sha256", provided_password.encode(), salt.encode(), 10000)
    return key.hex() == hash_value


def init_db() -> None:
    """Initialize database schema"""
    db = Database.get_instance()
    engine = db._get_engine()
    Base.metadata.create_all(engine)

    with db_session() as session:
        admin = session.execute(select(Admin)).first()
        if not admin:
            # Store default admin password with hash
            admin_username = config.settings.admin.username
            admin_password = config.settings.admin.password
            hashed_password = hash_password(admin_password)
            new_admin = Admin(username=admin_username, password=hashed_password)
            session.add(new_admin)
            # session_scope will commit automatically

    log_info("Database initialization complete")


def verify_mount_and_user(
    mount: str,
    username: str | None = None,
    password: str | None = None,
    mount_password: str | None = None,
    protocol_version: str = "1.0",
) -> tuple[bool, str]:
    """Verify mount point and user information"""
    with db_session() as session:
        try:
            # Check if mount point exists
            stmt = select(Mount).where(Mount.mount == mount)
            mount_obj = session.execute(stmt).scalar_one_or_none()

            if not mount_obj:
                log_authentication(username or "unknown", mount, False, "database", "Mount point does not exist")
                return False, "Mount point does not exist"

            # Validation logic based on protocol version
            if protocol_version == "2.0":
                if not username or not password:
                    log_authentication(
                        username or "unknown", mount, False, "database", "NTRIP 2.0 requires username and password"
                    )
                    return False, "NTRIP 2.0 requires username and password"

                # Verify user exists
                user_stmt = select(User).where(User.username == username)
                user_obj = session.execute(user_stmt).scalar_one_or_none()

                if not user_obj:
                    log_authentication(username, mount, False, "database", "User does not exist")
                    return False, "User does not exist"

                # Verify user password
                if not verify_password(user_obj.password, password):
                    log_authentication(username, mount, False, "database", "Incorrect password")
                    return False, "Incorrect password"

                # Verify if mount point is bound to this user
                if mount_obj.user_id is not None and mount_obj.user_id != user_obj.id:
                    log_authentication(
                        username, mount, False, "database", "User does not have access to this mount point"
                    )
                    return False, "User does not have access to this mount point"

                log_authentication(username, mount, True, "database", "NTRIP 2.0 authentication successful")
                return True, "NTRIP 2.0 authentication successful"

            else:
                # NTRIP 1.0 validation logic
                if not mount_password:
                    log_authentication(
                        username or "unknown", mount, False, "database", "NTRIP 1.0 requires mount point password"
                    )
                    return False, "NTRIP 1.0 requires mount point password"

                # Verify mount point password
                if mount_obj.password != mount_password:
                    log_authentication(
                        username or "unknown", mount, False, "database", "Incorrect mount point password"
                    )
                    return False, "Incorrect mount point password"

                log_authentication(
                    username or "unknown", mount, True, "database", "NTRIP 1.0 authentication successful"
                )
                return True, "NTRIP 1.0 authentication successful"

        except Exception as e:
            log_error(f"User authentication exception: {e}", exc_info=True)
            return False, f"Authentication exception: {e}"


def add_user(username: str, password: str) -> tuple[bool, str]:
    """Add new user to database"""
    with db_session() as session:
        try:
            # Check if user already exists
            stmt = select(User).where(User.username == username)
            if session.execute(stmt).first():
                return False, "Username already exists"

            # Hash password and add user
            hashed_password = hash_password(password)
            new_user = User(username=username, password=hashed_password)
            session.add(new_user)
            log_database_operation("add_user", "users", True, f"User: {username}")
            return True, "User added successfully"
        except Exception as e:
            log_database_operation("add_user", "users", False, str(e))
            return False, f"Failed to add user: {e}"


def update_user(user_id: int, username: str, password: str) -> tuple[bool, str]:
    """Update user information"""
    with db_session() as session:
        try:
            # Check for username conflict
            stmt = select(User).where(User.username == username, User.id != user_id)
            if session.execute(stmt).first():
                return False, "Username already exists"

            user_obj = session.get(User, user_id)
            if not user_obj:
                return False, "User not found"

            if "$" in user_obj.password and verify_password(user_obj.password, password):
                new_password = user_obj.password
            else:
                new_password = hash_password(password)

            user_obj.username = username
            user_obj.password = new_password
            log_database_operation("update_user", "users", True, f"User: {username}")
            return True, "User updated successfully"
        except Exception as e:
            log_database_operation("update_user", "users", False, str(e))
            return False, f"Failed to update user: {e}"


def delete_user(user_id: int) -> tuple[bool, str | bool]:
    """Delete user"""
    with db_session() as session:
        try:
            user_obj = session.get(User, user_id)
            if not user_obj:
                return False, "User does not exist"

            username = user_obj.username

            # Clear user_id for mount points bound to this user
            session.execute(update(Mount).where(Mount.user_id == user_id).values(user_id=None))

            session.delete(user_obj)

            log_database_operation("delete_user", "users", True, f"User: {username}")
            return True, username
        except Exception as e:
            log_database_operation("delete_user", "users", False, str(e))
            return False, f"Failed to delete user: {e}"


def get_all_users() -> list[tuple[Any, ...]]:
    """Get all users list"""
    with db_session() as session:
        try:
            stmt = select(User.id, User.username, User.password)
            results = session.execute(stmt).all()
            return [tuple(row) for row in results]
        except Exception:
            return []


def update_user_password(username: str, new_password: str) -> tuple[bool, str]:
    """Update user password"""
    with db_session() as session:
        try:
            stmt = select(User).where(User.username == username)
            user_obj = session.execute(stmt).scalar_one_or_none()
            if not user_obj:
                return False, "User does not exist"

            user_obj.password = hash_password(new_password)
            log_info(f"Password updated successfully for user {username}")
            return True, "Password updated successfully"
        except Exception as e:
            log_error(f"Failed to update user password: {e}")
            return False, f"Failed to update password: {e}"


def add_mount(mount: str, password: str, user_id: int | None = None) -> tuple[bool, str]:
    """Add new mount point"""
    with db_session() as session:
        try:
            stmt = select(Mount).where(Mount.mount == mount)
            if session.execute(stmt).first():
                return False, "Mount point name already exists"

            # Verify user exists if user_id is specified
            if user_id is not None:
                if not session.get(User, user_id):
                    return False, "Specified user does not exist"

            new_mount = Mount(mount=mount, password=password, user_id=user_id)
            session.add(new_mount)
            log_database_operation("add_mount", "mounts", True, f"Mount: {mount}, User ID: {user_id}")
            return True, "Mount point added successfully"
        except Exception as e:
            log_database_operation("add_mount", "mounts", False, str(e))
            return False, f"Failed to add mount point: {e}"


def update_mount(
    mount_id: int,
    mount: str | None = None,
    password: str | None = None,
    user_id: int | str | None = None,
) -> tuple[bool, str]:
    """Update mount point information"""
    with db_session() as session:
        try:
            mount_obj = session.get(Mount, mount_id)
            if not mount_obj:
                return False, "Mount point does not exist"

            old_mount = mount_obj.mount

            if mount is not None and mount != old_mount:
                stmt = select(Mount).where(Mount.mount == mount, Mount.id != mount_id)
                if session.execute(stmt).first():
                    return False, "Mount point name already exists"
                mount_obj.mount = mount

            if password is not None:
                mount_obj.password = password

            if user_id != "keep_current":
                if user_id is not None:
                    if not session.get(User, user_id):
                        return False, "Specified user does not exist"
                mount_obj.user_id = user_id

            log_database_operation("update_mount", "mounts", True, f"Mount: {old_mount} -> {mount_obj.mount}")
            return True, old_mount
        except Exception as e:
            log_database_operation("update_mount", "mounts", False, str(e))
            return False, f"Failed to update mount point: {e}"


def delete_mount(mount_id: int) -> tuple[bool, str]:
    """Delete mount point"""
    with db_session() as session:
        try:
            mount_obj = session.get(Mount, mount_id)
            if not mount_obj:
                return False, "Mount point does not exist"

            mount_name = mount_obj.mount
            session.delete(mount_obj)
            log_database_operation("delete_mount", "mounts", True, f"Mount: {mount_name}")
            return True, mount_name
        except Exception as e:
            log_database_operation("delete_mount", "mounts", False, str(e))
            return False, f"Failed to delete mount point: {e}"


def get_all_mounts() -> list[tuple[Any, ...]]:
    """Get all mount points list"""
    with db_session() as session:
        try:
            stmt = select(
                Mount.id, Mount.mount, Mount.password, Mount.user_id, User.username, Mount.lat, Mount.lon
            ).outerjoin(User, Mount.user_id == User.id)
            results = session.execute(stmt).all()
            return [tuple(row) for row in results]
        except Exception:
            return []


def verify_admin(username: str, password: str) -> bool:
    """Verify admin credentials"""
    with db_session() as session:
        try:
            stmt = select(Admin).where(Admin.username == username)
            admin_obj = session.execute(stmt).scalar_one_or_none()
            if admin_obj and verify_password(admin_obj.password, password):
                return True
            return False
        except Exception:
            return False


def update_admin_password(username: str, new_password: str) -> bool:
    """Update admin password"""
    with db_session() as session:
        try:
            stmt = select(Admin).where(Admin.username == username)
            admin_obj = session.execute(stmt).scalar_one_or_none()
            if not admin_obj:
                return False

            admin_obj.password = hash_password(new_password)
            log_database_operation("update_admin_password", "admins", True, f"Admin: {username}")
            return True
        except Exception as e:
            log_database_operation("update_admin_password", "admins", False, str(e))
            return False


class DatabaseManager:
    """Database Manager class, wraps database operation functions"""

    def __init__(self) -> None:
        pass

    def init_database(self) -> None:
        """Initialize database"""
        return init_db()

    def verify_mount_and_user(
        self,
        mount: str,
        username: str | None = None,
        password: str | None = None,
        mount_password: str | None = None,
        protocol_version: str = "1.0",
    ) -> tuple[bool, str]:
        """Verify mount point and user"""
        return verify_mount_and_user(mount, username, password, mount_password, protocol_version)

    def add_user(self, username: str, password: str) -> tuple[bool, str]:
        """Add user"""
        return add_user(username, password)

    def update_user_password(self, username: str, new_password: str) -> tuple[bool, str]:
        """Update user password"""
        return update_user_password(username, new_password)

    def delete_user(self, username: str) -> tuple[bool, str | bool]:
        """Delete user"""
        with db_session() as session:
            stmt = select(User).where(User.username == username)
            user_obj = session.execute(stmt).scalar_one_or_none()
            if not user_obj:
                return False, "User does not exist"
            return delete_user(user_obj.id)

    def get_all_users(self) -> list[tuple[Any, ...]]:
        """Get all users"""
        return get_all_users()

    def get_user_password(self, username: str) -> str | None:
        """Get user password, used for Digest authentication"""
        with db_session() as session:
            stmt = select(User.password).where(User.username == username)
            result = session.execute(stmt).scalar_one_or_none()
            return result

    def check_mount_exists_in_db(self, mount: str) -> bool:
        """Check if mount point exists in database"""
        with db_session() as session:
            stmt = select(Mount.id).where(Mount.mount == mount)
            return session.execute(stmt).first() is not None

    def verify_download_user(self, mount: str, username: str, password: str) -> tuple[bool, str]:
        """Verify download user, checks username/password, ignores_binding"""
        with db_session() as session:
            stmt = select(Mount.id).where(Mount.mount == mount)
            if not session.execute(stmt).first():
                log_authentication(username, mount, False, "database", "Mount point does not exist")
                return False, "Mount point does not exist"

            user_stmt = select(User).where(User.username == username)
            user_obj = session.execute(user_stmt).scalar_one_or_none()
            if not user_obj:
                log_authentication(username, mount, False, "database", "User does not exist")
                return False, "User does not exist"

            if not verify_password(user_obj.password, password):
                log_authentication(username, mount, False, "database", "Incorrect password")
                return False, "Incorrect password"

            log_authentication(username, mount, True, "database", "Download authentication successful")
            return True, "Download authentication successful"

    def add_mount(self, mount: str, password: str, user_id: int | None = None) -> tuple[bool, str]:
        """Add mount point"""
        return add_mount(mount, password, user_id)

    def update_mount_password(self, mount: str, new_password: str) -> tuple[bool, str]:
        """Update mount point password"""
        with db_session() as session:
            try:
                stmt = select(Mount).where(Mount.mount == mount)
                mount_obj = session.execute(stmt).scalar_one_or_none()
                if mount_obj:
                    mount_obj.password = new_password
                    return True, "Mount point password updated successfully"
                else:
                    return False, "Mount point does not exist"
            except Exception as e:
                return False, f"Failed to update mount point password: {e!s}"

    def update_user(self, user_id: int, username: str, password: str) -> tuple[bool, str]:
        """Update user info"""
        return update_user(user_id, username, password)

    def update_mount(
        self,
        mount_id: int,
        mount: str | None = None,
        password: str | None = None,
        user_id: int | str | None = None,
    ) -> tuple[bool, str]:
        """Update mount point info"""
        return update_mount(mount_id, mount, password, user_id)

    def delete_mount(self, mount: str) -> tuple[bool, str]:
        """Delete mount point"""
        with db_session() as session:
            stmt = select(Mount).where(Mount.mount == mount)
            mount_obj = session.execute(stmt).scalar_one_or_none()
            if not mount_obj:
                return False, "Mount point does not exist"
            return delete_mount(mount_obj.id)

    def get_all_mounts(self) -> list[tuple[Any, ...]]:
        """Get all mount points"""
        return get_all_mounts()

    def verify_admin(self, username: str, password: str) -> bool:
        """Verify admin"""
        return verify_admin(username, password)

    def update_admin_password(self, username: str, new_password: str) -> bool:
        """Update admin password"""
        return update_admin_password(username, new_password)
