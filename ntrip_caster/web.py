#!/usr/bin/env python3
"""
web.py - Web Management Module
Function: Provides frontend interface, displays real-time mount point info, supports viewing and querying parsed RTCM data.
"""

import time
import json
import logging
import psutil
import re
from datetime import datetime
from functools import wraps
from threading import Thread

from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify, send_from_directory
import os
from flask_socketio import SocketIO, emit, join_room

from .database import DatabaseManager
from . import config
from . import logger
from .logger import log_debug, log_info, log_warning, log_error, log_critical, log_web_request, log_system_event
from . import connection
from . import forwarder
from .rtcm2_manager import parser_manager as rtcm_manager

# Global server instance reference
server_instance = None

def set_server_instance(server):
    """Set server instance"""
    global server_instance
    server_instance = server

def get_server_instance():
    """Get server instance"""
    return server_instance

class WebManager:
    """Web Manager"""
    
    def __init__(self, db_manager, data_forwarder, start_time):
        self.db_manager = db_manager
        self.data_forwarder = data_forwarder
        self.start_time = start_time
        
        # Template and static file directories
        self.template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates')
        self.static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'static')
        
        # Create Flask application
        self.app = Flask(__name__, static_folder=self.static_dir, static_url_path='/static')
        self.app.secret_key = config.FLASK_SECRET_KEY
        
        # Create SocketIO instance
        self.socketio = SocketIO(
            self.app, 
            async_mode='threading',
            ping_timeout=config.WEBSOCKET_CONFIG['ping_timeout'],
            ping_interval=config.WEBSOCKET_CONFIG['ping_interval']
        )
        
        # Register routes and SocketIO events
        self._register_routes()
        self._register_socketio_events()
        
        # Real-time data push thread
        self.push_thread = None
        self.push_running = False
        
        # Set web instance for logger to push real-time logs
        logger.set_web_instance(self)
    
    def _format_uptime_simple(self, uptime_seconds):
        """Format uptime (simple version)"""
        try:
            days = int(uptime_seconds // 86400)
            hours = int((uptime_seconds % 86400) // 3600)
            minutes = int((uptime_seconds % 3600) // 60)
            
            if days > 0:
                return f"{days}d {hours}h {minutes}m"
            elif hours > 0:
                return f"{hours}h {minutes}m"
            else:
                return f"{minutes}m"
        except:
            return "0m"
    
    def _validate_alphanumeric(self, value, field_name):
        """Validate input contains only letters, numbers, underscores and hyphens"""
        if not value:
            return False, f"{field_name} cannot be empty"
        if not re.match(r'^[a-zA-Z0-9_-]+$', value):
            return False, f"{field_name} can only contain letters, numbers, underscores and hyphens"
        return True, ""
    
    def _load_template(self, template_name, **kwargs):
        """Load external template file"""
        template_path = os.path.join(self.template_dir, template_name)
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                template_content = f.read()
            return render_template_string(template_content, **kwargs)
        except FileNotFoundError:
            log_error(f"Template file not found: {template_path}")
            return f"<h1>Template not found: {template_name}</h1>"
        except Exception as e:
            log_error(f"Failed to load template file: {e}")
            return f"<h1>Failed to load template: {str(e)}</h1>"
    
    def _register_routes(self):
        """Register Flask routes"""
        
        @self.app.route('/static/<path:filename>')
        def static_files(filename):
            """Serve static files"""
            static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'static')
            return send_from_directory(static_dir, filename)
        
        @self.app.route('/')
        def index():
            """Main index - SPA Application"""
            app_name = config.get_config_value('app', 'name', '2RTK NTRIP Caster')
            app_version = config.get_config_value('app', 'version', config.APP_VERSION)
            current_year = datetime.now().year
            
            return self._load_template('spa.html', 
                                     app_name=app_name,
                                     app_version=app_version,
                                     current_year=current_year,
                                     contact_email='i@jia.by',
                                     website_url='2RTK.COM')
        
        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            """Login page"""
            if request.method == 'POST':
                username = request.form.get('username', '').strip()
                password = request.form.get('password', '').strip()
                
                if not username or not password:
                    return self._load_template('login.html', error="Username and password are required")
                
                if not (2 <= len(username) <= 50):
                    return self._load_template('login.html', error="Username must be between 2 and 50 characters")
                if not (6 <= len(password) <= 100):
                    return self._load_template('login.html', error="Password must be between 6 and 100 characters")
                
                valid, err = self._validate_alphanumeric(username, "Username")
                if not valid: return self._load_template('login.html', error=err)
                valid, err = self._validate_alphanumeric(password, "Password")
                if not valid: return self._load_template('login.html', error=err)
                
                if self.db_manager.verify_admin(username, password):
                    session['admin_logged_in'] = True
                    session['admin_username'] = username
                    redirect_page = request.args.get('redirect')
                    if redirect_page in ['users', 'mounts', 'settings']:
                        return redirect(f'/?page={redirect_page}')
                    return redirect(url_for('index'))
                else:
                    return self._load_template('login.html', error="Invalid username or password")
            
            return self._load_template('login.html')
        
        @self.app.route('/logout', methods=['GET', 'POST'])
        def logout():
            """Logout"""
            session.clear()
            if request.method == 'POST':
                return jsonify({'success': True})
            return redirect(url_for('login'))
        
        @self.app.route('/api/login', methods=['POST'])
        def api_login():
            """API Login"""
            try:
                data = request.get_json()
                if not data: return jsonify({'error': 'Invalid request format'}), 400
                username, password = data.get('username', '').strip(), data.get('password', '').strip()
                
                if not username or not password: return jsonify({'error': 'Username and password required'}), 400
                if not (2 <= len(username) <= 50): return jsonify({'error': 'Invalid username length'}), 400
                if not (6 <= len(password) <= 100): return jsonify({'error': 'Invalid password length'}), 400
                
                if self.db_manager.verify_admin(username, password):
                    session['admin_logged_in'] = True
                    session['admin_username'] = username
                    return jsonify({'success': True, 'message': 'Login successful', 'token': 'session_based'})
                else:
                    return jsonify({'error': 'Invalid username or password'}), 401
            except Exception as e:
                log_error(f"API Login failed: {e}")
                return jsonify({'error': 'Login failed'}), 500

        @self.app.route('/api/mount_info/<mount>')
        @self.require_login
        def mount_info(mount):
            """Get parsing info for a specific mount point"""
            parsed_data = rtcm_manager.get_parsed_mount_data(mount)
            statistics = rtcm_manager.get_mount_statistics(mount)
            if parsed_data:
                return jsonify({'success': True, 'data': parsed_data, 'statistics': statistics})
            else:
                return jsonify({'success': False, 'message': 'Mount point data does not exist or is not parsed'})
        
        @self.app.route('/api/system/restart', methods=['POST'])
        @self.require_login
        def restart_system():
            """System restart API"""
            try:
                import threading
                def delayed_restart():
                    time.sleep(1)
                    log_info("Admin requested system restart")
                    os._exit(0)
                threading.Thread(target=delayed_restart, daemon=True).start()
                return jsonify({'success': True, 'message': 'Restart command sent'})
            except Exception as e:
                log_error(f"Restart failed: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500
        
        @self.app.route('/api/mount/<mount_name>/rtcm-parse/start', methods=['POST'])
        @self.require_login
        def api_start_rtcm_parsing(mount_name):
            """Start real-time RTCM parsing for a mount point"""
            try:
                def push_callback(parsed_data):
                    if 'mount_name' not in parsed_data:
                        log_warning("Push data missing mount_name")
                        return
                    self.socketio.emit('rtcm_realtime_data', parsed_data)
                
                success = rtcm_manager.start_realtime_parsing(mount_name=mount_name, push_callback=push_callback)
                if success:
                    log_system_event(f"Real-time RTCM parsing started for {mount_name}")
                    return jsonify({'success': True, 'message': f'Real-time RTCM parsing started for {mount_name}'})
                else:
                    return jsonify({'error': 'Failed to start parsing - mount may be offline'}), 400
            except Exception as e:
                log_error(f"Failed to start RTCM parsing: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/mount/rtcm-parse/stop', methods=['POST'])
        @self.require_login
        def api_stop_rtcm_parsing():
            """Stop all real-time RTCM parsing"""
            try:
                rtcm_manager.stop_realtime_parsing()
                log_system_event("All real-time RTCM parsing stopped")
                return jsonify({'success': True, 'message': 'Real-time RTCM parsing stopped'})
            except Exception as e:
                log_error(f"Failed to stop RTCM parsing: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/mount/rtcm-parse/status', methods=['GET'])
        @self.require_login
        def api_get_rtcm_parsing_status():
            """Get RTCM parser status info"""
            try:
                status = rtcm_manager.get_parser_status()
                return jsonify({'success': True, 'status': status, 'message': 'Parser status retrieved successfully'})
            except Exception as e:
                log_error(f"Failed to get parser status: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/app_info')
        def api_app_info():
            """Get application info"""
            try:
                return jsonify({
                    'name': config.APP_NAME,
                    'version': config.APP_VERSION,
                    'description': config.APP_DESCRIPTION,
                    'author': config.APP_AUTHOR,
                    'contact': config.APP_CONTACT,
                    'website': config.APP_WEBSITE
                })
            except Exception as e:
                log_error(f"Failed to get app info: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/users', methods=['GET', 'POST'])
        @self.require_login
        def api_users():
            """User management API"""
            if request.method == 'GET':
                try:
                    users = self.db_manager.get_all_users()
                    online_users = connection.get_connection_manager().get_online_users()
                    user_list = []
                    for user in users:
                        username = user[1]
                        user_list.append({
                            'id': user[0],
                            'username': username,
                            'online': username in online_users,
                            'connection_count': connection.get_connection_manager().get_user_connection_count(username),
                            'connect_time': connection.get_connection_manager().get_user_connect_time(username) or '-'
                        })
                    return jsonify(user_list)
                except Exception as e:
                    log_error(f"Failed to get users: {e}")
                    return jsonify({'error': str(e)}), 500
            elif request.method == 'POST':
                try:
                    data = request.get_json()
                    if not data: return jsonify({'error': 'Invalid data format'}), 400
                    username, password = data.get('username', '').strip(), data.get('password', '').strip()
                    if not username or not password: return jsonify({'error': 'Username and password required'}), 400
                    valid, err = self._validate_alphanumeric(username, "Username")
                    if not valid: return jsonify({'error': err}), 400
                    if not (2 <= len(username) <= 50) or not (6 <= len(password) <= 100):
                        return jsonify({'error': 'Invalid length'}), 400
                    success, message = self.db_manager.add_user(username, password)
                    return jsonify({'message': message}), 201 if success else 400
                except Exception as e:
                    log_error(f"Failed to add user: {e}")
                    return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/users/<username>', methods=['PUT', 'DELETE'])
        @self.require_login
        def api_user_detail(username):
            """User detail API"""
            if request.method == 'PUT':
                try:
                    data = request.get_json()
                    new_password, new_username = data.get('password', '').strip(), data.get('username', '').strip()
                    if username == config.DEFAULT_ADMIN['username']:
                        if new_username: return jsonify({'error': 'Admin username cannot be changed'}), 400
                        if not new_password: return jsonify({'error': 'New password required'}), 400
                        success = self.db_manager.update_admin_password(username, new_password)
                        return jsonify({'message': 'Admin password updated'}) if success else 500
                    else:
                        forwarder.force_disconnect_user(username)
                        if new_username:
                            users = self.db_manager.get_all_users()
                            user_id = next((u[0] for u in users if u[1] == username), None)
                            if user_id is None: return jsonify({'error': 'User not found'}), 400
                            success, msg = self.db_manager.update_user(user_id, new_username, next(u[2] for u in users if u[1] == username))
                            return jsonify({'message': f'Username updated to {new_username}'}) if success else (jsonify({'error': msg}), 400)
                        elif new_password:
                            success, msg = self.db_manager.update_user_password(username, new_password)
                            return jsonify({'message': f'Password updated for {username}'}) if success else (jsonify({'error': msg}), 400)
                    return jsonify({'error': 'Nothing to update'}), 400
                except Exception as e:
                    log_error(f"Failed to update user: {e}")
                    return jsonify({'error': str(e)}), 500
            elif request.method == 'DELETE':
                try:
                    forwarder.force_disconnect_user(username)
                    success, result = self.db_manager.delete_user(username)
                    return jsonify({'message': f'User {result} deleted'}) if success else (jsonify({'error': result}), 400)
                except Exception as e:
                    log_error(f"Failed to delete user: {e}")
                    return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/mounts', methods=['GET', 'POST'])
        @self.require_login
        def api_mounts():
            """Mount point management API"""
            if request.method == 'GET':
                try:
                    mounts = self.db_manager.get_all_mounts()
                    online_mounts = connection.get_connection_manager().get_online_mounts()
                    mount_list = []
                    for mount in mounts:
                        mount_name = mount[1]
                        is_online = mount_name in online_mounts
                        data_rate_str = '0 B/s'
                        if is_online:
                            mount_info = connection.get_connection_manager().get_mount_info(mount_name)
                            if mount_info and 'data_rate' in mount_info:
                                dr = mount_info['data_rate']
                                data_rate_str = f'{dr/1024:.2f} KB/s' if dr >= 1024 else f'{dr:.2f} B/s'
                        mount_list.append({
                            'id': mount[0], 'mount': mount_name, 'password': mount[2],
                            'username': mount[4] if len(mount) > 4 else None,
                            'lat': mount[5] if len(mount) > 5 and mount[5] is not None else 0,
                            'lon': mount[6] if len(mount) > 6 and mount[6] is not None else 0,
                            'active': is_online,
                            'connections': connection.get_connection_manager().get_mount_connection_count(mount_name) if is_online else 0,
                            'data_rate': data_rate_str
                        })
                    return jsonify(mount_list)
                except Exception as e:
                    log_error(f"Failed to get mounts: {e}")
                    return jsonify({'error': str(e)}), 500
            elif request.method == 'POST':
                try:
                    data = request.get_json()
                    mount, password, user_id = data.get('mount', '').strip(), data.get('password', '').strip(), data.get('user_id')
                    if not mount or not password: return jsonify({'error': 'Name and password required'}), 400
                    if not (2 <= len(mount) <= 50) or not (6 <= len(password) <= 100): return jsonify({'error': 'Invalid length'}), 400
                    success, message = self.db_manager.add_mount(mount, password, user_id)
                    return jsonify({'message': message}), 201 if success else 400
                except Exception as e:
                    log_error(f"Failed to add mount: {e}")
                    return jsonify({'error': str(e)}), 500

        @self.app.route('/api/mounts/<mount_name>', methods=['PUT', 'DELETE'])
        @self.require_login
        def api_mount_detail(mount_name):
            """Mount point detail API"""
            if request.method == 'PUT':
                try:
                    data = request.get_json()
                    new_password, new_mount_name, username = data.get('password', '').strip(), data.get('mount_name', '').strip(), data.get('username')
                    new_user_id = None
                    if username:
                        users = self.db_manager.get_all_users()
                        user = next((u for u in users if u[1] == username), None)
                        if not user: return jsonify({'error': f'User "{username}" not found'}), 400
                        new_user_id = user[0]
                    forwarder.force_disconnect_mount(mount_name)
                    mounts = self.db_manager.get_all_mounts()
                    mount_id = next((m[0] for m in mounts if m[1] == mount_name), None)
                    if mount_id is None: return jsonify({'error': 'Mount not found'}), 400
                    success, result = self.db_manager.update_mount(mount_id, new_mount_name or None, new_password or None, new_user_id if username is not None else 'keep_current')
                    return jsonify({'message': 'Mount updated'}) if success else (jsonify({'error': result}), 400)
                except Exception as e:
                    log_error(f"Failed to update mount: {e}")
                    return jsonify({'error': str(e)}), 500
            elif request.method == 'DELETE':
                try:
                    forwarder.force_disconnect_mount(mount_name)
                    success, result = self.db_manager.delete_mount(mount_name)
                    if success: connection.get_connection_manager().remove_mount_connection(mount_name)
                    return jsonify({'message': f'Mount {result} deleted'}) if success else (jsonify({'error': result}), 400)
                except Exception as e:
                    log_error(f"Failed to delete mount: {e}")
                    return jsonify({'error': str(e)}), 500

        @self.app.route('/api/system/stats')
        def api_system_stats():
            """System stats API"""
            try:
                server = get_server_instance()
                if server and hasattr(server, 'get_system_stats'):
                    return jsonify(server.get_system_stats())
                return jsonify({'error': 'Unable to get system stats'}), 500
            except Exception as e:
                log_error(f"API Error getting system stats: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/str-table', methods=['GET'])
        def api_str_table():
            """Get real-time STR table data"""
            try:
                cm = connection.get_connection_manager()
                return jsonify({'success': True, 'str_data': cm.get_all_str_data(), 'mount_list': cm.generate_mount_list(), 'timestamp': time.time()})
            except Exception as e:
                log_error(f"Failed to get STR table: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500

    def _register_socketio_events(self):
        """Register SocketIO events"""
        
        @self.socketio.on('connect')
        def handle_connect():
            log_web_request('websocket', 'connect', session.get('sid', 'unknown'), 'WebSocket connected')
            join_room('data_push')
            emit('status', {'message': 'Connected successfully'})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            log_web_request('websocket', 'disconnect', session.get('sid', 'unknown'), 'WebSocket disconnected')
            try:
                current_web_mount = rtcm_manager.get_current_web_mount()
                if current_web_mount:
                    log_info(f"WebSocket disconnected, cleaning up Web parsing thread [Mount: {current_web_mount}]")
                    rtcm_manager.stop_realtime_parsing()
            except Exception as e:
                log_error(f"Failed to clean up Web parser on disconnect: {e}")
        
        @self.socketio.on('request_system_stats')
        def handle_request_system_stats():
            try:
                server = get_server_instance()
                if server and hasattr(server, 'get_system_stats'):
                    stats = server.get_system_stats()
                    if stats: emit('system_stats_update', {'stats': stats, 'timestamp': time.time()})
                    else: emit('error', {'message': 'Unable to get stats'})
                else: emit('error', {'message': 'Server instance not available'})
            except Exception as e:
                log_error(f"Failed to handle system stats request: {e}")
                emit('error', {'message': str(e)})
    
    def require_login(self, f):
        """Login decorator"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('admin_logged_in'):
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Not logged in or session expired'}), 401
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    
    def start_rtcm_parsing(self):
        """Start real-time data push thread"""
        if not self.push_running:
            self.push_running = True
            self.push_thread = Thread(target=self._push_data_loop, daemon=True)
            self.push_thread.start()
            log_system_event('Web real-time data push started')
    
    def stop_rtcm_parsing(self):
        """Stop real-time data push thread"""
        if self.push_running:
            self.push_running = False
            if self.push_thread: self.push_thread.join(timeout=5)
            log_system_event('Web real-time data push stopped')
    
    def _push_data_loop(self):
        """Real-time data push loop"""
        log_info("Data push loop started")
        while self.push_running:
            try:
                server = get_server_instance()
                if server and hasattr(server, 'get_system_stats'):
                    stats = server.get_system_stats()
                    if stats: self.socketio.emit('system_stats_update', {'stats': stats, 'timestamp': time.time()}, to='data_push')
                
                cm = connection.get_connection_manager()
                self.socketio.emit('online_users_update', {'users': cm.get_online_users(), 'timestamp': time.time()}, to='data_push')
                self.socketio.emit('online_mounts_update', {'mounts': cm.get_online_mounts(), 'timestamp': time.time()}, to='data_push')
                self.socketio.emit('str_data_update', {'str_data': cm.get_all_str_data(), 'timestamp': time.time()}, to='data_push')
                
                time.sleep(config.REALTIME_PUSH_INTERVAL)
            except Exception as e:
                log_error(f"Data push exception: {e}", exc_info=True)
                time.sleep(1)
    
    def push_log_message(self, message, log_type='info'):
        """Push log message to frontend"""
        try:
            self.socketio.emit('log_message', {'message': message, 'type': log_type, 'timestamp': time.time()}, to='data_push')
        except Exception as e:
            log_error(f"Failed to push log message: {e}")
    
    def run(self, host=None, port=None, debug=None):
        """Start Web server"""
        self.socketio.run(self.app, host=host or config.HOST, port=port or config.WEB_PORT, debug=debug if debug is not None else config.DEBUG, allow_unsafe_werkzeug=True)

def create_web_manager(db_manager, data_forwarder, start_time):
    """Create Web Manager instance"""
    return WebManager(db_manager, data_forwarder, start_time)
