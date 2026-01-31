#!/usr/bin/env python3
"""
ntrip.py - NTRIP Caster Main Program Module
Function: Listens to NTRIP request port, receives upload and download requests, validates user and mount point validity.
"""

import sys
import time
import socket
import logging
import threading
import base64
from datetime import datetime, timezone
from threading import Thread
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue, Full, Empty
from collections import defaultdict

from . import forwarder
from . import config
from . import logger
from .logger import log_debug, log_info, log_warning, log_error, log_critical, log_system_event
from . import connection

DEBUG = config.DEBUG
VERSION = config.VERSION
NTRIP_PORT = config.NTRIP_PORT
WEB_PORT = config.WEB_PORT
BUFFER_SIZE = config.BUFFER_SIZE

class AntiSpamLogger:
    def __init__(self, time_window=60, max_count=5):
        self.time_window = time_window  
        self.max_count = max_count      
        self.message_counts = defaultdict(list)  
        self.suppressed_counts = defaultdict(int)  
        self.lock = threading.Lock()
    
    def should_log(self, message_key):
        """Determine if a log should be recorded"""
        with self.lock:
            now = time.time()
            self.message_counts[message_key] = [
                timestamp for timestamp in self.message_counts[message_key]
                if now - timestamp < self.time_window
            ]
            
            if len(self.message_counts[message_key]) < self.max_count:
                self.message_counts[message_key].append(now)
                return True
            else:
                self.suppressed_counts[message_key] += 1
                return False
    
    def get_suppressed_count(self, message_key):
        """Get the number of suppressed messages"""
        with self.lock:
            count = self.suppressed_counts[message_key]
            self.suppressed_counts[message_key] = 0  
            return count

anti_spam_logger = AntiSpamLogger(time_window=60, max_count=3)
MAX_CONNECTIONS = config.MAX_CONNECTIONS
MAX_CONNECTIONS_PER_USER = config.MAX_CONNECTIONS_PER_USER
MAX_WORKERS = config.MAX_WORKERS
CONNECTION_QUEUE_SIZE = config.CONNECTION_QUEUE_SIZE

class NTRIPHandler:
    """NTRIP Request Handler"""
    
    def __init__(self, client_socket, client_address, db_manager):
        self.client_socket = client_socket
        self.client_address = client_address
        self.db_manager = db_manager
        self.ntrip_version = "1.0"
        self.protocol_type = "ntrip1_0"
        self.user_agent = ""
        self.mount = ""
        self.username = ""
        self.ntrip1_password = ""  
        self.current_method = "GET"  
        
        self.client_socket.settimeout(config.SOCKET_TIMEOUT)
        self._configure_keepalive()
    
    def _configure_keepalive(self):
        """Configure TCP Keep-Alive"""
        try:
            if not config.TCP_KEEPALIVE['enabled']:
                return
            self.client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            
            try:
                if hasattr(socket, 'TCP_KEEPIDLE'):
                    self.client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, config.TCP_KEEPALIVE['idle'])
                if hasattr(socket, 'TCP_KEEPINTVL'):
                    self.client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, config.TCP_KEEPALIVE['interval'])
                if hasattr(socket, 'TCP_KEEPCNT'):
                    self.client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, config.TCP_KEEPALIVE['count'])
                
                message_key = "tcp_keepalive_configured"
                if anti_spam_logger.should_log(message_key):
                    suppressed = anti_spam_logger.get_suppressed_count(message_key)
                    if suppressed > 0:
                        logger.log_debug(f"TCP Keep-Alive configured: idle={config.TCP_KEEPALIVE['idle']}s (Suppressed {suppressed} similar messages)", 'ntrip')
                    else:
                        logger.log_debug(f"TCP Keep-Alive configured: idle={config.TCP_KEEPALIVE['idle']}s", 'ntrip')
            except OSError:
                logger.log_debug("TCP Keep-Alive enabled (using system defaults)", 'ntrip')
        except Exception as e:
            logger.log_debug(f"Failed to configure Keep-Alive: {e}", 'ntrip')
    
    def handle_request(self):
        """Handle NTRIP request with enhanced validation and error handling"""
        try:
            log_debug(f"=== Starting request handling {self.client_address} ===")
            request_data = self.client_socket.recv(BUFFER_SIZE).decode('utf-8', errors='ignore')
            if not request_data:
                log_debug(f"Client {self.client_address} sent empty request")
                return
            
            raw_request = request_data[:200]
            sanitized_request = self._sanitize_request_for_logging(raw_request)
            log_debug(f"Detected connection request from {self.client_address}: {sanitized_request}")
            
            lines = request_data.strip().split('\r\n')
            if not lines or not lines[0].strip():
                self.send_error_response(400, "Bad Request: Empty request line")
                return
            
            request_line = lines[0]
            try:
                method, path, protocol = self._parse_request_line(request_line)
                self.current_method = method.upper()
            except ValueError as e:
                log_debug(f"Failed to parse request line {self.client_address}: {e}")
                self.send_error_response(400, f"Bad Request: {str(e)}")
                return
            
            headers = self._parse_headers(lines[1:])
            
            if self._is_empty_request(method, path, headers):
                log_debug(f"Detected empty request from {self.client_address}")
                self.send_error_response(400, "Bad Request: Empty request")
                return
            
            self._determine_ntrip_version(headers, request_line)
            
            is_valid, error_msg = self._is_valid_request(method, path, headers)
            if not is_valid:
                log_info(f"Request validation failed for {self.client_address}: {error_msg}")
                self.send_error_response(400, f"Bad Request: {error_msg}")
                return
            
            self.user_agent = headers.get('user-agent', 'Unknown')
            log_debug(f"Request validation passed for {self.client_address}: {method} {path} (Protocol: {self.protocol_type})")

            if method.upper() in ['SOURCE', 'POST']:
                self.handle_upload(path, headers)
            elif method.upper() == 'GET':
                if self.protocol_type in ['ntrip1_0_http', 'ntrip2_0', 'ntrip1_0', 'ntrip0_8']:
                    self.handle_download(path, headers)
                else:
                    self.handle_http_get(path, headers)
            elif method.upper() == 'OPTIONS':
                self.handle_options(headers)
            elif method.upper() in ['DESCRIBE', 'SETUP', 'PLAY', 'PAUSE', 'TEARDOWN', 'RECORD']:
                self.handle_rtsp_command(method, path, headers)
            else:
                self.send_error_response(405, f"Method Not Allowed: {method}")
        
        except socket.timeout:
            log_debug(f"Client {self.client_address} timed out")
            self._cleanup()
        except UnicodeDecodeError as e:
            log_debug(f"Failed to decode request {self.client_address}: {e}")
            self.send_error_response(400, "Bad Request: Invalid encoding")
            self._cleanup()
        except Exception as e:
            log_error(f"Error handling request from {self.client_address}: {e}", exc_info=True)
            self.send_error_response(500, "Internal Server Error")
            self._cleanup()
    
    def _parse_request_line(self, request_line):
        """Parse request line supporting various NTRIP versions"""
        parts = request_line.split()
        if not parts:
            raise ValueError("Empty request line")
        
        method = parts[0].upper()
        if method == 'SOURCE':
            if len(parts) >= 2:
                if len(parts) == 2:
                    url_or_path = parts[1]
                    if url_or_path.startswith('/') and not url_or_path.startswith(('http://', 'https://', 'rtsp://')):
                        return 'SOURCE', url_or_path, 'NTRIP/1.0'
                    else:
                        return self._parse_source_url_format(url_or_path)
                elif len(parts) >= 3:
                    password = parts[1]
                    mountpoint_or_url = parts[2]
                    if mountpoint_or_url.startswith(('http://', 'https://', 'rtsp://')):
                        return self._parse_source_url_format(mountpoint_or_url, password)
                    else:
                        mountpoint = mountpoint_or_url if mountpoint_or_url.startswith('/') else '/' + mountpoint_or_url
                        self.ntrip1_password = password
                        return 'SOURCE', mountpoint, 'NTRIP/1.0'
            else:
                raise ValueError(f"Invalid SOURCE request format: {request_line}")
        elif method == 'ADMIN' and len(parts) >= 3:
            password = parts[1]
            path = parts[2] if parts[2].startswith('/') else '/' + parts[2]
            self.ntrip1_password = password
            return 'ADMIN', path, 'NTRIP/1.0'
        elif len(parts) == 3:
            method, path, protocol = parts
            if not protocol.startswith('RTSP/') and not path.startswith('/'):
                path = '/' + path
            return method, path, protocol
        else:
            raise ValueError(f"Invalid request line format: {request_line}")
    
    def _parse_source_url_format(self, url, password=None):
        """Parse URL format in SOURCE request"""
        from urllib.parse import urlparse
        if url.startswith(('http://', 'https://')):
            parsed = urlparse(url)
            mountpoint = parsed.path if parsed.path and parsed.path != '/' else None
            if not mountpoint:
                raise ValueError(f"Invalid mountpoint in URL: {url}")
            if not mountpoint.startswith('/'):
                mountpoint = '/' + mountpoint
            if parsed.username and parsed.password:
                self.ntrip1_password = parsed.password
            elif password:
                self.ntrip1_password = password
            return 'SOURCE', mountpoint, 'NTRIP/0.8'
        elif url.startswith('rtsp://'):
            parsed = urlparse(url)
            mountpoint = parsed.path if parsed.path and parsed.path != '/' else None
            if not mountpoint:
                raise ValueError(f"Invalid mountpoint in RTSP URL: {url}")
            if not mountpoint.startswith('/'):
                mountpoint = '/' + mountpoint
            if parsed.username and parsed.password:
                self.ntrip1_password = parsed.password
            elif password:
                self.ntrip1_password = password
            return 'SOURCE', mountpoint, 'NTRIP/0.8'
        elif url.startswith('/'):
            if password:
                self.ntrip1_password = password
            return 'SOURCE', url, 'NTRIP/0.8'
        else:
            mountpoint = '/' + url
            if password:
                self.ntrip1_password = password
            return 'SOURCE', mountpoint, 'NTRIP/0.8'
    
    def _parse_headers(self, header_lines):
        """Parse request headers"""
        headers = {}
        for line in header_lines:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        return headers
    
    def _determine_ntrip_version(self, headers, request_line):
        """Determine NTRIP protocol type"""
        if request_line.startswith(('SOURCE ', 'ADMIN ')):
            parts = request_line.split()
            if len(parts) >= 2:
                second_param = parts[1] if len(parts) == 2 else parts[2] if len(parts) >= 3 else ""
                if (second_param.startswith(('http://', 'https://', 'rtsp://')) or 
                    (len(parts) == 2 and (second_param.startswith('/') or not second_param.startswith('http')))):
                    self.ntrip_version = "0.8"
                    self.protocol_type = "ntrip0_8"
                    message_key = f"ntrip_08_request_{self.client_address[0]}"
                    if anti_spam_logger.should_log(message_key):
                        suppressed = anti_spam_logger.get_suppressed_count(message_key)
                        logger.log_debug(f"Detected NTRIP 0.8 request: {request_line.split()[0]} - {self.client_address}" + (f" (Suppressed {suppressed} similar messages)" if suppressed > 0 else ""), 'ntrip')
                    return
            self.ntrip_version = "1.0"
            self.protocol_type = "ntrip1_0"
            message_key = f"ntrip_10_request_{self.client_address[0]}"
            if anti_spam_logger.should_log(message_key):
                suppressed = anti_spam_logger.get_suppressed_count(message_key)
                logger.log_debug(f"Detected NTRIP 1.0 request: {request_line.split()[0]} - {self.client_address}" + (f" (Suppressed {suppressed} similar messages)" if suppressed > 0 else ""), 'ntrip')
            return
        
        if 'HTTP/' in request_line:
            protocol_type = "http"
        elif 'RTSP/' in request_line:
            protocol_type = "rtsp"
            self.ntrip_version = "1.0"
            self.protocol_type = "rtsp"
            logger.log_debug(f"Detected RTSP protocol from {self.client_address}", 'ntrip')
            return
        else:
            protocol_type = "unknown"
        
        if request_line.startswith(('POST ', 'GET ')) and 'HTTP/' in request_line:
            user_agent = headers.get('user-agent', '').lower()
            if any(ntrip_ua in user_agent for ntrip_ua in ['ntrip', 'rtk', 'gnss', 'gps']):
                if '2.0' in user_agent or 'HTTP/1.1' in request_line:
                    self.ntrip_version = "2.0"
                    self.protocol_type = "ntrip2_0"
                    logger.log_debug(f"Detected NTRIP 2.0 HTTP format from {self.client_address}", 'ntrip')
                else:
                    self.ntrip_version = "1.0"
                    self.protocol_type = "ntrip1_0_http"
                    log_debug(f"Detected NTRIP 1.0 HTTP format from {self.client_address}")
                return
            
            if 'authorization' in headers:
                if 'HTTP/1.1' in request_line:
                    self.ntrip_version = "2.0"
                    self.protocol_type = "ntrip2_0"
                    log_debug(f"Detected NTRIP 2.0 HTTP auth format from {self.client_address}")
                else:
                    self.ntrip_version = "1.0"
                    self.protocol_type = "ntrip1_0_http"
                    log_debug(f"Detected NTRIP 1.0 HTTP auth format from {self.client_address}")
                return
            
            if protocol_type == "http" and "ntrip" in user_agent and path not in ["/", ""]:
                self.ntrip_version = "2.0"
                self.protocol_type = "ntrip2_0"
                log_debug(f"Detected NTRIP 2.0 based on path from {self.client_address}")
                return
        
        ntrip_version = headers.get('ntrip-version', '')
        if 'NTRIP/2.0' in ntrip_version:
            self.ntrip_version = "2.0"
            self.protocol_type = "ntrip2_0"
            log_debug(f"Detected NTRIP 2.0 protocol from {self.client_address}")
        elif protocol_type == "http":
            if self._should_downgrade_protocol(headers):
                self.ntrip_version = "1.0"
                self.protocol_type = "ntrip1_0"
                log_debug(f"Protocol downgraded to NTRIP 1.0 for {self.client_address}")
            else:
                user_agent = headers.get('user-agent', '').lower()
                if any(keyword in user_agent for keyword in ['ntrip', 'rtk', 'gnss']):
                    self.ntrip_version = "2.0"
                    self.protocol_type = "ntrip2_0"
                    log_debug(f"Detected NTRIP 2.0 based on User-Agent from {self.client_address}")
                else:
                    self.ntrip_version = "2.0"
                    self.protocol_type = "http"
                    log_debug(f"Using HTTP protocol for {self.client_address}")
        else:
            self.ntrip_version = "1.0"
            self.protocol_type = "ntrip1_0"
            log_debug(f"Defaulting to NTRIP 1.0 for {self.client_address}")
    
    def _should_downgrade_protocol(self, headers):
        """Determine if protocol should be downgraded to NTRIP 1.0"""
        user_agent = headers.get('user-agent', '').lower()
        old_clients = ['ntrip', 'rtk', 'gnss', 'leica', 'trimble']
        for client in old_clients:
            if client in user_agent and '2.0' not in user_agent:
                return True
        required_headers = ['connection', 'host']
        return any(h not in headers for h in required_headers)
    
    def _is_valid_request(self, method, path, headers):
        """Validate request validity"""
        if not method:
            return False, "Missing request method"
        if not path:
            return False, "Invalid path format"
        
        if hasattr(self, 'protocol_type') and self.protocol_type == 'rtsp':
            if not (path.startswith('/') or path.startswith('rtsp://')):
                return False, "Invalid RTSP path format"
        else:
            if not path.startswith('/'):
                return False, "Invalid path format"
        
        if self.protocol_type in ['http', 'ntrip2_0'] and 'host' not in headers:
            return False, "Missing Host header"
        
        supported_methods = ['GET', 'POST', 'SOURCE', 'ADMIN', 'OPTIONS']
        if hasattr(self, 'protocol_type') and self.protocol_type == 'rtsp':
            supported_methods.extend(['DESCRIBE', 'SETUP', 'PLAY', 'PAUSE', 'TEARDOWN', 'RECORD'])
        
        if method.upper() not in supported_methods:
            return False, f"Unsupported method: {method}"
        
        return True, "Valid request"
    
    def _is_empty_request(self, method, path, headers):
        """Check if request is empty"""
        return not method and not path and not headers
    
    def _sanitize_request_for_logging(self, request_data):
        """Filter sensitive information from request data"""
        try:
            lines = request_data.replace('\r\n', '\n').replace('\r', '\n').split('\n')
            sanitized_lines = []
            if lines:
                first_line = lines[0].strip()
                if (first_line.startswith('SOURCE ') and len(first_line.split()) >= 3) or \
                   (first_line.startswith('GET ') and len(first_line.split()) >= 3):
                    parts = first_line.split()
                    method = parts[0]
                    if method == 'SOURCE':
                        mount = parts[2]
                        sanitized_lines.append(f"{method} [PASSWORD_REDACTED] {mount}" + (f" {' '.join(parts[3:])}" if len(parts) > 3 else ""))
                    elif method == 'GET':
                        mount = parts[1]
                        sanitized_lines.append(f"{method} {mount} [PASSWORD_REDACTED]")
                    else:
                        sanitized_lines.append(first_line)
                else:
                    sanitized_lines.append(first_line)
            
            for line in lines[1:]:
                line_lower = line.lower()
                if 'authorization:' in line_lower:
                    if 'basic' in line_lower:
                        sanitized_lines.append('Authorization: Basic [REDACTED]')
                    elif 'digest' in line_lower:
                        sanitized_lines.append('Authorization: Digest [REDACTED]')
                    else:
                        sanitized_lines.append('Authorization: [REDACTED]')
                else:
                    sanitized_lines.append(line)
            return '\n'.join(sanitized_lines).replace('\r', '').strip()
        except Exception:
            return '[REQUEST DATA - SANITIZATION FAILED]'
    
    def verify_user(self, mount, auth_header, request_type="upload"):
        """Verify if NTRIP request user and mount point are valid"""
        try:
            mount_name = mount.lstrip('/')
            self.mount = mount_name
            
            if self.protocol_type == "ntrip1_0":
                if auth_header.startswith('Basic '):
                    return self._verify_basic_auth(mount, auth_header, request_type)
                elif auth_header.startswith('Digest '):
                    return self._verify_digest_auth(mount, auth_header, request_type)
                elif hasattr(self, 'ntrip1_password') and self.ntrip1_password:
                    is_valid, error_msg = self.db_manager.verify_mount_and_user(mount_name, mount_password=self.ntrip1_password)
                    if not is_valid:
                        return False, error_msg
                    self.username = f"source_{mount_name}"
                    return True, "Authentication successful"
                else:
                    return False, "Authentication required"
            
            elif self.protocol_type == "ntrip1_0_http":
                 if auth_header.startswith('Basic '):
                     return self._verify_basic_auth(mount, auth_header, request_type)
                 elif auth_header.startswith('Digest '):
                     return self._verify_digest_auth(mount, auth_header, request_type)
                 else:
                     if hasattr(self, 'ntrip1_password') and self.ntrip1_password:
                         is_valid, error_msg = self.db_manager.verify_mount_and_user(mount_name, mount_password=self.ntrip1_password, protocol_version="1.0")
                         if not is_valid:
                             return False, error_msg
                         self.username = f"http_{mount_name}"
                         return True, "Authentication successful"
                     return False, "Missing authorization"
            
            elif self.protocol_type == "ntrip0_8":
                 if hasattr(self, 'ntrip1_password') and self.ntrip1_password:
                     is_valid, error_msg = self.db_manager.verify_mount_and_user(mount_name, mount_password=self.ntrip1_password, protocol_version="1.0")
                     if not is_valid:
                         return False, error_msg
                     self.username = f"ntrip08_{mount_name}"
                     return True, "Authentication successful"
                 else:
                     return False, "Authentication required"
            
            elif self.protocol_type == "ntrip2_0":
                 if auth_header.startswith('Basic '):
                     return self._verify_basic_auth(mount, auth_header, request_type)
                 elif auth_header.startswith('Digest '):
                     return self._verify_digest_auth(mount, auth_header, request_type)
                 elif not auth_header and hasattr(self, 'ntrip1_password') and self.ntrip1_password:
                     is_valid, error_msg = self.db_manager.verify_mount_and_user(mount_name, mount_password=self.ntrip1_password, protocol_version="1.0")
                     if not is_valid:
                         return False, error_msg
                     self.username = f"ntrip20_{mount_name}"
                     return True, "Authentication successful"
                 else:
                     return False, "Invalid authorization format"
            
            elif self.protocol_type == "rtsp":
                 if auth_header.startswith('Basic '):
                     return self._verify_basic_auth(mount, auth_header, request_type)
                 elif auth_header.startswith('Digest '):
                     return self._verify_digest_auth(mount, auth_header, request_type)
                 elif not auth_header and hasattr(self, 'ntrip1_password') and self.ntrip1_password:
                     is_valid, error_msg = self.db_manager.verify_mount_and_user(mount_name, mount_password=self.ntrip1_password, protocol_version="1.0")
                     if not is_valid:
                         return False, error_msg
                     self.username = f"rtsp_{mount_name}"
                     return True, "Authentication successful"
                 else:
                     return False, "Invalid authorization format"
            
            else:
                 if not auth_header:
                     return False, "Missing authorization"
                 if not auth_header.startswith('Basic '):
                     return False, "Invalid authorization format"
                 encoded_credentials = auth_header[6:]
                 decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
                 if ':' not in decoded_credentials:
                     return False, "Invalid credentials format"
                 username, password = decoded_credentials.split(':', 1)
                 self.username = username
                 is_valid, error_msg = self.db_manager.verify_mount_and_user(mount_name, username, password, mount_password=password, protocol_version="1.0")
                 if not is_valid:
                     return False, error_msg
                 if connection.get_user_connection_count(username) >= MAX_CONNECTIONS_PER_USER:
                     return False, f"User connection limit exceeded (max: {MAX_CONNECTIONS_PER_USER})"
                 return True, "Authentication successful"
        except Exception as e:
            logger.log_error(f"User validation exception: {e}", exc_info=True)
            return False, "Authentication error"
    
    def _verify_basic_auth(self, mount, auth_header, request_type="upload"):
        """Verify Basic authentication"""
        try:
            mount_name = mount.lstrip('/')
            encoded_credentials = auth_header[6:]
            try:
                decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
            except (ValueError, UnicodeDecodeError) as e:
                logger.log_debug(f"Basic auth decode failed for {self.client_address}: {e}", 'ntrip')
                return False, "Invalid credentials format"
            
            if ':' not in decoded_credentials:
                return False, "Invalid credentials format"
            
            username, password = decoded_credentials.split(':', 1)
            self.username = username
            if request_type == "download":
                is_valid, error_msg = self.db_manager.verify_download_user(mount_name, username, password)
            else:
                protocol = "2.0" if self.protocol_type == "ntrip2_0" else "1.0"
                is_valid, error_msg = self.db_manager.verify_mount_and_user(mount_name, username, password, mount_password=password if protocol == "1.0" else None, protocol_version=protocol)
            
            if not is_valid:
                return False, error_msg
            if connection.get_user_connection_count(username) >= MAX_CONNECTIONS_PER_USER:
                return False, f"User connection limit exceeded (max: {MAX_CONNECTIONS_PER_USER})"
            return True, "Authentication successful"
        except Exception as e:
            logger.log_error(f"Basic auth exception: {e}", exc_info=True)
            return False, "Authentication error"
    
    def _verify_digest_auth(self, mount, auth_header, request_type="upload"):
        """Verify Digest authentication"""
        try:
            mount_name = mount.lstrip('/')
            digest_params = self._parse_digest_auth(auth_header)
            if not digest_params:
                return False, "Invalid digest format"
            username = digest_params.get('username')
            if not username:
                return False, "Missing username in digest"
            self.username = username
            stored_password = self.db_manager.get_user_password(username)
            if not stored_password:
                return False, "Invalid credentials"
            if not self._validate_digest_response(digest_params, stored_password, mount_name):
                return False, "Invalid digest response"
            if request_type == "download":
                is_valid, error_msg = self.db_manager.verify_download_user(mount_name, username, stored_password)
            else:
                protocol = "2.0" if self.protocol_type == "ntrip2_0" else "1.0"
                is_valid, error_msg = self.db_manager.verify_mount_and_user(mount_name, username, stored_password, mount_password=stored_password if protocol == "1.0" else None, protocol_version=protocol)
            if not is_valid:
                return False, error_msg
            if connection.get_user_connection_count(username) >= MAX_CONNECTIONS_PER_USER:
                return False, f"User connection limit exceeded (max: {MAX_CONNECTIONS_PER_USER})"
            return True, "Authentication successful"
        except Exception as e:
            logger.log_error(f"Digest auth exception: {e}", exc_info=True)
            return False, "Authentication error"
    
    def _parse_digest_auth(self, auth_header):
        """Parse Digest authentication header"""
        import re
        digest_pattern = r'(\w+)=(?:"([^"]*)"|([^,\s]*))'  
        matches = re.findall(digest_pattern, auth_header[7:])
        params = {match[0]: match[1] if match[1] else match[2] for match in matches}
        return params
    
    def _validate_digest_response(self, params, password, uri):
        """Validate Digest response"""
        import hashlib
        try:
            username, realm, nonce, response = params.get('username'), params.get('realm'), params.get('nonce'), params.get('response')
            method = getattr(self, 'current_method', 'GET')
            if not all([username, realm, nonce, response]):
                return False
            ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
            ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
            expected_response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
            return response.lower() == expected_response.lower()
        except Exception:
            return False
    
    def handle_options(self, headers):
        """Handle OPTIONS request"""
        try:
            logger.log_debug(f"OPTIONS request from {self.client_address}")
            self._send_response("HTTP/1.1 200 OK", content_type="text/plain", content="")
            logger.log_debug(f"OPTIONS request handled for {self.client_address}")
        except Exception as e:
            logger.log_error(f"Error handling OPTIONS request from {self.client_address}: {e}", exc_info=True)
            self.send_error_response(500, "Internal Server Error")
    
    def handle_rtsp_command(self, method, path, headers):
        """Handle RTSP protocol commands"""
        try:
            if path.startswith('rtsp://'):
                from urllib.parse import urlparse
                parsed = urlparse(path)
                mount = parsed.path.lstrip('/')
            else:
                mount = path.lstrip('/')
            
            if not mount:
                self.send_error_response(400, "Missing mount point")
                return
            self.mount = mount
            auth_header = headers.get('authorization', '')
            is_valid, message = self.verify_user(mount, auth_header)
            if not is_valid:
                self.send_auth_challenge(message)
                return
            
            if method.upper() == 'DESCRIBE':
                self._handle_rtsp_describe(mount, headers)
            elif method.upper() == 'SETUP':
                self._handle_rtsp_setup(mount, headers)
            elif method.upper() == 'PLAY':
                self._handle_rtsp_play(mount, headers)
            elif method.upper() == 'PAUSE':
                self._handle_rtsp_pause(mount, headers)
            elif method.upper() == 'TEARDOWN':
                self._handle_rtsp_teardown(mount, headers)
            elif method.upper() == 'RECORD':
                self._handle_rtsp_record(mount, headers)
            else:
                self.send_error_response(501, f"RTSP method not implemented: {method}")
        except Exception as e:
            logger.log_error(f"Error handling RTSP command: {e}", exc_info=True)
            self.send_error_response(500, "Internal Server Error")
    
    def _handle_rtsp_describe(self, mount, headers):
        """Handle RTSP DESCRIBE command"""
        if not connection.check_mount_exists(mount):
            self.send_error_response(404, "Mount point not found")
            return
        sdp_content = self._generate_sdp_description(mount)
        rtsp_headers = {'Content-Type': 'application/sdp', 'Content-Length': str(len(sdp_content))}
        self._send_response('RTSP/1.0 200 OK', content_type='application/sdp', content=sdp_content, additional_headers=rtsp_headers)
    
    def _handle_rtsp_setup(self, mount, headers):
        """Handle RTSP SETUP command"""
        if not connection.check_mount_exists(mount):
            cseq = headers.get('cseq', '1')
            self._send_response("RTSP/1.0 404 Not Found", additional_headers={'CSeq': cseq})
            return
        transport = headers.get('transport', 'RTP/AVP;unicast')
        client_port = '8000-8001'
        if 'client_port=' in transport:
            try:
                client_port = transport.split('client_port=')[1].split(';')[0]
            except:
                pass
        session_id = f"{mount}-{int(time.time())}"
        cseq = headers.get('cseq', '1')
        rtsp_headers = {'CSeq': cseq, 'Transport': f'RTP/AVP;unicast;client_port={client_port};server_port=8002-8003', 'Session': session_id, 'Cache-Control': 'no-cache'}
        self._send_response('RTSP/1.0 200 OK', additional_headers=rtsp_headers)
    
    def _handle_rtsp_play(self, mount, headers):
        """Handle RTSP PLAY command"""
        cseq, session = headers.get('cseq', '1'), headers.get('session', '')
        rtsp_headers = {'CSeq': cseq, 'Session': session, 'Range': 'npt=0.000-', 'RTP-Info': f'url=rtsp://{config.HOST if config.HOST != "0.0.0.0" else "localhost"}:{config.NTRIP_PORT}/{mount};seq=1;rtptime=0'}
        self._send_response('RTSP/1.0 200 OK', additional_headers=rtsp_headers)
        self.handle_download('/' + mount, headers)
    
    def _handle_rtsp_pause(self, mount, headers):
        """Handle RTSP PAUSE command"""
        cseq, session = headers.get('cseq', '1'), headers.get('session', '')
        self._send_response('RTSP/1.0 200 OK', additional_headers={'CSeq': cseq, 'Session': session})
    
    def _handle_rtsp_teardown(self, mount, headers):
        """Handle RTSP TEARDOWN command"""
        cseq, session = headers.get('cseq', '1'), headers.get('session', '')
        self._send_response('RTSP/1.0 200 OK', additional_headers={'CSeq': cseq, 'Session': session})
        self._cleanup()
    
    def _handle_rtsp_record(self, mount, headers):
        """Handle RTSP RECORD command"""
        cseq, session = headers.get('cseq', '1'), headers.get('session', '')
        self._send_response('RTSP/1.0 200 OK', additional_headers={'CSeq': cseq, 'Session': session})
        self.handle_upload('/' + mount, headers)
    
    def _generate_sdp_description(self, mount):
        """Generate SDP description"""
        origin_ip = config.HOST if config.HOST != "0.0.0.0" else "127.0.0.1"
        return f"""v=0\no=- 0 0 IN IP4 {origin_ip}\ns=NTRIP Stream {mount}\nc=IN IP4 0.0.0.0\nt=0 0\nm=application 0 RTP/AVP 96\na=rtpmap:96 rtcm/1000\na=control:*\n"""
    
    def handle_upload(self, path, headers):
        """Handle upload request"""
        try:
            message_key = f"handle_upload_{self.client_address[0]}_{path}"
            if anti_spam_logger.should_log(message_key):
                suppressed = anti_spam_logger.get_suppressed_count(message_key)
                logger.log_info(f"HANDLE_UPLOAD called for {self.client_address}: path={path}" + (f" (Suppressed {suppressed} similar messages)" if suppressed > 0 else ""))
            log_debug(f"Starting handle_upload for {self.client_address}: path={path}")
            
            connection.get_connection_manager().cleanup_zombie_connections()
            connection.get_connection_manager().force_refresh_connections()
            
            mount = path.lstrip('/')
            if not mount:
                self.send_error_response(400, "Missing mount point")
                return
            self.mount = mount
             
            if connection.get_connection_manager().is_mount_online(mount):
                existing_mount = connection.get_connection_manager().get_mount_info(mount)
                if existing_mount and existing_mount['ip_address'] != self.client_address[0]:
                    message_key = f"mount_occupied_{mount}_{existing_mount['ip_address']}"
                    if anti_spam_logger.should_log(message_key):
                        suppressed = anti_spam_logger.get_suppressed_count(message_key)
                        logger.log_warning(f"Mount point {mount} is already occupied by {existing_mount['ip_address']}, rejecting connection from {self.client_address[0]}" + (f" (Suppressed {suppressed} similar messages)" if suppressed > 0 else ""))
                    self.send_error_response(409, f"Mount point {mount} is already online from {existing_mount['ip_address']}")
                    try: self.client_socket.close()
                    except: pass
                    return
                elif existing_mount and existing_mount['ip_address'] == self.client_address[0]:
                    logger.log_warning(f"Detected duplicate connection from same IP ({self.client_address[0]}), allowing reconnection")
                    connection.get_connection_manager().remove_mount_connection(mount, "Duplicate connection from same IP")
            
            auth_header = headers.get('authorization', '')
            log_info(f"Verifying handle_upload for {self.client_address}: mount={mount}")
            is_valid, message = self.verify_user(mount, auth_header)
            log_info(f"Validation result for {self.client_address}: is_valid={is_valid}, message={message}")
            
            if not is_valid:
                log_warning(f"handle_upload authentication failed for {self.client_address}: {message}")
                self.send_auth_challenge(message)
                try: self.client_socket.close()
                except: pass
                return
             
            try:
                success, message = connection.get_connection_manager().add_mount_connection(mount, self.client_address[0], getattr(self, 'user_agent', 'Unknown'), getattr(self, 'ntrip_version', '1.0'), self.client_socket)
                if not success:
                    log_warning(f"Mount point {mount} connection rejected: {message}")
                    self.send_error_response(409, message)
                    try: self.client_socket.close()
                    except: pass
                    return
                self.mount_connection_established = True
                log_info(f"Mount point {mount} successfully added to connection manager")
            except Exception as e:
                log_error(f"Error adding mount point {mount} to connection manager: {e}", exc_info=True)

            self.send_upload_success_response()
            username_for_log = getattr(self, 'username', mount)
            logger.log_mount_operation('upload_connected', mount, username_for_log)
            log_info(f"=== Starting to receive RTCM data for mount {mount} ===")
            self._receive_rtcm_data(mount)
        except Exception as e:
            logger.log_error(f"Exception handling upload request: {e}", exc_info=True)
            self.send_error_response(500, "Internal Server Error")
    
    def handle_download(self, path, headers):
        """Handle download request"""
        try:
            if path.strip().lower() in ['/', '', '/sourcetable']:
                self._send_mount_list()
                return
            mount = path.lstrip('/')
            self.mount = mount
            auth_header = next((v for k, v in headers.items() if k.lower() == 'authorization'), '')
            is_valid, message = self.verify_user(mount, auth_header, "download")
            if not is_valid:
                self.send_auth_challenge(message)
                return
            if not self.db_manager.check_mount_exists_in_db(mount):
                self.send_error_response(404, "Mount point not found")
                return
            connection_id = connection.add_user_connection(self.username, mount, self.client_address[0])
            try:
                self.client_info = forwarder.add_client(self.client_socket, self.username, mount, self.user_agent, self.client_address, self.ntrip_version, connection_id)
                if not self.client_info:
                    self.send_error_response(500, "Failed to add client")
                    return
            except Exception as e:
                log_error(f"Failed to add client: {e}", exc_info=True)
                self.send_error_response(500, "Failed to add client")
                return
            self.send_download_success_response()
            logger.log_client_connect(self.username, mount, self.client_address[0], self.user_agent)
            self._keep_connection_alive()
        except Exception as e:
            logger.log_error(f"Exception handling download request: {e}", exc_info=True)
            self.send_error_response(500, "Internal Server Error")
    
    def handle_http_get(self, path, headers):
        """Handle standard HTTP GET request"""
        try:
            if path == '/' or path == '':
                content = "<!DOCTYPE html><html><head><title>NTRIP Caster</title></head><body><h1>NTRIP Caster Server</h1><p>This is an NTRIP Caster server.</p></body></html>"
                self._send_response("HTTP/1.1 200 OK", content_type="text/html", content=content)
            else:
                self.send_error_response(404, "Not Found")
        except Exception as e:
            logger.log_error(f"Exception handling HTTP GET request: {e}", exc_info=True)
            self.send_error_response(500, "Internal Server Error")
    
    def _receive_rtcm_data(self, mount):
        """Loop to receive RTCM data"""
        try:
            while True:
                try:
                    data = self.client_socket.recv(BUFFER_SIZE)
                    if not data:
                        log_debug(f"Mount point {mount} connection closed", 'ntrip')
                        break
                    forwarder.upload_data(mount, data)
                    connection.get_connection_manager().update_mount_data_stats(mount, len(data))
                except OSError as e:
                    log_debug(f"Mount point {mount} socket closed, stopping data reception", 'ntrip')
                    break
                except socket.timeout:
                    log_debug(f"Data reception timed out for mount {mount}", 'ntrip')
                    continue
        except Exception as e:
            logger.log_error(f"Exception receiving RTCM data: {e}", exc_info=True)
        finally:
            def delayed_cleanup():
                try: forwarder.remove_mount_buffer(mount)
                except Exception as e: log_warning(f"Failed to clean up forwarder buffer: {e}", 'ntrip')
                try: connection.get_connection_manager().remove_mount_connection(mount)
                except Exception as e: log_warning(f"Failed to clean up mount connection: {e}")
                logger.log_mount_operation('disconnected', mount)
                log_debug(f"Delayed cleanup complete for mount {mount}")
            log_warning(f"Mount point {mount} disconnected, cleaning up in 1.5 seconds")
            cleanup_timer = threading.Timer(1.5, delayed_cleanup)
            cleanup_timer.daemon = True
            cleanup_timer.start()
            self._cleanup()
    
    def _keep_connection_alive(self):
        """Keep download connection alive"""
        try:
            while True:
                time.sleep(5)  
                if hasattr(self, 'client_info') and self.client_info:
                    try: self.client_socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    except (OSError, AttributeError): break
                else: break
        except: pass
        finally:
            if hasattr(self, 'client_info') and self.client_info:
                forwarder.remove_client(self.client_info)
                logger.log_client_disconnect(self.username, self.mount, self.client_address[0])
    
    def _send_mount_list(self):
        """Send mount point list"""
        try:
            mount_list = connection.generate_mount_list()
            log_debug(f"Generated mount list: {mount_list}", 'ntrip')
            content_lines = []
            cas_line = f"CAS;{config.APP_AUTHOR};{config.NTRIP_PORT};{config.APP_NAME};{config.APP_AUTHOR};0;{config.CASTER_COUNTRY};{config.CASTER_LATITUDE};{config.CASTER_LONGITUDE};{config.HOST};0;{config.APP_WEBSITE}"
            content_lines.append(cas_line)
            net_line = f"NET;{config.APP_AUTHOR};{config.APP_AUTHOR};B;{config.CASTER_COUNTRY};{config.APP_WEBSITE};{config.APP_WEBSITE};{config.APP_CONTACT};none"
            content_lines.append(net_line)
            content_lines.extend(mount_list)
            content_str = '\r\n'.join(content_lines) + '\r\n' if content_lines else '\r\n'
            log_debug(f"Mount list content length: {len(content_str)}")
            
            current_time = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
            if self.ntrip_version == "2.0":
                response_lines = ["HTTP/1.1 200 OK", f"Server: NTRIP 2RTK caster {config.APP_VERSION}", f"Date: {current_time}", "Ntrip-Version: Ntrip/2.0", f"Content-Length: {len(content_str.encode('utf-8'))}", "Content-Type: text/plain", "Connection: close", "", content_str]
                response = '\r\n'.join(response_lines)
                try:
                    self.client_socket.send(response.encode('utf-8'))
                    log_debug(f"Sent NTRIP 2.0 mount list to {self.client_address}")
                except Exception as e: log_error(f"Failed to send NTRIP 2.0 mount list: {e}", exc_info=True)
            else:
                response_lines = ["SOURCETABLE 200 OK", f"Server: NTRIP 2RTK caster {config.APP_VERSION}", f"Date: {current_time}", "Ntrip-Version: Ntrip/1.0", f"Content-Length: {len(content_str.encode('utf-8'))}", "Content-Type: text/plain", "Connection: close", "", content_str, "ENDSOURCETABLE"]
                response = '\r\n'.join(response_lines)
                try:
                    self.client_socket.send(response.encode('utf-8'))
                    log_debug(f"Sent NTRIP 1.0 mount list to {self.client_address}")
                except Exception as e: log_error(f"Failed to send NTRIP 1.0 mount list: {e}", exc_info=True)
        except Exception as e: log_error(f"Exception sending mount list: {e}", exc_info=True)
    
    def send_upload_success_response(self):
        """Send upload success response"""
        if self.ntrip_version == "2.0":
            self._send_response("HTTP/1.1 200 OK", additional_headers=["Connection: keep-alive"])
        else:
            try: self.client_socket.send("ICY 200 OK\r\n\r\n".encode('utf-8'))
            except Exception as e: log_error(f"Failed to send upload success response: {e}", exc_info=True)
    
    def send_download_success_response(self):
        """Send download success response"""
        if self.ntrip_version == "2.0":
            self._send_response("HTTP/1.1 200 OK", content_type="application/octet-stream", additional_headers=["Connection: keep-alive"])
        else:
            try:
                self.client_socket.send("ICY 200 OK\r\nConnection: keep-alive\r\n\r\n".encode('utf-8'))
                log_debug(f"NTRIP 1.0 download response sent, maintaining long connection for {self.client_address}", 'ntrip')
            except Exception as e: log_error(f"Failed to send download success response: {e}", exc_info=True)
    
    def send_auth_challenge(self, message="Authentication required", auth_type="both"):
        """Send authentication challenge"""
        import secrets
        nonce = secrets.token_hex(16)
        realm = "NTRIP"
        auth_headers = []
        if auth_type in ["basic", "both"]: auth_headers.append(f'WWW-Authenticate: Basic realm="{realm}"')
        if auth_type in ["digest", "both"]: auth_headers.append(f'WWW-Authenticate: Digest realm="{realm}", nonce="{nonce}", algorithm=MD5, qop="auth"')
        
        if self.ntrip_version == "2.0":
            self._send_response("HTTP/1.1 401 Unauthorized", content_type="text/plain", content=message, additional_headers=auth_headers)
        else:
            try:
                response = "SOURCETABLE 401 Unauthorized\r\n" + "".join([f"{h}\r\n" for h in auth_headers]) + "\r\n"
                self.client_socket.send(response.encode('utf-8'))
            except Exception as e: log_error(f"Failed to send auth challenge: {e}", exc_info=True)
    
    def send_error_response(self, code, message):
        """Send HTTP error response"""
        if self.ntrip_version == "2.0":
            status_messages = {400: "Bad Request", 401: "Unauthorized", 404: "Not Found", 405: "Method Not Allowed", 409: "Conflict", 500: "Internal Server Error"}
            self._send_response(f"HTTP/1.1 {code} {status_messages.get(code, 'Error')}", content_type="text/plain", content=message)
        else:
            try: self.client_socket.send(f"ERROR {code} {message}\r\n\r\n".encode('utf-8'))
            except Exception as e: log_error(f"Failed to send error response: {e}", exc_info=True)
    
    def _generate_standard_headers(self, additional_headers=None):
        """Generate standard HTTP response headers"""
        current_time = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        headers = []
        if self.protocol_type == "ntrip2_0":
            headers.extend(["Ntrip-Version: NTRIP/2.0", "Cache-Control: no-cache, no-store, must-revalidate", "Pragma: no-cache", "Expires: 0"])
        elif self.protocol_type == "rtsp":
            headers.extend(["CSeq: 1", f"Session: {id(self)}"])
        elif self.ntrip_version == "2.0":
            headers.append("Ntrip-Version: NTRIP/2.0")
        headers.extend([f"Date: {current_time}", f"Server: {config.APP_NAME}/{config.VERSION}", "X-Content-Type-Options: nosniff", "X-Frame-Options: DENY"])
        if additional_headers: headers.extend(additional_headers)
        return "\r\n".join(headers) + "\r\n"
    
    def _send_response(self, status_line, content_type=None, content=None, additional_headers=None):
        """Send standardized HTTP response"""
        try:
            response = status_line + "\r\n"
            headers = []
            if content_type: headers.append(f"Content-Type: {content_type}")
            if content: headers.append(f"Content-Length: {len(content)}")
            response += self._generate_standard_headers(headers + (additional_headers or [])) + "\r\n"
            if content: response += content
            self.client_socket.send(response.encode('utf-8'))
        except Exception as e: log_error(f"Failed to send response: {e}", exc_info=True)
    
    def _cleanup(self):
        """Clean up resources"""
        try:
            if hasattr(self, 'username') and hasattr(self, 'mount'):
                if hasattr(self, 'client_info'):
                    connection.remove_user_connection(self.username, self.client_address[0], self.mount)
                else:
                    if hasattr(self, 'mount_connection_established') and self.mount_connection_established:
                        connection.remove_mount_connection(self.mount)
            self.client_socket.close()
        except Exception as e: log_error(f"Error cleaning up resources: {e}", exc_info=True)

class NTRIPCaster:
    """NTRIP Caster Server - Handles high concurrent connections using thread pool"""
    
    def __init__(self, db_manager):
        self.server_socket = None
        self.running = False
        self.db_manager = db_manager
        self.thread_pool = None
        self.connection_queue = Queue(maxsize=CONNECTION_QUEUE_SIZE)
        self.active_connections = 0
        self.connection_lock = threading.Lock()
        self.total_connections = 0
        self.rejected_connections = 0
    
    def start(self):
        """Start NTRIP server"""
        try:
            self._start_ntrip_server()
            log_system_event(f'NTRIP server started, listening on port: {NTRIP_PORT}')
            self._main_loop()
        except Exception as e:
            log_error(f"Failed to start NTRIP server: {e}", exc_info=True)
            self.stop()
    
    def _start_ntrip_server(self):
        """Initialize NTRIP server socket and thread pool"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('0.0.0.0', NTRIP_PORT))
        self.server_socket.listen(MAX_CONNECTIONS)
        self.running = True
        self.thread_pool = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="NTRIP-Worker")
        self._start_connection_handler()
        ntrip_urls = config.get_display_urls(NTRIP_PORT, "NTRIP Server")
        log_system_event('NTRIP server started, accessible via the following addresses:')
        for url in ntrip_urls: log_system_event(f'  - {url}')
        log_system_event(f'Thread pool size: {MAX_WORKERS}, Connection queue size: {CONNECTION_QUEUE_SIZE}')
    
    def _main_loop(self):
        """Main loop to accept client connections"""
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                with self.connection_lock:
                    if self.active_connections >= MAX_CONNECTIONS:
                        log_warning(f"Connection limit reached ({MAX_CONNECTIONS}), rejecting {client_address}")
                        client_socket.close()
                        self.rejected_connections += 1
                        continue
                try:
                    self.connection_queue.put((client_socket, client_address), timeout=1.0)
                    with self.connection_lock: self.total_connections += 1
                    log_info(f"Accepted connection from {client_address}, queue size: {self.connection_queue.qsize()}, active: {self.active_connections}")
                except Full:
                    log_warning(f"Connection queue full, rejecting {client_address}")
                    client_socket.close()
                    self.rejected_connections += 1
            except socket.error as e:
                if self.running: log_error(f"Socket accept error: {e}", exc_info=True)
                break
            except Exception as e:
                log_error(f"Main loop exception: {e}", exc_info=True)
                break
    
    def _start_connection_handler(self):
        """Start connection handler thread"""
        handler_thread = Thread(target=self._connection_handler, daemon=True)
        handler_thread.start()
        log_debug("Connection handler started")
    
    def _connection_handler(self):
        """Process connections from queue and submit to thread pool"""
        while self.running:
            try:
                client_socket, client_address = self.connection_queue.get(timeout=1.0)
                self.thread_pool.submit(self._handle_client_connection, client_socket, client_address)
                with self.connection_lock: self.active_connections += 1
                log_info(f"Connection {client_address} submitted to thread pool")
            except Empty: continue
            except Exception as e: log_error(f"Connection handler exception: {e}", exc_info=True)
    
    def _handle_client_connection(self, client_socket, client_address):
        """Handle individual client connection"""
        try:
            handler = NTRIPHandler(client_socket, client_address, self.db_manager)
            handler.handle_request()
        except Exception as e: log_error(f"Exception handling client {client_address}: {e}", exc_info=True)
        finally:
            with self.connection_lock: self.active_connections -= 1
            try: client_socket.close()
            except: pass
            log_info(f"Client {client_address} processing complete, active connections: {self.active_connections}")
    
    def get_performance_stats(self):
        """Get performance statistics"""
        with self.connection_lock:
            return {'active_connections': self.active_connections, 'total_connections': self.total_connections, 'rejected_connections': self.rejected_connections, 'queue_size': self.connection_queue.qsize(), 'max_connections': MAX_CONNECTIONS, 'max_workers': MAX_WORKERS, 'connection_queue_size': CONNECTION_QUEUE_SIZE}
    
    def log_performance_stats(self):
        """Log performance statistics"""
        stats = self.get_performance_stats()
        log_info(f"Performance stats - Active: {stats['active_connections']}/{stats['max_connections']}, Queue: {stats['queue_size']}/{stats['connection_queue_size']}, Total: {stats['total_connections']}, Rejected: {stats['rejected_connections']}")
    
    def stop(self):
        """Stop NTRIP server"""
        log_system_event('Closing NTRIP server')
        self.running = False
        if self.server_socket:
            try: self.server_socket.close()
            except: pass
        if self.thread_pool:
            log_system_event("Shutting down thread pool...")
            self.thread_pool.shutdown(wait=True)
            log_system_event("Thread pool closed")
        while not self.connection_queue.empty():
            try:
                client_socket, client_address = self.connection_queue.get_nowait()
                client_socket.close()
            except Empty: break
            except Exception as e: log_error(f"Error cleaning connection queue: {e}", exc_info=True)
        log_system_event(f'NTRIP server stopped - Total: {self.total_connections}, Rejected: {self.rejected_connections}')
