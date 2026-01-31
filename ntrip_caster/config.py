#!/usr/bin/env python3
"""
config.py - Configuration file
Reads all configuration parameters for NTRIP Caster from config.ini file
"""

import os
import socket
import configparser
from pathlib import Path
from typing import List, Tuple

CONFIG_FILE = os.environ.get('NTRIP_CONFIG_FILE', 
                            os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.ini'))

config = configparser.ConfigParser()

if os.path.exists(CONFIG_FILE):
    print(f"Loading configuration file: {CONFIG_FILE}")
    config.read(CONFIG_FILE, encoding='utf-8')
else:
    raise FileNotFoundError(f"Configuration file {CONFIG_FILE} does not exist")

def get_config_value(section, key, fallback=None, value_type=str):
    """Get configuration value and convert type"""
    try:
        if value_type == bool:
            return config.getboolean(section, key, fallback=fallback)
        elif value_type == int:
            return config.getint(section, key, fallback=fallback)
        elif value_type == float:
            return config.getfloat(section, key, fallback=fallback)
        elif value_type == list:
            value = config.get(section, key, fallback='')
            return [item.strip() for item in value.split(',') if item.strip()] if value else fallback or []
        else:
            return config.get(section, key, fallback=fallback)
    except (configparser.NoSectionError, configparser.NoOptionError):
        return fallback

# ==================== Basic Configuration ====================

# Basic application information
APP_NAME = get_config_value('app', 'name', '2RTK Ntrip Caster')
APP_VERSION = get_config_value('app', 'version', '2.2.0')
APP_DESCRIPTION = get_config_value('app', 'description', 'Ntrip Caster')
APP_AUTHOR = get_config_value('app', 'author', '2rtk')
APP_CONTACT = get_config_value('app', 'contact', 'i@jia.by')
APP_WEBSITE = get_config_value('app', 'website', 'https://2rtk.com')

VERSION = APP_VERSION

DEBUG = get_config_value('development', 'debug_mode', False, bool)

# ==================== CASTER Configuration ====================

# NTRIP Caster geographic information
CASTER_COUNTRY = get_config_value('caster', 'country', 'CHN')
CASTER_LATITUDE = get_config_value('caster', 'latitude', 25.20341154, float)
CASTER_LONGITUDE = get_config_value('caster', 'longitude', 110.277492, float)

# ==================== Network Configuration ====================

def get_all_network_interfaces() -> List[Tuple[str, str]]:
    """Get IP addresses of all network interfaces"""
    interfaces = []
    
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            family, socktype, proto, canonname, sockaddr = info
            if family == socket.AF_INET:  # Only IPv4
                ip = sockaddr[0]
                if ip not in [addr[1] for addr in interfaces]:  # Avoid duplicates
                    interfaces.append((f"Interface-{len(interfaces)+1}", ip))
    except Exception:
        pass
    
    if not any(addr[1] == '127.0.0.1' for addr in interfaces):
        interfaces.append(("Loopback", "127.0.0.1"))
    
    return interfaces

def get_private_ips() -> List[Tuple[str, str]]:
    """Get all private IP addresses"""
    private_ips = []
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            primary_ip = s.getsockname()[0]
            private_ips.append(("Primary", primary_ip))
    except Exception:
        pass
    
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            family, socktype, proto, canonname, sockaddr = info
            if family == socket.AF_INET:
                ip = sockaddr[0]
                if (ip.startswith('192.168.') or 
                    ip.startswith('10.') or 
                    ip.startswith('172.') or 
                    ip == '127.0.0.1'):
                    if ip not in [addr[1] for addr in private_ips]:
                        interface_name = f"Interface-{len(private_ips)+1}"
                        if ip == '127.0.0.1':
                            interface_name = "Loopback"
                        elif ip.startswith('192.168.'):
                            interface_name = "LAN"
                        private_ips.append((interface_name, ip))
    except Exception:
        pass
    
    return private_ips

def get_display_urls(port: int, service_name: str = "Service") -> List[str]:
    """Get all accessible URLs for display"""
    urls = []
    
    listen_host = get_config_value('network', 'host', '0.0.0.0')
    
    if listen_host == '0.0.0.0':
        for interface_name, ip in get_private_ips():
            urls.append(f"http://{ip}:{port}")
    else:
        urls.append(f"http://{listen_host}:{port}")
    
    return urls

# Network settings
HOST = get_config_value('network', 'host', '0.0.0.0') 

NTRIP_HOST = HOST  
NTRIP_PORT = get_config_value('ntrip', 'port', 2101, int)  # NTRIP service port

WEB_HOST = HOST  # Web service listen address
WEB_PORT = get_config_value('web', 'port', 5757, int)      # Web service port

# Maximum connections
MAX_CONNECTIONS = get_config_value('network', 'max_connections', 5000, int)

# Buffer size
BUFFER_SIZE = get_config_value('network', 'buffer_size', 81920, int)      # 80KB
MAX_BUFFER_SIZE = get_config_value('network', 'max_buffer_size', 655360, int) # 640KB

# ==================== Database Configuration ====================

DATABASE_PATH = get_config_value('database', 'path', '2rtk.db')
DB_POOL_SIZE = get_config_value('database', 'pool_size', 10, int)
DB_TIMEOUT = get_config_value('database', 'timeout', 30, int)

# ==================== Logging Configuration ====================

LOG_DIR = get_config_value('logging', 'log_dir', 'logs')
LOG_FILES = {
    'main': get_config_value('logging', 'main_log_file', 'main.log'),
    'ntrip': get_config_value('logging', 'ntrip_log_file', 'ntrip.log'), 
    'errors': get_config_value('logging', 'error_log_file', 'errors.log')
}

LOG_LEVEL = get_config_value('logging', 'log_level', "WARNING")

LOG_FORMAT = get_config_value('logging', 'log_format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

LOG_MAX_SIZE = get_config_value('logging', 'max_log_size', 10 * 1024 * 1024, int)  # 10MB

LOG_BACKUP_COUNT = get_config_value('logging', 'backup_count', 5, int)  # Keep 5 backup files

LOG_FREQUENT_STATUS = get_config_value('logging', 'log_frequent_status', False, bool)

# Flask Secret Key
SECRET_KEY = get_config_value('security', 'secret_key', '8f4a9c2e7d1b6f3a5e8d7c9b2a4f6e3d5c8b7a9f2e4d6c8b3a5f7e9d1c2b4a6')
FLASK_SECRET_KEY = SECRET_KEY

# Password hash configuration
PASSWORD_HASH_ROUNDS = get_config_value('security', 'password_hash_rounds', 3, int)
SESSION_TIMEOUT = get_config_value('security', 'session_timeout', 3600, int)  # 1 hour

# Default administrator account
DEFAULT_ADMIN = {
    'username': get_config_value('admin', 'username', 'admin'),
    'password': get_config_value('admin', 'password', 'admin123')
}

# ==================== NTRIP Protocol Configuration ====================

SUPPORTED_NTRIP_VERSIONS = get_config_value('ntrip', 'supported_versions', ['1.0', '2.0'], list)

DEFAULT_NTRIP_VERSION = get_config_value('ntrip', 'default_version', '1.0')
MAX_USER_CONNECTIONS_PER_MOUNT = get_config_value('ntrip', 'max_user_connections_per_mount', 3000, int)
MAX_USERS_PER_MOUNT = get_config_value('ntrip', 'max_users_per_mount', 3000, int)
MAX_CONNECTIONS_PER_USER = get_config_value('ntrip', 'max_connections_per_user', 3, int)
MOUNT_TIMEOUT = get_config_value('ntrip', 'mount_timeout', 1800, int)  # 30 minutes
CLIENT_TIMEOUT = get_config_value('ntrip', 'client_timeout', 300, int)  # 5 minutes
CONNECTION_TIMEOUT = get_config_value('ntrip', 'connection_timeout', 1800, int)  # Connection timeout (seconds)

# ==================== TCP Configuration ====================

# TCP Keep-Alive Configuration
TCP_KEEPALIVE = {
    'enabled': get_config_value('tcp', 'keepalive_enabled', True, bool),
    'idle': get_config_value('tcp', 'keepalive_idle', 60, int),
    'interval': get_config_value('tcp', 'keepalive_interval', 10, int),
    'count': get_config_value('tcp', 'keepalive_count', 3, int)
}
SOCKET_TIMEOUT = get_config_value('tcp', 'socket_timeout', 120, int)

# ==================== Data Forwarding Configuration ====================

# Ring buffer configuration
RING_BUFFER_SIZE = get_config_value('data_forwarding', 'ring_buffer_size', 60, int)

BROADCAST_INTERVAL = get_config_value('data_forwarding', 'broadcast_interval', 0.01, float)

DATA_SEND_TIMEOUT = get_config_value('data_forwarding', 'data_send_timeout', 5, int)

CLIENT_HEALTH_CHECK_INTERVAL = get_config_value('data_forwarding', 'client_health_check_interval', 120, int)

# ==================== RTCM Parsing ====================

# RTCM parsing interval (seconds)
RTCM_PARSE_INTERVAL = get_config_value('rtcm', 'parse_interval', 5, int)

# RTCM buffer size
RTCM_BUFFER_SIZE = get_config_value('rtcm', 'buffer_size', 1000, int)

# RTCM data parsing duration (seconds) - used to correct STR table
RTCM_PARSE_DURATION = get_config_value('rtcm', 'parse_duration', 30, int)

# RTCM message type descriptions
RTCM_MESSAGE_DESCRIPTIONS = {
    1001: "L1-Only GPS RTK Observables",
    1002: "Extended L1-Only GPS RTK Observables", 
    1003: "L1&L2 GPS RTK Observables",
    1004: "Extended L1&L2 GPS RTK Observables",
    1005: "Stationary RTK Reference Station ARP",
    1006: "Stationary RTK Reference Station ARP with Antenna Height",
    1007: "Antenna Descriptor",
    1008: "Antenna Descriptor & Serial Number",
    1009: "L1-Only GLONASS RTK Observables",
    1010: "Extended L1-Only GLONASS RTK Observables",
    1011: "L1&L2 GLONASS RTK Observables",
    1012: "Extended L1&L2 GLONASS RTK Observables",
    1013: "System Parameters",
    1019: "GPS Ephemerides",
    1020: "GLONASS Ephemerides",
    1033: "Receiver and Antenna Descriptors",
    1074: "GPS MSM4",
    1075: "GPS MSM5",
    1077: "GPS MSM7",
    1084: "GLONASS MSM4",
    1085: "GLONASS MSM5",
    1087: "GLONASS MSM7",
    1094: "Galileo MSM4",
    1095: "Galileo MSM5",
    1097: "Galileo MSM7",
    1124: "BeiDou MSM4",
    1125: "BeiDou MSM5",
    1127: "BeiDou MSM7"
}

# ==================== Web Interface Configuration ====================

# WebSocket Configuration
WEBSOCKET_CONFIG = {
    'ping_timeout': get_config_value('websocket', 'ping_timeout', 120, int),
    'ping_interval': get_config_value('websocket', 'ping_interval', 15, int)
}
WEBSOCKET_ENABLED = get_config_value('websocket', 'enabled', True, bool)

# Real-time data push interval (seconds)
REALTIME_PUSH_INTERVAL = get_config_value('web', 'realtime_push_interval', 3, int)

PAGE_REFRESH_INTERVAL = get_config_value('web', 'page_refresh_interval', 30, int)

# ==================== Reserved ====================
# Payment QR Code URLs
PAYMENT_QR_CODES = {
    'alipay': get_config_value('payment', 'alipay_qr_code', ''),
    'wechat': get_config_value('payment', 'wechat_qr_code', '')
}

ALIPAY_QR_URL = PAYMENT_QR_CODES['alipay']
WECHAT_QR_URL = PAYMENT_QR_CODES['wechat']

# Performance configuration
THREAD_POOL_SIZE = get_config_value('performance', 'thread_pool_size', 5000, int)
MAX_WORKERS = get_config_value('performance', 'max_workers', 5000, int)
CONNECTION_QUEUE_SIZE = get_config_value('performance', 'connection_queue_size', 5000, int)

MAX_MEMORY_USAGE = get_config_value('performance', 'max_memory_usage', 2048, int)

CPU_WARNING_THRESHOLD = get_config_value('performance', 'cpu_warning_threshold', 80, int)

MEMORY_WARNING_THRESHOLD = get_config_value('performance', 'memory_warning_threshold', 80, int)

def load_from_env():
    """Load configuration from environment variables"""
    global NTRIP_PORT, WEB_PORT, DEBUG, DATABASE_PATH
    
    if 'NTRIP_PORT' in os.environ:
        try:
            NTRIP_PORT = int(os.environ['NTRIP_PORT'])
        except ValueError:
            pass
    
    if 'WEB_PORT' in os.environ:
        try:
            WEB_PORT = int(os.environ['WEB_PORT'])
        except ValueError:
            pass
    
    if 'DEBUG' in os.environ:
        DEBUG = os.environ['DEBUG'].lower() in ('true', '1', 'yes', 'on')
    
    if 'DATABASE_PATH' in os.environ:
        DATABASE_PATH = os.environ['DATABASE_PATH']
    
    if 'SECRET_KEY' in os.environ:
        global SECRET_KEY
        SECRET_KEY = os.environ['SECRET_KEY']

# ==================== Configuration Validation ====================

def validate_config():
    """Validate configuration parameters"""
    errors = []
    
    if not (1024 <= NTRIP_PORT <= 65535):
        errors.append(f"NTRIP port {NTRIP_PORT} is out of valid range (1024-65535)")
    
    if not (1024 <= WEB_PORT <= 65535):
        errors.append(f"Web port {WEB_PORT} is out of valid range (1024-65535)")
    
    if BUFFER_SIZE <= 0 or BUFFER_SIZE > MAX_BUFFER_SIZE:
        errors.append(f"Buffer size {BUFFER_SIZE} is invalid")
    
    if not os.path.exists(LOG_DIR):
        try:
            os.makedirs(LOG_DIR)
        except Exception as e:
            errors.append(f"Cannot create log directory {LOG_DIR}: {e}")
    
    return errors

def init_config():
    """Initialize configuration"""
    load_from_env()
    errors = validate_config()
    if errors:
        return False
    return True

def get_config_dict():
    """Get configuration dictionary for debugging"""
    return {
        'version': VERSION,
        'app_name': APP_NAME,
        'debug': DEBUG,
        'ntrip_host': NTRIP_HOST,
        'ntrip_port': NTRIP_PORT,
        'web_host': WEB_HOST,
        'web_port': WEB_PORT,
        'max_connections': MAX_CONNECTIONS,
        'buffer_size': BUFFER_SIZE,
        'database_path': DATABASE_PATH,
        'log_level': LOG_LEVEL,
        'tcp_keepalive': TCP_KEEPALIVE,
        'ring_buffer_size': RING_BUFFER_SIZE,
        'rtcm_parse_interval': RTCM_PARSE_INTERVAL
    }
