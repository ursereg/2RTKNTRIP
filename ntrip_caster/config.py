#!/usr/bin/env python3
"""
config.py - Configuration module
Reads configuration parameters from JSON, YAML or INI file using Pydantic
"""

import os
import socket
import configparser
import json
import yaml
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# ==================== Models ====================

class AppConfig(BaseModel):
    name: str = "2RTK Ntrip Caster"
    version: str = "2.2.0"
    description: str = "Ntrip Caster"
    author: str = "2rtk"
    contact: str = "i@jia.by"
    website: str = "https://2rtk.com"

class DevelopmentConfig(BaseModel):
    debug_mode: bool = False

class CasterConfig(BaseModel):
    country: str = "CHN"
    latitude: float = 25.20341154
    longitude: float = 110.277492

class NetworkConfig(BaseModel):
    host: str = "0.0.0.0"
    max_connections: int = 5000
    buffer_size: int = 81920
    max_buffer_size: int = 655360

class NtripConfig(BaseModel):
    port: int = Field(default=2101, ge=1024, le=65535)
    supported_versions: List[str] = ["1.0", "2.0"]
    default_version: str = "1.0"
    max_user_connections_per_mount: int = 3000
    max_users_per_mount: int = 3000
    max_connections_per_user: int = 3
    mount_timeout: int = 1800
    client_timeout: int = 300
    connection_timeout: int = 1800

class WebConfig(BaseModel):
    port: int = Field(default=5757, ge=1024, le=65535)
    realtime_push_interval: int = 3
    page_refresh_interval: int = 30

class DatabaseConfig(BaseModel):
    path: str = "2rtk.db"
    pool_size: int = 10
    timeout: int = 30

class LoggingConfig(BaseModel):
    log_dir: str = "logs"
    main_log_file: str = "main.log"
    ntrip_log_file: str = "ntrip.log"
    error_log_file: str = "errors.log"
    log_level: str = "WARNING"
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    max_log_size: int = 10 * 1024 * 1024
    backup_count: int = 5
    log_frequent_status: bool = False

class SecurityConfig(BaseModel):
    secret_key: str = "8f4a9c2e7d1b6f3a5e8d7c9b2a4f6e3d5c8b7a9f2e4d6c8b3a5f7e9d1c2b4a6"
    password_hash_rounds: int = 3
    session_timeout: int = 3600

class AdminConfig(BaseModel):
    username: str = "admin"
    password: str = "admin123"

class TcpConfig(BaseModel):
    keepalive_enabled: bool = True
    keepalive_idle: int = 60
    keepalive_interval: int = 10
    keepalive_count: int = 3
    socket_timeout: int = 120

class DataForwardingConfig(BaseModel):
    ring_buffer_size: int = 60
    broadcast_interval: float = 0.01
    data_send_timeout: int = 5
    client_health_check_interval: int = 120

class RtcmConfig(BaseModel):
    parse_interval: int = 5
    buffer_size: int = 1000
    parse_duration: int = 30

class WebsocketConfig(BaseModel):
    enabled: bool = True
    ping_timeout: int = 120
    ping_interval: int = 15

class PaymentConfig(BaseModel):
    alipay_qr_code: str = ""
    wechat_qr_code: str = ""

class PerformanceConfig(BaseModel):
    thread_pool_size: int = 5000
    max_workers: int = 5000
    connection_queue_size: int = 5000
    max_memory_usage: int = 2048
    cpu_warning_threshold: int = 80
    memory_warning_threshold: int = 80

class Settings(BaseSettings):
    app: AppConfig = AppConfig()
    development: DevelopmentConfig = DevelopmentConfig()
    caster: CasterConfig = CasterConfig()
    network: NetworkConfig = NetworkConfig()
    ntrip: NtripConfig = NtripConfig()
    web: WebConfig = WebConfig()
    database: DatabaseConfig = DatabaseConfig()
    logging: LoggingConfig = LoggingConfig()
    security: SecurityConfig = SecurityConfig()
    admin: AdminConfig = AdminConfig()
    tcp: TcpConfig = TcpConfig()
    data_forwarding: DataForwardingConfig = DataForwardingConfig()
    rtcm: RtcmConfig = RtcmConfig()
    websocket: WebsocketConfig = WebsocketConfig()
    payment: PaymentConfig = PaymentConfig()
    performance: PerformanceConfig = PerformanceConfig()

    model_config = SettingsConfigDict(env_nested_delimiter='__', env_prefix='NTRIP_CASTER_')

# ==================== Load Configuration ====================

def load_settings() -> Settings:
    config_file = os.environ.get('NTRIP_CONFIG_FILE')

    if not config_file:
        defaults = ['config.yaml', 'config.yml', 'config.json', 'config.ini']
        root_dir = Path(__file__).parent.parent
        for d in defaults:
            p = root_dir / d
            if p.exists():
                config_file = str(p)
                break

    if not config_file or not os.path.exists(config_file):
        # Even if file doesn't exist, pydantic-settings will still load from env vars
        return Settings()

    ext = os.path.splitext(config_file)[1].lower()

    try:
        if ext in ('.yaml', '.yml'):
            with open(config_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                return Settings.model_validate(data)
        elif ext == '.json':
            with open(config_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return Settings.model_validate(data)
        elif ext == '.ini':
            cp = configparser.ConfigParser()
            cp.read(config_file, encoding='utf-8')
            data = {}
            for section in cp.sections():
                section_data = {}
                for key, value in cp.items(section):
                    # INI values are always strings, Pydantic will try to convert them
                    # But for lists, we need to handle it
                    if section == 'ntrip' and key == 'supported_versions':
                        section_data[key] = [item.strip() for item in value.split(',') if item.strip()]
                    else:
                        section_data[key] = value
                data[section] = section_data
            return Settings.model_validate(data)
    except Exception as e:
        print(f"Error loading config file {config_file}: {e}")

    return Settings()

settings = load_settings()

def update_globals():
    """Update global variables from settings object"""
    global APP_NAME, APP_VERSION, APP_DESCRIPTION, APP_AUTHOR, APP_CONTACT, APP_WEBSITE, VERSION
    global DEBUG, CASTER_COUNTRY, CASTER_LATITUDE, CASTER_LONGITUDE, HOST, NTRIP_HOST, NTRIP_PORT
    global WEB_HOST, WEB_PORT, MAX_CONNECTIONS, BUFFER_SIZE, MAX_BUFFER_SIZE, DATABASE_PATH
    global DB_POOL_SIZE, DB_TIMEOUT, LOG_DIR, LOG_FILES, LOG_LEVEL, LOG_FORMAT, LOG_MAX_SIZE
    global LOG_BACKUP_COUNT, LOG_FREQUENT_STATUS, SECRET_KEY, FLASK_SECRET_KEY, PASSWORD_HASH_ROUNDS
    global SESSION_TIMEOUT, DEFAULT_ADMIN, SUPPORTED_NTRIP_VERSIONS, DEFAULT_NTRIP_VERSION
    global MAX_USER_CONNECTIONS_PER_MOUNT, MAX_USERS_PER_MOUNT, MAX_CONNECTIONS_PER_USER
    global MOUNT_TIMEOUT, CLIENT_TIMEOUT, CONNECTION_TIMEOUT, TCP_KEEPALIVE, SOCKET_TIMEOUT
    global RING_BUFFER_SIZE, BROADCAST_INTERVAL, DATA_SEND_TIMEOUT, CLIENT_HEALTH_CHECK_INTERVAL
    global RTCM_PARSE_INTERVAL, RTCM_BUFFER_SIZE, RTCM_PARSE_DURATION, WEBSOCKET_CONFIG, WEBSOCKET_ENABLED
    global REALTIME_PUSH_INTERVAL, PAGE_REFRESH_INTERVAL, PAYMENT_QR_CODES, ALIPAY_QR_URL, WECHAT_QR_URL
    global THREAD_POOL_SIZE, MAX_WORKERS, CONNECTION_QUEUE_SIZE, MAX_MEMORY_USAGE, CPU_WARNING_THRESHOLD
    global MEMORY_WARNING_THRESHOLD

    APP_NAME = settings.app.name
    APP_VERSION = settings.app.version
    APP_DESCRIPTION = settings.app.description
    APP_AUTHOR = settings.app.author
    APP_CONTACT = settings.app.contact
    APP_WEBSITE = settings.app.website
    VERSION = APP_VERSION
    DEBUG = settings.development.debug_mode
    CASTER_COUNTRY = settings.caster.country
    CASTER_LATITUDE = settings.caster.latitude
    CASTER_LONGITUDE = settings.caster.longitude
    HOST = settings.network.host
    NTRIP_HOST = HOST
    NTRIP_PORT = settings.ntrip.port
    WEB_HOST = HOST
    WEB_PORT = settings.web.port
    MAX_CONNECTIONS = settings.network.max_connections
    BUFFER_SIZE = settings.network.buffer_size
    MAX_BUFFER_SIZE = settings.network.max_buffer_size
    DATABASE_PATH = settings.database.path
    DB_POOL_SIZE = settings.database.pool_size
    DB_TIMEOUT = settings.database.timeout
    LOG_DIR = settings.logging.log_dir
    LOG_FILES = {
        'main': settings.logging.main_log_file,
        'ntrip': settings.logging.ntrip_log_file,
        'errors': settings.logging.error_log_file
    }
    LOG_LEVEL = settings.logging.log_level
    LOG_FORMAT = settings.logging.log_format
    LOG_MAX_SIZE = settings.logging.max_log_size
    LOG_BACKUP_COUNT = settings.logging.backup_count
    LOG_FREQUENT_STATUS = settings.logging.log_frequent_status
    SECRET_KEY = settings.security.secret_key
    FLASK_SECRET_KEY = SECRET_KEY
    PASSWORD_HASH_ROUNDS = settings.security.password_hash_rounds
    SESSION_TIMEOUT = settings.security.session_timeout
    DEFAULT_ADMIN = {
        'username': settings.admin.username,
        'password': settings.admin.password
    }
    SUPPORTED_NTRIP_VERSIONS = settings.ntrip.supported_versions
    DEFAULT_NTRIP_VERSION = settings.ntrip.default_version
    MAX_USER_CONNECTIONS_PER_MOUNT = settings.ntrip.max_user_connections_per_mount
    MAX_USERS_PER_MOUNT = settings.ntrip.max_users_per_mount
    MAX_CONNECTIONS_PER_USER = settings.ntrip.max_connections_per_user
    MOUNT_TIMEOUT = settings.ntrip.mount_timeout
    CLIENT_TIMEOUT = settings.ntrip.client_timeout
    CONNECTION_TIMEOUT = settings.ntrip.connection_timeout
    TCP_KEEPALIVE = {
        'enabled': settings.tcp.keepalive_enabled,
        'idle': settings.tcp.keepalive_idle,
        'interval': settings.tcp.keepalive_interval,
        'count': settings.tcp.keepalive_count
    }
    SOCKET_TIMEOUT = settings.tcp.socket_timeout
    RING_BUFFER_SIZE = settings.data_forwarding.ring_buffer_size
    BROADCAST_INTERVAL = settings.data_forwarding.broadcast_interval
    DATA_SEND_TIMEOUT = settings.data_forwarding.data_send_timeout
    CLIENT_HEALTH_CHECK_INTERVAL = settings.data_forwarding.client_health_check_interval
    RTCM_PARSE_INTERVAL = settings.rtcm.parse_interval
    RTCM_BUFFER_SIZE = settings.rtcm.buffer_size
    RTCM_PARSE_DURATION = settings.rtcm.parse_duration
    WEBSOCKET_CONFIG = {
        'ping_timeout': settings.websocket.ping_timeout,
        'ping_interval': settings.websocket.ping_interval
    }
    WEBSOCKET_ENABLED = settings.websocket.enabled
    REALTIME_PUSH_INTERVAL = settings.web.realtime_push_interval
    PAGE_REFRESH_INTERVAL = settings.web.page_refresh_interval
    PAYMENT_QR_CODES = {
        'alipay': settings.payment.alipay_qr_code,
        'wechat': settings.payment.wechat_qr_code
    }
    ALIPAY_QR_URL = PAYMENT_QR_CODES['alipay']
    WECHAT_QR_URL = PAYMENT_QR_CODES['wechat']
    THREAD_POOL_SIZE = settings.performance.thread_pool_size
    MAX_WORKERS = settings.performance.max_workers
    CONNECTION_QUEUE_SIZE = settings.performance.connection_queue_size
    MAX_MEMORY_USAGE = settings.performance.max_memory_usage
    CPU_WARNING_THRESHOLD = settings.performance.cpu_warning_threshold
    MEMORY_WARNING_THRESHOLD = settings.performance.memory_warning_threshold

# Initialize globals
update_globals()

# ==================== Exported Globals ====================
# (They are already defined and initialized above via update_globals)

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

# ==================== Utility Functions ====================

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
    
    listen_host = settings.network.host
    
    if listen_host == '0.0.0.0':
        for interface_name, ip in get_private_ips():
            urls.append(f"http://{ip}:{port}")
    else:
        urls.append(f"http://{listen_host}:{port}")
    
    return urls

def load_from_env():
    """
    Load configuration from environment variables.
    Note: Pydantic Settings already handles environment variables.
    This function refreshes the settings and updates globals.
    """
    global settings
    # We can't easily re-read the file here without re-running load_settings
    # but we can rely on Pydantic Settings to pick up environment variables.
    # For compatibility with the old load_from_env, we'll manually check the same vars
    # if they are not picked up by the prefix.
    
    new_data = {}
    if 'NTRIP_PORT' in os.environ:
        new_data.setdefault('ntrip', {})['port'] = os.environ['NTRIP_PORT']
    if 'WEB_PORT' in os.environ:
        new_data.setdefault('web', {})['port'] = os.environ['WEB_PORT']
    if 'DEBUG' in os.environ:
        new_data.setdefault('development', {})['debug_mode'] = os.environ['DEBUG'].lower() in ('true', '1', 'yes', 'on')
    if 'DATABASE_PATH' in os.environ:
        new_data.setdefault('database', {})['path'] = os.environ['DATABASE_PATH']
    if 'SECRET_KEY' in os.environ:
        new_data.setdefault('security', {})['secret_key'] = os.environ['SECRET_KEY']

    if new_data:
        # Update existing settings with new env data
        # This is a bit tricky with nested models, but for these few it's okay
        for section, values in new_data.items():
            section_model = getattr(settings, section)
            for k, v in values.items():
                setattr(section_model, k, v)

    update_globals()

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
