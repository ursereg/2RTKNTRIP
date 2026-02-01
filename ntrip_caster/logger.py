#!/usr/bin/env python3

import logging
import os
import sys
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Optional

import structlog

# Import configuration
from . import config


class NTRIPLogger:
    """
    NTRIP Caster Logger Manager
    """

    _instance: Optional["NTRIPLogger"] = None
    _lock = threading.Lock()
    _web_instance: Any | None = None

    def __new__(cls) -> "NTRIPLogger":
        """Singleton implementation"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(NTRIPLogger, cls).__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        """Initialize logging system"""
        if hasattr(self, "_initialized"):
            return

        self._initialized = True
        self._loggers: dict[str, logging.Logger] = {}
        self._setup_logging()

    @classmethod
    def set_web_instance(cls, web_instance: Any) -> None:
        """Set Web instance for real-time log pushing"""
        cls._web_instance = web_instance

    def _setup_logging(self) -> None:
        """Setup logging system"""
        log_dir = Path(config.settings.logging.log_dir)
        log_dir.mkdir(exist_ok=True)

        formatter = logging.Formatter(config.settings.logging.log_format, datefmt="%Y-%m-%d %H:%M:%S")

        # Configure structlog
        processors: list[Any] = [
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
        ]

        if config.settings.development.debug_mode:
            processors.append(structlog.dev.ConsoleRenderer())
        else:
            processors.append(structlog.processors.JSONRenderer())

        structlog.configure(
            processors=processors,
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )

        # Create different types of loggers
        self._create_logger("main", config.settings.logging.main_log_file, logging.INFO, formatter)
        self._create_logger("ntrip", config.settings.logging.ntrip_log_file, logging.DEBUG, formatter)
        self._create_logger("error", config.settings.logging.error_log_file, logging.ERROR, formatter)

        self._create_root_logger(formatter)
        self.struct_logger = structlog.get_logger("ntrip")

    def _create_logger(self, name: str, filename: str, level: int, formatter: logging.Formatter) -> logging.Logger:
        """Create a specific type of logger"""
        logger = logging.getLogger(f"ntrip.{name}")
        logger.setLevel(level)

        logger.handlers.clear()

        file_path = os.path.join(config.settings.logging.log_dir, filename)
        file_handler = RotatingFileHandler(
            file_path,
            maxBytes=config.settings.logging.max_log_size,
            backupCount=config.settings.logging.backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        if config.settings.development.debug_mode or level >= logging.ERROR:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(level)
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

        self._loggers[name] = logger
        return logger

    def _create_root_logger(self, formatter: logging.Formatter) -> None:
        """Create root logger"""
        root_logger = logging.getLogger()
        root_level = getattr(logging, config.settings.logging.log_level, logging.INFO)
        root_logger.setLevel(root_level)

        if not root_logger.handlers:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            root_logger.addHandler(console_handler)

    def get_logger(self, name: str = "main") -> logging.Logger:
        """Get a logger by name"""
        if name in self._loggers:
            return self._loggers[name]
        return logging.getLogger(f"ntrip.{name}")

    def _push_to_web(self, message: str, log_type: str = "info") -> None:
        """Push log message to Web interface"""
        # Filter some high-frequency logs to avoid overwhelming the frontend
        filtered_keywords = [
            "User activity update",
            "MSM",
            "Satellite",
            "Pushing data",
            "Client connection",
            "RTCM data",
            "Performance:",
            "Database",
            "bytes for mount",
        ]

        if any(keyword in message for keyword in filtered_keywords):
            return

        if self._web_instance and hasattr(self._web_instance, "push_log_message"):
            try:
                self._web_instance.push_log_message(message, log_type)
            except Exception:
                pass

    def log_info(self, message: str, module: str = "main", **kwargs: Any) -> None:
        """Log info message"""
        logger = self.get_logger(module)
        logger.info(message, **kwargs)
        self._push_to_web(message, "info")

    def log_debug(self, message: str, module: str = "main", **kwargs: Any) -> None:
        """Log debug message"""
        logger = self.get_logger(module)
        logger.debug(message, **kwargs)

    def log_warning(self, message: str, module: str = "main", **kwargs: Any) -> None:
        """Log warning message"""
        logger = self.get_logger(module)
        logger.warning(message, **kwargs)
        self._push_to_web(message, "warning")

    def log_error(self, message: str, module: str = "error", exc_info: Any = False, **kwargs: Any) -> None:
        """Log error message"""
        logger = self.get_logger(module)
        logger.error(message, exc_info=exc_info, **kwargs)
        self._push_to_web(message, "error")

    def log_critical(self, message: str, module: str = "error", exc_info: Any = False) -> None:
        """Log critical message"""
        logger = self.get_logger(module)
        logger.critical(message, exc_info=exc_info)
        self._push_to_web(message, "error")

    def log_ntrip_request(self, method: str, path: str, client_ip: str, user_agent: str = "") -> None:
        """Log NTRIP request"""
        message = f"NTRIP {method} request: {path} from {client_ip}"
        if user_agent:
            message += f" (User-Agent: {user_agent})"
        self.get_logger("ntrip").info(message)

    def log_ntrip_response(self, method: str, path: str, status_code: int, client_ip: str) -> None:
        """Log NTRIP response"""
        message = f"NTRIP {method} response: {status_code} for {path} to {client_ip}"
        self.get_logger("ntrip").info(message)

    def log_client_connect(self, username: str, mount: str, client_ip: str, ntrip_version: str) -> None:
        """Log client connection"""
        message = f"Client connected: {username}@{mount} from {client_ip} (NTRIP {ntrip_version})"
        self.get_logger("ntrip").info(message)

    def log_client_disconnect(self, username: str, mount: str, client_ip: str, reason: str = "") -> None:
        """Log client disconnection"""
        message = f"Client disconnected: {username}@{mount} from {client_ip}"
        if reason:
            message += f" (Reason: {reason})"
        self.get_logger("ntrip").info(message)

    def log_data_transfer(self, mount: str, bytes_sent: int, client_count: int) -> None:
        """Log data transfer"""
        message = f"Data transfer: {bytes_sent} bytes sent to {client_count} clients for mount {mount}"
        self.get_logger("ntrip").debug(message)

    def log_mount_operation(self, operation: str, mount: str, username: str = "", details: str = "") -> None:
        """Log mount point operation"""
        message = f"Mount {operation}: {mount}"
        if username:
            message += f" by {username}"
        if details:
            message += f" ({details})"
        self.get_logger("ntrip").info(message)

    def log_authentication(self, username: str, mount: str, success: bool, client_ip: str, reason: str = "") -> None:
        """Log authentication"""
        status = "SUCCESS" if success else "FAILED"
        message = f"Authentication {status}: {username}@{mount} from {client_ip}"
        if reason:
            message += f" (Reason: {reason})"

        if success:
            self.get_logger("ntrip").info(message)
        else:
            self.get_logger("error").warning(message)

    def log_system_event(self, event: str, details: str = "") -> None:
        """Log system event"""
        message = f"System event: {event}"
        if details:
            message += f" - {details}"
        self.get_logger("main").info(message)
        self._push_to_web(f"System event: {event}" + (f" - {details}" if details else ""), "info")

    def log_performance(self, metric: str, value: Any, unit: str = "") -> None:
        """Log performance metric"""
        message = f"Performance: {metric} = {value}"
        if unit:
            safe_unit = str(unit).replace("%", "%%")
            message += f" {safe_unit}"
        self.get_logger("main").debug(message)

    def log_rtcm_data(self, mount: str, message_type: Any, message_length: int, client_count: int) -> None:
        """Log RTCM data processing"""
        message = (
            f"RTCM data: Type {message_type}, {message_length} bytes for mount {mount}, sent to {client_count} clients"
        )
        self.get_logger("ntrip").debug(message)

    def log_database_operation(self, operation: str, table: str, success: bool, details: str = "") -> None:
        """Log database operation"""
        status = "SUCCESS" if success else "FAILED"
        message = f"Database {operation} {status}: {table}"
        if details:
            message += f" ({details})"

        if success:
            self.get_logger("main").debug(message)
        else:
            self.get_logger("error").error(message)

    def log_web_request(
        self, method: str, path: str, client_ip: str, status_code: int, response_time: float | None = None
    ) -> None:
        """Log Web request"""
        message = f"Web {method} {path} from {client_ip} - {status_code}"
        if response_time is not None:
            message += f" ({response_time:.3f}s)"
        self.get_logger("main").info(message)

    def shutdown(self) -> None:
        """Shutdown logging system"""
        for logger in self._loggers.values():
            for handler in logger.handlers:
                handler.close()
                logger.removeHandler(handler)

        root_logger = logging.getLogger()
        for handler in root_logger.handlers:
            handler.close()
            root_logger.removeHandler(handler)


_logger_instance: NTRIPLogger | None = None
_logger_lock = threading.Lock()


def get_logger(name: str = "root") -> logging.Logger:
    """Get global logger instance"""
    global _logger_instance
    if _logger_instance is None:
        with _logger_lock:
            if _logger_instance is None:
                _logger_instance = NTRIPLogger()
    return _logger_instance.get_logger(name)


def init_logging() -> NTRIPLogger:
    """Initialize logging system"""
    global _logger_instance
    if _logger_instance is None:
        with _logger_lock:
            if _logger_instance is None:
                _logger_instance = NTRIPLogger()
    return _logger_instance


def set_web_instance(web_instance: Any) -> None:
    """Set Web instance reference for real-time log pushing"""
    NTRIPLogger.set_web_instance(web_instance)


def log_info(message: str, module: str = "main", **kwargs: Any) -> None:
    """Log info message"""
    logger_instance = init_logging()
    logger_instance.log_info(message, module, **kwargs)


def log_debug(message: str, module: str = "main", **kwargs: Any) -> None:
    """Log debug message"""
    logger_instance = init_logging()
    logger_instance.log_debug(message, module, **kwargs)


def log_warning(message: str, module: str = "main", **kwargs: Any) -> None:
    """Log warning message"""
    logger_instance = init_logging()
    logger_instance.log_warning(message, module, **kwargs)


def log_error(message: str, module: str = "error", exc_info: Any = False, **kwargs: Any) -> None:
    """Log error message"""
    logger_instance = init_logging()
    logger_instance.log_error(message, module, exc_info, **kwargs)


def log_critical(message: str, module: str = "error", exc_info: Any = False) -> None:
    """Log critical message"""
    logger_instance = init_logging()
    logger_instance.log_critical(message, module, exc_info)


def log_ntrip_request(method: str, path: str, client_ip: str, user_agent: str = "") -> None:
    """Log NTRIP request"""
    logger_instance = init_logging()
    logger_instance.log_ntrip_request(method, path, client_ip, user_agent)


def log_ntrip_response(method: str, path: str, status_code: int, client_ip: str) -> None:
    """Log NTRIP response"""
    logger_instance = init_logging()
    logger_instance.log_ntrip_response(method, path, status_code, client_ip)


def log_client_connect(username: str, mount: str, client_ip: str, ntrip_version: str) -> None:
    """Log client connection"""
    logger_instance = init_logging()
    logger_instance.log_client_connect(username, mount, client_ip, ntrip_version)


def log_client_disconnect(username: str, mount: str, client_ip: str, reason: str = "") -> None:
    """Log client disconnection"""
    logger_instance = init_logging()
    logger_instance.log_client_disconnect(username, mount, client_ip, reason)


def log_data_transfer(mount: str, bytes_sent: int, client_count: int) -> None:
    """Log data transfer"""
    logger_instance = init_logging()
    logger_instance.log_data_transfer(mount, bytes_sent, client_count)


def log_mount_operation(operation: str, mount: str, username: str = "", details: str = "") -> None:
    """Log mount point operation"""
    logger_instance = init_logging()
    logger_instance.log_mount_operation(operation, mount, username, details)


def log_authentication(username: str, mount: str, success: bool, client_ip: str, reason: str = "") -> None:
    """Log authentication"""
    logger_instance = init_logging()
    logger_instance.log_authentication(username, mount, success, client_ip, reason)


def log_system_event(event: str, details: str = "") -> None:
    """Log system event"""
    logger_instance = init_logging()
    logger_instance.log_system_event(event, details)


def log_performance(metric: str, value: Any, unit: str = "") -> None:
    """Log performance metric"""
    logger_instance = init_logging()
    logger_instance.log_performance(metric, value, unit)


def log_rtcm_data(mount: str, message_type: Any, message_length: int, client_count: int) -> None:
    """Log RTCM data processing"""
    logger_instance = init_logging()
    logger_instance.log_rtcm_data(mount, message_type, message_length, client_count)


def log_database_operation(operation: str, table: str, success: bool, details: str = "") -> None:
    """Log database operation"""
    logger_instance = init_logging()
    logger_instance.log_database_operation(operation, table, success, details)


def log_web_request(
    method: str, path: str, client_ip: str, status_code: int, response_time: float | None = None
) -> None:
    """Log Web request"""
    logger_instance = init_logging()
    logger_instance.log_web_request(method, path, client_ip, status_code, response_time)


def shutdown_logging() -> None:
    """Shutdown logging system"""
    global _logger_instance
    if _logger_instance is not None:
        _logger_instance.shutdown()
        _logger_instance = None


logger = get_logger("main")
ntrip_logger = get_logger("ntrip")
error_logger = get_logger("error")
