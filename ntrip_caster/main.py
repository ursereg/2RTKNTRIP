#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
import signal
import logging
import psutil
import threading
import argparse
import os
from pathlib import Path
from threading import Thread

# Parse command line arguments
parser = argparse.ArgumentParser(description='2RTK NTRIP Caster')
parser.add_argument('--config', type=str, help='Path to configuration file')
args = parser.parse_args()

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# If config file specified, set environment variable
if args.config:
    os.environ['NTRIP_CONFIG_FILE'] = args.config

# Import configuration and core modules
from ntrip_caster import config
from ntrip_caster import logger
from ntrip_caster import forwarder
from ntrip_caster.database import DatabaseManager
from ntrip_caster.web import create_web_manager
from ntrip_caster.ntrip import NTRIPCaster
from ntrip_caster.connection import get_connection_manager

def setup_logging():
    """Setup logging system"""
    # Initialize logging module
    logger.init_logging()
    
    # Set log levels for specific modules
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('socketio').setLevel(logging.WARNING)
    logging.getLogger('engineio').setLevel(logging.WARNING)
    
    # Log system startup event
    logger.log_system_event('Logging system initialization complete')

def print_banner():
    """Print startup banner"""
    banner = f"""

    ██████╗ ██████╗ ████████╗██╗  ██╗
    ╚════██╗██╔══██╗╚══██╔══╝██║ ██╔╝
     █████╔╝██████╗╔   ██║   █████╔╝ 
    ██╔═══╝ ██╔══██╗   ██║   ██║  ██╗
    ███████╗██║  ██║   ██║   ██║  ██╗
    ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝
    2RTK Ntrip Caster {config.VERSION}

NTRIP Port: {config.NTRIP_PORT:<8} Web Management Port: {config.WEB_PORT:<8} 
Debug Mode: {str(config.DEBUG):<9} Max Connections: {config.MAX_CONNECTIONS:<8} 

    """
    print(banner)

def check_environment():
    """Check running environment"""
    env_logger = logging.getLogger('main')
    
    # Check Python version
    if sys.version_info < (3, 7):
        env_logger.error("Python 3.7 or higher is required")
        sys.exit(1)
    
    # Check necessary directories
    required_dirs = [
        Path(config.DATABASE_PATH).parent,
        Path(config.LOG_DIR)
    ]
    
    for dir_path in required_dirs:
        if not dir_path.exists():
            env_logger.info(f"Creating directory: {dir_path}")
            dir_path.mkdir(parents=True, exist_ok=True)
    
    # Check if ports are available
    import socket
    
    def check_port(port, name):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('', port))
            return True
        except OSError:
            env_logger.error(f"{name} port {port} is already in use")
            return False
    
    ports_ok = True
    ports_ok &= check_port(config.NTRIP_PORT, "NTRIP")
    ports_ok &= check_port(config.WEB_PORT, "Web")
    
    if not ports_ok:
        env_logger.error("Port check failed, please check port usage")
        sys.exit(1)
    
    env_logger.info("Environment check passed")

class ServiceManager:
    """Service Manager - Unifies management of all service components"""
    
    def __init__(self):
        self.db_manager = None
        self.web_manager = None
        self.ntrip_caster = None
        self.web_thread = None
        self.running = False
        self.stopping = False  # Stop flag to prevent duplicate calls
        self.start_time = None
        self.stats_thread = None
        self.stats_interval = 10  # Stats printing interval (seconds)
        self.last_network_stats = None
        self.print_stats = False  # Control whether to print stats in console
        self.system_stats_cache = {}  # Cache system stats for Web API
        
    def start_all_services(self):
        """Start all services"""
        try:
            self.start_time = time.time()
            logger.log_system_event(f'Starting 2RTK NTRIP Caster v{config.VERSION}')
            
            # 1. Initialize database
            self.db_manager = DatabaseManager()
            self.db_manager.init_database()
            logger.log_system_event('Database initialization complete')
            
            # 2. Initialize and start data forwarder
            forwarder.initialize()
            forwarder.start_forwarder()
            logger.log_system_event('Data forwarder initialization complete')
            
            # 3. RTCM parsing is now integrated in connection_manager, no need to start separately
            logger.log_system_event('RTCM parser integration complete')
            
            # 4. Start Web management interface
            self._start_web_interface()
            
            # 5. Start NTRIP server (in a separate thread)
            self.ntrip_caster = NTRIPCaster(self.db_manager)
            self.ntrip_thread = threading.Thread(target=self.ntrip_caster.start, daemon=True)
            self.ntrip_thread.start()
            time.sleep(1)  # Wait for NTRIP server to start
            
            # 6. Register signal handlers
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
            
            self.running = True
            logger.log_system_event(f'All services started - NTRIP port: {config.NTRIP_PORT}, Web port: {config.WEB_PORT}')
            
            # Start stats monitor thread
            self._start_stats_monitor()
            
            # Main loop - Keep services running
            self._main_loop()
            
        except Exception as e:
            logger.log_error(f"Failed to start services: {e}", exc_info=True)
            self.stop_all_services()
            raise
    
    def _start_web_interface(self):
        """Start Web management interface"""
        from ntrip_caster.web import set_server_instance
        self.web_manager = create_web_manager(
            self.db_manager, 
            forwarder.get_forwarder(), 
            self.start_time
        )
        # Set server instance for Web API use
        set_server_instance(self)
        self.web_manager.start_rtcm_parsing()
        
        def run_web():
            self.web_manager.run(host=config.HOST, port=config.WEB_PORT, debug=False)
        
        self.web_thread = Thread(target=run_web, daemon=True)
        self.web_thread.start()
        
        # Display all accessible Web management interface addresses
        web_urls = config.get_display_urls(config.WEB_PORT, "Web Management Interface")
        if len(web_urls) == 1:
            logger.log_info(f'Web management interface started, management address: {web_urls[0]}')
        else:
            logger.log_system_event('Web management interface started, accessible via the following addresses:')
            for url in web_urls:
                logger.log_system_event(f'  - {url}')
    
    def _start_stats_monitor(self):
        """Start stats monitor thread"""
        self.stats_thread = Thread(target=self._stats_monitor_worker, daemon=True)
        self.stats_thread.start()
 
    def _stats_monitor_worker(self):
        """Stats monitor worker thread"""
        while self.running:
            try:
                time.sleep(self.stats_interval)
                if self.running:
                    self._update_system_stats()
            except Exception as e:
                logger.log_error(f"Stats monitor exception: {e}", exc_info=True)
    
    def _update_system_stats(self):
        """Update system stats to cache"""
        try:
            # Get system performance data
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            
            # Get network stats
            network_stats = psutil.net_io_counters()
            network_bandwidth = self._calculate_network_bandwidth(network_stats)
            
            # Get NTRIP server stats
            ntrip_stats = self.ntrip_caster.get_performance_stats() if self.ntrip_caster else {}
            
            # Get connection manager stats
            conn_manager = get_connection_manager()
            conn_stats = conn_manager.get_statistics()
            
            # Calculate uptime
            uptime = time.time() - self.start_time if self.start_time else 0
            uptime_str = self._format_uptime(uptime)
            
            # Calculate data transfer stats
            total_data_bytes = sum(mount['total_bytes'] for mount in conn_stats.get('mounts', []) if 'total_bytes' in mount)
            total_data_mb = total_data_bytes / (1024 * 1024)
            
            # Update cache
            self.system_stats_cache = {
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'uptime': uptime,  # Save numeric uptime
                'uptime_str': uptime_str,  # Save formatted uptime string
                'cpu_percent': cpu_percent,
                'memory': memory,
                'network_bandwidth': network_bandwidth,
                'ntrip_stats': ntrip_stats,
                'conn_stats': conn_stats,
                'total_data_mb': total_data_mb
            }
            
        except Exception as e:
            logger.log_error(f"Failed to update stats: {e}", exc_info=True)
    
    def get_system_stats(self):
        """Get system stats for Web API use"""
        try:
            stats = self.system_stats_cache.copy()
            if not stats:
                # If cache is empty, update once immediately
                self._update_system_stats()
                stats = self.system_stats_cache.copy()
            
            # Format data for frontend use
            if stats:
                memory_info = stats.get('memory')
                network_info = stats.get('network_bandwidth', {})
                
                return {
                    'timestamp': stats.get('timestamp'),
                    'uptime': stats.get('uptime', 0),
                    'cpu_percent': round(stats.get('cpu_percent', 0), 1),
                    'memory': {
                        'percent': round(getattr(memory_info, 'percent', 0), 1),
                        'used': getattr(memory_info, 'used', 0),
                        'total': getattr(memory_info, 'total', 0)
                    },
                    'network_bandwidth': {
                        'sent_rate': network_info.get('sent_rate', 0) if isinstance(network_info, dict) else 0,
                        'recv_rate': network_info.get('recv_rate', 0) if isinstance(network_info, dict) else 0
                    },
                    'connections': {
                        'active': stats.get('ntrip_stats', {}).get('active_connections', 0),
                        'total': stats.get('ntrip_stats', {}).get('total_connections', 0),
                        'rejected': stats.get('ntrip_stats', {}).get('rejected_connections', 0),
                        'max_concurrent': stats.get('ntrip_stats', {}).get('max_concurrent', 0)
                    },
                    'mounts': stats.get('conn_stats', {}).get('mounts', {}),
                    'users': stats.get('conn_stats', {}).get('users', {}),
                    'data_transfer': {
                        'total_bytes': stats.get('total_data_mb', 0) * 1024 * 1024
                    }
                }
            return {}
        except Exception as e:
            logger.log_error(f"Failed to get system stats: {e}", exc_info=True)
            return {}
    
    def set_print_stats(self, enabled):
        """Set whether to print stats in console"""
        self.print_stats = enabled
        if enabled:
            logger.log_system_event('Console statistics printing enabled')
        else:
            logger.log_system_event('Console statistics printing disabled')
    
    def _calculate_network_bandwidth(self, current_stats):
        """Calculate network bandwidth"""
        if self.last_network_stats is None:
            self.last_network_stats = (current_stats, time.time())
            return "Calculating..."
        
        last_stats, last_time = self.last_network_stats
        current_time = time.time()
        time_diff = current_time - last_time
        
        if time_diff <= 0:
            return "Calculating..."
        
        bytes_sent_diff = current_stats.bytes_sent - last_stats.bytes_sent
        bytes_recv_diff = current_stats.bytes_recv - last_stats.bytes_recv
        
        upload_mbps = (bytes_sent_diff * 8) / (time_diff * 1024 * 1024)
        download_mbps = (bytes_recv_diff * 8) / (time_diff * 1024 * 1024)
        total_mbps = upload_mbps + download_mbps
        
        self.last_network_stats = (current_stats, current_time)
        
        return f"↑{upload_mbps:.2f} Mbps ↓{download_mbps:.2f} Mbps (Total: {total_mbps:.2f} Mbps)"
    
    def _format_uptime(self, seconds):
        """Format uptime"""
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        
        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m {secs}s"

    def _main_loop(self):
        """Main loop - Monitors service status"""
        while self.running:
            try:
                # Check service status
                if self.ntrip_caster and not self.ntrip_caster.running:
                    logger.log_error('NTRIP server stopped unexpectedly')
                    break
                    
                if self.web_thread and not self.web_thread.is_alive():
                    logger.log_error('Web service stopped unexpectedly')
                    break
                
                # Brief sleep to avoid high CPU usage
                time.sleep(1)
                
            except Exception as e:
                logger.log_error(f"Main loop exception: {e}", exc_info=True)
                break
    
    def _signal_handler(self, signum, frame):
        """Signal handler"""
        if self.stopping:
            logger.log_system_event(f'Received signal {signum}, but service is already closing. Ignoring duplicate signal.')
            return
        logger.log_system_event(f'Received signal {signum}, starting to close all services')
        self.stop_all_services()
    
    def stop_all_services(self):
        """Stop all services"""
        if self.stopping:
            logger.log_system_event('Services are closing, avoiding duplicate calls')
            return
            
        self.stopping = True
        logger.log_system_event('Closing all services')
        
        try:
            self.running = False
            
            # Wait for stats monitor thread to end
            if self.stats_thread and self.stats_thread.is_alive():
                logger.log_system_event('Stopping stats monitor thread')
                self.stats_thread.join(timeout=2)
            
            # Stop NTRIP server
            if self.ntrip_caster:
                try:
                    self.ntrip_caster.stop()
                except Exception as e:
                    logger.log_error(f'Error stopping NTRIP server: {e}')
        
            # Stop data forwarder
            try:
                forwarder.stop_forwarder()
            except Exception as e:
                logger.log_error(f'Error stopping data forwarder: {e}')
            
            # Stop Web manager
            if self.web_manager:
                try:
                    self.web_manager.stop_rtcm_parsing()
                except Exception as e:
                    logger.log_error(f'Error stopping Web manager: {e}')
            
            logger.log_system_event('All services closed')
            
        except Exception as e:
            logger.log_error(f'Exception occurred while closing services: {e}')
        finally:
            self.stopping = False

# Global server instance
server = None

def get_server_instance():
    """Get server instance"""
    return server

def main():
    """Main function"""
    global server
    try:
        # Setup logging
        setup_logging()
        
        # Print startup info
        print_banner()
        
        # Check environment
        check_environment()
        
        # Initialize configuration
        config.init_config()
        logger.log_system_event('Configuration initialization complete')
        
        # Create server instance and start all services
        server = ServiceManager()
        globals()['server'] = server
        server.start_all_services()
        
    except KeyboardInterrupt:
        logger.log_system_event('Received interrupt signal, closing services')
    except Exception as e:
        logger.log_error(f"Startup failed: {e}", exc_info=True)
        sys.exit(1)
    finally:
        if server:
            server.stop_all_services()
        logger.log_system_event('Program exited')
        logger.shutdown_logging()

if __name__ == '__main__':
    main()
