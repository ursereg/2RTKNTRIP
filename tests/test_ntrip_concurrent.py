#!/usr/bin/env python3
"""
NTRIP Concurrent Connection Test Script
Function: Use multiple users to concurrently connect to NTRIP server, test system stability
"""

import socket
import threading
import time
import json
import random
import base64
import hashlib
import sys
import psutil
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# NTRIP Server Configuration
NTRIP_SERVER = "localhost"
NTRIP_PORT = 2101
MOUNT_POINTS = ["TEST01", "TEST02"]
TEST_DURATION = 60  # Reduced for verification
MAX_CONCURRENT_CONNECTIONS = 100
TARGET_CONNECTIONS = [10, 20, 50]
CONNECTION_STEP = 10

# Stats Information
stats = {
    "total_connections": 0,
    "successful_connections": 0,
    "failed_connections": 0,
    "data_received": 0,
    "total_bytes": 0,
    "ntrip_bytes_sent": 0,
    "ntrip_bytes_received": 0,
    "connection_errors": [],
    "start_time": None,
    "end_time": None,
    "performance_data": [],
    "server_stats": [],
    "network_stats": []
}
stats_lock = threading.Lock()

def load_test_users():
    """Load test users list"""
    try:
        with open("tests/test_users.json", "r", encoding="utf-8") as f:
            users = json.load(f)
        print(f"Successfully loaded {len(users)} test users")
        return users
    except FileNotFoundError:
        print("Error: test_users.json not found, run test_add_users.py first")
        sys.exit(1)
    except Exception as e:
        print(f"Failed to load users file: {e}")
        sys.exit(1)

def get_system_performance():
    """Get system performance data"""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        net_io = psutil.net_io_counters()
        
        return {
            "timestamp": time.time(),
            "cpu_percent": cpu_percent,
            "memory_percent": memory.percent,
            "memory_used_mb": memory.used / 1024 / 1024,
            "memory_total_mb": memory.total / 1024 / 1024,
            "network_bytes_sent": net_io.bytes_sent,
            "network_bytes_recv": net_io.bytes_recv
        }
    except Exception as e:
        print(f"Failed to get performance data: {e}")
        return None

def get_server_stats():
    """Get NTRIP server stats via API"""
    try:
        response = requests.get(f"http://{NTRIP_SERVER}:5757/api/system/stats", timeout=5)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        pass
    return None

def create_ntrip_request(mount_point, username, password, protocol="basic"):
    """Create NTRIP request"""
    auth_string = f"{username}:{password}"
    auth_b64 = base64.b64encode(auth_string.encode('ascii')).decode('ascii')
    
    if protocol == "ntrip2_0":
        request = (
            f"GET /{mount_point} HTTP/1.1\r\n"
            f"Host: {NTRIP_SERVER}:{NTRIP_PORT}\r\n"
            f"Ntrip-Version: Ntrip/2.0\r\n"
            f"User-Agent: NTRIP-Test-Client/2.0\r\n"
            f"Authorization: Basic {auth_b64}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
    else:
        request = (
            f"GET /{mount_point} HTTP/1.0\r\n"
            f"User-Agent: NTRIP-Test-Client/1.0\r\n"
            f"Authorization: Basic {auth_b64}\r\n"
            f"\r\n"
        )
    return request

def ntrip_client_test(user_info, test_duration):
    """Single NTRIP client test"""
    username = user_info["username"]
    password = user_info["password"]
    mount_point = random.choice(MOUNT_POINTS)
    protocol = "ntrip2_0"
    
    client_stats = {
        "connected": False,
        "bytes_received": 0,
        "error_message": None
    }
    
    sock = None
    start_time = time.time()
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((NTRIP_SERVER, NTRIP_PORT))
        
        request = create_ntrip_request(mount_point, username, password, protocol)
        request_bytes = request.encode('utf-8')
        sock.send(request_bytes)
        
        with stats_lock:
            stats["ntrip_bytes_sent"] += len(request_bytes)
        
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        
        if "200 OK" in response or "ICY 200 OK" in response:
            client_stats["connected"] = True
            
            end_time = start_time + test_duration
            sock.settimeout(1)
            
            while time.time() < end_time:
                try:
                    data = sock.recv(4096)
                    if data:
                        client_stats["bytes_received"] += len(data)
                        with stats_lock:
                            stats["ntrip_bytes_received"] += len(data)
                    else:
                        break
                except socket.timeout:
                    continue
                except Exception:
                    break
        else:
            client_stats["error_message"] = f"Auth failed: {response[:50]}"
    
    except Exception as e:
        client_stats["error_message"] = str(e)
    finally:
        if sock: sock.close()
    
    with stats_lock:
        stats["total_connections"] += 1
        if client_stats["connected"]:
            stats["successful_connections"] += 1
            stats["total_bytes"] += client_stats["bytes_received"]
            if client_stats["bytes_received"] > 0:
                stats["data_received"] += 1
        else:
            stats["failed_connections"] += 1
    
    return client_stats

def run_connection_test(users, target_connections, test_name):
    """Run connection test with target number of connections"""
    print(f"\nStarting {test_name} - Target: {target_connections}")
    
    with stats_lock:
        stats.update({
            "total_connections": 0, "successful_connections": 0, "failed_connections": 0,
            "data_received": 0, "total_bytes": 0, "ntrip_bytes_sent": 0, "ntrip_bytes_received": 0,
            "start_time": time.time(), "end_time": None
        })
    
    test_users = users[:target_connections]
    
    results = []
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_CONNECTIONS) as executor:
        futures = [executor.submit(ntrip_client_test, user, TEST_DURATION) for user in test_users]
        for i, future in enumerate(as_completed(futures)):
            results.append(future.result())
            if (i + 1) % 10 == 0:
                print(f"Finished {i+1}/{len(test_users)} connections...")

    with stats_lock:
        stats["end_time"] = time.time()
        duration = stats["end_time"] - stats["start_time"]
        print(f"\n{test_name} Results:")
        print(f"  Duration: {duration:.2f}s")
        print(f"  Success: {stats['successful_connections']}/{stats['total_connections']}")
        print(f"  Total Data Received: {stats['total_bytes']/1024:.2f} KB")
        if stats['failed_connections'] > 0:
            print(f"  First 5 errors: {[e['error_message'] for e in results[:5] if e.get('error_message')]}")

def main():
    """Main Function"""
    print("NTRIP Concurrent Connection Test")
    users = load_test_users()
    
    test_stages = [10, 20]
    for stage in test_stages:
        run_connection_test(users, stage, f"{stage} connections test")
        time.sleep(2)

if __name__ == "__main__":
    main()
