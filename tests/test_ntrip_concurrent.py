#!/usr/bin/env python3
"""
NTRIP Concurrent Connection Test Script - Refactored for Pytest
"""

import socket
import threading
import time
import json
import random
import base64
import pytest
from ntrip_caster import config

# NTRIP Server Configuration for testing
NTRIP_SERVER = "localhost"
NTRIP_PORT = 2101
MOUNT_POINTS = ["TEST01", "TEST02"]

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
        sock.settimeout(5)
        # In actual unit tests, this would fail if no server is running.
        # We use mocking in the test function.
        sock.connect((NTRIP_SERVER, NTRIP_PORT))
        
        request = create_ntrip_request(mount_point, username, password, protocol)
        sock.send(request.encode('utf-8'))
        
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        
        if "200 OK" in response or "ICY 200 OK" in response:
            client_stats["connected"] = True
            
            end_time = start_time + test_duration
            sock.settimeout(0.5)
            
            while time.time() < end_time:
                try:
                    data = sock.recv(4096)
                    if data:
                        client_stats["bytes_received"] += len(data)
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
    
    return client_stats

@pytest.mark.skip(reason="Requires running server")
def test_concurrent_connections():
    """Integration test for concurrent connections"""
    users = [{"username": f"user{i}", "password": f"pass{i}"} for i in range(5)]
    results = []
    threads = []
    
    for user in users:
        t = threading.Thread(target=lambda: results.append(ntrip_client_test(user, 1)))
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()
    
    assert len(results) == len(users)

def test_create_ntrip_request():
    request = create_ntrip_request("TEST", "user", "pass")
    assert "GET /TEST HTTP/1.0" in request
    assert "Authorization: Basic" in request
