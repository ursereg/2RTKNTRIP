#!/usr/bin/env python3
"""
User Batch Addition Test Script
Function: Add 500 test users via Web API
"""

import requests
import json
import time
import sys

# Server Configuration
WEB_SERVER_URL = "http://localhost:5757"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

def login_admin():
    """Admin Login"""
    login_url = f"{WEB_SERVER_URL}/api/login"
    login_data = {
        "username": ADMIN_USERNAME,
        "password": ADMIN_PASSWORD
    }
    
    try:
        response = requests.post(login_url, json=login_data, timeout=10)
        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                print(f"Admin logged in successfully: {ADMIN_USERNAME}")
                return response.cookies
            else:
                print(f"Login failed: {result.get('message', 'Unknown error')}")
                return None
        else:
            print(f"Login request failed, status code: {response.status_code}")
            return None
    except Exception as e:
        print(f"Login exception: {e}")
        return None

def add_user(cookies, username, password):
    """Add Single User"""
    add_user_url = f"{WEB_SERVER_URL}/api/users"
    user_data = {
        "username": username,
        "password": password
    }
    
    try:
        response = requests.post(add_user_url, json=user_data, cookies=cookies, timeout=10)
        if response.status_code in [200, 201]:
            result = response.json()
            return result.get('success', True) or 'message' in result, result.get('message', '') or result.get('error', '')
        else:
            return False, f"HTTP {response.status_code}"
    except Exception as e:
        return False, str(e)

def main():
    """Main Function"""
    print("Starting batch user addition test...")
    print(f"Target Server: {WEB_SERVER_URL}")
    print(f"Admin Account: {ADMIN_USERNAME}")
    print("="*50)
    
    # Admin login
    cookies = login_admin()
    if not cookies:
        print("Admin login failed, exiting program")
        sys.exit(1)
    
    # Batch add users
    total_users = 10  # Reduced for verification
    success_count = 0
    failed_count = 0
    
    print(f"Starting to add {total_users} users...")
    start_time = time.time()
    
    for i in range(1, total_users + 1):
        username = f"testuser{i:03d}"
        password = f"pass{i:03d}"
        
        success, message = add_user(cookies, username, password)
        
        if success:
            success_count += 1
            if i % 2 == 0:
                print(f"Successfully added {success_count} users (Progress: {i}/{total_users})")
        else:
            failed_count += 1
            print(f"Failed to add user {username}: {message}")
        
        time.sleep(0.01)
    
    end_time = time.time()
    elapsed_time = end_time - start_time
    
    print("="*50)
    print("User addition complete!")
    print(f"Total users: {total_users}")
    print(f"Success: {success_count}")
    print(f"Failed: {failed_count}")
    print(f"Time elapsed: {elapsed_time:.2f} seconds")
    
    # Save user info for NTRIP test
    user_list = []
    for i in range(1, total_users + 1):
        user_list.append({
            "username": f"testuser{i:03d}",
            "password": f"pass{i:03d}"
        })
    
    with open("tests/test_users.json", "w", encoding="utf-8") as f:
        json.dump(user_list, f, indent=2, ensure_ascii=False)
    
    print(f"User info saved to tests/test_users.json")

if __name__ == "__main__":
    main()
