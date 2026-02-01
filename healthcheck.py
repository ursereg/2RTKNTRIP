import requests
import sys
import os

def check_health():
    # Use config if available, otherwise defaults
    web_port = os.environ.get("WEB_PORT", "5757")
    try:
        response = requests.get(f"http://localhost:{web_port}/health", timeout=5)
        if response.status_code == 200:
            print("Health check passed")
            sys.exit(0)
        else:
            print(f"Health check failed with status code: {response.status_code}")
            sys.exit(1)
    except Exception as e:
        print(f"Health check failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    check_health()
