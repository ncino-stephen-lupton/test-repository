import subprocess
import socket
import requests
import dns.resolver
import time
import logging
import traceback
import platform
import ssl
import threading
from datetime import datetime

# Add these imports
import os
import certifi

# Create a custom CA bundle
custom_ca_path = os.path.join(os.path.dirname(__file__), 'custom_ca_bundle.pem')
if not os.path.exists(custom_ca_path):
    with open(custom_ca_path, 'wb') as outfile:
        with open('zscalerrootcert.crt', 'rb') as infile:
            outfile.write(infile.read())
        with open(certifi.where(), 'rb') as infile:
            outfile.write(infile.read())

# Then in your SSL/HTTPS verification functions, use:
verify = custom_ca_path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("zscaler_monitor.log"),
        logging.StreamHandler()
    ]
)

ZSCALER_ENDPOINTS = [
    "104.129.205.77",
    "104.129.195.20", 
    "104.129.204.228",
    "gateway.zscalertwo.net"
]

PUBLIC_REFERENCE = ["8.8.8.8", "1.1.1.1", "www.google.com"]
TEST_INTERVAL = 5  # seconds between tests
TOTAL_RUNTIME = 3600  # run for 1 hour by default

def current_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

def run_ping(host, count=4):
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        command = ["ping", param, str(count), host]
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        success = result.returncode == 0
        
        if success:
            logging.info(f"PING {host}: Success")
        else:
            logging.warning(f"PING {host}: Failed with return code {result.returncode}")
            logging.debug(f"Output: {result.stdout}")
        
        return success, result.stdout
    except Exception as e:
        logging.error(f"PING {host}: Exception {str(e)}")
        return False, str(e)

def run_dns_lookup(hostname):
    try:
        answers = dns.resolver.resolve(hostname, 'A')
        ips = [answer.address for answer in answers]
        logging.info(f"DNS {hostname}: Resolved to {', '.join(ips)}")
        return True, ips
    except Exception as e:
        logging.error(f"DNS {hostname}: Failed with {str(e)}")
        return False, str(e)

def run_traceroute(host):
    try:
        command = ["tracert" if platform.system().lower() == "windows" else "traceroute", host]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        logging.info(f"TRACEROUTE {host}: Completed with {result.returncode}")
        logging.debug(f"Output: {result.stdout}")
        return result.returncode == 0, result.stdout
    except Exception as e:
        logging.error(f"TRACEROUTE {host}: Exception {str(e)}")
        return False, str(e)

def check_http_connection(url, timeout=10):
    try:
        start_time = time.time()
        response = requests.get(f"http://{url}/zcc_conn_test", timeout=timeout, allow_redirects=False)
        elapsed = time.time() - start_time
        
        logging.info(f"HTTP {url}: Status {response.status_code}, Time {elapsed:.2f}s")
        if response.status_code >= 400:
            logging.warning(f"HTTP {url}: Response content: {response.text[:200]}")
        
        return response.status_code < 400, f"Status: {response.status_code}, Time: {elapsed:.2f}s"
    except requests.exceptions.RequestException as e:
        logging.error(f"HTTP {url}: Exception {str(e)}")
        return False, str(e)

def check_https_connection(url, timeout=10):
    try:
        start_time = time.time()
        response = requests.get(f"https://{url}", timeout=timeout, verify=True)
        elapsed = time.time() - start_time
        
        logging.info(f"HTTPS {url}: Status {response.status_code}, Time {elapsed:.2f}s")
        return response.status_code < 400, f"Status: {response.status_code}, Time: {elapsed:.2f}s"
    except requests.exceptions.RequestException as e:
        logging.error(f"HTTPS {url}: Exception {str(e)}")
        return False, str(e)

def check_ssl_handshake(host, port=443, timeout=10):
    try:
        start_time = time.time()
        # Use the same certificate bundle as requests
        context = ssl.create_default_context(cafile=os.environ.get('REQUESTS_CA_BUNDLE'))
        # Alternatively, if you need to be more permissive for testing:
        # context.check_hostname = False
        # context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        
        elapsed = time.time() - start_time
        logging.info(f"SSL {host}:{port}: Successful handshake in {elapsed:.2f}s")
        return True, f"Time: {elapsed:.2f}s"
    except Exception as e:
        logging.error(f"SSL {host}:{port}: Failed with {str(e)}")
        return False, str(e)

def create_socket_connection(host, port, timeout=10):
    try:
        start_time = time.time()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            elapsed = time.time() - start_time
            logging.info(f"SOCKET {host}:{port}: Connected in {elapsed:.2f}s")
            return True, f"Time: {elapsed:.2f}s"
    except Exception as e:
        logging.error(f"SOCKET {host}:{port}: Failed with {str(e)}")
        return False, str(e)

def run_batch_tests(is_reference=False):
    """Run tests on a batch of endpoints, either Zscaler or reference endpoints"""
    targets = PUBLIC_REFERENCE if is_reference else ZSCALER_ENDPOINTS
    group_name = "REFERENCE" if is_reference else "ZSCALER"
    
    logging.info(f"------- Starting {group_name} tests -------")
    results = {target: {} for target in targets}
    
    # Basic connectivity tests for all targets
    for target in targets:
        is_ip = all(c.isdigit() or c == '.' for c in target)
        
        # Always run ping
        results[target]['ping'] = run_ping(target)
        
        # DNS lookup for hostnames only
        if not is_ip:
            results[target]['dns'] = run_dns_lookup(target)
        
        # Socket tests for likely IPs
        if is_ip:
            results[target]['socket_80'] = create_socket_connection(target, 80)
            results[target]['socket_443'] = create_socket_connection(target, 443)
            
        # HTTP/HTTPS tests where appropriate
        if not is_ip or target in ["104.129.195.20", "104.129.204.228"]:
            results[target]['http'] = check_http_connection(target)
            
        if not is_ip or is_reference:
            results[target]['https'] = check_https_connection(target)
            results[target]['ssl'] = check_ssl_handshake(target)
    
    # Run traceroute to one representative target
    if targets:
        sample_target = targets[0]
        run_traceroute(sample_target)
    
    logging.info(f"------- Completed {group_name} tests -------")
    return results

def detect_zscaler_status():
    """Try to detect if Zscaler is currently active"""
    try:
        # Check for Zscaler process
        if platform.system().lower() == "windows":
            cmd = "tasklist | findstr /i zscaler"
        else:
            cmd = "ps aux | grep -i zscaler | grep -v grep"
        
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        zscaler_running = "zscaler" in result.stdout.lower()
        
        # Check for Zscaler in routes
        if platform.system().lower() == "windows":
            route_cmd = "route print"
        else:
            route_cmd = "netstat -rn"
        
        route_result = subprocess.run(route_cmd, shell=True, capture_output=True, text=True)
        zscaler_in_routes = any(ip in route_result.stdout for ip in ZSCALER_ENDPOINTS if all(c.isdigit() or c == '.' for c in ip))
        
        status = "ACTIVE" if (zscaler_running or zscaler_in_routes) else "INACTIVE/UNKNOWN"
        logging.info(f"ZSCALER STATUS: {status} (Process: {zscaler_running}, Routes: {zscaler_in_routes})")
        return status
    except Exception as e:
        logging.error(f"ZSCALER STATUS CHECK: Failed with {str(e)}")
        return "UNKNOWN"

def periodic_full_test():
    """Run a more comprehensive test periodically"""
    try:
        logging.info("========== STARTING COMPREHENSIVE TEST ==========")
        
        # Check Zscaler status
        zscaler_status = detect_zscaler_status()
        
        # Run tests on both Zscaler and reference endpoints
        zscaler_results = run_batch_tests(is_reference=False)
        reference_results = run_batch_tests(is_reference=True)
        
        # Calculate success rates
        zscaler_success = sum(1 for target in zscaler_results for test, (success, _) 
                             in zscaler_results[target].items() if success)
        zscaler_total = sum(1 for target in zscaler_results for test in zscaler_results[target])
        
        reference_success = sum(1 for target in reference_results for test, (success, _) 
                               in reference_results[target].items() if success)
        reference_total = sum(1 for target in reference_results for test in reference_results[target])
        
        # Log summary
        if zscaler_total > 0 and reference_total > 0:
            zscaler_rate = (zscaler_success / zscaler_total) * 100
            reference_rate = (reference_success / reference_total) * 100
            
            logging.info(f"SUMMARY: Zscaler Success Rate: {zscaler_rate:.1f}% ({zscaler_success}/{zscaler_total})")
            logging.info(f"SUMMARY: Reference Success Rate: {reference_rate:.1f}% ({reference_success}/{reference_total})")
            
            # Detect potential issues
            if zscaler_rate < 70 and reference_rate > 90:
                logging.warning("DETECTED: Likely Zscaler tunnel issue (good reference connections but poor Zscaler connections)")
            elif zscaler_rate < 70 and reference_rate < 70:
                logging.warning("DETECTED: Likely general network issue (both Zscaler and reference connections failing)")
        
        logging.info("========== COMPLETED COMPREHENSIVE TEST ==========")
    except Exception as e:
        logging.error(f"COMPREHENSIVE TEST: Failed with exception")
        logging.error(traceback.format_exc())

def main():
    start_time = time.time()
    iteration = 0
    
    logging.info("======================================================")
    logging.info("ZSCALER MONITORING STARTED")
    logging.info(f"System: {platform.system()} {platform.release()}")
    logging.info(f"Monitoring Zscaler endpoints: {', '.join(ZSCALER_ENDPOINTS)}")
    logging.info(f"Reference endpoints: {', '.join(PUBLIC_REFERENCE)}")
    logging.info("======================================================")
    
    try:
        while time.time() - start_time < TOTAL_RUNTIME:
            iteration += 1
            logging.info(f"TEST ITERATION #{iteration} (Elapsed: {(time.time() - start_time):.0f}s)")
            
            # Run the full test
            periodic_full_test()
            
            # Wait for the next test interval
            time.sleep(TEST_INTERVAL)
            
    except KeyboardInterrupt:
        logging.info("Monitoring stopped by user")
    except Exception as e:
        logging.error(f"Monitoring stopped due to error: {str(e)}")
        logging.error(traceback.format_exc())
    finally:
        logging.info("======================================================")
        logging.info(f"ZSCALER MONITORING COMPLETED: Ran {iteration} iterations over {(time.time() - start_time):.0f} seconds")
        logging.info("======================================================")

if __name__ == "__main__":
    main()