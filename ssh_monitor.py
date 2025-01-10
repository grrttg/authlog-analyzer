#!/usr/bin/env python3
import sys
import os
import re
import requests
import configparser
import argparse
import socket
import ipaddress
from dotenv import load_dotenv
from dataclasses import dataclass
from datetime import datetime

print("[DEBUG] Entered ssh_monitor.py – top of file!")
print("[DEBUG] Python interpreter in use:", sys.executable)

from dotenv import load_dotenv
print("[DEBUG] Attempting to load .env")
load_dotenv()
import os
print("[DEBUG] ABUSEIPDB_API_KEY from env is:", os.environ.get("ABUSEIPDB_API_KEY"))

# New comprehensive regex pattern
FAILED_REGEX = r"Failed password for .* from ([^\s]+) port"
SUCCESS_REGEX = r"Accepted (?:password|publickey) for .* from ([^\s]+) port"

# Event types
LOGIN_FAILED = "FAILED"
LOGIN_SUCCESS = "SUCCESS"

print("Script has started!")

@dataclass
class LoginEvent:
    """Represents a single login attempt."""
    timestamp: datetime
    ip: str
    event_type: str
    username: str
    auth_method: str  # password or publickey

def sanitize_file_path(file_path, allowed_paths=None):
    """
    Sanitize and validate a file path.
    
    Args:
        file_path (str): The path to sanitize
        allowed_paths (list): Optional list of allowed base directories
        
    Returns:
        str: Sanitized absolute path, or None if invalid
    """
    if not file_path:
        return None
        
    try:
        # Convert to absolute path and resolve any symbolic links
        clean_path = os.path.abspath(os.path.realpath(file_path))
        
        # Check if path exists and is a file
        if not os.path.isfile(clean_path):
            return None
            
        # If allowed paths specified, verify path is within allowed directories
        if allowed_paths:
            if not any(clean_path.startswith(os.path.abspath(base)) for base in allowed_paths):
                print(f"[WARNING] Path {clean_path} is outside allowed directories")
                return None
                
        return clean_path
        
    except (ValueError, TypeError, OSError) as e:
        print(f"[ERROR] Path validation failed: {e}")
        return None

def parse_auth_log(log_path):
    """Parse the SSH auth log and extract chronological login events."""
    print(f"[INFO] Parsing log file: {log_path}")
    
    # Sanitize the log path
    clean_path = sanitize_file_path(log_path, ['/var/log', 'sample-logs'])
    if not clean_path:
        print(f"[ERROR] Invalid or inaccessible log file path: {log_path}")
        sys.exit(1)
        
    try:
        with open(clean_path, 'r') as log_file:
            lines = log_file.readlines()
        if not lines:
            print("[INFO] Log file is empty.")
            return [], {}
            
        # Store events chronologically and by IP
        chronological_events = []
        events_by_ip = {}
        
        for line in lines:
            # Check for failed attempts
            match = re.search(FAILED_REGEX, line)
            event_type = LOGIN_FAILED if match else None
            
            # If no failed match, check for successful attempts
            if not match:
                match = re.search(SUCCESS_REGEX, line)
                event_type = LOGIN_SUCCESS if match else None
            
            if match and event_type:
                raw_ip = match.group(1)
                if raw_ip == "<INSERT_KNOWN_MALICIOUS_IP>":
                    continue
                    
                normalized_ip = validate_and_normalize_ip(raw_ip)
                if not normalized_ip:
                    print(f"[WARNING] Invalid IP or hostname found: {raw_ip}")
                    continue
                
                # Extract username and auth method
                username = re.search(r"for (?:invalid user )?(\w+)", line)
                username = username.group(1) if username else "unknown"
                auth_method = "publickey" if "publickey" in line else "password"
                
                # Create login event
                event = LoginEvent(
                    timestamp=parse_log_timestamp(line),
                    ip=normalized_ip,
                    event_type=event_type,
                    username=username,
                    auth_method=auth_method
                )
                
                # Store chronologically
                chronological_events.append(event)
                
                # Store by IP
                if normalized_ip not in events_by_ip:
                    events_by_ip[normalized_ip] = []
                events_by_ip[normalized_ip].append(event)
        
        return chronological_events, events_by_ip
        
    except FileNotFoundError:
        print(f"[ERROR] Log file '{log_path}' not found.")
        sys.exit(1)

def check_ip_reputation(ip, api_key, base_url):
    """Check the reputation of an IP using the AbuseIPDB API."""
    print(f"[INFO] Checking reputation for IP: {ip}")
    headers = {'Key': api_key, 'Accept': 'application/json'}
    params = {'ipAddress': ip}
    try:
        response = requests.get(base_url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data['data']['abuseConfidenceScore']
        else:
            print(f"[ERROR] API returned status code {response.status_code} for IP {ip}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Request failed for IP {ip}: {e}")
        return None

def log_alert(alert_log_path, ip, score):
    """Log an alert to a file."""
    try:
        if score == -1:
            alert_message = f"[ALERT] Internal IP detected: {ip} (RFC 1918 address)\n"
        else:
            alert_message = f"[ALERT] IP: {ip}, Abuse Score: {score}\n"
            
        print(alert_message.strip())
        with open(alert_log_path, 'a') as log_file:
            log_file.write(alert_message)
    except Exception as e:
        print(f"[ERROR] Could not write to alert log: {e}")

def validate_and_normalize_ip(ip_or_host):
    """Validate and normalize IP addresses or hostnames."""
    try:
        # Try to resolve hostname to IP
        if not re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$', ip_or_host):
            try:
                ip_or_host = socket.gethostbyname(ip_or_host)
            except socket.gaierror:
                return None

        # Validate IPv4
        if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', ip_or_host):
            addr = ipaddress.IPv4Address(ip_or_host)
            return str(addr)
        # Validate IPv6
        else:
            addr = ipaddress.IPv6Address(ip_or_host)
            return str(addr)
    except ValueError:
        return None

def is_ip_whitelisted(ip, whitelist):
    """Check if an IP is in the whitelist. Supports individual IPs and CIDR notation."""
    if not whitelist:
        return False
        
    try:
        ip_obj = ipaddress.ip_address(ip)
        for entry in whitelist:
            entry = entry.strip()
            try:
                if '/' in entry:  # CIDR notation
                    if ip_obj in ipaddress.ip_network(entry, strict=False):
                        return True
                else:  # Single IP
                    if ip_obj == ipaddress.ip_address(entry):
                        return True
            except ValueError:
                print(f"[WARNING] Invalid whitelist entry: {entry}")
                continue
        return False
    except ValueError:
        print(f"[WARNING] Invalid IP address: {ip}")
        return False

def is_ip_blacklisted(ip, blacklist):
    """Check if an IP is in the blacklist. Supports individual IPs and CIDR notation."""
    if not blacklist:
        return False
        
    try:
        ip_obj = ipaddress.ip_address(ip)
        for entry in blacklist:
            entry = entry.strip()
            try:
                if '/' in entry:  # CIDR notation
                    if ip_obj in ipaddress.ip_network(entry, strict=False):
                        return True
                else:  # Single IP
                    if ip_obj == ipaddress.ip_address(entry):
                        return True
            except ValueError:
                print(f"[WARNING] Invalid blacklist entry: {entry}")
                continue
        return False
    except ValueError:
        print(f"[WARNING] Invalid IP address: {ip}")
        return False

def is_rfc1918(ip):
    """Check if an IP address is in RFC 1918 private ranges."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        if not ip_obj.is_private:
            return False
            
        private_networks = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16')
        ]
        return any(ip_obj in network for network in private_networks)
    except ValueError:
        return False

def get_api_key():
    """Get API key from environment variable or config file."""
    # Try to load from .env file
    load_dotenv()
    
    print("API_KEY is:", os.environ.get("ABUSEIPDB_API_KEY"))  # Note: Changed API_KEY to ABUSEIPDB_API_KEY to match your existing code
    
    # Check environment variable first
    api_key = os.getenv('ABUSEIPDB_API_KEY')
    if api_key:
        return api_key
        
    # Fall back to config.ini if env var not found
    try:
        config = configparser.ConfigParser()
        config.read('config.ini')
        api_key = config.get('abuseipdb', 'api_key', fallback=None)
        if api_key:
            print("[WARNING] Using API key from config.ini. Consider moving it to environment variable.")
        return api_key
    except Exception as e:
        print(f"[ERROR] Failed to read API key from config: {e}")
        return None

def parse_log_timestamp(log_line: str) -> datetime:
    """Extract timestamp from log line and convert to datetime object."""
    try:
        # Example: "Mar 15 09:23:45"
        timestamp_str = " ".join(log_line.split()[:3])
        # Add current year since logs typically don't include it
        timestamp_str = f"{timestamp_str} {datetime.now().year}"
        return datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")
    except (ValueError, IndexError):
        return datetime.now()  # Fallback to current time if parsing fails

def analyze_login_patterns(
    events_by_ip: dict, 
    failed_threshold: int = 3,
    severity_low: int = 3,
    severity_medium: int = 6,
    severity_high: int = 10,
    whitelist: list = None
) -> list:
    """
    Analyze login patterns for each IP and identify suspicious behavior.
    Returns list of suspicious IPs and their patterns.
    
    Severity levels:
    - LOW: failed_attempts >= severity_low
    - MEDIUM: failed_attempts >= severity_medium
    - HIGH: failed_attempts >= severity_high
    """
    suspicious_patterns = []
    
    for ip, events in events_by_ip.items():
        # Skip whitelisted IPs
        if whitelist and is_ip_whitelisted(ip, whitelist):
            print(f"[INFO] Skipping pattern detection for whitelisted IP: {ip}")
            continue
            
        # Sort events chronologically
        sorted_events = sorted(events, key=lambda x: x.timestamp)
        
        # Count failed attempts before each successful login
        failed_count = 0
        for event in sorted_events:
            if event.event_type == LOGIN_FAILED:
                failed_count += 1
            elif event.event_type == LOGIN_SUCCESS and failed_count >= failed_threshold:
                # Determine severity
                severity = "LOW"
                if failed_count >= severity_high:
                    severity = "HIGH"
                elif failed_count >= severity_medium:
                    severity = "MEDIUM"
                
                suspicious_patterns.append({
                    'ip': ip,
                    'failed_attempts': failed_count,
                    'success_time': event.timestamp,
                    'username': event.username,
                    'auth_method': event.auth_method,
                    'severity': severity
                })
                failed_count = 0  # Reset counter after successful login
            elif event.event_type == LOGIN_SUCCESS:
                failed_count = 0  # Reset counter after any successful login
    
    return suspicious_patterns

def main():
    """Main script logic."""
    parser = argparse.ArgumentParser(description="Monitor and analyze SSH logs.")
    parser.add_argument('log_file', nargs='?', help="Path to the log file (overrides config.ini)", default=None)
    args = parser.parse_args()

    # Handle log file path
    log_file = args.log_file
    if not log_file:
        log_file = input("[PROMPT] Enter log file path (press Enter to use default): ").strip()
        log_file = log_file.strip("'\"").strip()
        if not log_file:
            print("[INFO] Using default log file from config.ini.")
            config = configparser.ConfigParser()
            config.read('config.ini')
            log_file = config.get('default', 'log_file', fallback='/var/log/auth.log')
            
    # Sanitize the path before proceeding
    clean_path = sanitize_file_path(log_file, ['/var/log', 'sample-logs'])
    if not clean_path:
        print("[ERROR] Invalid or inaccessible log file path")
        sys.exit(1)
    log_file = clean_path

    print("[INFO] Loading configuration...")
    config = configparser.ConfigParser()
    config.read('config.ini')
    
    threshold = config.getint('default', 'threshold', fallback=50)
    alert_log = config.get('default', 'alert_log', fallback='alerts.log')
    api_key = get_api_key()
    base_url = config.get('abuseipdb', 'base_url', fallback='https://api.abuseipdb.com/api/v2/check')
    
    # Get whitelist from config
    whitelist_str = config.get('default', 'whitelist', fallback='')
    whitelist = [ip.strip() for ip in whitelist_str.split(',') if ip.strip()] if whitelist_str else []
    
    if whitelist:
        print(f"[INFO] Loaded {len(whitelist)} whitelist entries")

    # Get blacklist from config
    blacklist_str = config.get('default', 'blacklist', fallback='')
    blacklist = [ip.strip() for ip in blacklist_str.split(',') if ip.strip()] if blacklist_str else []
    
    if blacklist:
        print(f"[INFO] Loaded {len(blacklist)} blacklist entries")

    if not api_key:
        print("[ERROR] API key is missing in config.ini.")
        sys.exit(1)

    # Add after loading other config values
    internal_ip_action = config.get('default', 'internal_ip_action', fallback='log').lower()
    if internal_ip_action not in ['ignore', 'log', 'check']:
        print("[WARNING] Invalid internal_ip_action in config. Using 'log' as default.")
        internal_ip_action = 'log'

    # Load pattern detection settings
    pattern_detection = config.getboolean('default', 'pattern_detection', fallback=True)
    failed_threshold = config.getint('default', 'failed_attempt_threshold', fallback=3)
    severity_low = config.getint('default', 'pattern_severity_low', fallback=3)
    severity_medium = config.getint('default', 'pattern_severity_medium', fallback=6)
    severity_high = config.getint('default', 'pattern_severity_high', fallback=10)

    print("[INFO] Starting log parsing...")
    chronological_events, events_by_ip = parse_auth_log(log_file)
    
    # Analyze patterns if enabled
    if pattern_detection:
        suspicious_patterns = analyze_login_patterns(
            events_by_ip,
            failed_threshold=failed_threshold,
            severity_low=severity_low,
            severity_medium=severity_medium,
            severity_high=severity_high,
            whitelist=whitelist
        )
        
        # Log suspicious patterns with severity-based formatting
        if suspicious_patterns:
            print("\n[WARNING] Detected suspicious login patterns:")
            for pattern in suspicious_patterns:
                severity_color = {
                    "LOW": "yellow",
                    "MEDIUM": "red",
                    "HIGH": "bold red"
                }.get(pattern['severity'], "yellow")
                
                message = (
                    f"[ALERT] [{pattern['severity']}] Suspicious login pattern from {pattern['ip']}: "
                    f"{pattern['failed_attempts']} failed attempts before successful "
                    f"{pattern['auth_method']} login as '{pattern['username']}' "
                    f"at {pattern['success_time']}"
                )
                print(f"[{severity_color}]{message}[/]")
                
                # Log to alert file with severity prefix
                alert_message = f"[PATTERN-{pattern['severity']}] {message}\n"
                try:
                    with open(alert_log, 'a') as f:
                        f.write(alert_message)
                except Exception as e:
                    print(f"[ERROR] Could not write pattern alert to log: {e}")

    # After pattern detection, process IPs for reputation checks
    unique_ips = set(events_by_ip.keys())
    if not unique_ips:
        print("[INFO] No valid IPs to check.")
        print("[INFO] No alerts were generated. alerts.log was not created.")
    else:
        print("[INFO] Checking IP reputations...")
        alerts_generated = False
        
        for ip in unique_ips:
            if is_ip_blacklisted(ip, blacklist):
                print(f"[INFO] Found blacklisted IP: {ip}")
                log_alert(alert_log, ip, 100)  # Use score 100 for blacklisted IPs
                alerts_generated = True
                continue
                
            if is_ip_whitelisted(ip, whitelist):
                print(f"[INFO] Skipping whitelisted IP: {ip}")
                continue
                
            if is_rfc1918(ip):
                if internal_ip_action == 'ignore':
                    print(f"[INFO] Ignoring internal IP: {ip}")
                    continue
                elif internal_ip_action == 'log':
                    print(f"[INFO] Logging internal IP attempt: {ip}")
                    log_alert(alert_log, ip, -1)  # Use -1 to indicate internal IP
                    alerts_generated = True
                    continue
                # If action is 'check', continue with normal processing
                
            score = check_ip_reputation(ip, api_key, base_url)
            if score is not None and score >= threshold:
                log_alert(alert_log, ip, score)
                alerts_generated = True

        if alerts_generated:
            print(f"[INFO] Alerts were logged to {alert_log}.")
        else:
            print("[INFO] No alerts were generated. alerts.log was not created.")

    print("[INFO] Script completed.")

if __name__ == "__main__":
    main()
