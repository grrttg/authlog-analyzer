#!/usr/bin/env python3
import sys
import os
import re
import requests
import configparser
import argparse

# Regex for extracting IPs from failed SSH login attempts
FAILED_REGEX = r"Failed password for .* from (\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)"

def parse_auth_log(log_path):
    """Parse the SSH auth log and extract IPs from failed login attempts."""
    print(f"[INFO] Parsing log file: {log_path}")
    try:
        with open(log_path, 'r') as log_file:
            lines = log_file.readlines()
        if not lines:
            print("[INFO] Log file is empty.")
            return []
            
        ip_addresses = []
        for line in lines:
            match = re.search(FAILED_REGEX, line)
            if match:
                ip_addresses.append(match.group(1))
                
        if not ip_addresses:
            print("[INFO] No failed login attempts with valid IPs found.")
        else:
            print(f"[INFO] Found {len(ip_addresses)} failed login attempts with valid IPs.")
            
        return ip_addresses
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
    print(f"[ALERT] Logging alert for IP: {ip} with score: {score}")
    try:
        alert_message = f"[ALERT] IP: {ip}, Abuse Score: {score}\n"
        with open(alert_log_path, 'a') as log_file:
            log_file.write(alert_message)
        print(alert_message.strip())
    except Exception as e:
        print(f"[ERROR] Could not write to alert log: {e}")

def main():
    """Main script logic."""
    parser = argparse.ArgumentParser(description="Monitor and analyze SSH logs.")
    parser.add_argument('log_file', nargs='?', help="Path to the log file (overrides config.ini)", default=None)
    args = parser.parse_args()

    # Handle log file path
    log_file = args.log_file
    if not log_file:
        log_file = input("[PROMPT] Enter log file path (press Enter to use default): ").strip()
        # Clean up the dragged file path by removing quotes and extra whitespace
        log_file = log_file.strip("'\"").strip()
        if not log_file:
            print("[INFO] Using default log file from config.ini.")
            config = configparser.ConfigParser()
            config.read('config.ini')
            log_file = config.get('default', 'log_file', fallback='/var/log/auth.log')

    print("[INFO] Loading configuration...")
    # Load configuration
    config = configparser.ConfigParser()
    config.read('config.ini')
    
    threshold = config.getint('default', 'threshold', fallback=50)
    alert_log = config.get('default', 'alert_log', fallback='alerts.log')
    api_key = config.get('abuseipdb', 'api_key', fallback=None)
    base_url = config.get('abuseipdb', 'base_url', fallback='https://api.abuseipdb.com/api/v2/check')

    if not api_key:
        print("[ERROR] API key is missing in config.ini.")
        sys.exit(1)

    print("[INFO] Starting log parsing...")
    # Parse the auth log
    ip_addresses = parse_auth_log(log_file)

    if not ip_addresses:
        print("[INFO] No valid IPs to check.")
        print("[INFO] No alerts were generated. alerts.log was not created.")
    else:
        print("[INFO] Checking IP reputations...")
        alerts_generated = False
        
        # Check each IP's reputation and log alerts if above threshold
        for ip in ip_addresses:
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
