import re
import csv
from collections import defaultdict
import sys

# Configuration
LOG_FILE = 'sample.log'
CSV_OUTPUT_FILE = 'log_analysis_results.csv'
FAILED_LOGIN_THRESHOLD = 10  # Threshold for flagging suspicious login attempts

# Pattern to extract details from log entries
LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<endpoint>\S+) \S+" (?P<status>\d{3}) \S+( "(?P<message>.*)")?$'
)

def extract_log_details(line):
    """
    Extracts details from a single log entry.

    Args:
        line (str): The log entry string.

    Returns:
        dict or None: Extracted log details as a dictionary, or None if the line is invalid.
    """
    match = LOG_PATTERN.match(line)
    return match.groupdict() if match else None

def calculate_ip_requests(log_entries):
    """
    Calculates the number of requests for each IP.

    Args:
        log_entries (list): Parsed log entries.

    Returns:
        dict: Mapping of IP addresses to request counts.
    """
    ip_requests = defaultdict(int)
    for entry in log_entries:
        ip_requests[entry['ip']] += 1
    return ip_requests

def calculate_endpoint_requests(log_entries):
    """
    Counts requests for each endpoint.

    Args:
        log_entries (list): Parsed log entries.

    Returns:
        dict: Mapping of endpoints to their request counts.
    """
    endpoint_requests = defaultdict(int)
    for entry in log_entries:
        endpoint_requests[entry['endpoint']] += 1
    return endpoint_requests

def detect_suspicious_activity(log_entries, threshold=10):
    """
    Detects potential brute-force login attempts.

    Args:
        log_entries (list): List of parsed log entry dictionaries.
        threshold (int): The failed login attempt threshold to flag an IP.

    Returns:
        dict: A dictionary of suspicious IPs and their failed login counts.
    """
    failed_attempts = defaultdict(int)
    
    for entry in log_entries:
        status = entry.get('status')
        message = entry.get('message') or ""  # Convert None to an empty string
        
        # Check for failed login conditions
        if status == '401' or 'Invalid credentials' in message:
            ip = entry.get('ip')
            failed_attempts[ip] += 1

    # Filter IPs exceeding the threshold
    suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count >= threshold}
    return suspicious_ips


def print_analysis_results(ip_requests, most_accessed_endpoint, suspicious_ips):
    """
    Prints analysis results to the console.

    Args:
        ip_requests (dict): Number of requests per IP.
        most_accessed_endpoint (tuple): Most accessed endpoint and its count.
        suspicious_ips (dict): Flagged IPs with their failed login counts.
    """
    print("\nRequests Per IP Address:")
    print(f"{'IP Address':<20} {'Request Count':<15}")
    print("-" * 35)
    for ip, count in ip_requests:
        print(f"{ip:<20} {count:<15}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    if suspicious_ips:
        print("\nSuspicious Activity Detected:")
        print(f"{'IP Address':<20} {'Failed Attempts':<15}")
        print("-" * 35)
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count:<15}")
    else:
        print("\nNo Suspicious Activity Detected.")

def export_results_to_csv(ip_requests, most_accessed_endpoint, suspicious_ips, file_name):
    """
    Saves analysis results to a CSV file.

    Args:
        ip_requests (list): List of IP requests sorted by count.
        most_accessed_endpoint (tuple): Most accessed endpoint and its count.
        suspicious_ips (dict): IPs flagged for suspicious activity.
        file_name (str): Name of the output CSV file.
    """
    try:
        with open(file_name, 'w', newline='') as file:
            writer = csv.writer(file)

            writer.writerow(['Requests Per IP Address'])
            writer.writerow(['IP Address', 'Request Count'])
            for ip, count in ip_requests:
                writer.writerow([ip, count])

            writer.writerow([])

            writer.writerow(['Most Frequently Accessed Endpoint'])
            writer.writerow(['Endpoint', 'Access Count'])
            writer.writerow(most_accessed_endpoint)

            writer.writerow([])

            writer.writerow(['Suspicious Activity'])
            writer.writerow(['IP Address', 'Failed Login Attempts'])
            for ip, count in suspicious_ips.items():
                writer.writerow([ip, count])

        print(f"\nResults saved to {file_name}")
    except Exception as error:
        print(f"Error saving results: {error}")

def main():
    try:
        with open(LOG_FILE, 'r') as file:
            parsed_entries = [
                extract_log_details(line.strip()) for line in file
                if (parsed := extract_log_details(line.strip())) is not None
            ]
    except FileNotFoundError:
        print(f"Error: Log file '{LOG_FILE}' not found.")
        sys.exit(1)
    except Exception as error:
        print(f"Error reading log file: {error}")
        sys.exit(1)

    ip_requests = sorted(calculate_ip_requests(parsed_entries).items(), key=lambda x: x[1], reverse=True)
    endpoint_requests = calculate_endpoint_requests(parsed_entries)
    most_accessed = max(endpoint_requests.items(), key=lambda x: x[1], default=("N/A", 0))
    suspicious_ips = detect_suspicious_activity(parsed_entries, FAILED_LOGIN_THRESHOLD)

    print_analysis_results(ip_requests, most_accessed, suspicious_ips)
    export_results_to_csv(ip_requests, most_accessed, suspicious_ips, CSV_OUTPUT_FILE)

if __name__ == "__main__":
    main()
