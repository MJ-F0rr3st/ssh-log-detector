"""
SSH Log Analysis Tool

This script analyses SSH authentication logs to detect:
- Brute-force attacks
- Password spraying
- Suspicious login patterns

It also enriches detected IPs using an external API.
"""

import argparse
import requests


def parse_log_file(file_path):
    """
    Reads an SSH log file and extracts:
    - Failed login counts per IP
    - Users targeted per IP
    - Whether an IP had failures followed by a success
    """

    failed_counts = {}              # Stores number of failed logins per IP
    ip_users = {}                   # Stores unique usernames targeted per IP
    ip_fail_then_success = {}       # Tracks failures followed by success

    # Open the log file safely
    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:

            # Only process authentication-related lines
            if "Failed password" in line or "Accepted password" in line:

                parts = line.split()

                # Extract timestamp (first 3 elements of log line)
                timestamp = " ".join(parts[0:3])

                # Safely extract username and IP address
                try:
                    # Extract username (after "for")
                    user_index = parts.index("for") + 1
                    username = parts[user_index]

                    # Extract IP address (after "from")
                    ip_index = parts.index("from") + 1
                    ip = parts[ip_index]
                except (ValueError, IndexError):
                    # Skip malformed or incomplete lines
                    continue

                # Determine login result
                if "Failed password" in line:
                    status = "FAIL"
                else:
                    status = "SUCCESS"

                # Print parsed log entry
                print(f"Time: {timestamp} | User: {username} | IP: {ip} | Status: {status}")

                # Track success after failures
                if ip not in ip_fail_then_success:
                    ip_fail_then_success[ip] = {"failures": 0, "success": False}

                if status == "FAIL":
                    ip_fail_then_success[ip]["failures"] += 1

                # If a success occurs after failures, flag it
                if status == "SUCCESS" and ip_fail_then_success[ip]["failures"] > 0:
                    ip_fail_then_success[ip]["success"] = True

                # Track failed login counts
                if status == "FAIL":
                    if ip in failed_counts:
                        failed_counts[ip] += 1
                    else:
                        failed_counts[ip] = 1

                    # Track which users were targeted by this IP
                    if ip not in ip_users:
                        ip_users[ip] = set()

                    ip_users[ip].add(username)

    return failed_counts, ip_users, ip_fail_then_success


def print_failed_counts(failed_counts):
    """Print number of failed login attempts per IP."""
    print("\nFailed login counts by IP:")
    for ip, count in failed_counts.items():
        print(f"{ip}: {count}")


def detect_brute_force(failed_counts, threshold=2):
    """
    Flags IPs with a high number of failed login attempts.
    """
    print("\nSuspicious IPs (possible brute force):")
    for ip, count in failed_counts.items():
        if count >= threshold:
            print(f"{ip} flagged with {count} failed attempts")


def detect_password_spraying(ip_users, user_threshold=2):
    """
    Flags IPs attempting multiple usernames (password spraying behaviour).
    """
    print("\nSuspicious IPs (possible password spraying):")
    for ip, users in ip_users.items():
        if len(users) >= user_threshold:
            print(f"{ip} targeted {len(users)} different users: {', '.join(sorted(users))}")


def detect_success_after_failure(ip_fail_then_success):
    """
    Flags IPs that succeed after multiple failed attempts
    (possible account compromise).
    """
    print("\nSuspicious IPs (success after multiple failures):")
    for ip, data in ip_fail_then_success.items():
        if data["failures"] > 1 and data["success"]:
            print(f"{ip} had {data['failures']} failures followed by a successful login")


def lookup_ip_info(ip):
    """
    Queries an external API to retrieve information about an IP address.
    """
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,query"

    try:
        response = requests.get(url, timeout=5)
        data = response.json()

        if data.get("status") == "success":
            return data
        else:
            return {"query": ip, "error": data.get("message", "Lookup failed")}

    except Exception as e:
        return {"query": ip, "error": str(e)}


def enrich_suspicious_ips(failed_counts, threshold=2):
    """
    Uses an external API to provide additional context
    for suspicious IP addresses.
    """
    print("\nAPI enrichment for suspicious IPs:")

    for ip, count in failed_counts.items():
        if count >= threshold:
            info = lookup_ip_info(ip)

            if "error" in info:
                print(f"{ip} | Lookup failed: {info['error']}")
            else:
                print(
                    f"{ip} | Country: {info.get('country', 'Unknown')} | "
                    f"City: {info.get('city', 'Unknown')} | "
                    f"ISP: {info.get('isp', 'Unknown')}"
                )


def get_arguments():
    """
    Defines and parses command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Detect suspicious activity in SSH authentication logs"
    )
    parser.add_argument(
        "-i", "--input", required=True,
        help="Path to the SSH log file"
    )
    return parser.parse_args()


def main():
    """
    Entry point of the script.
    Coordinates parsing, detection, and reporting.
    """
    args = get_arguments()
    file_path = args.input

    # Parse log file
    failed_counts, ip_users, ip_fail_then_success = parse_log_file(file_path)

    # Run detection and reporting
    print_failed_counts(failed_counts)
    detect_brute_force(failed_counts)
    detect_password_spraying(ip_users)
    detect_success_after_failure(ip_fail_then_success)
    enrich_suspicious_ips(failed_counts)


if __name__ == "__main__":
    main()