from datetime import datetime
from collections import Counter
import sys


def parse_failed_login(line):
    parts = line.split()

    timestamp = " ".join(parts[:3])
    ip = parts[parts.index("from") + 1]

    if "invalid user" in line:
        username = parts[parts.index("user") + 1]
    else:
        username = parts[parts.index("for") + 1]

    return timestamp, username, ip


def analyze_log(log_file):
    failed_ips = []
    invalid_users = []
    successful_ips = []
    failed_event = []
    auth_events = []

    try:
        with open(log_file, "r") as file:

            for line in file:

                if "Failed password" in line:
                    timestamp, username, ip = parse_failed_login(line)

                    failed_ips.append(ip)
                    failed_event.append((username, ip, timestamp))
                    auth_events.append((timestamp, "FAILED", username,ip))
                if "invalid user" in line:
                    parts = line.split()

                    username = parts[parts.index("user") + 1]
                    invalid_users.append(username)

                if "Accepted password" in line:
                    parts = line.split()
                    timestamp= " ".join(parts[:3])
                    username = parts[parts.index("for")+1]
                    ip = parts[parts.index("from") + 1]
                    successful_ips.append(ip)
                    auth_events.append((timestamp, "SUCCESS", username,ip))
    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' was not found.")
        sys.exit(1)

    except PermissionError:
        print(f"Error: Permission denied when reading '{log_file}'.")
        sys.exit(1)

    return failed_ips, invalid_users, successful_ips, failed_event,  auth_events
if len(sys.argv) != 2:
    print("Usage: python3 log_analyzer.py <log_file>")
    sys.exit(1)

log_file = sys.argv[1]

failed_ips, invalid_users, successful_ips, failed_event,  auth_events = analyze_log(log_file)
def sort_timestamp(event):
    timestamp = event[0]
    month, day, time = timestamp.split()

    timestamp_with_year = f"{month} {day} 2000 {time}"

    return datetime.strptime(
        timestamp_with_year,
        "%b %d %Y %H:%M:%S"
    )


auth_events.sort(key=sort_timestamp)

failed_users = []

for username, ip, timestamp in failed_event:
    failed_users.append(username)


print("\nFailed Login Attempts by Username:")
print("-----------------------------------")

for username, count in Counter(failed_users).items():
    print(f"{username}: {count} failed attempts")


print("\nFailed Login Attempts:")
print("----------------------")

for ip, count in Counter(failed_ips).items():
    print(f"{ip}: {count} failed attempts")

print("\nInvalid Usernames:")
print("-----------------")

for username, count in Counter(invalid_users).items():
    print(f"{username}: {count} attempts")

print("\nSuccessful Logins:")
print("------------------")

for event_timestamp,event_type,username,ip in auth_events:
   if event_type == "SUCCESS":
     print(
           f"username: {username}| " 
           f"ip: {ip} | "
           f"time: {event_timestamp}"
          )


print("\nSecurity Alerts:")
print("----------------")

failed_count = Counter(failed_ips)
successful_count = Counter(successful_ips)

for ip, count in failed_count.items():

    if count >= 5 and successful_count[ip] > 0:
        print(
            f"[HIGH] {ip} - "
            f"{count} failed attempts followed by "
            f"{successful_count[ip]} successful login(s)"
        )

    elif count >= 3:
        print(
            f"[MEDIUM] {ip} - "
            f"{count} failed login attempts"
        )

    else:
        print(
            f"[LOW] {ip} - "
            f"{count} failed login attempts"
        )


print("\nFailed Login Events:")
print("--------------------")

for username, ip, timestamp in failed_event:
    print(
        f"Username: {username} | "
        f"IP: {ip} | "
        f"Time: {timestamp}"
    )

