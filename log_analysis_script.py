
import re
import csv

# File paths
LOG_FILE = "sample.log" # Please replace the path according to your destination while evaluating
OUTPUT_CSV = "log_analysis_results.csv"

# Threshold for detecting suspicious activity
FAILED_LOGIN_THRESHOLD = 10

# Here we parse the log file
log_entries = []
with open(LOG_FILE, "r") as file:
    for line in file:
        match = re.match(r'(?P<ip>\d+\.\d+\.\d+\.\d+) .* "(?:GET|POST) (?P<endpoint>/\S*) HTTP/1\.\d" (?P<status>\d+)', line)
        if match:
            log_entries.append({
                "ip": match.group("ip"),
                "endpoint": match.group("endpoint"),
                "status": int(match.group("status")),
            })

# Here we count requests per IP
ip_counts = {}
for entry in log_entries:
    ip = entry["ip"]
    if ip not in ip_counts:
        ip_counts[ip] = 0
    ip_counts[ip] += 1

# Here we sort the IP counts
sorted_ip_counts = []
for ip, count in ip_counts.items():
    sorted_ip_counts.append((ip, count))

sorted_ip_counts.sort(key=lambda x: x[1], reverse=True)

# Here we count endpoint accesses
endpoint_counts = {}
for entry in log_entries:
    endpoint = entry["endpoint"]
    if endpoint not in endpoint_counts:
        endpoint_counts[endpoint] = 0
    endpoint_counts[endpoint] += 1

# Here we find most accessed endpoint
most_accessed_endpoint = None
max_count = 0
for endpoint, count in endpoint_counts.items():
    if count > max_count:
        most_accessed_endpoint = (endpoint, count)
        max_count = count

# Here we detect suspicious activity
failed_logins = {}
for entry in log_entries:
    if entry["status"] == 401:  # as 401 indicates Failed login status in the sample.log file
        ip = entry["ip"]
        if ip not in failed_logins:
            failed_logins[ip] = 0
        failed_logins[ip] += 1

# Here we collect suspicious IPs based on the threshold which is 10
suspicious_ips = []
for ip, count in failed_logins.items():
    if count > FAILED_LOGIN_THRESHOLD:
        suspicious_ips.append((ip, count))

# Displaying results
print("Requests per IP:")
for ip, count in sorted_ip_counts:
    print(f"{ip:<15} {count}")
print()

print("Most Frequently Accessed Endpoint:")
print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
print()

print("Suspicious Activity Detected:")
for ip, count in suspicious_ips:
    print(f"{ip:<15} {count}")
print()

# Here we save the results to a CSV file
with open(OUTPUT_CSV, "w", newline='') as file:
    writer = csv.writer(file)

    # Save requests per IP
    writer.writerow(["Requests per IP"])
    writer.writerow(["IP Address", "Request Count"])
    writer.writerows(sorted_ip_counts)
    writer.writerow([])

    # Save most accessed endpoint
    writer.writerow(["Most Accessed Endpoint"])
    writer.writerow(["Endpoint", "Access Count"])
    writer.writerow(most_accessed_endpoint)
    writer.writerow([])

    # Save suspicious activity
    writer.writerow(["Suspicious Activity"])
    writer.writerow(["IP Address", "Failed Login Count"])
    writer.writerows(suspicious_ips)

print(f"Results saved to {OUTPUT_CSV}")