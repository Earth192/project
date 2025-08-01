import os
import random
import json
import csv
from datetime import datetime

# Directory to save all logs
log_dir = "/Users/jenish/Documents/IDS/"
os.makedirs(log_dir, exist_ok=True)

# Generate random IP address
def generate_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

# Create one log entry in text, JSON, and dict (for CSV)
def generate_log_entry():
    timestamp = datetime.utcnow().isoformat() + "Z"
    src_ip = generate_ip()
    dst_ip = generate_ip()
    src_port = random.randint(1024, 65535)
    dst_port = random.choice([80, 443, 22, 3389, 53])
    protocol = random.choice(["TCP", "UDP", "ICMP"])
    action = random.choice(["ALLOW", "BLOCK"])
    device = "firewall-01"
    message = f"Connection {'allowed' if action == 'ALLOW' else 'blocked'} via {protocol}"

    log_dict = {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "action": action,
        "device": device,
        "message": message
    }

    log_text = f"{timestamp} {device}: {action} {protocol} connection from {src_ip}:{src_port} to {dst_ip}:{dst_port}"

    return log_text, log_dict

# File paths
txt_path = os.path.join(log_dir, "firewall_logs.txt")
json_path = os.path.join(log_dir, "firewall_logs.json")
csv_path = os.path.join(log_dir, "firewall_logs.csv")

# Open files for writing
with open(txt_path, "w") as txt_file, \
     open(json_path, "w") as json_file, \
     open(csv_path, "w", newline='') as csv_file:

    csv_writer = None

    for _ in range(1000):
        log_text, log_dict = generate_log_entry()

        # Write to .txt
        txt_file.write(log_text + "\n")

        # Write to .json (newline-delimited)
        json_file.write(json.dumps(log_dict) + "\n")

        # Write to .csv
        if csv_writer is None:
            csv_writer = csv.DictWriter(csv_file, fieldnames=log_dict.keys())
            csv_writer.writeheader()
        csv_writer.writerow(log_dict)

print(f"✅ Logs generated in: {log_dir}")
print(f"📄 - Text: firewall_logs.txt\n📄 - JSON: firewall_logs.json\n📄 - CSV : firewall_logs.csv")
