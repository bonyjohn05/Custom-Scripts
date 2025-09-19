#!/usr/bin/env python3
import os

# Exact JSON log entry
log_data = 'Sep 19 04:04:29 ubuntu-user sshd[6246]: Failed password for root from 192.168.0.161 port 54945 ssh2'

# File path (Windows style)
file_path = r"/fullpath/of/your/logfile"  # Replace it with your full log file path.

try:
    # Ensure the directory exists
    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    # Append the log twice, each on its own line
    with open(file_path, "a") as file:
        file.write(log_data + "\n")
        file.write(log_data + "\n")

    print(f"Two logs appended successfully to {file_path}")
except Exception as e:
    print(f"Error writing logs: {e}")
