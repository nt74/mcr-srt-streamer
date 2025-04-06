#!/usr/bin/env python3

import json
import subprocess
import os
import shlex
import sys
import time # Added for timestamping the safe list

# --- Configuration ---
IPERF_FULL_LIST_PATH = "app/data/iperf3_export_servers.json" # Original full list
UDP_SAFE_LIST_PATH = "app/data/udp_safe_servers.json"   # Output file for passing servers
DEFAULT_IPERF_PORT = 5201
IPERF_UDP_BITRATE = "10M"
IPERF_UDP_DURATION = 5       # Test duration in seconds
IPERF_PACKET_LENGTH = 1200
IPERF_CONNECT_TIMEOUT_MS = 5000
SUBPROCESS_TIMEOUT = 15 # Total time allowed for the iperf3 command

# --- Helper Function (adapted from network_test.py) ---
# (parse_host_port function remains exactly the same as before)
def parse_host_port(server_entry):
    """Parses host and port from the 'IP_HOST' string."""
    ip_host_string = server_entry.get("IP_HOST", "")
    if not ip_host_string: return None, None
    parts = ip_host_string.split()
    host = None
    port = DEFAULT_IPERF_PORT
    port_str = None
    try:
        if '-c' in parts:
            c_index = parts.index('-c')
            if c_index + 1 < len(parts): host = parts[c_index + 1]
        if not host: return None, None
        if '-p' in parts:
            p_index = parts.index('-p')
            if p_index + 1 < len(parts): port_str = parts[p_index + 1]
        if port_str:
            port_str = port_str.strip()
            if '-' in port_str:
                base_port_str = port_str.split('-')[0].strip()
                port = int(base_port_str) if base_port_str.isdigit() else DEFAULT_IPERF_PORT
            elif port_str.isdigit():
                port = int(port_str)
            else: port = DEFAULT_IPERF_PORT
        if port < 1 or port > 65535: port = DEFAULT_IPERF_PORT
        if not host or len(host) < 3: return None, None
    except (ValueError, IndexError): return None, None
    return host, port

# --- Main Script ---
def main():
    if not os.path.exists(IPERF_FULL_LIST_PATH):
        print(f"Error: Full server list file not found at {IPERF_FULL_LIST_PATH}", file=sys.stderr)
        print("Ensure you run this script from the mcr-srt-streamer root directory.", file=sys.stderr)
        sys.exit(1)

    data_dir = os.path.dirname(UDP_SAFE_LIST_PATH)
    if not os.path.exists(data_dir):
        try:
            os.makedirs(data_dir, exist_ok=True)
            print(f"Created data directory: {data_dir}")
        except OSError as e:
            print(f"Error creating data directory {data_dir}: {e}", file=sys.stderr)
            sys.exit(1)

    full_server_list = []
    try:
        with open(IPERF_FULL_LIST_PATH, 'r', encoding='utf-8') as f:
            full_server_list = json.load(f)
        if not isinstance(full_server_list, list):
             print(f"Error: Content of {IPERF_FULL_LIST_PATH} is not a valid JSON list.", file=sys.stderr)
             full_server_list = []
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from {IPERF_FULL_LIST_PATH}: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading server list {IPERF_FULL_LIST_PATH}: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Loaded {len(full_server_list)} server entries from full list. Starting UDP tests...")
    print("-" * 30)

    udp_safe_servers = [] # List to store servers that pass
    tested_count = 0
    passed_count = 0
    failed_count = 0

    for entry in full_server_list:
        if not isinstance(entry, dict): continue
        host, port = parse_host_port(entry)
        if not host or not port:
            continue

        tested_count += 1
        server_id = f"{host}:{port}"

        iperf_cmd_list = [
            "iperf3", "-c", host, "-p", str(port),
            "-u", "-b", IPERF_UDP_BITRATE, "-t", str(IPERF_UDP_DURATION),
            "-J", "--length", str(IPERF_PACKET_LENGTH),
            "--connect-timeout", str(IPERF_CONNECT_TIMEOUT_MS)
        ]

        print(f"Testing {server_id}...", end=" ", flush=True)

        reason = ""
        passed = False
        try:
            result = subprocess.run(iperf_cmd_list, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT, check=False)

            if result.returncode == 0:
                try:
                    iperf_output = json.loads(result.stdout)
                    if "error" not in iperf_output:
                        passed = True
                    else:
                        reason = f"iperf error: {iperf_output['error']}"
                except json.JSONDecodeError:
                    reason = "Invalid JSON output"
                except Exception as e:
                    reason = f"Error processing JSON: {e}"
            else:
                 stderr_lower = (result.stderr or "").lower()
                 if "connection refused" in stderr_lower: reason = "Connection refused"
                 elif "unable to connect" in stderr_lower: reason = "Unable to connect"
                 elif "interrupt" in stderr_lower: reason = "Interrupted"
                 elif "parameter" in stderr_lower: reason = "Bad parameters"
                 elif result.stderr: reason = f"stderr: {result.stderr.strip()}"
                 else: reason = f"Exit code {result.returncode}"

        except subprocess.TimeoutExpired:
            reason = f"Timeout >{SUBPROCESS_TIMEOUT}s"
        except FileNotFoundError:
            print("\nError: 'iperf3' command not found. Please ensure it's installed and in your PATH.")
            reason = "iperf3 not found" # Mark as failed
        except Exception as e:
            reason = f"Execution error: {e}"

        if passed:
            print(f"PASS")
            passed_count += 1
            udp_safe_servers.append(entry) # Add the original entry dictionary
        else:
            print(f"FAILED (Reason: {reason})")
            failed_count += 1

    print("-" * 30)
    print(f"Test Complete. Total Tested: {tested_count}, Passed UDP: {passed_count}, Failed UDP: {failed_count}")

    # *** MODIFIED: Save only the list of passing server dictionaries ***
    try:
        with open(UDP_SAFE_LIST_PATH, 'w', encoding='utf-8') as f:
            # Save the list directly, not nested in another dictionary
            json.dump(udp_safe_servers, f, indent=4)
        print(f"Saved {passed_count} passing servers to {UDP_SAFE_LIST_PATH}")
        # Add a timestamp comment inside the JSON maybe? Or rely on file mod time.
        # Let's add a simple timestamp file alongside it.
        try:
            with open(UDP_SAFE_LIST_PATH + ".timestamp", 'w') as ts_f:
                ts_f.write(str(time.time()))
        except Exception:
             print(f"Warning: Could not write timestamp file for {UDP_SAFE_LIST_PATH}")

    except Exception as e:
        print(f"Error writing results to {UDP_SAFE_LIST_PATH}: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
