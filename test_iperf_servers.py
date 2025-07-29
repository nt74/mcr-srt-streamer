#!/usr/bin/env python3

import json
import subprocess
import os
import sys
import time
import requests
from datetime import datetime, timedelta

# --- Configuration ---
IPERF_FULL_LIST_PATH = "app/data/listed_iperf3_servers.json"
UDP_SAFE_LIST_PATH = "app/data/udp_safe_servers.json"
DEFAULT_IPERF_PORT = 5201
IPERF_UDP_BITRATE = "10M"
IPERF_UDP_DURATION = 5
IPERF_PACKET_LENGTH = 1200
IPERF_CONNECT_TIMEOUT_MS = 5000
SUBPROCESS_TIMEOUT = 15

IPERF_JSON_URL = "https://export.iperf3serverlist.net/listed_iperf3_servers.json"
DOWNLOAD_CACHE_DURATION = timedelta(hours=6)


def download_iperf_list(force_update=False):
    """Download the iperf3 server list if missing or outdated."""
    needs_download = force_update
    if not os.path.exists(IPERF_FULL_LIST_PATH):
        print(f"Server list not found: {IPERF_FULL_LIST_PATH}. Downloading...")
        needs_download = True
    else:
        try:
            file_mod_time = datetime.fromtimestamp(
                os.path.getmtime(IPERF_FULL_LIST_PATH)
            )
            if datetime.now() - file_mod_time > DOWNLOAD_CACHE_DURATION:
                print("Server list cache is outdated. Downloading latest...")
                needs_download = True
        except Exception as e:
            print(f"Could not check cache file age: {e}. Will attempt download.")
            needs_download = True
    if needs_download:
        try:
            print(f"Downloading iperf3 server list from {IPERF_JSON_URL} ...")
            response = requests.get(IPERF_JSON_URL, timeout=30)
            response.raise_for_status()
            with open(IPERF_FULL_LIST_PATH, "wb") as f:
                f.write(response.content)
            print(f"Download successful, saved to {IPERF_FULL_LIST_PATH}.")
            return True
        except Exception as e:
            print(f"Failed to download iperf3 server list: {e}", file=sys.stderr)
            return False
    return True


def extract_host_port(server_entry, default_port=5201):
    host = server_entry.get("IP/HOST", "").strip()
    port_str = server_entry.get("PORT", "").strip()
    port = default_port
    if not host or not port_str:
        return None, None
    # Handle port range
    if "-" in port_str:
        port_candidate = port_str.split("-")[0].strip()
        if port_candidate.isdigit():
            port = int(port_candidate)
    elif port_str.isdigit():
        port = int(port_str)
    else:
        port = default_port
    if not (1 <= port <= 65535):
        return None, None
    return host, port


def main():
    # Ensure data directory exists
    data_dir = os.path.dirname(UDP_SAFE_LIST_PATH)
    if not os.path.exists(data_dir):
        try:
            os.makedirs(data_dir, exist_ok=True)
            print(f"Created data directory: {data_dir}")
        except OSError as e:
            print(f"Error creating data directory {data_dir}: {e}", file=sys.stderr)
            sys.exit(1)

    # Download/cached fetch latest iperf3 server list
    if not download_iperf_list():
        print(
            f"Error: Could not download or find a valid server list at {IPERF_FULL_LIST_PATH}",
            file=sys.stderr,
        )
        sys.exit(1)

    full_server_list = []
    try:
        with open(IPERF_FULL_LIST_PATH, "r", encoding="utf-8") as f:
            full_server_list = json.load(f)
        if not isinstance(full_server_list, list):
            print(
                f"Error: Content of {IPERF_FULL_LIST_PATH} is not a valid JSON list.",
                file=sys.stderr,
            )
            full_server_list = []
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from {IPERF_FULL_LIST_PATH}: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading server list {IPERF_FULL_LIST_PATH}: {e}", file=sys.stderr)
        sys.exit(1)

    print(
        f"Loaded {len(full_server_list)} server entries from listed server file. Starting UDP tests..."
    )
    print("-" * 30)

    udp_safe_servers = []
    tested_count = 0
    passed_count = 0
    failed_count = 0

    # Count by continent to show progress
    continent_counts = {}
    for entry in full_server_list:
        if isinstance(entry, dict):
            # FIXED: Use PROVIDER field as the continent (contains actual continent names)
            continent = entry.get("PROVIDER", "Unknown").strip()
            continent_counts[continent] = continent_counts.get(continent, 0) + 1

    print(f"Server distribution by continent/region:")
    for continent, count in sorted(continent_counts.items()):
        if continent and continent != "Unknown":
            print(f"  {continent}: {count} servers")
    print("-" * 30)

    for entry in full_server_list:
        if not isinstance(entry, dict):
            continue
        host, port = extract_host_port(entry)
        if not host or not port:
            continue

        # FIXED: Use PROVIDER field as the continent for display
        continent = entry.get("PROVIDER", "Unknown").strip()
        provider_name = entry.get("CONTINENT", "").strip()
        site = entry.get("SITE", "Unknown").strip()
        country = entry.get("COUNTRY", "").strip()

        tested_count += 1
        server_id = f"{host}:{port}"
        server_info = f"{site}, {country} ({continent})"
        if provider_name:
            server_info += f" - {provider_name}"

        iperf_cmd_list = [
            "iperf3",
            "-c",
            host,
            "-p",
            str(port),
            "-u",
            "-b",
            IPERF_UDP_BITRATE,
            "-t",
            str(IPERF_UDP_DURATION),
            "-J",
            "--length",
            str(IPERF_PACKET_LENGTH),
            "--connect-timeout",
            str(IPERF_CONNECT_TIMEOUT_MS),
        ]

        print(f"Testing {server_id} ({server_info})...", end=" ", flush=True)

        reason = ""
        passed = False
        try:
            result = subprocess.run(
                iperf_cmd_list,
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT,
                check=False,
            )

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
                if "connection refused" in stderr_lower:
                    reason = "Connection refused"
                elif "unable to connect" in stderr_lower:
                    reason = "Unable to connect"
                elif "interrupt" in stderr_lower:
                    reason = "Interrupted"
                elif "parameter" in stderr_lower:
                    reason = "Bad parameters"
                elif result.stderr:
                    reason = f"stderr: {result.stderr.strip()}"
                else:
                    reason = f"Exit code {result.returncode}"

        except subprocess.TimeoutExpired:
            reason = f"Timeout >{SUBPROCESS_TIMEOUT}s"
        except FileNotFoundError:
            print(
                "\nError: 'iperf3' command not found. Please ensure it's installed and in your PATH."
            )
            reason = "iperf3 not found"
        except Exception as e:
            reason = f"Execution error: {e}"

        if passed:
            print("PASS")
            passed_count += 1
            udp_safe_servers.append(entry)
        else:
            print(f"FAILED (Reason: {reason})")
            failed_count += 1

    print("-" * 30)
    print(
        f"Test Complete. Total Tested: {tested_count}, Passed UDP: {passed_count}, Failed UDP: {failed_count}"
    )

    # Show final distribution by continent
    if udp_safe_servers:
        safe_continent_counts = {}
        for entry in udp_safe_servers:
            # FIXED: Use PROVIDER field as the continent
            continent = entry.get("PROVIDER", "Unknown").strip()
            safe_continent_counts[continent] = (
                safe_continent_counts.get(continent, 0) + 1
            )

        print(f"\nUDP-safe servers by continent/region:")
        for continent, count in sorted(safe_continent_counts.items()):
            if continent and continent != "Unknown":
                print(f"  {continent}: {count} servers")

    try:
        with open(UDP_SAFE_LIST_PATH, "w", encoding="utf-8") as f:
            json.dump(udp_safe_servers, f, indent=4)
        print(f"\nSaved {passed_count} passing servers to {UDP_SAFE_LIST_PATH}")
        try:
            with open(UDP_SAFE_LIST_PATH + ".timestamp", "w") as ts_f:
                ts_f.write(str(time.time()))
        except Exception:
            print(f"Warning: Could not write timestamp file for {UDP_SAFE_LIST_PATH}")

    except Exception as e:
        print(f"Error writing results to {UDP_SAFE_LIST_PATH}: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
