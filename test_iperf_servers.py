#!/usr/bin/env python3

import json
import subprocess
import os
import sys
import time
import requests
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

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

# Set IPERF_MAX_WORKERS > 1 to enable parallel testing.
DEFAULT_MAX_WORKERS = 4

# --- Simple color helper (no external dependencies) ---
USE_COLOR = sys.stdout.isatty()


def color(text: str, *codes: int) -> str:
    """Wrap text in ANSI color codes if stdout is a TTY."""
    if not USE_COLOR or not codes:
        return text
    code_str = ";".join(str(c) for c in codes)
    return f"\033[{code_str}m{text}\033[0m"


GREEN = 32
RED = 31
YELLOW = 33
CYAN = 36
BOLD = 1


def get_max_workers() -> int:
    """Read max workers from env, defaulting to 1 (sequential)."""
    env_val = os.getenv("IPERF_MAX_WORKERS", "")
    if not env_val:
        return DEFAULT_MAX_WORKERS
    try:
        value = int(env_val)
        return max(1, value)
    except ValueError:
        print(
            color(
                f"Warning: Invalid IPERF_MAX_WORKERS value '{env_val}', using 1.",
                YELLOW,
            ),
            file=sys.stderr,
        )
        return DEFAULT_MAX_WORKERS


def download_iperf_list(force_update: bool = False) -> bool:
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


def extract_host_port(
    server_entry: Dict[str, Any], default_port: int = DEFAULT_IPERF_PORT
) -> Tuple[Optional[str], Optional[int]]:
    host = str(server_entry.get("IP/HOST", "")).strip()
    port_str = str(server_entry.get("PORT", "")).strip()
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


def build_server_info(entry: Dict[str, Any]) -> Tuple[str, str, str, str]:
    """Return (continent, provider_name, site, country) cleaned up."""
    # CONTINENT = region, PROVIDER = hosting/network provider
    continent = str(entry.get("CONTINENT", "Unknown")).strip()
    provider_name = str(entry.get("PROVIDER", "")).strip()
    site = str(entry.get("SITE", "Unknown")).strip()
    country = str(entry.get("COUNTRY", "")).strip()
    return continent, provider_name, site, country


def run_iperf_udp_test(host: str, port: int) -> Tuple[bool, str]:
    """Run a single iperf3 UDP test and return (passed, reason_if_failed)."""
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

    try:
        result = subprocess.run(
            iperf_cmd_list,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, f"Timeout >{SUBPROCESS_TIMEOUT}s"
    except FileNotFoundError:
        # Print once, but still return a reason so caller can log consistently
        print(
            color(
                "\nError: 'iperf3' command not found. Please ensure it's installed and in your PATH.",
                RED,
                BOLD,
            ),
            file=sys.stderr,
        )
        return False, "iperf3 not found"
    except Exception as e:
        return False, f"Execution error: {e}"

    if result.returncode == 0:
        try:
            iperf_output = json.loads(result.stdout)
            if "error" not in iperf_output:
                return True, ""
            else:
                return False, f"iperf error: {iperf_output['error']}"
        except json.JSONDecodeError:
            return False, "Invalid JSON output"
        except Exception as e:
            return False, f"Error processing JSON: {e}"

    # Non-zero return code
    stderr_lower = (result.stderr or "").lower()
    if "connection refused" in stderr_lower:
        return False, "Connection refused"
    elif "unable to connect" in stderr_lower:
        return False, "Unable to connect"
    elif "interrupt" in stderr_lower:
        return False, "Interrupted"
    elif "parameter" in stderr_lower:
        return False, "Bad parameters"
    elif result.stderr:
        return False, f"stderr: {result.stderr.strip()}"
    else:
        return False, f"Exit code {result.returncode}"


def main() -> None:
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

    full_server_list: List[Any] = []
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

    # Count by continent to show distribution
    continent_counts: Dict[str, int] = {}
    for entry in full_server_list:
        if isinstance(entry, dict):
            continent = str(entry.get("CONTINENT", "Unknown")).strip()
            continent_counts[continent] = continent_counts.get(continent, 0) + 1

    print("Server distribution by continent/region:")
    for continent, count in sorted(continent_counts.items()):
        if continent and continent != "Unknown":
            print(f"  {continent}: {count} servers")
    print("-" * 30)

    udp_safe_servers: List[Dict[str, Any]] = []
    tested_count = 0
    passed_count = 0
    failed_count = 0

    # Filter to entries that look remotely valid
    valid_entries: List[Dict[str, Any]] = [
        e for e in full_server_list if isinstance(e, dict)
    ]

    max_workers = get_max_workers()
    parallel = max_workers > 1

    if not parallel:
        # --- Original sequential behavior (but with continent/provider fix & colors) ---
        for entry in valid_entries:
            host, port = extract_host_port(entry)
            if not host or not port:
                continue

            continent, provider_name, site, country = build_server_info(entry)
            tested_count += 1

            server_id = f"{host}:{port}"
            server_info = f"{site}, {country} ({continent})"
            if provider_name:
                server_info += f" - {provider_name}"

            preamble = f"Testing {server_id} ({server_info})..."
            print(preamble, end=" ", flush=True)

            passed, reason = run_iperf_udp_test(host, port)

            if passed:
                print(color("PASS", GREEN, BOLD))
                passed_count += 1
                udp_safe_servers.append(entry)
            else:
                print(color(f"FAILED (Reason: {reason})", RED))
                failed_count += 1
    else:
        # --- Parallel behavior: results may be printed out of order ---
        print(
            color(
                f"Running tests in parallel with {max_workers} workers...",
                CYAN,
                BOLD,
            )
        )

        def task(entry: Dict[str, Any]) -> Tuple[Dict[str, Any], Optional[bool], str]:
            host, port = extract_host_port(entry)
            if not host or not port:
                return entry, None, "Invalid host/port"
            passed, reason = run_iperf_udp_test(host, port)
            return entry, passed, reason

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_entry = {
                executor.submit(task, entry): entry for entry in valid_entries
            }

            for future in as_completed(future_to_entry):
                entry, passed, reason = future.result()
                host, port = extract_host_port(entry)
                if not host or not port or passed is None:
                    # Skip invalid entries
                    continue

                continent, provider_name, site, country = build_server_info(entry)

                tested_count += 1
                server_id = f"{host}:{port}"
                server_info = f"{site}, {country} ({continent})"
                if provider_name:
                    server_info += f" - {provider_name}"

                if passed:
                    status = color("PASS", GREEN, BOLD)
                    passed_count += 1
                    udp_safe_servers.append(entry)
                else:
                    status = color(f"FAILED (Reason: {reason})", RED)
                    failed_count += 1

                print(f"Testing {server_id} ({server_info})... {status}")

    print("-" * 30)
    print(
        f"Test Complete. Total Tested: {tested_count}, Passed UDP: {passed_count}, Failed UDP: {failed_count}"
    )

    # Show final distribution by continent for UDP-safe servers
    if udp_safe_servers:
        safe_continent_counts: Dict[str, int] = {}
        for entry in udp_safe_servers:
            continent = str(entry.get("CONTINENT", "Unknown")).strip()
            safe_continent_counts[continent] = (
                safe_continent_counts.get(continent, 0) + 1
            )

        print("\nUDP-safe servers by continent/region:")
        for continent, count in sorted(safe_continent_counts.items()):
            if continent and continent != "Unknown":
                print(f"  {continent}: {count} servers")

    # Persist results
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
