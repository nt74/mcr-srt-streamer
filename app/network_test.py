# app/network_test.py
# Final version incorporating mechanism choice, safe list loading,
# UDP-only auto tests (in iperf mode), reduced timeout, and all syntax fixes.

import os
import json
import requests
import subprocess
import random
import time
from datetime import datetime, timedelta
import logging
import re

# Import the utility function for getting external IP
from app.utils import get_external_ip

logger = logging.getLogger(__name__)

# --- Configuration & Constants ---
NETWORK_TEST_MECHANISM = os.environ.get("NETWORK_TEST_MECHANISM", "ping_only").lower()
if NETWORK_TEST_MECHANISM not in ["ping_only", "iperf"]:
    logger.warning(
        f"Invalid NETWORK_TEST_MECHANISM '{NETWORK_TEST_MECHANISM}', defaulting to 'ping_only'."
    )
    NETWORK_TEST_MECHANISM = "ping_only"
logger.info(f"Network Test Mechanism set to: {NETWORK_TEST_MECHANISM}")

IPERF_JSON_URL = "https://export.iperf3serverlist.net/json.php?action=download"
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(APP_DIR, "data")
IPERF_FULL_LIST_PATH = os.path.join(DATA_DIR, "iperf3_export_servers.json")
UDP_SAFE_LIST_PATH = os.path.join(DATA_DIR, "udp_safe_servers.json")
UDP_SAFE_LIST_TIMESTAMP_PATH = UDP_SAFE_LIST_PATH + ".timestamp"
SAFE_LIST_MAX_AGE_SECONDS = 2 * 24 * 60 * 60  # 2 days validity for the safe list

GEOIP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,continentCode,continent,countryCode,country,query"
DEFAULT_IPERF_PORT = 5201
DOWNLOAD_CACHE_DURATION = timedelta(hours=6)
PING_COUNT = 4
IPERF_AUTO_UDP_DURATION = 5
IPERF_AUTO_UDP_BITRATE = "10M"
IPERF_MANUAL_UDP_DURATION = 5
IPERF_MANUAL_UDP_BITRATE = "10M"
IPERF_MANUAL_TCP_DURATION = 7
IPERF_PACKET_LENGTH = 1200
IPERF_SUBPROCESS_TIMEOUT = 15  # Reduced timeout
ASSUMED_LOSS_FOR_TCP_FALLBACK = 7.0

os.makedirs(DATA_DIR, exist_ok=True)


class NetworkTester:
    def __init__(self):
        self.servers = []
        self.load_servers()  # Load servers on initialization

    def _download_iperf_list(self, force_update=False):
        """Downloads the iperf3 server list if cache is missing or outdated."""
        needs_download = force_update
        # Use IPERF_FULL_LIST_PATH here
        if not os.path.exists(IPERF_FULL_LIST_PATH):
            logger.info(f"Cache file not found: {IPERF_FULL_LIST_PATH}. Downloading.")
            needs_download = True
        else:  # Cache file exists
            try:  # <-- Try checking cache age
                file_mod_time = datetime.fromtimestamp(
                    os.path.getmtime(IPERF_FULL_LIST_PATH)
                )
                # *** CORRECTED Multi-line 'if' statement ***
                if datetime.now() - file_mod_time > DOWNLOAD_CACHE_DURATION:
                    logger.info("Cache file outdated. Downloading.")
                    needs_download = True
                else:
                    logger.debug("Using cached iperf3 server list.")
                    # If cache is recent and valid, no download needed, return False
                    return False
            except Exception as e:  # <-- Except block for checking cache age
                logger.warning(
                    f"Could not check cache file age for {IPERF_FULL_LIST_PATH}: {e}. Will attempt download."
                )
                needs_download = True  # Ensures download if check fails

        if needs_download:
            logger.info(f"Fetching iperf3 server list from {IPERF_JSON_URL}...")
            try:  # <-- Try downloading and saving
                response = requests.get(IPERF_JSON_URL, timeout=30, stream=True)
                response.raise_for_status()
                content = b""
                first_chunk = True
                looks_like_json = False
                for chunk in response.iter_content(chunk_size=8192):
                    if first_chunk:
                        if chunk.strip().startswith(b"["):
                            looks_like_json = True
                        first_chunk = False
                    content += chunk
                if not looks_like_json or not content.strip().endswith(b"]"):
                    try:
                        error_hint = content.decode("utf-8", errors="ignore")[:200]
                    except Exception:
                        error_hint = "(Could not decode)"
                    raise ValueError(
                        f"Downloaded content not a JSON array. Starts with: {error_hint}"
                    )
                json.loads(content)  # Validate JSON
                with open(IPERF_FULL_LIST_PATH, "wb") as f:
                    f.write(content)
                logger.info(f"Download successful, saved to {IPERF_FULL_LIST_PATH}.")
                # Return True indicates download was attempted (successfully)
                return True
            except requests.exceptions.RequestException as e:
                logger.error(f"Error downloading iperf3 server list: {e}")
                # Return True indicates download was attempted (failed)
                return True
            except (json.JSONDecodeError, ValueError) as e:
                logger.error(
                    f"Downloaded content is not valid JSON or structure is wrong: {e}"
                )
                # Attempt to remove potentially corrupted cache file
                if os.path.exists(IPERF_FULL_LIST_PATH):
                    try:
                        os.remove(IPERF_FULL_LIST_PATH)
                        logger.info(
                            f"Removed potentially invalid cache file: {IPERF_FULL_LIST_PATH}"
                        )
                    except Exception as rm_e:
                        logger.warning(
                            f"Could not remove potentially invalid cache file {IPERF_FULL_LIST_PATH}: {rm_e}"
                        )
                # Return True indicates download was attempted (failed)
                return True
            except Exception as e:
                logger.error(
                    f"Unexpected error during iperf list download: {e}", exc_info=True
                )
                # Return True indicates download was attempted (failed)
                return True
        else:
            # This path is reached if needs_download was False initially
            # and the try block for checking cache age executed successfully without needing a download.
            return False  # No download needed/attempted

    def _parse_host_port(self, server_entry):
        """Parses host and port from the 'IP_HOST' string."""
        ip_host_string = server_entry.get("IP_HOST", "")
        if not ip_host_string:
            return None, None

        parts = ip_host_string.split()
        host = None
        port = DEFAULT_IPERF_PORT
        port_str = None

        try:
            if "-c" in parts:
                c_index = parts.index("-c")
                # Ensure indentation is 4 spaces
                if c_index + 1 < len(parts):
                    host = parts[c_index + 1]  # 8 spaces indent

            # This line should be at the same level as the 'if -c in parts'
            if not host:
                return None, None  # 4 spaces indent

            # This line should be at the same level as the 'if -c in parts'
            if "-p" in parts:
                p_index = parts.index("-p")
                # Ensure indentation is 4 spaces
                if p_index + 1 < len(parts):
                    port_str = parts[p_index + 1]  # 8 spaces indent

            if port_str:
                port_str = port_str.strip()
                if (
                    "-" in port_str
                ):  # Handle ranges like '5201-5209', use the first port
                    base_port_str = port_str.split("-")[0].strip()
                    port = (
                        int(base_port_str)
                        if base_port_str.isdigit()
                        else DEFAULT_IPERF_PORT
                    )
                elif port_str.isdigit():
                    port = int(port_str)
                else:
                    # Ensure indentation is 4 spaces
                    logger.warning(
                        f"Non-standard port format '{port_str}' in '{ip_host_string}', using default {DEFAULT_IPERF_PORT}."
                    )
                    port = DEFAULT_IPERF_PORT

            # Basic validation (4 spaces indent)
            if port < 1 or port > 65535:
                port = DEFAULT_IPERF_PORT
            if not host or len(host) < 3:
                logger.warning(
                    f"Extracted host '{host}' seems invalid from: {ip_host_string}"
                )
                return None, None

        except (ValueError, IndexError) as e:
            logger.error(f"Error parsing IP_HOST string '{ip_host_string}': {e}")
            return None, None  # 4 spaces indent

        return host, port  # 4 spaces indent

    def load_servers(self):
        """
        Loads iperf3 servers. If mechanism is 'iperf', tries recent safe list first.
        If mechanism is 'ping_only' or safe list fails, loads full list.
        """
        logger.info(
            f"Loading iperf3 server list (Mechanism: {NETWORK_TEST_MECHANISM})..."
        )
        processed_servers = []
        raw_servers = []
        source_file = None
        source_type = "full"  # Assume full list initially

        # If 'iperf' mechanism, try the safe list first
        if NETWORK_TEST_MECHANISM == "iperf":
            use_safe_list = False
            if os.path.exists(UDP_SAFE_LIST_PATH) and os.path.exists(
                UDP_SAFE_LIST_TIMESTAMP_PATH
            ):
                try:
                    with open(UDP_SAFE_LIST_TIMESTAMP_PATH, "r") as f_ts:
                        timestamp = float(f_ts.read().strip())
                    if time.time() - timestamp < SAFE_LIST_MAX_AGE_SECONDS:
                        source_file = UDP_SAFE_LIST_PATH
                        logger.info(f"Found recent UDP safe server list: {source_file}")
                        use_safe_list = True
                        source_type = "safe"
                    else:
                        logger.warning(
                            f"UDP safe server list is outdated (older than {SAFE_LIST_MAX_AGE_SECONDS/3600/24:.1f} days)."
                        )
                except Exception as e:
                    logger.warning(
                        f"Error checking UDP safe list timestamp: {e}. Will try full list."
                    )
            else:
                logger.info("UDP safe server list not found.")

            # Attempt to load from safe list if conditions met
            if use_safe_list:
                try:
                    with open(source_file, "r", encoding="utf-8") as f:
                        raw_servers = json.load(f)
                    # Check if loaded data is a non-empty list
                    if not isinstance(raw_servers, list):
                        logger.error(
                            f"Loaded data from {source_file} is not a list. Falling back."
                        )
                        raw_servers = []
                        use_safe_list = False
                        source_type = "full"
                    elif not raw_servers:
                        logger.warning(
                            f"UDP safe server list {source_file} is empty. Falling back."
                        )
                        use_safe_list = False
                        source_type = "full"
                    else:
                        logger.info(
                            f"Successfully loaded {len(raw_servers)} servers from UDP safe list."
                        )
                except Exception as e:
                    logger.error(
                        f"Error loading or parsing UDP safe list {source_file}: {e}. Falling back."
                    )
                    raw_servers = []
                    use_safe_list = False
                    source_type = "full"

        # If safe list wasn't used or failed, or if mechanism is 'ping_only', load the full list
        if source_type == "full":
            logger.info("Loading full iperf3 server list.")
            self._download_iperf_list()  # Ensure full list is downloaded/up-to-date
            source_file = IPERF_FULL_LIST_PATH
            if os.path.exists(source_file):
                try:
                    with open(source_file, "r", encoding="utf-8") as f:
                        raw_servers = json.load(f)
                    if not isinstance(raw_servers, list):
                        logger.error(
                            f"Loaded data from {source_file} is not a list. Server list will be empty."
                        )
                        raw_servers = []
                except json.JSONDecodeError as json_err:
                    logger.error(
                        f"JSON Decode Error in {source_file}: {json_err}. Server list will be empty."
                    )
                    raw_servers = []
                except Exception as e:
                    logger.error(
                        f"Unexpected error loading servers from {source_file}: {e}",
                        exc_info=True,
                    )
                    raw_servers = []
            else:
                logger.error(f"Full server list file unavailable: {source_file}")
                raw_servers = []

        # Process the loaded raw servers
        count_parsed = 0
        for index, raw_server in enumerate(raw_servers):
            if not isinstance(raw_server, dict):
                logger.warning(f"Skipping non-dictionary entry at index {index}.")
                continue
            host, port = self._parse_host_port(raw_server)
            continent = raw_server.get(
                "CONTINENT"
            )  # Need continent for filtering later
            if host and port and continent:
                processed_servers.append(
                    {
                        "host": host,
                        "port": port,
                        "site": raw_server.get("SITE", "N/A"),
                        "country": raw_server.get("COUNTRY"),
                        "continent": continent,
                        "provider": raw_server.get("PROVIDER"),
                        "options_str": raw_server.get("OPTIONS"),
                    }
                )
                count_parsed += 1
            else:
                logger.debug(
                    f"Skipping entry due to host/port parsing failure or missing continent: {raw_server.get('IP_HOST', 'N/A')}"
                )

        logger.info(
            f"Successfully processed {count_parsed} servers from {os.path.basename(source_file or 'N/A')}."
        )
        self.servers = processed_servers
        if not self.servers:
            logger.warning(f"Server list is empty after processing {source_type} list.")

    def get_server_regions(self):
        """Returns a sorted list of unique continents from the loaded servers."""
        if not self.servers:
            self.load_servers()
        continents = set(
            server.get("continent")
            for server in self.servers
            if server.get("continent")
        )
        return sorted(list(continents))

    def get_external_ip_and_location(self):
        """Gets external IP using utility function and looks up GeoIP location."""
        ip_address = None
        try:
            ip_address = get_external_ip()  # Use utility function
            if not ip_address or ip_address == "unknown":
                logger.warning("Could not determine external IP address using utils.")
                return {"ip": None, "error": "Could not determine external IP"}
            logger.info(f"Determined external IP via utils: {ip_address}")
        except Exception as e:
            logger.error(f"Error calling get_external_ip: {e}", exc_info=True)
            return {"ip": None, "error": "Failed to get external IP"}

        if not isinstance(ip_address, str) or not re.match(
            r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_address
        ):
            logger.warning(
                f"Invalid IP address format received from utils: {ip_address}"
            )
            return {"ip": ip_address, "error": "Invalid IP format returned"}

        api_url = GEOIP_API_URL.format(ip=ip_address)
        logger.info(f"Looking up GeoIP for {ip_address} via {api_url}")
        try:
            response = requests.get(api_url, timeout=7)
            response.raise_for_status()
            data = response.json()
            if data.get("status") == "success":
                location_info = {
                    "ip": data.get("query", ip_address),
                    "continent": data.get("continent"),
                    "continentCode": data.get("continentCode"),
                    "country": data.get("country"),
                    "countryCode": data.get("countryCode"),
                    "error": None,
                }
                logger.info(f"GeoIP Result: {location_info}")
                return location_info
            else:
                api_msg = data.get("message", "API Error")
                logger.warning(f"GeoIP API Error for {ip_address}: {api_msg}")
                return {"ip": ip_address, "error": api_msg}
        except requests.exceptions.Timeout:
            logger.error(f"GeoIP API timed out for IP {ip_address}")
            return {"ip": ip_address, "error": "GeoIP API Timeout"}
        except requests.exceptions.RequestException as e:
            logger.error(f"GeoIP API error for IP {ip_address}: {e}")
            return {"ip": ip_address, "error": "GeoIP Network Error"}
        except json.JSONDecodeError as e:
            logger.error(f"GeoIP decoding error for IP {ip_address}: {e}")
            return {"ip": ip_address, "error": "Invalid GeoIP Response"}
        except Exception as e:
            logger.error(f"GeoIP lookup error for IP {ip_address}: {e}", exc_info=True)
            return {"ip": ip_address, "error": "GeoIP Internal Error"}

    def run_ping(self, host):
        """Runs ping command and parses average RTT."""
        command = ["ping", "-c", str(PING_COUNT), "-i", "0.2", "-W", "2", host]
        logger.info(f"Running: {' '.join(command)}")
        try:
            env = os.environ.copy()
            env["LANG"] = "C"
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=8, check=False, env=env
            )
            if result.returncode != 0:
                logger.warning(
                    f"Ping failed {host}. Code:{result.returncode}. Err:{result.stderr.strip()}"
                )
                return None
            avg_rtt = None
            match_linux = re.search(
                r"min/avg/max/mdev\s*=\s*[\d.]+/([\d.]+)/",
                result.stdout,
                re.IGNORECASE | re.MULTILINE,
            )
            match_macos = re.search(
                r"min/avg/max/stddev\s*=\s*[\d.]+/([\d.]+)/",
                result.stdout,
                re.IGNORECASE | re.MULTILINE,
            )
            avg_rtt_str = None
            if match_linux:
                avg_rtt_str = match_linux.group(1)
            elif match_macos:
                avg_rtt_str = match_macos.group(1)
            if avg_rtt_str:
                try:
                    avg_rtt = float(avg_rtt_str)
                except ValueError:
                    avg_rtt = None
            if avg_rtt is not None:
                logger.info(f"Ping RTT {host}: {avg_rtt:.2f} ms")
                return avg_rtt
            else:
                logger.warning(f"Could not parse RTT for {host}.")
                return None
        except subprocess.TimeoutExpired:
            logger.warning(f"Ping timed out >8s for {host}")
            return None
        except FileNotFoundError:
            logger.error("'ping' not found.")
            return None
        except Exception as e:
            logger.error(f"Ping error {host}: {e}", exc_info=True)
            return None

    def run_iperf3_udp(
        self,
        host,
        port,
        bitrate=IPERF_MANUAL_UDP_BITRATE,
        duration=IPERF_MANUAL_UDP_DURATION,
    ):
        """Runs iperf3 UDP test. Returns dict with results or {'error': ...}."""
        iperf_cmd = [
            "iperf3",
            "-c",
            host,
            "-p",
            str(port),
            "-u",
            "-b",
            bitrate,
            "-t",
            str(duration),
            "-J",
            "--length",
            str(IPERF_PACKET_LENGTH),
            "--connect-timeout",
            "5000",
        ]
        logger.info(f"Running UDP iperf3: {' '.join(iperf_cmd)}")
        try:
            result = subprocess.run(
                iperf_cmd,
                capture_output=True,
                text=True,
                timeout=IPERF_SUBPROCESS_TIMEOUT,
                check=False,
            )
            iperf_data = None
            parse_error = None
            try:
                iperf_data = json.loads(result.stdout)
                # Corrected multi-line if
                if isinstance(iperf_data, dict) and "error" in iperf_data:
                    logger.warning(
                        f"iperf3 UDP test for {host}:{port} returned JSON error: {iperf_data['error']}"
                    )
                    return {"type": "UDP", "error": iperf_data["error"]}
            except json.JSONDecodeError as e:
                parse_error = e

            if parse_error or result.returncode != 0:
                stderr_msg = result.stderr.strip() if result.stderr else "(No stderr)"
                stdout_sample = (
                    result.stdout.strip()[:200] if result.stdout else "(No stdout)"
                )
                log_msg = (
                    f"iperf3 UDP failed for {host}:{port}. Code: {result.returncode}. "
                )
                if parse_error:
                    log_msg += f"JSON Error: {parse_error}. "
                log_msg += f"Stderr: {stderr_msg}. Stdout Sample: {stdout_sample}"
                logger.warning(log_msg)
                if "connection refused" in stderr_msg.lower():
                    return {"type": "UDP", "error": "Connection refused"}
                if (
                    "unable to connect" in stderr_msg.lower()
                    or "failed" in stderr_msg.lower()
                ):
                    return {"type": "UDP", "error": "Server unreachable/test failed"}
                if "interrupt" in stderr_msg.lower():
                    return {"type": "UDP", "error": "Test interrupted"}
                if "parameter" in stderr_msg.lower():
                    return {"type": "UDP", "error": "Invalid iperf3 parameter"}
                return {
                    "type": "UDP",
                    "error": (
                        f"Cmd fail (code {result.returncode})"
                        if result.returncode != 0
                        else "Invalid JSON"
                    ),
                }

            summary = iperf_data.get("end", {}).get("sum", {})
            jitter_ms = summary.get("jitter_ms")
            lost_packets = summary.get("lost_packets")
            total_packets = summary.get("packets")
            bandwidth_bps = summary.get("bits_per_second")

            if (
                total_packets is None
                or jitter_ms is None
                or lost_packets is None
                or bandwidth_bps is None
            ):
                error_msg = "Missing key UDP metrics (jitter, loss, packets, bandwidth) in iperf3 JSON output"
                logger.error(f"{error_msg} for {host}:{port}. Summary Data: {summary}")
                return {"type": "UDP", "error": error_msg}

            loss_percent = (
                (lost_packets / total_packets) * 100 if total_packets > 0 else 0.0
            )
            bandwidth_mbps = bandwidth_bps / 1_000_000

            results = {
                "type": "UDP",
                "bandwidth_mbps": f"{bandwidth_mbps:.2f}",
                "loss_percent": f"{loss_percent:.2f}",
                "jitter_ms": f"{jitter_ms:.2f}",
                "error": None,
            }
            logger.info(
                f"UDP results for {host}:{port}: BW={results['bandwidth_mbps']} Mbps, Loss={results['loss_percent']}%, Jitter={results['jitter_ms']}ms"
            )
            return results
        except subprocess.TimeoutExpired:
            logger.error(
                f"iperf3 UDP test timed out (>{IPERF_SUBPROCESS_TIMEOUT}s) for {host}:{port}"
            )
            return {"type": "UDP", "error": "Test timed out"}
        except FileNotFoundError:
            logger.error("'iperf3' command not found.")
            return {"type": "UDP", "error": "iperf3 command not found"}
        except Exception as e:
            logger.error(
                f"Unexpected error iperf3 UDP test for {host}:{port}: {e}",
                exc_info=True,
            )
            return {"type": "UDP", "error": f"Exec error: {e}"}

    def run_iperf3_tcp(self, host, port, duration=IPERF_MANUAL_TCP_DURATION):
        """Runs iperf3 TCP test (-R for reverse). Returns dict with results or {'error': ...}."""
        iperf_cmd = [
            "iperf3",
            "-c",
            host,
            "-p",
            str(port),
            "-R",
            "-t",
            str(duration),
            "-J",
            "--connect-timeout",
            "5000",
        ]
        logger.info(f"Running TCP iperf3 (-R): {' '.join(iperf_cmd)}")
        try:
            result = subprocess.run(
                iperf_cmd,
                capture_output=True,
                text=True,
                timeout=IPERF_SUBPROCESS_TIMEOUT,
                check=False,
            )
            iperf_data = None
            parse_error = None
            try:
                iperf_data = json.loads(result.stdout)
                # Corrected multi-line if
                if isinstance(iperf_data, dict) and "error" in iperf_data:
                    logger.warning(
                        f"iperf3 TCP test for {host}:{port} returned JSON error: {iperf_data['error']}"
                    )
                    return {"type": "TCP", "error": iperf_data["error"]}
            except json.JSONDecodeError as e:
                parse_error = e

            if parse_error or result.returncode != 0:
                stderr_msg = result.stderr.strip() if result.stderr else "(No stderr)"
                stdout_sample = (
                    result.stdout.strip()[:200] if result.stdout else "(No stdout)"
                )
                log_msg = (
                    f"iperf3 TCP failed for {host}:{port}. Code: {result.returncode}. "
                )
                if parse_error:
                    log_msg += f"JSON Error: {parse_error}. "
                log_msg += f"Stderr: {stderr_msg}. Stdout Sample: {stdout_sample}"
                logger.warning(log_msg)
                if "connection refused" in stderr_msg.lower():
                    return {"type": "TCP", "error": "Connection refused"}
                if (
                    "unable to connect" in stderr_msg.lower()
                    or "failed" in stderr_msg.lower()
                ):
                    return {"type": "TCP", "error": "Server unreachable/test failed"}
                return {
                    "type": "TCP",
                    "error": (
                        f"Cmd fail (code {result.returncode})"
                        if result.returncode != 0
                        else "Invalid JSON"
                    ),
                }

            summary = iperf_data.get("end", {}).get("sum_received", {})
            bandwidth_bps = summary.get("bits_per_second")

            if bandwidth_bps is None:
                error_msg = "Missing key TCP bandwidth metric ('bits_per_second' in sum_received) in iperf3 JSON output"
                logger.error(f"{error_msg} for {host}:{port}. Summary Data: {summary}")
                return {"type": "TCP", "error": error_msg}

            bandwidth_mbps = bandwidth_bps / 1_000_000
            results = {
                "type": "TCP",
                "bandwidth_mbps": f"{bandwidth_mbps:.2f}",
                "loss_percent": None,
                "jitter_ms": None,
                "error": None,
            }
            logger.info(
                f"TCP results for {host}:{port}: BW={results['bandwidth_mbps']} Mbps"
            )
            return results
        except subprocess.TimeoutExpired:
            logger.error(
                f"iperf3 TCP test timed out (>{IPERF_SUBPROCESS_TIMEOUT}s) for {host}:{port}"
            )
            return {"type": "TCP", "error": "Test timed out"}
        except FileNotFoundError:
            logger.error("'iperf3' command not found.")
            return {"type": "TCP", "error": "iperf3 command not found"}
        except Exception as e:
            logger.error(
                f"Unexpected error iperf3 TCP test for {host}:{port}: {e}",
                exc_info=True,
            )
            return {"type": "TCP", "error": f"Exec error: {e}"}

    def calculate_srt_settings(self, rtt, loss_percent):
        """Calculates recommended SRT Latency/Overhead based on Haivision guide table."""
        if rtt is None:
            logger.warning("Cannot calculate SRT settings: RTT is missing.")
            return None
        if loss_percent is None:
            logger.warning(
                "Cannot calculate SRT settings: Loss Percentage is missing. Assuming default."
            )
            loss_percent = ASSUMED_LOSS_FOR_TCP_FALLBACK

        try:
            rtt_float = max(1.0, float(rtt))
            loss_float = max(0.0, min(float(loss_percent), 100.0))
        except (ValueError, TypeError):
            logger.error(
                f"Invalid RTT ({rtt}) or Loss ({loss_percent}) values for SRT calculation."
            )
            return None

        # Haivision Guide Table Logic (Corrected multi-line structure)
        if loss_float <= 1.0:
            multiplier, overhead = 3, 1
        elif loss_float <= 3.0:
            multiplier, overhead = 4, 4
        elif loss_float <= 7.0:
            multiplier, overhead = 6, 9
        elif loss_float <= 10.0:
            multiplier, overhead = 8, 15
        elif loss_float <= 12.0:  # Note: Guide has 8 for both <=10 and <=12
            multiplier, overhead = 8, 20
        elif loss_float <= 20.0:
            multiplier, overhead = 10, 38
        elif loss_float <= 25.0:
            multiplier, overhead = 13, 46
        elif loss_float <= 27.0:
            multiplier, overhead = 14, 50
        elif loss_float <= 30.0:  # Note: Guide has 14 for both <=27 and <=30
            multiplier, overhead = 14, 61
        elif loss_float <= 40.0:
            multiplier, overhead = 30, 97
        else:  # loss > 40%
            multiplier, overhead = 30, 99  # Use max practical overhead (99%)
            logger.warning(
                f"Very high packet loss ({loss_float:.1f}%) detected. SRT may be unreliable."
            )

        min_latency_floor = 80
        recommended_latency = max(round(multiplier * rtt_float), min_latency_floor)
        max_latency_limit = 8000
        recommended_latency = min(recommended_latency, max_latency_limit)

        results = {
            "rtt_multiplier": multiplier,
            "overhead_percent": overhead,
            "latency_ms": recommended_latency,
        }
        logger.info(
            f"Calculated SRT settings (RTT={rtt_float:.1f}ms, Loss={loss_float:.1f}%): {results}"
        )
        return results

    def get_fallback_results(self, error_msg="Test failed or no servers available"):
        """Returns a default dictionary structure when tests cannot be fully completed."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logger.warning(f"Fallback results {now}. Reason: {error_msg}")
        return {
            "server": "N/A",
            "server_location": "N/A",
            "rtt_ms": None,
            "loss_percent": None,
            "jitter_ms": None,
            "bandwidth_mbps": None,
            "bandwidth_type": None,
            "latency_recommendation": 120,
            "overhead_recommendation": 25,
            "rtt_multiplier": 4,
            "test_time": now,
            "error": error_msg,
        }

    def run_network_test(
        self,
        mode,
        region,
        manual_host,
        manual_port,
        manual_protocol,
        duration,
        bitrate,
        location_info,
    ):
        """
        Orchestrates network tests based on mode and NETWORK_TEST_MECHANISM setting.
        'ping_only': Runs only ping, calculates SRT settings based on RTT + assumed loss.
        'iperf': Uses safe list (if available), runs ping + iperf3 (UDP for auto, chosen for manual).
        """
        logger.info(
            f"Run test: mechanism={NETWORK_TEST_MECHANISM}, mode={mode}, region={region}, host={manual_host}, port={manual_port}, proto={manual_protocol}, dur={duration}, bitrate={bitrate}"
        )

        # Reload servers based on mechanism (load_servers now handles safe list logic)
        self.load_servers()
        if not self.servers:
            return self.get_fallback_results(
                f"iperf3 server list unavailable (mechanism: {NETWORK_TEST_MECHANISM})."
            )

        target_servers_to_test = []
        test_target_label = "N/A"
        best_rtt_server_info = None

        # --- 1. Determine Target Server(s) ---
        if mode == "manual":
            if not manual_host:
                return self.get_fallback_results("Manual mode: no host.")
            m_port = int(manual_port) if manual_port else DEFAULT_IPERF_PORT
            target_servers_to_test = [
                {"host": manual_host, "port": m_port, "site": "Manual Input"}
            ]
            test_target_label = f"Manual: {manual_host}:{m_port}"
            logger.info(f"Manual target: {test_target_label}")
        elif mode == "regional":
            if not region:
                return self.get_fallback_results("Regional mode: no region.")
            regional_servers = [s for s in self.servers if s.get("continent") == region]
            if not regional_servers:
                return self.get_fallback_results(f"No servers for region: {region}")
            num_to_select = min(3, len(regional_servers))
            target_servers_to_test = random.sample(regional_servers, num_to_select)
            target_labels = [f"{s['host']}:{s['port']}" for s in target_servers_to_test]
            test_target_label = (
                f"{num_to_select} Random in {region}: {', '.join(target_labels)}"
            )
            logger.info(f"Regional targets({region}): {test_target_label}")
        else:  # Default to 'closest'
            mode = "closest"
            if not location_info or location_info.get("error"):
                err = (
                    location_info.get("error", "GeoIP Error")
                    if location_info
                    else "GeoIP unavailable"
                )
                return self.get_fallback_results(
                    f"Closest fail: Location unavailable ({err})"
                )
            continent_name = location_info.get("continent")
            if not continent_name:
                return self.get_fallback_results(
                    f"Could not get continent: {location_info}"
                )
            regional_servers = [
                s for s in self.servers if s.get("continent") == continent_name
            ]
            if not regional_servers:
                return self.get_fallback_results(
                    f"No servers for continent: {continent_name}"
                )
            num_candidates = min(7, len(regional_servers))
            candidates_to_ping = random.sample(regional_servers, num_candidates)
            ping_results = []
            logger.info(f"Pinging {num_candidates} candidates in {continent_name}...")
            for server in candidates_to_ping:
                rtt = self.run_ping(server["host"])
                # Corrected multi-line if block
                if rtt is not None:
                    server["rtt"] = rtt
                    ping_results.append(server)
            if not ping_results:
                return self.get_fallback_results(
                    f"Ping failed for all candidates in {continent_name}."
                )
            ping_results.sort(key=lambda x: x["rtt"])
            best_rtt_server_info = ping_results[0]
            target_servers_to_test = [best_rtt_server_info]
            test_target_label = f"Closest: {best_rtt_server_info['host']}:{best_rtt_server_info['port']} ({best_rtt_server_info.get('site','N/A')}, {best_rtt_server_info['rtt']:.1f}ms)"
            logger.info(f"Closest selected: {test_target_label}")

        # --- 2. Run Tests ---
        all_results_raw = []
        if not target_servers_to_test:
            return self.get_fallback_results("No targets selected.")
        for server in target_servers_to_test:
            host = server["host"]
            port = server["port"]
            logger.info(f"\n--- Testing server: {host}:{port} ---")
            rtt = server.get("rtt")
            if rtt is None:
                rtt = self.run_ping(
                    host
                )  # Run ping if not already done (e.g., manual/regional)
            iperf_result = None
            if NETWORK_TEST_MECHANISM == "ping_only":
                logger.info("Mechanism 'ping_only'. Skipping iperf3.")
                iperf_result = {"type": "N/A", "error": "iperf disabled"}
            elif rtt is None:
                logger.warning(f"Skipping iperf3 for {host}:{port} (ping failed).")
                iperf_result = {"type": "N/A", "error": "Ping failed"}
            elif mode == "closest" or mode == "regional":
                logger.info(f"Mode '{mode}', running UDP iperf3 (fixed).")
                iperf_result = self.run_iperf3_udp(
                    host,
                    port,
                    bitrate=IPERF_AUTO_UDP_BITRATE,
                    duration=IPERF_AUTO_UDP_DURATION,
                )
            elif mode == "manual":
                udp_duration = duration if duration else IPERF_MANUAL_UDP_DURATION
                udp_bitrate = bitrate if bitrate else IPERF_MANUAL_UDP_BITRATE
                tcp_duration = duration if duration else IPERF_MANUAL_TCP_DURATION
                if manual_protocol == "tcp":
                    logger.info("Manual(TCP), running TCP iperf3.")
                    iperf_result = self.run_iperf3_tcp(
                        host, port, duration=tcp_duration
                    )
                else:  # Assume UDP
                    logger.info("Manual(UDP), running UDP iperf3.")
                    iperf_result = self.run_iperf3_udp(
                        host, port, bitrate=udp_bitrate, duration=udp_duration
                    )
            else:
                logger.error(f"Unexpected mode '{mode}'.")
                iperf_result = {"type": "N/A", "error": f"Unknown mode {mode}"}
            all_results_raw.append(
                {
                    "host": host,
                    "port": port,
                    "site": server.get("site", "N/A"),
                    "rtt": rtt,
                    "iperf": iperf_result,
                }
            )
            if mode == "closest" or mode == "manual":
                break  # Only test one server

        # --- 3. Aggregate Results ---
        valid_rtts = [r["rtt"] for r in all_results_raw if r.get("rtt") is not None]
        successful_udp_results = [
            r["iperf"]
            for r in all_results_raw
            if isinstance(r.get("iperf"), dict)
            and not r["iperf"].get("error")
            and r["iperf"].get("type") == "UDP"
        ]
        successful_tcp_results = [
            r["iperf"]
            for r in all_results_raw
            if isinstance(r.get("iperf"), dict)
            and not r["iperf"].get("error")
            and r["iperf"].get("type") == "TCP"
        ]
        iperf_errors = [
            r["iperf"].get("error")
            for r in all_results_raw
            if isinstance(r.get("iperf"), dict)
            and r["iperf"].get("error")
            and r["iperf"].get("error") not in ["Ping failed", "iperf disabled"]
        ]

        # Corrected multi-line if block
        if not valid_rtts:
            ping_error_msg = "Ping failed for all servers."
            if iperf_errors:
                ping_error_msg += f" iperf errors: {'; '.join(iperf_errors)}"
            return self.get_fallback_results(ping_error_msg)
        # End corrected block

        avg_rtt = sum(valid_rtts) / len(valid_rtts)
        aggregate_loss = None
        aggregate_jitter = None
        aggregate_bandwidth = None
        bandwidth_type = None
        srt_settings = None
        final_status_message = None

        if NETWORK_TEST_MECHANISM == "ping_only":
            logger.info("Calculating SRT based on RTT only (ping_only mode).")
            aggregate_loss = ASSUMED_LOSS_FOR_TCP_FALLBACK
            bandwidth_type = "N/A"
            srt_settings = self.calculate_srt_settings(avg_rtt, aggregate_loss)
            final_status_message = (
                f"SRT estimated (Ping only, assumed {aggregate_loss}% loss)"
            )
        elif successful_udp_results:
            losses = [
                float(p["loss_percent"])
                for p in successful_udp_results
                if p.get("loss_percent") is not None
            ]
            jitters = [
                float(p["jitter_ms"])
                for p in successful_udp_results
                if p.get("jitter_ms") is not None
            ]
            bandwidths = [
                float(p["bandwidth_mbps"])
                for p in successful_udp_results
                if p.get("bandwidth_mbps") is not None
            ]
            aggregate_loss = max(losses) if losses else 0.0
            aggregate_jitter = sum(jitters) / len(jitters) if jitters else None
            aggregate_bandwidth = (
                sum(bandwidths) / len(bandwidths) if bandwidths else None
            )
            bandwidth_type = "UDP"
            srt_settings = self.calculate_srt_settings(avg_rtt, aggregate_loss)
            logger.info(f"Using UDP results (Loss={aggregate_loss:.2f}%).")
            final_status_message = (
                f"Used UDP test ({mode} mode)."
                if mode != "manual"
                else "Used Manual UDP test."
            )
        elif successful_tcp_results:
            bandwidths = [
                float(p["bandwidth_mbps"])
                for p in successful_tcp_results
                if p.get("bandwidth_mbps") is not None
            ]
            aggregate_bandwidth = (
                sum(bandwidths) / len(bandwidths) if bandwidths else None
            )
            bandwidth_type = "TCP"
            aggregate_loss = ASSUMED_LOSS_FOR_TCP_FALLBACK
            aggregate_jitter = None
            srt_settings = self.calculate_srt_settings(avg_rtt, aggregate_loss)
            logger.warning(
                f"Using TCP results (BW:{aggregate_bandwidth} Mbps) & assumed {aggregate_loss}% loss."
            )
            final_status_message = (
                f"SRT estimated (Manual TCP test, assumed {aggregate_loss}% loss)"
            )
        else:  # iperf mechanism selected, but iperf tests failed
            first_error = (
                iperf_errors[0] if iperf_errors else "iperf3 test skipped/failed"
            )
            error_msg = f"iperf3 failed: {first_error} (Avg RTT:{avg_rtt:.1f}ms)"
            logger.warning(error_msg + ". Using RTT only.")
            aggregate_loss = ASSUMED_LOSS_FOR_TCP_FALLBACK
            aggregate_jitter = None
            aggregate_bandwidth = None
            bandwidth_type = None
            srt_settings = self.calculate_srt_settings(avg_rtt, aggregate_loss)
            final_status_message = f"iperf3 failed. SRT estimated (RTT only, assumed {aggregate_loss}% loss)"

        # --- 4. Format final result ---
        server_location_display = "N/A"
        if mode == "closest" and best_rtt_server_info:
            server_location_display = f"{best_rtt_server_info.get('site','N/A')}, {best_rtt_server_info.get('country','N/A')}"
        elif mode == "manual":
            server_location_display = "Manual Input"
        elif mode == "regional":
            sites = list(set(s.get("site", "N/A") for s in target_servers_to_test))
            countries = list(
                set(s.get("country", "N/A") for s in target_servers_to_test)
            )
            server_location_display = (
                f"{sites[0]}, {countries[0]}"
                if len(target_servers_to_test) == 1
                else f"{region} (Multiple Servers)"
            )

        final_result = {
            "server": test_target_label,
            "server_location": server_location_display,
            "rtt_ms": avg_rtt,
            "loss_percent": aggregate_loss,
            "jitter_ms": aggregate_jitter,
            "bandwidth_mbps": (
                f"{aggregate_bandwidth:.2f}"
                if aggregate_bandwidth is not None
                else None
            ),
            "bandwidth_type": bandwidth_type,
            "latency_recommendation": (
                srt_settings.get("latency_ms") if srt_settings else None
            ),
            "overhead_recommendation": (
                srt_settings.get("overhead_percent") if srt_settings else None
            ),
            "rtt_multiplier": (
                srt_settings.get("rtt_multiplier") if srt_settings else None
            ),
            "test_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "error": final_status_message,
        }
        return final_result


# Note: Uses subprocess.run() with timeout. Ensure ping & iperf3 commands are available.
