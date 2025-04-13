# app/network_test.py
# Uses tuple (result, error_message) return pattern for internal functions.

import os
import json
import requests
import subprocess
import random
import time
from datetime import datetime, timedelta
import logging
import re
from typing import Tuple, Dict, Any, Optional, List, Union  # Added type hinting

# If get_external_ip_and_location is defined elsewhere or still returns dict, adjust import/handling
from app.utils import (
    get_external_ip_and_location,
)  # This function should now return a tuple

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
ASSUMED_LOSS_FOR_TCP_FALLBACK = 7.0  # Loss % used when only ping/TCP works

os.makedirs(DATA_DIR, exist_ok=True)


class NetworkTester:
    def __init__(self):
        self.servers = []
        self.load_servers()  # Load servers on initialization

    def _download_iperf_list(self, force_update=False):
        needs_download = force_update
        if not os.path.exists(IPERF_FULL_LIST_PATH):
            logger.info(f"Cache file not found: {IPERF_FULL_LIST_PATH}. Downloading.")
            needs_download = True
        else:
            try:
                file_mod_time = datetime.fromtimestamp(
                    os.path.getmtime(IPERF_FULL_LIST_PATH)
                )
                if datetime.now() - file_mod_time > DOWNLOAD_CACHE_DURATION:
                    logger.info("Cache file outdated. Downloading.")
                    needs_download = True
                else:
                    logger.debug("Using cached iperf3 server list.")
                    return False
            except Exception as e:
                logger.warning(
                    f"Could not check cache file age for {IPERF_FULL_LIST_PATH}: {e}. Will attempt download."
                )
                needs_download = True
        if needs_download:
            logger.info(f"Fetching iperf3 server list from {IPERF_JSON_URL}...")
            try:
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
                json.loads(content)
                with open(IPERF_FULL_LIST_PATH, "wb") as f:
                    f.write(content)
                logger.info(f"Download successful, saved to {IPERF_FULL_LIST_PATH}.")
                return True
            except requests.exceptions.RequestException as e:
                logger.error(f"Error downloading iperf3 server list: {e}")
                return True
            except (json.JSONDecodeError, ValueError) as e:
                logger.error(
                    f"Downloaded content is not valid JSON or structure is wrong: {e}"
                )
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
                return True
            except Exception as e:
                logger.error(
                    f"Unexpected error during iperf list download: {e}", exc_info=True
                )
                return True
        else:
            return False

    def _parse_host_port(self, server_entry):
        ip_host_string = server_entry.get("IP_HOST", "")
        parts = ip_host_string.split()
        host = None
        port = DEFAULT_IPERF_PORT
        port_str = None
        if not ip_host_string:
            return None, None
        try:
            if "-c" in parts:
                c_index = parts.index("-c")
                host = parts[c_index + 1] if c_index + 1 < len(parts) else None
            if not host:
                return None, None
            if "-p" in parts:
                p_index = parts.index("-p")
                port_str = parts[p_index + 1] if p_index + 1 < len(parts) else None
            if port_str:
                port_str = port_str.strip()
                if "-" in port_str:
                    base_port_str = port_str.split("-")[0].strip()
                    port = (
                        int(base_port_str)
                        if base_port_str.isdigit()
                        else DEFAULT_IPERF_PORT
                    )
                elif port_str.isdigit():
                    port = int(port_str)
                else:
                    logger.warning(
                        f"Non-standard port format '{port_str}' in '{ip_host_string}', using default {DEFAULT_IPERF_PORT}."
                    )
                    port = DEFAULT_IPERF_PORT
            if not (1 <= port <= 65535):
                port = DEFAULT_IPERF_PORT
            if not host or len(host) < 3:
                logger.warning(
                    f"Extracted host '{host}' seems invalid from: {ip_host_string}"
                )
                return None, None
        except (ValueError, IndexError) as e:
            logger.error(f"Error parsing IP_HOST string '{ip_host_string}': {e}")
            return None, None
        return host, port

    def load_servers(self):
        logger.info(
            f"Loading iperf3 server list (Mechanism: {NETWORK_TEST_MECHANISM})..."
        )
        processed_servers = []
        raw_servers = []
        source_file = None
        source_type = "full"
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
            if use_safe_list:
                try:
                    with open(source_file, "r", encoding="utf-8") as f:
                        raw_servers = json.load(f)
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
        if source_type == "full":
            logger.info("Loading full iperf3 server list.")
            self._download_iperf_list()
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
        count_parsed = 0
        for index, raw_server in enumerate(raw_servers):
            if not isinstance(raw_server, dict):
                logger.warning(f"Skipping non-dictionary entry at index {index}.")
                continue
            host, port = self._parse_host_port(raw_server)
            continent = raw_server.get("CONTINENT")
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
        if not self.servers:
            self.load_servers()
        continents = set(
            server.get("continent")
            for server in self.servers
            if server.get("continent")
        )
        return sorted(list(continents))

    # run_ping refactored to return tuple
    def run_ping(self, host: str) -> Tuple[Optional[float], Optional[str]]:
        command = ["ping", "-c", str(PING_COUNT), "-i", "0.2", "-W", "2", host]
        logger.info(f"Running: {' '.join(command)}")
        try:
            env = os.environ.copy()
            env["LANG"] = "C"
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=8, check=False, env=env
            )
            if result.returncode != 0:
                err_msg = f"Ping command failed (Code:{result.returncode}). Err:{result.stderr.strip()}"
                logger.warning(f"{err_msg} for host {host}")
                return None, err_msg
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
            avg_rtt_str = (
                match_linux.group(1)
                if match_linux
                else (match_macos.group(1) if match_macos else None)
            )
            if avg_rtt_str:
                try:
                    avg_rtt = float(avg_rtt_str)
                    logger.info(f"Ping RTT {host}: {avg_rtt:.2f} ms")
                    return avg_rtt, None  # Success
                except ValueError:
                    err_msg = f"Could not convert parsed RTT '{avg_rtt_str}' to float for {host}."
                    logger.warning(err_msg)
                    return None, err_msg
            else:
                err_msg = f"Could not parse RTT from ping output for {host}."
                logger.warning(err_msg)
                return None, err_msg
        except subprocess.TimeoutExpired:
            err_msg = f"Ping timed out >8s for {host}"
            logger.warning(err_msg)
            return None, err_msg
        except FileNotFoundError:
            err_msg = "'ping' command not found."
            logger.error(err_msg)
            return None, err_msg
        except Exception as e:
            err_msg = f"Unexpected ping error for {host}: {e}"
            logger.error(err_msg, exc_info=True)
            return None, err_msg

    # run_iperf3_udp refactored to return tuple
    def run_iperf3_udp(
        self,
        host: str,
        port: int,
        bitrate: str = IPERF_MANUAL_UDP_BITRATE,
        duration: int = IPERF_MANUAL_UDP_DURATION,
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
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
            error_msg = None
            try:
                iperf_data = json.loads(result.stdout)
                if isinstance(iperf_data, dict) and "error" in iperf_data:
                    error_msg = f"iperf error: {iperf_data['error']}"
                    logger.warning(
                        f"iperf3 UDP JSON error for {host}:{port}: {error_msg}"
                    )
                    return None, error_msg
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
                log_msg += f"JSON Error: {parse_error}. " if parse_error else ""
                log_msg += f"Stderr: {stderr_msg}. Stdout Sample: {stdout_sample}"
                logger.warning(log_msg)
                if "connection refused" in stderr_msg.lower():
                    error_msg = "Connection refused"
                elif (
                    "unable to connect" in stderr_msg.lower()
                    or "failed" in stderr_msg.lower()
                ):
                    error_msg = "Server unreachable/test failed"
                elif "interrupt" in stderr_msg.lower():
                    error_msg = "Test interrupted"
                elif "parameter" in stderr_msg.lower():
                    error_msg = "Invalid iperf3 parameter"
                else:
                    error_msg = (
                        f"Cmd fail (code {result.returncode})"
                        if result.returncode != 0
                        else "Invalid JSON output"
                    )
                return None, error_msg
            summary = iperf_data.get("end", {}).get("sum", {})
            jitter_ms = summary.get("jitter_ms")
            lost_packets = summary.get("lost_packets")
            total_packets = summary.get("packets")
            bandwidth_bps = summary.get("bits_per_second")
            if not all(
                v is not None
                for v in [total_packets, jitter_ms, lost_packets, bandwidth_bps]
            ):
                error_msg = "Missing key UDP metrics in iperf3 JSON"
                logger.error(f"{error_msg} for {host}:{port}. Summary: {summary}")
                return None, error_msg
            loss_percent = (
                (lost_packets / total_packets) * 100 if total_packets > 0 else 0.0
            )
            bandwidth_mbps = bandwidth_bps / 1_000_000
            results = {
                "type": "UDP",
                "bandwidth_mbps": f"{bandwidth_mbps:.2f}",
                "loss_percent": f"{loss_percent:.2f}",
                "jitter_ms": f"{jitter_ms:.2f}",
            }
            logger.info(
                f"UDP results for {host}:{port}: BW={results['bandwidth_mbps']} Mbps, Loss={results['loss_percent']}%, Jitter={results['jitter_ms']}ms"
            )
            return results, None  # Success
        except subprocess.TimeoutExpired:
            error_msg = f"Test timed out (>{IPERF_SUBPROCESS_TIMEOUT}s)"
            logger.error(f"iperf3 UDP {error_msg} for {host}:{port}")
            return None, error_msg
        except FileNotFoundError:
            error_msg = "iperf3 command not found"
            logger.error(error_msg)
            return None, error_msg
        except Exception as e:
            error_msg = f"Exec error: {e}"
            logger.error(
                f"Unexpected error iperf3 UDP test for {host}:{port}: {e}",
                exc_info=True,
            )
            return None, error_msg

    # run_iperf3_tcp refactored to return tuple
    def run_iperf3_tcp(
        self, host: str, port: int, duration: int = IPERF_MANUAL_TCP_DURATION
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
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
            error_msg = None
            try:
                iperf_data = json.loads(result.stdout)
                if isinstance(iperf_data, dict) and "error" in iperf_data:
                    error_msg = f"iperf error: {iperf_data['error']}"
                    logger.warning(
                        f"iperf3 TCP JSON error for {host}:{port}: {error_msg}"
                    )
                    return None, error_msg
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
                log_msg += f"JSON Error: {parse_error}. " if parse_error else ""
                log_msg += f"Stderr: {stderr_msg}. Stdout Sample: {stdout_sample}"
                logger.warning(log_msg)
                if "connection refused" in stderr_msg.lower():
                    error_msg = "Connection refused"
                elif (
                    "unable to connect" in stderr_msg.lower()
                    or "failed" in stderr_msg.lower()
                ):
                    error_msg = "Server unreachable/test failed"
                else:
                    error_msg = (
                        f"Cmd fail (code {result.returncode})"
                        if result.returncode != 0
                        else "Invalid JSON output"
                    )
                return None, error_msg
            summary = iperf_data.get("end", {}).get("sum_received", {})
            bandwidth_bps = summary.get("bits_per_second")
            if bandwidth_bps is None:
                error_msg = "Missing key TCP bandwidth metric in iperf3 JSON"
                logger.error(f"{error_msg} for {host}:{port}. Summary: {summary}")
                return None, error_msg
            bandwidth_mbps = bandwidth_bps / 1_000_000
            results = {
                "type": "TCP",
                "bandwidth_mbps": f"{bandwidth_mbps:.2f}",
                "loss_percent": None,
                "jitter_ms": None,
            }
            logger.info(
                f"TCP results for {host}:{port}: BW={results['bandwidth_mbps']} Mbps"
            )
            return results, None  # Success
        except subprocess.TimeoutExpired:
            error_msg = f"Test timed out (>{IPERF_SUBPROCESS_TIMEOUT}s)"
            logger.error(f"iperf3 TCP {error_msg} for {host}:{port}")
            return None, error_msg
        except FileNotFoundError:
            error_msg = "iperf3 command not found"
            logger.error(error_msg)
            return None, error_msg
        except Exception as e:
            error_msg = f"Exec error: {e}"
            logger.error(
                f"Unexpected error iperf3 TCP test for {host}:{port}: {e}",
                exc_info=True,
            )
            return None, error_msg

    # calculate_srt_settings refactored to return tuple
    def calculate_srt_settings(
        self, rtt: Optional[float], loss_percent: Optional[Union[float, str]]
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        if rtt is None:
            msg = "Cannot calculate SRT settings: RTT is missing."
            logger.warning(msg)
            return None, msg
        if loss_percent is None:
            logger.warning("SRT Loss Percentage missing, assuming default.")
            loss_percent = ASSUMED_LOSS_FOR_TCP_FALLBACK
        try:
            rtt_float = max(1.0, float(rtt))
            loss_float = max(0.0, min(float(loss_percent), 100.0))
        except (ValueError, TypeError) as e:
            msg = f"Invalid RTT ({rtt}) or Loss ({loss_percent}) for SRT calculation."
            logger.error(msg)
            return None, msg
        if loss_float <= 1.0:
            multiplier, overhead = 3, 1
        elif loss_float <= 3.0:
            multiplier, overhead = 4, 4
        elif loss_float <= 7.0:
            multiplier, overhead = 6, 9
        elif loss_float <= 10.0:
            multiplier, overhead = 8, 15
        elif loss_float <= 12.0:
            multiplier, overhead = 8, 20
        elif loss_float <= 20.0:
            multiplier, overhead = 10, 38
        elif loss_float <= 25.0:
            multiplier, overhead = 13, 46
        elif loss_float <= 27.0:
            multiplier, overhead = 14, 50
        elif loss_float <= 30.0:
            multiplier, overhead = 14, 61
        elif loss_float <= 40.0:
            multiplier, overhead = 30, 97
        else:
            multiplier, overhead = 30, 99
            logger.warning(
                f"Very high packet loss ({loss_float:.1f}%) detected. SRT may be unreliable."
            )
        min_latency_floor = 80
        max_latency_limit = 8000
        recommended_latency = min(
            max(round(multiplier * rtt_float), min_latency_floor), max_latency_limit
        )
        results = {
            "rtt_multiplier": multiplier,
            "overhead_percent": overhead,
            "latency_ms": recommended_latency,
        }
        logger.info(
            f"Calculated SRT settings (RTT={rtt_float:.1f}ms, Loss={loss_float:.1f}%): {results}"
        )
        return results, None  # Success

    # run_network_test refactored to return tuple and handle tuple returns
    def run_network_test(
        self,
        mode,
        region,
        manual_host,
        manual_port,
        manual_protocol,
        duration,
        bitrate,
        location_info_dict_from_caller,
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        logger.info(
            f"Run test: mechanism={NETWORK_TEST_MECHANISM}, mode={mode}, region={region}, host={manual_host}, port={manual_port}, proto={manual_protocol}, dur={duration}, bitrate={bitrate}"
        )
        self.load_servers()
        if not self.servers:
            err = (
                f"iperf3 server list unavailable (mechanism: {NETWORK_TEST_MECHANISM})."
            )
            logger.error(err)
            return None, err
        target_servers_to_test = []
        test_target_label = "N/A"
        best_rtt_server_info = None

        # --- 1. Determine Target Server(s) ---
        if mode == "manual":
            if not manual_host:
                return None, "Manual mode selected but no host provided."
            m_port = int(manual_port) if manual_port else DEFAULT_IPERF_PORT
            target_servers_to_test = [
                {"host": manual_host, "port": m_port, "site": "Manual Input"}
            ]
            test_target_label = f"Manual: {manual_host}:{m_port}"
            logger.info(f"Manual target: {test_target_label}")
        elif mode == "regional":
            if not region:
                return None, "Regional mode selected but no region provided."
            regional_servers = [s for s in self.servers if s.get("continent") == region]
            if not regional_servers:
                return None, f"No servers found for region: {region}"
            num_to_select = min(3, len(regional_servers))
            target_servers_to_test = random.sample(regional_servers, num_to_select)
            target_labels = [f"{s['host']}:{s['port']}" for s in target_servers_to_test]
            test_target_label = (
                f"{num_to_select} Random in {region}: {', '.join(target_labels)}"
            )
            logger.info(f"Regional targets({region}): {test_target_label}")
        else:  # 'closest' mode
            mode = "closest"
            # Use the location info dictionary passed in from the caller
            if not location_info_dict_from_caller:
                return None, f"Closest mode failed: Location info not provided."
            continent_name = location_info_dict_from_caller.get("continent")
            if not continent_name:
                return (
                    None,
                    f"Could not get continent from location data: {location_info_dict_from_caller}",
                )
            regional_servers = [
                s for s in self.servers if s.get("continent") == continent_name
            ]
            if not regional_servers:
                return None, f"No servers found for your continent: {continent_name}"
            num_candidates = min(7, len(regional_servers))
            candidates_to_ping = random.sample(regional_servers, num_candidates)
            ping_results = []
            logger.info(f"Pinging {num_candidates} candidates in {continent_name}...")
            for server in candidates_to_ping:
                rtt, ping_error = self.run_ping(server["host"])  # Expect tuple
                if rtt is not None:
                    server["rtt"] = rtt
                    ping_results.append(server)
                elif ping_error:
                    logger.warning(
                        f"Ping failed for candidate {server['host']}: {ping_error}"
                    )
            if not ping_results:
                return (
                    None,
                    f"Ping failed for all {num_candidates} candidates in {continent_name}.",
                )
            ping_results.sort(key=lambda x: x["rtt"])
            best_rtt_server_info = ping_results[0]
            target_servers_to_test = [best_rtt_server_info]
            test_target_label = f"Closest: {best_rtt_server_info['host']}:{best_rtt_server_info['port']} ({best_rtt_server_info.get('site','N/A')}, {best_rtt_server_info['rtt']:.1f}ms)"
            logger.info(f"Closest selected: {test_target_label}")

        # --- 2. Run Tests ---
        all_results_raw = []
        if not target_servers_to_test:
            return None, "No target servers selected for testing."
        for server in target_servers_to_test:
            host = server["host"]
            port = server["port"]
            logger.info(f"\n--- Testing server: {host}:{port} ---")
            rtt = server.get("rtt")
            ping_error = None
            if rtt is None:
                rtt, ping_error = self.run_ping(host)
            iperf_result = None
            iperf_error = None
            if NETWORK_TEST_MECHANISM == "ping_only":
                logger.info("Mechanism 'ping_only'. Skipping iperf3.")
                iperf_result = None
                iperf_error = "iperf disabled"
            elif rtt is None:
                logger.warning(f"Skipping iperf3 for {host}:{port} (ping failed).")
                iperf_result = None
                iperf_error = f"Ping failed ({ping_error or 'Unknown reason'})"
            elif mode in ["closest", "regional"]:
                logger.info(f"Mode '{mode}', running UDP iperf3.")
                iperf_result, iperf_error = self.run_iperf3_udp(
                    host,
                    port,
                    bitrate=IPERF_AUTO_UDP_BITRATE,
                    duration=IPERF_AUTO_UDP_DURATION,
                )
            elif mode == "manual":
                udp_duration = duration or IPERF_MANUAL_UDP_DURATION
                udp_bitrate = bitrate or IPERF_MANUAL_UDP_BITRATE
                tcp_duration = duration or IPERF_MANUAL_TCP_DURATION
                if manual_protocol == "tcp":
                    logger.info("Manual(TCP), running TCP iperf3.")
                    iperf_result, iperf_error = self.run_iperf3_tcp(
                        host, port, duration=tcp_duration
                    )
                else:
                    logger.info("Manual(UDP), running UDP iperf3.")
                    iperf_result, iperf_error = self.run_iperf3_udp(
                        host, port, bitrate=udp_bitrate, duration=udp_duration
                    )
            else:
                iperf_result = None
                iperf_error = f"Unknown mode '{mode}'"
                logger.error(f"Unexpected mode '{mode}'.")
            all_results_raw.append(
                {
                    "host": host,
                    "port": port,
                    "site": server.get("site", "N/A"),
                    "rtt": rtt,
                    "ping_error": ping_error,
                    "iperf_result": iperf_result,
                    "iperf_error": iperf_error,
                }
            )
            if mode == "closest" or mode == "manual":
                break

        # --- 3. Aggregate Results ---
        valid_rtts = [r["rtt"] for r in all_results_raw if r.get("rtt") is not None]
        successful_udp_results = [
            r["iperf_result"]
            for r in all_results_raw
            if r.get("iperf_result") and r["iperf_result"].get("type") == "UDP"
        ]
        successful_tcp_results = [
            r["iperf_result"]
            for r in all_results_raw
            if r.get("iperf_result") and r["iperf_result"].get("type") == "TCP"
        ]
        all_errors = [
            r["ping_error"] for r in all_results_raw if r.get("ping_error")
        ] + [r["iperf_error"] for r in all_results_raw if r.get("iperf_error")]
        first_error_msg = all_errors[0] if all_errors else None

        if not valid_rtts:
            err = f"Ping failed for all servers tested. ({first_error_msg or 'No specific error'})"
            logger.error(err)
            return None, err

        avg_rtt = sum(valid_rtts) / len(valid_rtts)
        aggregate_loss = None
        aggregate_jitter = None
        aggregate_bandwidth = None
        bandwidth_type = None
        srt_settings = None
        srt_calc_error = None
        final_status_message = None

        if NETWORK_TEST_MECHANISM == "ping_only":
            logger.info("Calculating SRT based on RTT only (ping_only mode).")
            aggregate_loss = ASSUMED_LOSS_FOR_TCP_FALLBACK
            bandwidth_type = "N/A"
            srt_settings, srt_calc_error = self.calculate_srt_settings(
                avg_rtt, aggregate_loss
            )
            final_status_message = (
                f"SRT estimated (Ping only, assumed {aggregate_loss}% loss)"
            )
        elif successful_udp_results:
            udp_res = successful_udp_results[0]
            aggregate_loss = float(udp_res.get("loss_percent", 0.0))
            aggregate_jitter = float(udp_res.get("jitter_ms", 0.0))
            aggregate_bandwidth = float(udp_res.get("bandwidth_mbps", 0.0))
            bandwidth_type = "UDP"
            srt_settings, srt_calc_error = self.calculate_srt_settings(
                avg_rtt, aggregate_loss
            )
            logger.info(f"Using UDP results (Loss={aggregate_loss:.2f}%).")
            final_status_message = (
                f"Used UDP test ({mode} mode)."
                if mode != "manual"
                else "Used Manual UDP test."
            )
        elif successful_tcp_results:
            tcp_res = successful_tcp_results[0]
            aggregate_bandwidth = float(tcp_res.get("bandwidth_mbps", 0.0))
            bandwidth_type = "TCP"
            aggregate_loss = ASSUMED_LOSS_FOR_TCP_FALLBACK
            aggregate_jitter = None
            srt_settings, srt_calc_error = self.calculate_srt_settings(
                avg_rtt, aggregate_loss
            )
            logger.warning(
                f"Using TCP results (BW:{aggregate_bandwidth:.2f} Mbps) & assumed {aggregate_loss}% loss."
            )
            final_status_message = (
                f"SRT estimated (TCP test only, assumed {aggregate_loss}% loss)"
            )
        else:
            err = f"iperf3 failed: {first_error_msg or 'Unknown iperf error'} (Avg RTT:{avg_rtt:.1f}ms)"
            logger.warning(err + ". Using RTT only.")
            aggregate_loss = ASSUMED_LOSS_FOR_TCP_FALLBACK
            aggregate_jitter = None
            aggregate_bandwidth = None
            bandwidth_type = None
            srt_settings, srt_calc_error = self.calculate_srt_settings(
                avg_rtt, aggregate_loss
            )
            final_status_message = f"iperf3 failed. SRT estimated (RTT only, assumed {aggregate_loss}% loss)"

        if srt_calc_error:
            logger.error(f"SRT calculation failed: {srt_calc_error}")
            final_status_message = f"{final_status_message or 'Test complete'}. SRT calc failed: {srt_calc_error}"

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
            "error": final_status_message,  # Final status message, not necessarily a fatal error
        }
        return final_result, None  # Success, return result dict and None for error
