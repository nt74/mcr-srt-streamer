# /opt/srt-streamer-enhanced/app/network_test.py
# Updated to force TCP for auto modes and allow TCP/UDP choice for manual mode.

import os
import json
import requests
import subprocess
import random
import time
from datetime import datetime, timedelta
import logging
import re

logger = logging.getLogger(__name__)

# --- Constants ---
IPERF_JSON_URL = "https://export.iperf3serverlist.net/json.php?action=download"
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(APP_DIR, 'data')
IPERF_JSON_PATH = os.path.join(DATA_DIR, 'iperf3_export_servers.json')
EXTERNAL_IP_FILE_PATH = os.path.join(DATA_DIR, 'external_ip.txt') # Assuming external_ip.txt is used
GEOIP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,continentCode,continent,countryCode,country,query"
DEFAULT_IPERF_PORT = 5201
DOWNLOAD_CACHE_DURATION = timedelta(hours=6)
PING_COUNT = 4
IPERF_UDP_DURATION = 5          # Default duration for UDP tests (manual mode)
IPERF_DEFAULT_UDP_BITRATE = "10M" # Default bitrate for UDP tests (manual mode)
IPERF_TCP_DURATION = 7          # Default duration for TCP tests (auto modes and manual TCP)
IPERF_PACKET_LENGTH = 1200      # For UDP tests
IPERF_SUBPROCESS_TIMEOUT = 35   # Generous overall timeout
RTT_THRESHOLD_FOR_TCP_FALLBACK = 250 # No longer used for auto modes, potentially for manual UDP warning
ASSUMED_LOSS_FOR_TCP_FALLBACK = 7.0 # Used if only TCP or Ping results are available

os.makedirs(DATA_DIR, exist_ok=True)

class NetworkTester:
    def __init__(self):
        self.servers = []
        self.load_servers() # Load servers on initialization

    def _download_iperf_list(self, force_update=False):
        """Downloads the iperf3 server list if cache is missing or outdated."""
        needs_download = force_update
        if not os.path.exists(IPERF_JSON_PATH):
            logger.info(f"Cache file not found: {IPERF_JSON_PATH}. Downloading.")
            needs_download = True
        else:
            try:
                file_mod_time = datetime.fromtimestamp(os.path.getmtime(IPERF_JSON_PATH))
                if datetime.now() - file_mod_time > DOWNLOAD_CACHE_DURATION:
                    logger.info("Cache file outdated. Downloading.")
                    needs_download = True
                else:
                    logger.debug("Using cached iperf3 server list.")
                    return False # No download needed
            except Exception as e:
                logger.warning(f"Could not check cache file age for {IPERF_JSON_PATH}: {e}. Will attempt download.")
                needs_download = True

        if needs_download:
            logger.info(f"Fetching iperf3 server list from {IPERF_JSON_URL}...")
            try:
                response = requests.get(IPERF_JSON_URL, timeout=30, stream=True)
                response.raise_for_status()
                # Basic validation: Check if content looks like a JSON array
                content = b""
                first_chunk = True
                looks_like_json = False
                for chunk in response.iter_content(chunk_size=8192):
                    if first_chunk:
                        if chunk.strip().startswith(b'['): looks_like_json = True
                        first_chunk = False
                    content += chunk
                if not looks_like_json or not content.strip().endswith(b']'):
                    try: error_hint = content.decode('utf-8', errors='ignore')[:200]
                    except Exception: error_hint = "(Could not decode non-JSON response)"
                    raise ValueError(f"Downloaded content does not appear to be a JSON array. Starts with: {error_hint}")

                # Further validation by trying to parse
                json.loads(content) # This will raise json.JSONDecodeError if invalid

                with open(IPERF_JSON_PATH, 'wb') as f:
                    f.write(content)
                logger.info(f"Download successful, saved to {IPERF_JSON_PATH}.")
                return True # Download happened
            except requests.exceptions.RequestException as e:
                logger.error(f"Error downloading iperf3 server list: {e}")
                return True # Indicate download was attempted (and failed)
            except (json.JSONDecodeError, ValueError) as e:
                 logger.error(f"Downloaded content is not valid JSON or structure is wrong: {e}")
                 # Attempt to remove potentially corrupted cache file
                 if os.path.exists(IPERF_JSON_PATH):
                     try: os.remove(IPERF_JSON_PATH); logger.info(f"Removed potentially invalid cache file: {IPERF_JSON_PATH}")
                     except Exception as rm_e: logger.warning(f"Could not remove potentially invalid cache file {IPERF_JSON_PATH}: {rm_e}")
                 return True # Indicate download was attempted (and failed)
            except Exception as e:
                logger.error(f"Unexpected error during iperf list download: {e}", exc_info=True)
                return True # Indicate download was attempted (and failed)
        else:
            return False # No download needed

    def _parse_host_port(self, server_entry):
        """Parses host and port from the 'IP_HOST' string in the server list JSON."""
        ip_host_string = server_entry.get("IP_HOST", "")
        if not ip_host_string: return None, None

        parts = ip_host_string.split()
        host = None
        port = DEFAULT_IPERF_PORT
        port_str = None

        try:
            # Find host after '-c'
            if '-c' in parts:
                c_index = parts.index('-c')
                if c_index + 1 < len(parts):
                    host = parts[c_index + 1]
            if not host: logger.warning(f"Could not find host after '-c' in: {ip_host_string}"); return None, None

            # Find port after '-p'
            if '-p' in parts:
                p_index = parts.index('-p')
                if p_index + 1 < len(parts):
                    port_str = parts[p_index + 1]

            # Parse port string (handles single ports and ranges like '5201-5209')
            if port_str:
                port_str = port_str.strip()
                if '-' in port_str: # Handle ranges like '5201-5209', use the first port
                    base_port_str = port_str.split('-')[0].strip()
                    port = int(base_port_str) if base_port_str.isdigit() else DEFAULT_IPERF_PORT
                elif port_str.isdigit():
                    port = int(port_str)
                else:
                    logger.warning(f"Non-standard port format '{port_str}' found in '{ip_host_string}', using default {DEFAULT_IPERF_PORT}.")
                    port = DEFAULT_IPERF_PORT

            # Basic validation
            if port < 1 or port > 65535: port = DEFAULT_IPERF_PORT
            if not host or len(host) < 3: logger.warning(f"Extracted host '{host}' seems invalid from: {ip_host_string}"); return None, None

        except (ValueError, IndexError) as e: logger.error(f"Error parsing IP_HOST string '{ip_host_string}': {e}"); return None, None
        return host, port

    def load_servers(self):
        """Loads iperf3 servers from the cached JSON file."""
        logger.info("Attempting to load/update iperf3 server list...")
        self._download_iperf_list() # Ensure list is up-to-date

        processed_servers = []
        if not os.path.exists(IPERF_JSON_PATH):
            logger.error(f"Server list file unavailable after download attempt: {IPERF_JSON_PATH}")
            self.servers = []
            return

        try:
            with open(IPERF_JSON_PATH, 'r', encoding='utf-8') as f:
                try:
                    raw_servers = json.load(f)
                except json.JSONDecodeError as json_err:
                    logger.error(f"JSON Decode Error in {IPERF_JSON_PATH}: {json_err}. Server list will be empty.")
                    raw_servers = []

            if not isinstance(raw_servers, list):
                logger.error(f"Loaded server data is not a list. Server list will be empty.")
                raw_servers = []

            logger.info(f"Loaded {len(raw_servers)} raw server entries from cache.")
            count_parsed = 0
            for index, raw_server in enumerate(raw_servers):
                 if not isinstance(raw_server, dict):
                     logger.warning(f"Skipping non-dictionary entry at index {index}.")
                     continue

                 host, port = self._parse_host_port(raw_server)
                 if host and port:
                     continent = raw_server.get('CONTINENT')
                     # Require continent for regional filtering
                     if not continent:
                         logger.debug(f"Skipping server with missing CONTINENT: {host}")
                         continue
                     processed_servers.append({
                         'host': host,
                         'port': port,
                         'site': raw_server.get('SITE', 'N/A'),
                         'country': raw_server.get('COUNTRY'),
                         'continent': continent,
                         'provider': raw_server.get('PROVIDER'),
                         'options_str': raw_server.get('OPTIONS') # Keep original options string if needed
                     })
                     count_parsed += 1
                 else:
                     logger.debug(f"Skipping entry due to host/port parsing failure: {raw_server.get('IP_HOST', 'N/A')}")

            logger.info(f"Successfully processed {count_parsed} servers with valid host, port, and continent info.")
            self.servers = processed_servers
        except FileNotFoundError:
            logger.error(f"Server list file not found during load: {IPERF_JSON_PATH}")
            self.servers = []
        except Exception as e:
            logger.error(f"Unexpected error loading servers: {e}", exc_info=True)
            self.servers = [] # Ensure servers list is empty on error

    def get_server_regions(self):
        """Returns a sorted list of unique continents from the loaded servers."""
        if not self.servers:
            self.load_servers() # Attempt to load if empty
        continents = set(server.get('continent') for server in self.servers if server.get('continent'))
        return sorted(list(continents))

    def get_external_ip_and_location(self):
        """Reads external IP from file and looks up GeoIP location."""
        ip_address = None
        ip_source = "Unknown"
        # Read IP from the text file
        try:
            logger.debug(f"Attempting to read external IP from: {EXTERNAL_IP_FILE_PATH}")
            if os.path.exists(EXTERNAL_IP_FILE_PATH):
                with open(EXTERNAL_IP_FILE_PATH, 'r', encoding='utf-8') as f:
                    ip_address = f.readline().strip()
                if not ip_address:
                    logger.warning(f"External IP file '{EXTERNAL_IP_FILE_PATH}' is empty.")
                    return {'ip': None, 'error': 'Local IP file is empty'}
                ip_source = f"file ({os.path.basename(EXTERNAL_IP_FILE_PATH)})"
                logger.info(f"Read external IP from {ip_source}: {ip_address}")
            else:
                logger.warning(f"External IP file not found: {EXTERNAL_IP_FILE_PATH}")
                return {'ip': None, 'error': 'Local IP file not found'}
        except Exception as e:
            logger.error(f"Error reading external IP file '{EXTERNAL_IP_FILE_PATH}': {e}", exc_info=True)
            return {'ip': None, 'error': f'Error reading local IP file'}

        # Validate IP format before API call
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_address):
            logger.warning(f"Invalid IP address format found in file: {ip_address}")
            return {'ip': ip_address, 'error': 'Invalid IP format in local file'}

        # Lookup GeoIP using the fetched IP
        api_url = GEOIP_API_URL.format(ip=ip_address)
        logger.info(f"Looking up GeoIP for {ip_address} via {api_url}")
        try:
            response = requests.get(api_url, timeout=7)
            response.raise_for_status()
            data = response.json()
            if data.get('status') == 'success':
                location_info = {
                    'ip': data.get('query', ip_address), # Use the IP returned by API if possible
                    'continent': data.get('continent'),
                    'continentCode': data.get('continentCode'),
                    'country': data.get('country'),
                    'countryCode': data.get('countryCode'),
                    'error': None
                }
                logger.info(f"GeoIP Result: {location_info}")
                return location_info
            else:
                api_msg = data.get('message', 'API Error')
                logger.warning(f"GeoIP API Error for {ip_address}: {api_msg}")
                return {'ip': ip_address, 'error': api_msg}
        except requests.exceptions.Timeout:
            logger.error(f"GeoIP API call timed out for IP {ip_address}")
            return {'ip': ip_address, 'error': 'GeoIP API Timeout'}
        except requests.exceptions.RequestException as e:
            logger.error(f"Error calling GeoIP API for IP {ip_address}: {e}")
            return {'ip': ip_address, 'error': f"GeoIP Network Error"}
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding GeoIP API response for IP {ip_address}: {e}")
            return {'ip': ip_address, 'error': 'Invalid GeoIP Response'}
        except Exception as e:
            logger.error(f"Unexpected error in GeoIP lookup for IP {ip_address}: {e}", exc_info=True)
            return {'ip': ip_address, 'error': 'GeoIP Internal Error'}

    def run_ping(self, host):
        """Runs ping command and parses average RTT."""
        # Use -i 0.2 for faster pings, -W 2 for 2-second timeout per ping
        command = ['ping', '-c', str(PING_COUNT), '-i', '0.2', '-W', '2', host]
        logger.info(f"Running: {' '.join(command)}")
        try:
            # Force LANG=C to ensure consistent output format for parsing
            env = os.environ.copy()
            env['LANG'] = 'C'
            result = subprocess.run(command, capture_output=True, text=True, timeout=8, check=False, env=env)

            if result.returncode != 0:
                logger.warning(f"Ping failed for {host}. Return Code: {result.returncode}. Stderr: {result.stderr.strip()}")
                return None

            # Parse average RTT from output (handle Linux and macOS formats)
            avg_rtt = None
            # Linux format: min/avg/max/mdev = 1.234/5.678/9.012/1.111 ms
            match_linux = re.search(r'min/avg/max/mdev\s*=\s*[\d.]+/([\d.]+)/', result.stdout, re.IGNORECASE | re.MULTILINE)
            # macOS format: min/avg/max/stddev = 1.234/5.678/9.012/1.111 ms
            match_macos = re.search(r'min/avg/max/stddev\s*=\s*[\d.]+/([\d.]+)/', result.stdout, re.IGNORECASE | re.MULTILINE)

            avg_rtt_str = None
            if match_linux: avg_rtt_str = match_linux.group(1); logger.debug(f"Parsed Linux style ping RTT for {host}")
            elif match_macos: avg_rtt_str = match_macos.group(1); logger.debug(f"Parsed macOS style ping RTT for {host}")

            if avg_rtt_str:
                try: avg_rtt = float(avg_rtt_str)
                except ValueError: logger.warning(f"Could not convert parsed RTT '{avg_rtt_str}' to float for {host}"); avg_rtt = None

            if avg_rtt is not None:
                logger.info(f"Ping Avg RTT for {host}: {avg_rtt:.2f} ms")
                return avg_rtt
            else:
                logger.warning(f"Could not parse ping average RTT for {host}. Output:\n{result.stdout}")
                return None
        except subprocess.TimeoutExpired:
            logger.warning(f"Ping command timed out (>{8}s) for {host}")
            return None
        except FileNotFoundError:
            logger.error(f"'ping' command not found. Cannot measure RTT.")
            return None # Indicate ping command is missing
        except Exception as e:
            logger.error(f"Error running/processing ping for {host}: {e}", exc_info=True)
            return None

    def run_iperf3_udp(self, host, port, bitrate=IPERF_DEFAULT_UDP_BITRATE, duration=IPERF_UDP_DURATION):
        """Runs iperf3 UDP test. Returns dict with results or {'error': ...}."""
        # UDP test parameters
        timeout_seconds = duration + 25 # Allow generous time for connection and test
        iperf_cmd = [
            "iperf3", "-c", host, "-p", str(port), # Connect to server
            "-u",                                   # UDP mode
            "-b", bitrate,                          # Target bitrate
            "-t", str(duration),                    # Test duration
            "-J",                                   # JSON output
            "--length", str(IPERF_PACKET_LENGTH),   # Specify packet length
            "--connect-timeout", "5000"             # 5-second connect timeout (ms)
        ]
        logger.info(f"Running UDP iperf3: {' '.join(iperf_cmd)}")
        try:
            result = subprocess.run(iperf_cmd, capture_output=True, text=True, timeout=timeout_seconds, check=False) # Don't check=True, parse output first

            iperf_data = None
            parse_error = None
            try:
                # Attempt to parse JSON output
                 iperf_data = json.loads(result.stdout)
                 # Check for errors reported within the JSON structure itself
                 if isinstance(iperf_data, dict) and 'error' in iperf_data:
                     logger.warning(f"iperf3 UDP test for {host}:{port} returned JSON error: {iperf_data['error']}")
                     return {'type': 'UDP', 'error': iperf_data['error']} # Return the error from iperf3
            except json.JSONDecodeError as e:
                parse_error = e # Store parse error to report later

            # Handle non-zero return codes or JSON parsing errors
            if parse_error or result.returncode != 0:
                 stderr_msg = result.stderr.strip() if result.stderr else "(No stderr)"
                 stdout_sample = result.stdout.strip()[:200] if result.stdout else "(No stdout)"
                 log_msg = f"iperf3 UDP failed for {host}:{port}. Code: {result.returncode}. "
                 if parse_error: log_msg += f"JSON Parse Error: {parse_error}. "
                 log_msg += f"Stderr: {stderr_msg}. Stdout Sample: {stdout_sample}"
                 logger.warning(log_msg)
                 # Provide more specific error messages based on common iperf3 stderr
                 if "connection refused" in stderr_msg.lower(): return {'type': 'UDP', 'error': 'Connection refused'}
                 if "unable to connect" in stderr_msg.lower() or "failed" in stderr_msg.lower(): return {'type': 'UDP', 'error': 'Server unreachable/test failed'}
                 if "interrupt" in stderr_msg.lower(): return {'type': 'UDP', 'error': 'Test interrupted'}
                 if "parameter" in stderr_msg.lower(): return {'type': 'UDP', 'error': 'Invalid iperf3 parameter'}
                 # Generic fallback error
                 return {'type': 'UDP', 'error': f'Test command failed (code {result.returncode})' if result.returncode != 0 else 'Invalid JSON output'}

            # Extract results from the 'end'->'sum' section for UDP client
            summary = iperf_data.get('end', {}).get('sum', {})
            jitter_ms = summary.get('jitter_ms')
            lost_packets = summary.get('lost_packets')
            total_packets = summary.get('packets')
            bandwidth_bps = summary.get('bits_per_second')

            # Validate that essential metrics were found
            if total_packets is None or jitter_ms is None or lost_packets is None or bandwidth_bps is None:
                error_msg = "Missing key UDP metrics (jitter, loss, packets, bandwidth) in iperf3 JSON output"
                logger.error(f"{error_msg} for {host}:{port}. Summary Data: {summary}")
                return {'type': 'UDP', 'error': error_msg}

            # Calculate loss percentage
            loss_percent = (lost_packets / total_packets) * 100 if total_packets > 0 else 0.0
            # Convert bandwidth to Mbps
            bandwidth_mbps = bandwidth_bps / 1_000_000

            results = {
                'type': 'UDP',
                'bandwidth_mbps': f"{bandwidth_mbps:.2f}",
                'loss_percent': f"{loss_percent:.2f}",
                'jitter_ms': f"{jitter_ms:.2f}",
                'error': None
            }
            logger.info(f"UDP iperf3 results for {host}:{port}: BW={results['bandwidth_mbps']} Mbps, Loss={results['loss_percent']}%, Jitter={results['jitter_ms']}ms")
            return results

        except subprocess.TimeoutExpired:
            logger.error(f"iperf3 UDP test timed out (>{timeout_seconds}s) for {host}:{port}")
            return {'type': 'UDP', 'error': 'Test timed out'}
        except FileNotFoundError:
            logger.error(f"'iperf3' command not found.")
            return {'type': 'UDP', 'error': 'iperf3 command not found'}
        except Exception as e:
            logger.error(f"Unexpected error during iperf3 UDP test for {host}:{port}: {e}", exc_info=True)
            return {'type': 'UDP', 'error': f'Test execution error: {e}'}

    def run_iperf3_tcp(self, host, port, duration=IPERF_TCP_DURATION):
        """Runs iperf3 TCP test (-R for reverse). Returns dict with results or {'error': ...}."""
        timeout_seconds = duration + 25 # Generous overall timeout
        iperf_cmd = [
            "iperf3", "-c", host, "-p", str(port), # Connect to server
            "-R",                                   # Reverse mode (server sends, client receives) - better reflects streaming ingest
            "-t", str(duration),                    # Test duration
            "-J",                                   # JSON output
            "--connect-timeout", "5000"             # 5-second connect timeout (ms)
        ]
        logger.info(f"Running TCP iperf3 (-R): {' '.join(iperf_cmd)}")
        try:
            result = subprocess.run(iperf_cmd, capture_output=True, text=True, timeout=timeout_seconds, check=False)

            iperf_data = None; parse_error = None
            try:
                 iperf_data = json.loads(result.stdout)
                 if isinstance(iperf_data, dict) and 'error' in iperf_data:
                     logger.warning(f"iperf3 TCP test for {host}:{port} returned JSON error: {iperf_data['error']}")
                     return {'type': 'TCP', 'error': iperf_data['error']}
            except json.JSONDecodeError as e:
                 parse_error = e

            if parse_error or result.returncode != 0:
                 stderr_msg = result.stderr.strip() if result.stderr else "(No stderr)"
                 stdout_sample = result.stdout.strip()[:200] if result.stdout else "(No stdout)"
                 log_msg = f"iperf3 TCP failed for {host}:{port}. Code: {result.returncode}. "
                 if parse_error: log_msg += f"JSON Parse Error: {parse_error}. "
                 log_msg += f"Stderr: {stderr_msg}. Stdout Sample: {stdout_sample}"
                 logger.warning(log_msg)
                 # Provide more specific error messages
                 if "connection refused" in stderr_msg.lower(): return {'type': 'TCP', 'error': 'Connection refused'}
                 if "unable to connect" in stderr_msg.lower() or "failed" in stderr_msg.lower(): return {'type': 'TCP', 'error': 'Server unreachable/test failed'}
                 # Generic fallback error
                 return {'type': 'TCP', 'error': f'Test command failed (code {result.returncode})' if result.returncode != 0 else 'Invalid JSON output'}

            # For TCP -R (reverse mode), the client receives, so look in 'end' -> 'sum_received'
            summary = iperf_data.get('end', {}).get('sum_received', {})
            bandwidth_bps = summary.get('bits_per_second')
            # Retransmits might be interesting but aren't a primary metric here
            # retransmits = summary.get('retransmits') # Typically in 'sum_sent' for standard TCP test

            if bandwidth_bps is None:
                error_msg = "Missing key TCP bandwidth metric ('bits_per_second' in sum_received) in iperf3 JSON output"
                logger.error(f"{error_msg} for {host}:{port}. Summary Data: {summary}")
                return {'type': 'TCP', 'error': error_msg}

            bandwidth_mbps = bandwidth_bps / 1_000_000

            results = {
                'type': 'TCP',
                'bandwidth_mbps': f"{bandwidth_mbps:.2f}",
                'loss_percent': None, # Loss is not directly measured/meaningful in standard TCP iperf3 output
                'jitter_ms': None,    # Jitter is not measured for TCP
                'error': None
            }
            logger.info(f"TCP iperf3 results for {host}:{port}: BW={results['bandwidth_mbps']} Mbps")
            return results

        except subprocess.TimeoutExpired:
            logger.error(f"iperf3 TCP test timed out (>{timeout_seconds}s) for {host}:{port}")
            return {'type': 'TCP', 'error': 'Test timed out'}
        except FileNotFoundError:
            logger.error(f"'iperf3' command not found.")
            return {'type': 'TCP', 'error': 'iperf3 command not found'}
        except Exception as e:
            logger.error(f"Unexpected error during iperf3 TCP test for {host}:{port}: {e}", exc_info=True)
            return {'type': 'TCP', 'error': f'Test execution error: {e}'}

    def calculate_srt_settings(self, rtt, loss_percent):
        """Calculates recommended SRT Latency/Overhead based on Haivision guide table."""
        if rtt is None:
             logger.warning("Cannot calculate SRT settings: RTT is missing.")
             return None
        if loss_percent is None:
            logger.warning("Cannot calculate SRT settings: Loss Percentage is missing. Assuming default.")
            # Handle missing loss (e.g., if only TCP ran) by assuming a default loss for calculation
            loss_percent = ASSUMED_LOSS_FOR_TCP_FALLBACK

        # Ensure values are floats and within reasonable bounds
        try:
            rtt_float = max(1.0, float(rtt)) # Ensure RTT is at least 1ms
            loss_float = max(0.0, min(float(loss_percent), 100.0)) # Clamp loss between 0 and 100
        except (ValueError, TypeError):
            logger.error(f"Invalid RTT ({rtt}) or Loss ({loss_percent}) values for SRT calculation.")
            return None

        # Haivision Guide Table Logic (Table from page 57 [cite: 352])
        if loss_float <= 1.0:     multiplier, overhead = 3, 1
        elif loss_float <= 3.0:   multiplier, overhead = 4, 4
        elif loss_float <= 7.0:   multiplier, overhead = 6, 9
        elif loss_float <= 10.0:  multiplier, overhead = 8, 15
        elif loss_float <= 12.0:  multiplier, overhead = 8, 20  # Note: Guide has 8 for both <=10 and <=12
        elif loss_float <= 20.0:  multiplier, overhead = 10, 38
        elif loss_float <= 25.0:  multiplier, overhead = 13, 46
        elif loss_float <= 27.0:  multiplier, overhead = 14, 50
        elif loss_float <= 30.0:  multiplier, overhead = 14, 61  # Note: Guide has 14 for both <=27 and <=30
        elif loss_float <= 40.0:  multiplier, overhead = 30, 97
        else: # loss > 40%
             multiplier, overhead = 30, 99 # Use max practical overhead (99%)
             logger.warning(f"Very high packet loss ({loss_float:.1f}%) detected. SRT may be unreliable.")

        # Calculate recommended latency: Multiplier * RTT, but enforce minimum practical latency
        # Minimum SRT Latency based on RTT <= 20ms row from table [cite: 352] or a general floor like 80ms [cite: 383]
        min_latency_floor = 80 # A reasonable minimum floor
        recommended_latency = max(round(multiplier * rtt_float), min_latency_floor)

        # Ensure latency doesn't exceed max allowed (e.g., 8000ms from forms)
        max_latency_limit = 8000
        recommended_latency = min(recommended_latency, max_latency_limit)

        results = {
            'rtt_multiplier': multiplier,
            'overhead_percent': overhead,
            'latency_ms': recommended_latency
        }
        logger.info(f"Calculated SRT settings (RTT={rtt_float:.1f}ms, Loss={loss_float:.1f}%): {results}")
        return results

    def get_fallback_results(self, error_msg="Test failed or no servers available"):
        """Returns a default dictionary structure when tests cannot be fully completed."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logger.warning(f"Returning fallback results at {now}. Reason: {error_msg}")
        return {
            'server': "N/A",
            'server_location': "N/A",
            'rtt_ms': None,
            'loss_percent': None,
            'jitter_ms': None,
            'bandwidth_mbps': None,
            'bandwidth_type': None, # Indicate type of bandwidth measured (TCP/UDP)
            'latency_recommendation': 120, # Default fallback latency
            'overhead_recommendation': 25, # Default fallback overhead
            'rtt_multiplier': 4,           # Default fallback multiplier
            'test_time': now,
            'error': error_msg # Include the reason for the fallback
        }

    # --- run_network_test: Updated signature and logic ---
    def run_network_test(self, mode, region, manual_host, manual_port, manual_protocol, duration, bitrate, location_info):
        """
        Orchestrates network tests based on mode. Uses TCP for auto modes,
        respects manual_protocol for manual mode.
        """
        logger.info(f"Running network test: mode={mode}, region={region}, manual_host={manual_host}, manual_port={manual_port}, manual_protocol={manual_protocol}, duration={duration}, bitrate={bitrate}")

        if not self.servers:
            logger.warning("Server list is empty, attempting reload.")
            self.load_servers()
            if not self.servers:
                return self.get_fallback_results("iperf3 server list unavailable.")

        target_servers_to_test = []
        test_target_label = "N/A"
        best_rtt_server_info = None # Store info of the best server found in 'closest' mode

        # --- 1. Determine Target Server(s) ---
        if mode == 'manual':
            if not manual_host: return self.get_fallback_results("Manual mode selected but no host provided.")
            m_port = int(manual_port) if manual_port else DEFAULT_IPERF_PORT
            target_servers_to_test = [{'host': manual_host, 'port': m_port, 'site': 'Manual Input'}]
            test_target_label = f"Manual: {manual_host}:{m_port}"
            logger.info(f"Manual mode target: {test_target_label}")
        elif mode == 'regional':
            if not region: return self.get_fallback_results("Regional mode selected but no region provided.")
            regional_servers = [s for s in self.servers if s.get('continent') == region]
            if not regional_servers: return self.get_fallback_results(f"No iperf3 servers found for region: {region}")
            # Test up to 3 random servers in the region
            num_to_select = min(3, len(regional_servers))
            target_servers_to_test = random.sample(regional_servers, num_to_select)
            target_labels = [f"{s['host']}:{s['port']}" for s in target_servers_to_test]
            test_target_label = f"{num_to_select} Random in {region}: {', '.join(target_labels)}"
            logger.info(f"Regional mode targets ({region}): {test_target_label}")
        else: # Default to 'closest'
            mode = 'closest' # Ensure mode is set correctly
            if not location_info or location_info.get('error'):
                err = location_info.get('error', 'GeoIP Error') if location_info else 'GeoIP unavailable'
                return self.get_fallback_results(f"Cannot determine closest server: Location unavailable ({err})")
            continent_name = location_info.get('continent')
            if not continent_name: return self.get_fallback_results(f"Could not determine continent from GeoIP info: {location_info}")

            regional_servers = [s for s in self.servers if s.get('continent') == continent_name]
            if not regional_servers: return self.get_fallback_results(f"No iperf3 servers found for your continent: {continent_name}")

            # Ping a sample of regional servers to find the closest
            num_candidates = min(7, len(regional_servers))
            candidates_to_ping = random.sample(regional_servers, num_candidates)
            ping_results = []
            logger.info(f"Pinging up to {num_candidates} candidates in {continent_name} to find closest...")
            for server in candidates_to_ping:
                rtt = self.run_ping(server['host'])
                if rtt is not None:
                    server['rtt'] = rtt # Add RTT to server dict
                    ping_results.append(server)
                # Add a small delay between pings if needed
                # time.sleep(0.1)

            if not ping_results: return self.get_fallback_results(f"Ping failed for all candidate servers in {continent_name}.")

            # Select the server with the best (lowest) RTT
            ping_results.sort(key=lambda x: x['rtt'])
            best_rtt_server_info = ping_results[0]
            target_servers_to_test = [best_rtt_server_info] # Test only the best one
            test_target_label = f"Closest: {best_rtt_server_info['host']}:{best_rtt_server_info['port']} ({best_rtt_server_info.get('site', 'N/A')}, {best_rtt_server_info['rtt']:.1f}ms)"
            logger.info(f"Closest server selected: {test_target_label}")

        # --- 2. Run Tests ---
        all_results_raw = []
        if not target_servers_to_test:
            return self.get_fallback_results("No target servers were selected for testing.")

        for server in target_servers_to_test:
            host = server['host']; port = server['port']
            logger.info(f"\n--- Testing server: {host}:{port} ---")

            # Ensure RTT is available (either from pinging candidates or ping now)
            rtt = server.get('rtt') # RTT might already be populated for 'closest' mode
            if rtt is None:
                rtt = self.run_ping(host)

            iperf_result = None
            if rtt is None:
                logger.warning(f"Skipping iperf3 test for {host}:{port} because ping failed.")
                iperf_result = {'type': 'N/A', 'error': 'Ping failed'}
            # --- >>> Protocol Selection Logic <<< ---
            elif mode == 'closest' or mode == 'regional':
                # Force TCP for Auto modes
                logger.info(f"Mode is '{mode}', running TCP iperf3 test for {host}:{port}.")
                iperf_result = self.run_iperf3_tcp(host, port, duration=IPERF_TCP_DURATION)
            elif mode == 'manual':
                # Use the protocol selected by the user for Manual mode
                if manual_protocol == 'tcp':
                    logger.info(f"Manual mode (TCP selected), running TCP iperf3 test for {host}:{port}.")
                    iperf_result = self.run_iperf3_tcp(host, port, duration=IPERF_TCP_DURATION) # Use TCP duration
                else: # Assume UDP if not TCP
                    logger.info(f"Manual mode (UDP selected), running UDP iperf3 test for {host}:{port}.")
                    # Note: 'bitrate' and 'duration' from form are used here
                    iperf_result = self.run_iperf3_udp(host, port, bitrate=bitrate, duration=duration)
            # --- >>> End Protocol Selection Logic <<< ---
            else:
                # Should not happen if form validation works
                logger.error(f"Unexpected test mode '{mode}' encountered during iperf execution.")
                iperf_result = {'type': 'N/A', 'error': f'Unknown mode {mode}'}

            # Store raw results including RTT and iperf output (or error)
            all_results_raw.append({'host': host, 'port': port, 'site': server.get('site', 'N/A'), 'rtt': rtt, 'iperf': iperf_result})

            # For 'closest' and 'manual', only test one server
            if mode == 'closest' or mode == 'manual':
                break

        # --- 3. Aggregate Results and Calculate SRT Settings ---
        valid_rtts = [r['rtt'] for r in all_results_raw if r.get('rtt') is not None]

        # Separate successful UDP and TCP results
        successful_udp_results = [r['iperf'] for r in all_results_raw if isinstance(r.get('iperf'), dict) and not r['iperf'].get('error') and r['iperf'].get('type') == 'UDP']
        successful_tcp_results = [r['iperf'] for r in all_results_raw if isinstance(r.get('iperf'), dict) and not r['iperf'].get('error') and r['iperf'].get('type') == 'TCP']
        # Collect any iperf errors (excluding 'Ping failed' as RTT check handles that)
        iperf_errors = [r['iperf'].get('error') for r in all_results_raw if isinstance(r.get('iperf'), dict) and r['iperf'].get('error') and r['iperf'].get('error') != 'Ping failed']

        # Check if any ping tests were successful
        if not valid_rtts:
            ping_error_msg = "Ping tests failed for all selected servers."
            if iperf_errors: ping_error_msg += f" iperf errors: {'; '.join(iperf_errors)}"
            return self.get_fallback_results(ping_error_msg)

        # Calculate average RTT from successful pings
        avg_rtt = sum(valid_rtts) / len(valid_rtts)

        # Initialize aggregate metrics
        aggregate_loss = None
        aggregate_jitter = None
        aggregate_bandwidth = None
        bandwidth_type = None # To indicate if measured BW is TCP or UDP
        srt_settings = None
        final_status_message = None # To add informational messages (e.g., assumed loss)

        # --- Determine final metrics based on available iperf results ---
        if successful_udp_results: # Prioritize UDP results if available (only from manual UDP)
            losses = [float(p['loss_percent']) for p in successful_udp_results if p.get('loss_percent') is not None]
            jitters = [float(p['jitter_ms']) for p in successful_udp_results if p.get('jitter_ms') is not None]
            bandwidths = [float(p['bandwidth_mbps']) for p in successful_udp_results if p.get('bandwidth_mbps') is not None]

            # Use max loss found across tests (if multiple regional tests ran)
            aggregate_loss = max(losses) if losses else 0.0 # Default to 0 loss if UDP ran but reported none
            aggregate_jitter = sum(jitters) / len(jitters) if jitters else None
            aggregate_bandwidth = sum(bandwidths) / len(bandwidths) if bandwidths else None
            bandwidth_type = 'UDP'

            # Calculate SRT settings using measured UDP loss
            srt_settings = self.calculate_srt_settings(avg_rtt, aggregate_loss)
            logger.info(f"Using UDP results for SRT calculation (Loss={aggregate_loss:.2f}%).")

        elif successful_tcp_results: # Fallback to TCP results if no UDP results (auto modes or manual TCP)
            bandwidths = [float(p['bandwidth_mbps']) for p in successful_tcp_results if p.get('bandwidth_mbps') is not None]
            aggregate_bandwidth = sum(bandwidths) / len(bandwidths) if bandwidths else None
            bandwidth_type = 'TCP'

            # Cannot get loss/jitter from TCP, so use assumed loss for SRT calculation
            aggregate_loss = ASSUMED_LOSS_FOR_TCP_FALLBACK # Use the predefined assumed loss
            aggregate_jitter = None # Jitter not available from TCP
            srt_settings = self.calculate_srt_settings(avg_rtt, aggregate_loss)
            logger.warning(f"No valid UDP results. Using TCP results (Avg BW: {aggregate_bandwidth} Mbps) and assumed {aggregate_loss}% loss for SRT calculation.")
            final_status_message = f"SRT settings estimated (Used TCP test, assumed {aggregate_loss}% loss)"

        else: # No successful UDP or TCP tests, only ping worked
            first_error = iperf_errors[0] if iperf_errors else "iperf3 tests failed or were skipped"
            error_msg = f"iperf3 failed: {first_error} (Avg RTT: {avg_rtt:.1f}ms)"
            logger.warning(error_msg + ". Only RTT available for SRT calculation.")

            # Use assumed loss for SRT calculation based only on RTT
            aggregate_loss = ASSUMED_LOSS_FOR_TCP_FALLBACK
            aggregate_jitter = None
            aggregate_bandwidth = None
            bandwidth_type = None
            srt_settings = self.calculate_srt_settings(avg_rtt, aggregate_loss)
            final_status_message = f"iperf3 failed. SRT settings estimated (Used RTT only, assumed {aggregate_loss}% loss)"

        # Determine location display string for the results
        server_location_display = "N/A"
        if mode == 'closest' and best_rtt_server_info:
            server_location_display = f"{best_rtt_server_info.get('site', 'N/A')}, {best_rtt_server_info.get('country', 'N/A')}"
        elif mode == 'manual': server_location_display = "Manual Input"
        elif mode == 'regional':
            # If multiple servers tested, just show region. If only one, show its site/country.
            sites = list(set(s.get('site', 'N/A') for s in target_servers_to_test))
            countries = list(set(s.get('country', 'N/A') for s in target_servers_to_test))
            if len(target_servers_to_test) == 1:
                 server_location_display = f"{sites[0]}, {countries[0]}"
            else:
                 server_location_display = f"{region} (Multiple Servers)"

        # --- 4. Format final result dictionary ---
        final_result = {
            'server': test_target_label, # Display label showing mode/target(s)
            'server_location': server_location_display,
            'rtt_ms': avg_rtt,
            'loss_percent': aggregate_loss, # Will be the assumed loss if only TCP/Ping worked
            'jitter_ms': aggregate_jitter, # Will be None if only TCP/Ping worked
            'bandwidth_mbps': f"{aggregate_bandwidth:.2f}" if aggregate_bandwidth is not None else None,
            'bandwidth_type': bandwidth_type, # 'TCP' or 'UDP' or None
            'latency_recommendation': srt_settings.get('latency_ms') if srt_settings else None,
            'overhead_recommendation': srt_settings.get('overhead_percent') if srt_settings else None,
            'rtt_multiplier': srt_settings.get('rtt_multiplier') if srt_settings else None,
            'test_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'error': final_status_message # Null if UDP worked, info message if TCP/Ping fallback used, or error message from get_fallback_results
        }
        return final_result
