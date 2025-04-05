# /opt/mcr-srt-streamer/app/utils.py
# Restored structure from 'old' version provided by user.
# Integrated dynamic user lookup (os/pwd) from newer version.
# Removed unused get_current_username function.
# Corrected AF_INET reference in get_network_interfaces.
# Modified get_network_interfaces to include UP interfaces even without IPv4. <-- Key Change!

import psutil
import os
import pwd  # Import pwd for user lookup
import socket # Import socket for AF_INET
import subprocess
import requests
from datetime import datetime, timedelta # timedelta needed for uptime formatting
import logging
import time
import json

logger = logging.getLogger(__name__)

# Define paths for external IP cache
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
EXTERNAL_IP_FILE = os.path.join(DATA_DIR, 'external_ip.txt') # Kept from old version
EXTERNAL_IP_CACHE_FILE = os.path.join(DATA_DIR, 'external_ip_cache.json') # Kept from old version

# Ensure data directory exists
os.makedirs(DATA_DIR, exist_ok=True)

def format_size(bytes_value, suffix="B"):
    """Format bytes to human-readable format"""
    # Restored from old version
    if bytes_value is None: return "N/A" # Handle None input
    try:
         bytes_value = float(bytes_value)
         for unit in ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']:
             if abs(bytes_value) < 1024.0:
                 # Format with 1 decimal place for non-Bytes values
                 precision = 1 if unit else 0
                 return f"{bytes_value:.{precision}f} {unit}{suffix}"
             bytes_value /= 1024.0
         precision = 1 # Ensure YB has precision too
         return f"{bytes_value:.{precision}f} Y{suffix}"
    except (ValueError, TypeError) as e:
         logger.error(f"Error formatting size '{bytes_value}': {e}")
         return "N/A"

# --- Network Interface Detection (Removed IPv4 filter) ---
def get_network_interfaces():
    """
    Retrieves a list of active, non-loopback network interface names.
    """
    logger_if = logging.getLogger(__name__)
    active_interfaces = []
    try:
        if_stats = psutil.net_if_stats()
        # No longer need if_addrs just to check for IPv4
        if not if_stats:
             logger_if.warning("psutil could not retrieve network interface stats.")
             return []

        for name, stats in if_stats.items():
            # Check if UP and not loopback
            if stats.isup and 'lo' not in name.lower():
                 # *** REMOVED check for has_ipv4 ***
                 active_interfaces.append(name)

        logger_if.info(f"Detected active (UP, non-loopback) network interfaces: {active_interfaces}")
        return sorted(active_interfaces)

    except ImportError:
         logger_if.error("psutil library not found. Cannot detect network interfaces.")
         return []
    except Exception as e:
        logger_if.error(f"Error detecting network interfaces: {e}", exc_info=True)
        return []
# --- END Network Interface Detection ---

def get_external_ip():
    """Get external IP address with enhanced caching and multiple fallback methods"""
    # Restored from old version
    cached_ip = _load_cached_ip()
    if cached_ip:
        return cached_ip

    ip = "unknown"
    services = [
        "https://api.ipify.org",
        "https://ipinfo.io/ip",
        "https://icanhazip.com",
        "https://ifconfig.me/ip",
        "https://checkip.amazonaws.com"
    ]

    for service in services:
        try:
            logger.info(f"Trying to fetch external IP from {service}")
            response = requests.get(service, timeout=5)
            if response.status_code == 200:
                ip = response.text.strip()
                if _is_valid_ip(ip):
                    _cache_ip(ip)
                    return ip
        except Exception as e:
            logger.warning(f"Failed to fetch IP from {service}: {e}")
            continue

    ip = _try_command_line_methods()
    if ip != "unknown":
        _cache_ip(ip)
        return ip

    return cached_ip or ip # Return expired cache if all else fails

def _is_valid_ip(ip_str):
    """Basic validation of IP address format"""
    # Restored from old version
    if not ip_str:
        return False
    parts = ip_str.split('.')
    if len(parts) != 4:
        # Basic check for IPv6 might be needed if services return that
        return ':' in ip_str # Very basic IPv6 check
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False

def _load_cached_ip():
    """Load cached IP address if recent enough"""
    # Restored from old version
    cache_ttl = 3600 # 1 hour
    try:
        # Try JSON cache first
        if os.path.exists(EXTERNAL_IP_CACHE_FILE):
            with open(EXTERNAL_IP_CACHE_FILE, 'r') as f:
                cache = json.load(f)
                if time.time() - cache.get('timestamp', 0) < cache_ttl:
                    ip = cache.get('ip')
                    if ip and _is_valid_ip(ip): return ip

        # Fallback to plain text file
        if os.path.exists(EXTERNAL_IP_FILE):
            file_age = time.time() - os.path.getmtime(EXTERNAL_IP_FILE)
            if file_age < cache_ttl:
                with open(EXTERNAL_IP_FILE, 'r') as f:
                    ip = f.read().strip()
                    if ip and _is_valid_ip(ip):
                        # Update JSON cache if using old text file
                        _cache_ip(ip)
                        return ip
    except Exception as e:
        logger.warning(f"Failed to read cached IP: {e}")
    return None

def _cache_ip(ip):
    """Cache the IP address with timestamp"""
    # Restored from old version
    try:
        cache_data = { 'ip': ip, 'timestamp': time.time() }
        os.makedirs(os.path.dirname(EXTERNAL_IP_CACHE_FILE), exist_ok=True) # Ensure dir exists
        with open(EXTERNAL_IP_CACHE_FILE, 'w') as f: json.dump(cache_data, f)
        # Also save to plain text file for backward compatibility or simple access
        os.makedirs(os.path.dirname(EXTERNAL_IP_FILE), exist_ok=True) # Ensure dir exists
        with open(EXTERNAL_IP_FILE, 'w') as f: f.write(ip)
    except Exception as e:
        logger.warning(f"Couldn't write IP to cache: {e}")

def _try_command_line_methods():
    """Try various command line methods to get external IP"""
    # Restored from old version
    methods = [
        "dig +short myip.opendns.com @resolver1.opendns.com",
        "curl -s --max-time 4 ifconfig.me",
        "curl -s --max-time 4 icanhazip.com",
        "curl -s --max-time 4 ipinfo.io/ip"
    ]
    for cmd in methods:
        try:
            result = subprocess.run( cmd, shell=True, check=True, capture_output=True, text=True, timeout=5 )
            ip = result.stdout.strip()
            if ip and _is_valid_ip(ip): return ip
        except Exception as e: logger.debug(f"Command {cmd} failed: {e}"); continue
    return "unknown"

def get_system_info():
    """Get comprehensive system information"""
    # Based on old version, but with dynamic user lookup integrated

    external_ip = get_external_ip()
    current_utc = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    # --- Get Actual Running User (integrated from newer version) ---
    try:
        uid = os.geteuid()
        current_user = pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError, AttributeError, OSError) as e:
        logger.warning(f"Could not determine current user via pwd: {e}. Falling back...")
        try: current_user = os.getlogin()
        except Exception: current_user = "unknown"
    # --- End User Lookup ---

    try: cpu_usage = round(psutil.cpu_percent(interval=0.1)) # Use short interval
    except Exception as e: logger.warning(f"Couldn't get CPU usage: {e}"); cpu_usage = 0

    try:
        mem = psutil.virtual_memory()
        memory_total = format_size(mem.total)
        memory_used = format_size(mem.used)
        memory_percent = round(mem.percent)
    except Exception as e: logger.warning(f"Couldn't get memory info: {e}"); memory_total = memory_used = "N/A"; memory_percent = 0

    try:
        disk = psutil.disk_usage("/")
        disk_total = format_size(disk.total)
        disk_used = format_size(disk.used)
        disk_percent = round(disk.percent)
    except Exception as e: logger.warning(f"Couldn't get disk info: {e}"); disk_total = disk_used = "N/A"; disk_percent = 0

    # Get network information (IO counters - from old version)
    try:
        net_io = psutil.net_io_counters()
        net_info = {
            'bytes_sent': format_size(net_io.bytes_sent),
            'bytes_recv': format_size(net_io.bytes_recv),
            'packets_sent': net_io.packets_sent, # Keep as number
            'packets_recv': net_io.packets_recv  # Keep as number
        }
    except Exception as e: logger.warning(f"Couldn't get network info: {e}"); net_info = {}

    # Get system uptime (using timedelta from newer version's logic)
    try:
        boot_time_timestamp = psutil.boot_time()
        uptime_seconds = time.time() - boot_time_timestamp
        uptime_delta = timedelta(seconds=uptime_seconds)
        days = uptime_delta.days
        seconds = uptime_delta.seconds
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        parts = []
        if days > 0: parts.append(f"{days}d")
        if hours > 0: parts.append(f"{hours}h")
        if minutes > 0: parts.append(f"{minutes}m")
        if not parts or seconds >= 0 : parts.append(f"{int(seconds)}s") # Ensure seconds show even if 0
        uptime = " ".join(parts) if parts else "0s"
    except Exception as e: logger.warning(f"Couldn't get uptime: {e}"); uptime = "N/A"

    # Compile all information
    info = {
        "cpu_usage": cpu_usage,
        "memory_total": memory_total,
        "memory_used": memory_used,
        "memory_percent": memory_percent,
        "disk_total": disk_total,
        "disk_used": disk_used,
        "disk_percent": disk_percent,
        "external_ip": external_ip,
        "utc_time": current_utc,
        "current_user": current_user, # Now dynamically determined
        "uptime": uptime,
        "network": net_info
    }
    return info

def check_disk_space(path="/", min_gb=5):
    """Check if there's enough disk space available"""
    # Restored from old version
    try:
        stat = psutil.disk_usage(path)
        free_gb = stat.free / (1024 ** 3)
        return free_gb >= min_gb
    except Exception as e: logger.error(f"Error checking disk space: {e}"); return False

def get_system_load():
    """Get system load averages"""
    # Restored from old version
    try:
        # os.getloadavg() is POSIX specific
        if hasattr(os, 'getloadavg'):
             load_avg = os.getloadavg()
             return { "1min": round(load_avg[0], 2), "5min": round(load_avg[1], 2), "15min": round(load_avg[2], 2) }
        else:
             logger.warning("os.getloadavg not available on this system.")
             return None # Indicate unavailability
    except Exception as e: logger.error(f"Error getting system load: {e}"); return None
