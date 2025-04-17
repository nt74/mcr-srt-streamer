# /opt/mcr-srt-streamer/app/utils.py

import psutil
import os
import pwd
import socket
import subprocess
import requests
from datetime import datetime, timedelta
import logging
import time
import json
from typing import Tuple, Dict, Any, Optional, List, Union

logger = logging.getLogger(__name__)

# --- Constants ---
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
EXTERNAL_IP_FILE = os.path.join(DATA_DIR, "external_ip.txt")
EXTERNAL_IP_CACHE_FILE = os.path.join(DATA_DIR, "external_ip_cache.json")
GEOIP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,continentCode,continent,countryCode,country,query"

os.makedirs(DATA_DIR, exist_ok=True)


def format_size(bytes_value, suffix="B"):
    if bytes_value is None:
        return "N/A"
    try:
        bytes_value = float(bytes_value)
        for unit in ["", "K", "M", "G", "T", "P", "E", "Z"]:
            if abs(bytes_value) < 1024.0:
                precision = 1 if unit else 0
                return f"{bytes_value:.{precision}f} {unit}{suffix}"
            bytes_value /= 1024.0
        precision = 1
        return f"{bytes_value:.{precision}f} Y{suffix}"
    except (ValueError, TypeError) as e:
        logger.error(f"Error formatting size '{bytes_value}': {e}")
        return "N/A"


def _is_valid_ip(ip_str):
    if not ip_str:
        return False
    parts = ip_str.split(".")
    if len(parts) != 4:
        return ":" in ip_str
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def _load_cached_ip():
    cache_ttl = 3600
    try:
        if os.path.exists(EXTERNAL_IP_CACHE_FILE):
            with open(EXTERNAL_IP_CACHE_FILE, "r") as f:
                cache = json.load(f)
            if time.time() - cache.get("timestamp", 0) < cache_ttl:
                ip = cache.get("ip")
                if ip and _is_valid_ip(ip):
                    return ip
        if os.path.exists(EXTERNAL_IP_FILE):
            file_age = time.time() - os.path.getmtime(EXTERNAL_IP_FILE)
            if file_age < cache_ttl:
                with open(EXTERNAL_IP_FILE, "r") as f:
                    ip = f.read().strip()
                if ip and _is_valid_ip(ip):
                    _cache_ip(ip)
                    return ip
    except Exception as e:
        logger.warning(f"Failed to read cached IP: {e}")
    return None


def _cache_ip(ip):
    try:
        cache_data = {"ip": ip, "timestamp": time.time()}
        os.makedirs(os.path.dirname(EXTERNAL_IP_CACHE_FILE), exist_ok=True)
        with open(EXTERNAL_IP_CACHE_FILE, "w") as f:
            json.dump(cache_data, f)
        os.makedirs(os.path.dirname(EXTERNAL_IP_FILE), exist_ok=True)
        with open(EXTERNAL_IP_FILE, "w") as f:
            f.write(ip)
    except Exception as e:
        logger.warning(f"Couldn't write IP to cache: {e}")


def _try_command_line_methods():
    methods = [
        "dig +short myip.opendns.com @resolver1.opendns.com",
        "curl -s --max-time 4 ifconfig.me",
        "curl -s --max-time 4 icanhazip.com",
        "curl -s --max-time 4 ipinfo.io/ip",
    ]
    for cmd in methods:
        try:
            result = subprocess.run(
                cmd, shell=True, check=True, capture_output=True, text=True, timeout=5
            )
            ip = result.stdout.strip()
            if ip and _is_valid_ip(ip):
                return ip
        except Exception as e:
            logger.debug(f"Command {cmd} failed: {e}")
            continue
    return None


# --- get_network_interfaces ---
def get_network_interfaces() -> Tuple[Optional[List[str]], Optional[str]]:
    logger_if = logging.getLogger(__name__)
    active_interfaces = []
    try:
        if psutil is None:
            raise ImportError("psutil library is required but not found.")
        if_stats = psutil.net_if_stats()
        if not if_stats:
            err_msg = "psutil could not retrieve network interface stats."
            logger_if.warning(err_msg)
            return None, err_msg
        for name, stats in if_stats.items():
            if stats.isup and "lo" not in name.lower():
                active_interfaces.append(name)
        sorted_interfaces = sorted(active_interfaces)
        # Log at DEBUG level now
        logger_if.debug(
            f"Detected active (UP, non-loopback) network interfaces: {sorted_interfaces}"
        )
        return sorted_interfaces, None  # Success
    except ImportError as e:
        err_msg = f"psutil library not found: {e}. Cannot detect network interfaces."
        logger_if.error(err_msg)
        return None, err_msg
    except Exception as e:
        err_msg = f"Error detecting network interfaces: {e}"
        logger_if.error(err_msg, exc_info=True)
        return None, err_msg


# --- get_external_ip ---
def get_external_ip() -> Tuple[Optional[str], Optional[str]]:
    cached_ip = _load_cached_ip()
    if cached_ip:
        return cached_ip, None
    ip = None
    services = [
        "https://api.ipify.org",
        "https://ipinfo.io/ip",
        "https://icanhazip.com",
        "https://ifconfig.me/ip",
        "https://checkip.amazonaws.com",
    ]
    last_service_error = None
    for service in services:
        try:
            # Log at DEBUG level
            logger.debug(f"Trying to fetch external IP from {service}")
            response = requests.get(service, timeout=10)
            if response.status_code == 200:
                ip_candidate = response.text.strip()
                if _is_valid_ip(ip_candidate):
                    ip = ip_candidate
                    _cache_ip(ip)
                    return ip, None
                else:
                    logger.warning(
                        f"Service {service} returned invalid IP format: {ip_candidate}"
                    )
                    last_service_error = f"Invalid format from {service}"
            else:
                logger.warning(
                    f"Service {service} failed with status: {response.status_code}"
                )
                last_service_error = f"Service {service} status {response.status_code}"
        except Exception as e:
            last_service_error = f"Failed fetching from {service}: {e}"
            logger.warning(last_service_error)
            continue
    if not ip:
        ip = _try_command_line_methods()
        if ip:
            _cache_ip(ip)
            return ip, None
        else:
            last_service_error = last_service_error or "All command line methods failed"
    err_msg = f"Could not determine external IP. Last error: {last_service_error}"
    logger.error(err_msg)
    if cached_ip:
        return cached_ip, err_msg
    else:
        return None, err_msg


# --- get_external_ip_and_location ---
def get_external_ip_and_location() -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    ip_address, ip_error = get_external_ip()
    if not ip_address:
        return None, ip_error or "Failed to get external IP (unknown reason)."
    api_url = GEOIP_API_URL.format(ip=ip_address)
    # Log lookup attempt at DEBUG level
    logger.debug(f"Looking up GeoIP for {ip_address} via {api_url}")
    try:
        response = requests.get(api_url, timeout=10)
        response.raise_for_status()
        data = response.json()
        if data.get("status") == "success":
            location_info = {
                "ip": data.get("query", ip_address),
                "continent": data.get("continent"),
                "continentCode": data.get("continentCode"),
                "country": data.get("country"),
                "countryCode": data.get("countryCode"),
            }
            # *** CHANGED Log Level Here ***
            logger.debug(f"GeoIP Result: {location_info}")
            return location_info, ip_error
        else:
            api_msg = data.get("message", "API Error")
            logger.warning(f"GeoIP API Error for {ip_address}: {api_msg}")
            return None, f"GeoIP API Error: {api_msg}"
    except requests.exceptions.Timeout:
        geoip_err = "GeoIP API Timeout"
        logger.error(f"{geoip_err} for IP {ip_address}")
        return None, geoip_err
    except requests.exceptions.RequestException as e:
        geoip_err = f"GeoIP Network Error: {e}"
        logger.error(f"GeoIP API error for IP {ip_address}: {e}")
        return None, geoip_err
    except json.JSONDecodeError as e:
        geoip_err = "Invalid GeoIP Response"
        logger.error(f"GeoIP decoding error for IP {ip_address}: {e}")
        return None, geoip_err
    except Exception as e:
        geoip_err = f"GeoIP Internal Error: {e}"
        logger.error(f"GeoIP lookup error for IP {ip_address}: {e}", exc_info=True)
        return None, geoip_err


# --- get_system_info ---
def get_system_info():
    location_data, location_error = get_external_ip_and_location()
    external_ip = (
        location_data.get("ip", "unknown") if location_data else "error fetching IP"
    )
    if location_error:
        logger.warning(
            f"get_system_info: Issue getting location data: {location_error}"
        )
    current_utc = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    try:
        uid = os.geteuid()
        current_user = pwd.getpwuid(uid).pw_name
    except Exception as e:
        logger.warning(f"Could not determine current user: {e}")
        current_user = "unknown"
    try:
        cpu_usage = round(psutil.cpu_percent(interval=0.1))
    except Exception as e:
        logger.warning(f"Couldn't get CPU usage: {e}")
        cpu_usage = None
    try:
        mem = psutil.virtual_memory()
        memory_total = format_size(mem.total)
        memory_used = format_size(mem.used)
        memory_percent = round(mem.percent)
    except Exception as e:
        logger.warning(f"Couldn't get memory info: {e}")
        memory_total = memory_used = "N/A"
        memory_percent = None
    try:
        disk = psutil.disk_usage("/")
        disk_total = format_size(disk.total)
        disk_used = format_size(disk.used)
        disk_percent = round(disk.percent)
    except Exception as e:
        logger.warning(f"Couldn't get disk info: {e}")
        disk_total = disk_used = "N/A"
        disk_percent = None
    try:
        net_io = psutil.net_io_counters()
        net_info = {
            "bytes_sent": format_size(net_io.bytes_sent),
            "bytes_recv": format_size(net_io.bytes_recv),
            "packets_sent": net_io.packets_sent,
            "packets_recv": net_io.packets_recv,
        }
    except Exception as e:
        logger.warning(f"Couldn't get network info: {e}")
        net_info = {}
    try:
        boot_time_timestamp = psutil.boot_time()
        uptime_seconds = time.time() - boot_time_timestamp
        uptime_delta = timedelta(seconds=uptime_seconds)
        days = uptime_delta.days
        seconds = uptime_delta.seconds
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        parts = []
        days > 0 and parts.append(f"{days}d")
        hours > 0 and parts.append(f"{hours}h")
        minutes > 0 and parts.append(f"{minutes}m")
        (not parts or seconds >= 0) and parts.append(f"{int(seconds)}s")
        uptime = " ".join(parts) if parts else "0s"
    except Exception as e:
        logger.warning(f"Couldn't get uptime: {e}")
        uptime = "N/A"

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
        "current_user": current_user,
        "uptime": uptime,
        "network": net_info,
        "location_error": location_error,
    }
    return info


# --- check_disk_space ---
def check_disk_space(path="/", min_gb=5) -> Tuple[Optional[bool], Optional[str]]:
    try:
        stat = psutil.disk_usage(path)
        free_gb = stat.free / (1024**3)
        is_ok = free_gb >= min_gb
        return is_ok, None
    except FileNotFoundError:
        err_msg = f"Path not found for disk space check: {path}"
        logger.error(err_msg)
        return None, err_msg
    except Exception as e:
        err_msg = f"Error checking disk space for path '{path}': {e}"
        logger.error(err_msg, exc_info=True)
        return None, err_msg


# --- get_system_load ---
def get_system_load() -> Tuple[Optional[Dict[str, float]], Optional[str]]:
    try:
        if hasattr(os, "getloadavg"):
            load_avg = os.getloadavg()
            load_dict = {
                "1min": round(load_avg[0], 2),
                "5min": round(load_avg[1], 2),
                "15min": round(load_avg[2], 2),
            }
            return load_dict, None
        else:
            err_msg = "os.getloadavg not available on this system."
            logger.warning(err_msg)
            return None, err_msg
    except Exception as e:
        err_msg = f"Error getting system load: {e}"
        logger.error(err_msg, exc_info=True)
        return None, err_msg
