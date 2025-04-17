# /opt/mcr-srt-streamer/app/smpte_manager.py

import gi

gi.require_version("Gst", "1.0")
gi.require_version("Gio", "2.0")
from gi.repository import Gst, GLib, GObject, Gio
import threading
import logging
import time
import os
import re
import socket
import json
from datetime import timedelta
from app.utils import get_network_interfaces

COLORBAR_URIS = {"720p50": "udp://224.1.1.1:5004", "1080i25": "udp://224.1.1.1:5005"}
DEFAULT_MULTICAST_INTERFACE = "vlan2"


class SMPTEManager:
    def __init__(self, main_stream_manager_ref=None):
        self.active_pairs = {}
        self.lock = threading.RLock()
        self.logger = logging.getLogger(__name__)
        self.main_stream_manager = main_stream_manager_ref
        self.network_interfaces = self._get_interface_ips()

    def _get_interface_ips(self):
        interfaces = {}
        try:
            import psutil

            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            for name, snics in addrs.items():
                if name == "lo" or not stats.get(name) or not stats[name].isup:
                    continue
                for snic in snics:
                    if snic.family == socket.AF_INET:
                        interfaces[name] = snic.address
                        break
        except ImportError:
            self.logger.warning(
                "psutil not found, cannot automatically determine interface IPs."
            )
        except Exception as e:
            self.logger.error(f"Failed to get interface IPs: {e}")
        return interfaces

    def _extract_ip_from_socket_address(self, addr):
        if addr is None:
            return None
        try:
            if isinstance(addr, Gio.InetSocketAddress):
                inet_addr = addr.get_address()
                return inet_addr.to_string() if inet_addr else None
            elif isinstance(addr, Gio.InetAddress):
                return addr.to_string()
            elif isinstance(addr, Gio.SocketAddress):
                family = addr.get_family()
                if family == Gio.SocketFamily.IPV4 or family == Gio.SocketFamily.IPV6:
                    try:
                        inet_sock_addr = addr.cast(Gio.InetSocketAddress)
                        if inet_sock_addr:
                            inet_addr = inet_sock_addr.get_address()
                            return inet_addr.to_string() if inet_addr else None
                    except TypeError:
                        pass
                addr_str = addr.to_string()
                ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", addr_str)
                return ip_match.group(1) if ip_match else addr_str
            else:
                return str(addr)
        except Exception as e:
            self.logger.error(
                f"Error extracting IP from address object ({type(addr)}): {str(e)}"
            )
            return str(addr)

    def _sanitize_for_json(self, obj):
        if isinstance(obj, (str, int, float, bool, type(None))):
            return obj
        elif isinstance(obj, (list, tuple)):
            return [self._sanitize_for_json(item) for item in obj]
        elif isinstance(obj, dict):
            return {str(k): self._sanitize_for_json(v) for k, v in obj.items()}
        elif isinstance(
            obj, (Gio.SocketAddress, Gio.InetAddress, Gio.InetSocketAddress)
        ):
            return self._extract_ip_from_socket_address(obj)
        elif isinstance(obj, GLib.Error):
            return f"GLib.Error: {obj.message} (domain:{obj.domain}, code:{obj.code})"
        elif isinstance(obj, GObject.GObject):
            try:
                if hasattr(obj, "to_string") and callable(obj.to_string):
                    return obj.to_string()
                elif hasattr(obj, "get_name") and callable(obj.get_name):
                    return f"{type(obj).__name__}(name='{obj.get_name()}')"
            except Exception:
                pass
            return str(obj)
        else:
            try:
                json.dumps(obj)
                return obj  # Check if already serializable
            except TypeError:
                return str(obj)  # Fallback to string representation

    def _build_srt_uri(self, leg_config, shared_config):
        # (Remains the same)
        port = leg_config["port"]
        mode = leg_config["mode"]
        srt_params = [
            f"mode={mode}",
            "transtype=live",
            f"latency={shared_config['latency']}",
            f"peerlatency={shared_config['latency']}",
            "rcvbuf=8388608",
            "sndbuf=8388608",
            "fc=8192",
            "tlpktdrop=true",
            "nakreport=true",
            f"overheadbandwidth={shared_config['overhead_bandwidth']}",
            f"streamid=smpte_pair_{shared_config.get('pair_id', 'unknown')}_leg{leg_config['leg_num']}",
            f"smoother=live",
            f"qos={'true' if shared_config.get('qos', False) else 'false'}",
        ]
        encryption = shared_config.get("encryption", "none")
        if encryption != "none":
            passphrase = shared_config.get("passphrase", "")
            if passphrase:
                pbkeylen = 16 if encryption == "aes-128" else 32
                srt_params.extend([f"passphrase={passphrase}", f"pbkeylen={pbkeylen}"])
            else:
                self.logger.warning(
                    f"Encryption '{encryption}' requested for pair {shared_config.get('pair_id', 'unknown')} but no passphrase provided."
                )
        uri_base = ""
        interface_name = leg_config.get("output_interface")
        interface_ip = (
            self.network_interfaces.get(interface_name) if interface_name else None
        )
        if mode == "listener":
            bind_address = interface_ip if interface_ip else "0.0.0.0"
            uri_base = f"srt://{bind_address}:{port}"
        elif mode == "caller":
            target_addr = leg_config.get("target_address")
            target_port = port
            if not target_addr:
                raise ValueError(
                    f"Missing target address for caller leg {leg_config['leg_num']}"
                )
            uri_base = f"srt://{target_addr}:{target_port}"
            if interface_ip:
                srt_params.append(f"adapter={interface_ip}")
        return f"{uri_base}?{'&'.join(srt_params)}"

    def start_smpte_stream_pair(self, config):
        pair_id = min(config["port_1"], config["port_2"])
        config["pair_id"] = pair_id
        pipeline = None
        pipeline_str = ""
        try:
            with self.lock:
                if pair_id in self.active_pairs:
                    self.stop_smpte_stream_pair(str(pair_id), force_remove=True)
                    time.sleep(0.5)
            input_type = config["input_type"]
            input_pipeline_part = ""
            input_detail_log = "N/A"
            if input_type == "multicast":
                mc_address = config.get("multicast_address")
                mc_port = config.get("multicast_port")
                mc_interface = (
                    config.get("multicast_interface") or DEFAULT_MULTICAST_INTERFACE
                )
                if not mc_address or not mc_port:
                    raise ValueError("Missing multicast address or port.")
                input_pipeline_part = f'udpsrc uri="udp://{mc_address}:{mc_port}" multicast-iface="{mc_interface}" buffer-size=20971520 caps="video/mpegts, systemstream=(boolean)true, packetsize=(int)188"'
                input_detail_log = f"udp://{mc_address}:{mc_port} via {mc_interface}"
            elif input_type.startswith("colorbar_"):
                resolution = config.get("colorbar_resolution")
                udp_uri = COLORBAR_URIS.get(resolution)
                if not udp_uri:
                    raise ValueError(f"Invalid colorbar resolution: {resolution}")
                if (
                    self.main_stream_manager
                    and not self.main_stream_manager._start_generator_if_needed(
                        resolution
                    )
                ):
                    raise RuntimeError(f"Failed to start generator for {resolution}")
                elif not self.main_stream_manager:
                    self.logger.warning(
                        "Main Stream Manager ref not available, cannot ensure colorbar generator is running."
                    )
                input_pipeline_part = f'udpsrc uri="{udp_uri}" buffer-size=20971520 caps="video/mpegts, systemstream=(boolean)true, packetsize=(int)188"'
                input_detail_log = f"Colorbars {resolution.upper()}"
            else:
                raise ValueError(f"Unsupported input_type: {input_type}")
            tsparse_name = f"tsparse_smpte_{pair_id}"
            smoothing_choice = config.get("smoothing_latency_ms", 30)
            try:
                smoothing_latency_us = int(smoothing_choice) * 1000
            except (ValueError, TypeError):
                smoothing_latency_us = 30000
                self.logger.warning(
                    f"Invalid smoothing latency '{smoothing_choice}', using default 30ms."
                )
            tsparse_part = f'tsparse name="{tsparse_name}" set-timestamps=true alignment=7 smoothing-latency={smoothing_latency_us} parse-private-sections=true'
            try:
                ssrc_int = int(config["ssrc"], 16)
                ssrc_str = f"{ssrc_int}"
                ssrc_property_val = f"ssrc={ssrc_str}"
            except ValueError:
                raise ValueError(f"Invalid SSRC format: {config['ssrc']}")
            rtp_part = f"rtpmp2tpay pt=33 mtu=1316 {ssrc_property_val}"
            tee_part = "tee name=t"
            uri_1 = self._build_srt_uri(
                {
                    "leg_num": 1,
                    "port": config["port_1"],
                    "mode": config["mode_1"],
                    "output_interface": config.get("output_interface_1"),
                    "target_address": config.get("target_address_1"),
                },
                config,
            )
            uri_2 = self._build_srt_uri(
                {
                    "leg_num": 2,
                    "port": config["port_2"],
                    "mode": config["mode_2"],
                    "output_interface": config.get("output_interface_2"),
                    "target_address": config.get("target_address_2"),
                },
                config,
            )
            sink_1_name = f"srtsink_smpte_{pair_id}_1"
            sink_2_name = f"srtsink_smpte_{pair_id}_2"
            sink_common_params = "async=false sync=false wait-for-connection=false"
            pipeline_str = f'{input_pipeline_part} ! queue ! {tsparse_part} ! queue ! {rtp_part} ! {tee_part} t. ! queue ! srtsink name="{sink_1_name}" uri="{uri_1}" {sink_common_params} t. ! queue ! srtsink name="{sink_2_name}" uri="{uri_2}" {sink_common_params}'
            pipeline_str = " ".join(pipeline_str.split())
            self.logger.debug(
                f"Constructed SMPTE pipeline string {pair_id}: {pipeline_str}"
            )
            try:
                pipeline = Gst.parse_launch(pipeline_str)
            except GLib.Error as e:
                self.logger.error(f"SMPTE Parse error {pair_id}: {str(e)}")
                return False, f"Parse error: {str(e)}"
            if not pipeline:
                raise RuntimeError(f"Gst.parse_launch returned None for {pair_id}.")
            bus = pipeline.get_bus()
            bus.add_signal_watch()
            pair_info = {
                "pipeline": pipeline,
                "bus": bus,
                "config": config,
                "pair_id": pair_id,
                "status": "Starting",
                "start_time": time.time(),
                "input_detail": input_detail_log,
            }
            with self.lock:
                self.active_pairs[pair_id] = pair_info
            ret = pipeline.set_state(Gst.State.PLAYING)
            if ret == Gst.StateChangeReturn.FAILURE:
                pair_info["status"] = "Start Error"
                self.logger.error(f"Failed PLAYING {pair_id}")
                return False, f"Failed start {pair_id}."
            elif ret == Gst.StateChangeReturn.ASYNC:
                pair_info["status"] = "Starting (Async)"
                self.logger.info(f"SMPTE {pair_id} starting async...")
            else:
                pair_info["status"] = "Running"
                self.logger.info(f"SMPTE {pair_id} started (State: {ret}).")
            return True, f"SMPTE Pair {pair_id} ({input_detail_log}) starting."
        except (ValueError, FileNotFoundError, RuntimeError) as e:
            self.logger.error(f"Start error {pair_id}: {e}")
            return False, f"Start error: {e}"
        except Exception as e:
            self.logger.error(f"Unexpected start error {pair_id}: {e}", exc_info=True)
            return False, f"Unexpected start error: {e}"

    def stop_smpte_stream_pair(self, pair_id_str, force_remove=False):
        try:
            pair_id = int(pair_id_str)
            assert pair_id > 0
        except (ValueError, AssertionError):
            return False, "Invalid Pair ID format."
        pipeline_to_stop = None
        bus_to_clear = None
        with self.lock:
            if pair_id not in self.active_pairs:
                return False, f"SMPTE Pair {pair_id} not found."
            self.logger.info(f"Attempting to stop SMPTE Pair: {pair_id}")
            pair_info = self.active_pairs.pop(pair_id)
            pipeline_to_stop = pair_info.get("pipeline")
            bus_to_clear = pair_info.get("bus")
        if pipeline_to_stop:
            if bus_to_clear:
                try:
                    bus_to_clear.remove_signal_watch()
                except Exception as bus_e:
                    self.logger.warning(
                        f"Error removing signal watch {pair_id}: {bus_e}"
                    )
            self.logger.info(f"Scheduling NULL state for {pair_id}.")

            def set_null_safe(p, k):
                ret = p.set_state(Gst.State.NULL)
                self.logger.info(f"Async set_state(NULL) for {k} returned: {ret}")

            GLib.idle_add(
                set_null_safe, pipeline_to_stop, pair_id, priority=GLib.PRIORITY_DEFAULT
            )
            return True, f"SMPTE Pair {pair_id} stop initiated."
        else:
            return False, f"SMPTE Pair {pair_id} active but pipeline missing."

    def get_active_smpte_pairs(self):
        pairs_data = {}
        now = time.time()
        with self.lock:
            for pair_id, pair_info in self.active_pairs.items():
                config = pair_info.get("config", {})
                status = pair_info.get("status", "Unknown")
                start_time = pair_info.get("start_time", now)
                input_detail = pair_info.get("input_detail", "N/A")
                pairs_data[pair_id] = {
                    "pair_id": pair_id,
                    "status": status,
                    "uptime": self._format_uptime(now - start_time),
                    "start_time_str": time.strftime(
                        "%Y-%m-%d %H:%M:%S UTC", time.gmtime(start_time)
                    ),
                    "input_type": config.get("input_type"),
                    "input_detail": input_detail,
                    "ssrc": config.get("ssrc", "N/A"),
                    "latency": config.get("latency"),
                    "overhead": config.get("overhead_bandwidth"),
                    "encryption": config.get("encryption"),
                    "qos": config.get("qos"),
                    "smoothing_latency_ms": config.get("smoothing_latency_ms"),
                    "leg1": {
                        "port": config.get("port_1"),
                        "mode": config.get("mode_1"),
                        "interface": config.get("output_interface_1") or "Auto",
                        "target": (
                            f"{config.get('target_address_1')}:{config.get('port_1')}"
                            if config.get("mode_1") == "caller"
                            else None
                        ),
                    },
                    "leg2": {
                        "port": config.get("port_2"),
                        "mode": config.get("mode_2"),
                        "interface": config.get("output_interface_2") or "Auto",
                        "target": (
                            f"{config.get('target_address_2')}:{config.get('port_2')}"
                            if config.get("mode_2") == "caller"
                            else None
                        ),
                    },
                }
        return pairs_data

    def _extract_stats_from_gstruct(self, stats_struct):
        result = {}
        raw_stats_string_for_debug = "N/A"
        if not stats_struct or not isinstance(stats_struct, Gst.Structure):
            self.logger.warning(
                "Invalid Gst.Structure passed to _extract_stats_from_gstruct."
            )
            return result
        try:
            raw_stats_string_for_debug = stats_struct.to_string()
            self.logger.debug(
                f"STATS PARSE: Raw Gst.Structure string:\n{raw_stats_string_for_debug}"
            )
            if not raw_stats_string_for_debug:
                self.logger.warning("Gst.Structure.to_string() returned empty string.")
                return result

            def parse_value(value_str, value_type):
                value_type = value_type.lower()
                value_str = value_str.strip()
                if value_str.endswith("\\"):
                    value_str = value_str[:-1]
                is_quoted = value_str.startswith('"') and value_str.endswith('"')
                if is_quoted:
                    value_str_unquoted = (
                        value_str[1:-1].replace('\\"', '"').replace("\\\\", "\\")
                    )
                else:
                    value_str_unquoted = value_str
                if value_str_unquoted == "NULL":
                    return None
                if value_str_unquoted == "TRUE":
                    return True
                if value_str_unquoted == "FALSE":
                    return False
                try:
                    if "int" in value_type:
                        return int(value_str_unquoted)
                    if "double" in value_type or "float" in value_type:
                        return round(float(value_str_unquoted), 2)
                except ValueError:
                    return 0 if "int" in value_type else 0.0
                return value_str_unquoted

            inner_listener_pattern = re.compile(
                r'([a-zA-Z0-9\-]+)\s*\\\=\s*\\\(([^)]+)\\\)\s*("(?:[^"\\]|\\.)*"|[^,]+)'
            )
            top_level_listener_pattern = re.compile(
                r'([a-zA-Z0-9\-]+)\s*=\s*\(([^)]+)\)\s*("(?:[^"\\]|\\.)*"|[^;]+)'
            )
            caller_pattern = re.compile(
                r'([a-zA-Z0-9\-]+)\s*=\s*\(([^)]+)\)\s*("(?:[^"\\]|\\.)*"|[^,;]+)'
            )

            def parse_with_finditer(text_to_parse, target_dict, pattern):
                processed_keys = set(target_dict.keys())
                match_count = 0
                for match in pattern.finditer(text_to_parse):
                    match_count += 1
                    key_raw, value_type, value_part = match.groups()[:3]
                    key = key_raw.replace("-", "_")
                    if key not in processed_keys:
                        parsed_val = parse_value(value_part, value_type)
                        self.logger.debug(
                            f"STATS PARSE: Regex matched Key='{key}', Type='{value_type}', RawValue='{value_part}', ParsedValue='{parsed_val}'"
                        )
                        target_dict[key] = parsed_val
                        processed_keys.add(key)
                if match_count == 0:
                    self.logger.debug(
                        f"STATS PARSE: Pattern {pattern.pattern} found 0 matches in text:\n{text_to_parse}"
                    )

            payload_str = raw_stats_string_for_debug
            if "," in payload_str:
                payload_str = payload_str.split(",", 1)[1]
            payload_str = payload_str.strip(";{} ")
            self.logger.debug(f"STATS PARSE: Payload string for regex:\n{payload_str}")
            if "callers=" in payload_str:
                inner_kv_string = None
                top_level_str = payload_str
                callers_match = re.search(
                    r"callers=\(GValueArray\)<(.*?)>", payload_str, re.DOTALL
                )
                self.logger.debug(
                    f"STATS PARSE: Listener mode detected. Callers match: {'Found' if callers_match else 'Not Found'}"
                )
                if callers_match:
                    callers_content = callers_match.group(1).strip()
                    inner_struct_match = re.match(
                        r'\s*"(?:application/x-srt-statistics\\,)?(.*?)\s*;?"\s*',
                        callers_content,
                        re.DOTALL,
                    )
                    self.logger.debug(
                        f"STATS PARSE: Inner struct match: {'Found' if inner_struct_match else 'Not Found'}"
                    )
                    if inner_struct_match:
                        inner_kv_string = (
                            inner_struct_match.group(1)
                            .replace("\\,", ",")
                            .replace('\\"', '"')
                            .replace("\\\\", "\\")
                            .strip()
                            .lstrip("\\ ")
                        )
                        top_level_str = (
                            payload_str[: callers_match.start()]
                            + payload_str[callers_match.end() :]
                        )
                        top_level_str = top_level_str.strip("; ,")
                        self.logger.debug(
                            f"STATS PARSE: Inner KV String:\n{inner_kv_string}"
                        )
                        self.logger.debug(
                            f"STATS PARSE: Top Level String:\n{top_level_str}"
                        )
                    else:
                        self.logger.warning(
                            f"StatsParse: Could not extract inner stats string from callers: {callers_content[:100]}..."
                        )
                else:
                    self.logger.warning(
                        "StatsParse: Failed to match 'callers=' structure."
                    )
                if inner_kv_string:
                    parse_with_finditer(inner_kv_string, result, inner_listener_pattern)
                parse_with_finditer(top_level_str, result, top_level_listener_pattern)
            else:
                self.logger.debug(
                    "STATS PARSE: Caller mode detected (no 'callers=' found)."
                )
                parse_with_finditer(payload_str, result, caller_pattern)
            self.logger.debug(f"STATS PARSE: Initial parse result dict: {result}")
            final_key_map = {
                "bitrate_mbps": ["send_rate_mbps"],
                "rtt_ms": ["rtt_ms", "link_rtt"],
                "loss_rate": ["pkt_loss_rate"],
                "packets_sent_total": ["pkt_sent_total", "packets_sent"],
                "packets_lost_total": ["pkt_lost_total", "packets_sent_lost"],
                "packets_retransmitted_total": [
                    "pkt_retransmitted_total",
                    "packets_retransmitted",
                ],
                "bytes_sent_total": ["bytes_sent_total"],
                "estimated_bandwidth_mbps": ["bandwidth_mbps", "link_bandwidth"],
                "packets_received_total": ["pkt_received_total", "packets_received"],
                "packets_received_lost": ["packets_received_lost"],
                "packets_received_retransmitted": ["packets_received_retransmitted"],
                "packets_received_dropped": ["packets_received_dropped"],
                "bytes_sent": ["bytes_sent"],
                "bytes_received": ["bytes_received"],
                "bytes_retransmitted": ["bytes_retransmitted"],
                "bytes_sent_dropped": ["bytes_sent_dropped"],
                "bytes_received_lost": ["bytes_received_lost"],
                "packet_ack_received": ["packet_ack_received"],
                "packet_nack_received": ["packet_nack_received"],
                "packet_ack_sent": ["packet_ack_sent"],
                "packet_nack_sent": ["packet_nack_sent"],
                "send_buffer_level_ms": ["snd_buf_ms"],
                "recv_buffer_level_ms": ["rcv_buf_ms"],
                "flow_window": ["flow_wnd", "snd_flow_wnd"],
                "negotiated_latency_ms": ["negotiated_latency_ms"],
            }
            final_result = {
                k: 0.0 if "rate" in k or "mbps" in k else 0 for k in final_key_map
            }
            final_result["packet_loss_percent"] = 0.0
            for final_key, source_keys in final_key_map.items():
                val = None
                for source_key in source_keys:
                    if source_key in result:
                        val = result[source_key]
                        break
                if val is not None:
                    final_result[final_key] = val
                elif final_key not in final_result:
                    final_result[final_key] = (
                        0.0 if "rate" in final_key or "mbps" in final_key else 0
                    )
            sent = final_result.get("packets_sent_total", 0)
            lost = final_result.get("packets_lost_total", 0)
            final_result["packet_loss_percent"] = (
                round((lost / sent) * 100, 2)
                if isinstance(sent, (int, float))
                and isinstance(lost, (int, float))
                and sent > 0
                else 0.0
            )
            for k, v in result.items():
                final_result.setdefault(k, v)
            self.logger.debug(f"STATS PARSE: Final mapped result dict: {final_result}")
            return final_result
        except Exception as e:
            self.logger.error(f"CRITICAL Error parsing SRT stats: {e}", exc_info=True)
            return {
                "error": f"Parse Fail: {e}",
                "raw_string": raw_stats_string_for_debug,
            }

    def get_smpte_pair_statistics(self, pair_id_str):
        stats = {"leg1_stats": None, "leg2_stats": None, "error": None}
        try:
            pair_id = int(pair_id_str)
            with self.lock:
                if pair_id not in self.active_pairs:
                    stats["error"] = f"SMPTE Pair {pair_id} not found."
                    return stats
                pair_info = self.active_pairs[pair_id]
                pipeline = pair_info.get("pipeline")
            if not pipeline:
                stats["error"] = f"Pipeline object missing for pair {pair_id}."
                return stats
            sink_1_name = f"srtsink_smpte_{pair_id}_1"
            sink_2_name = f"srtsink_smpte_{pair_id}_2"
            sink1 = pipeline.get_by_name(sink_1_name)
            sink2 = pipeline.get_by_name(sink_2_name)

            def get_stats_from_sink(sink, leg_num):
                if sink:
                    try:
                        stats_struct = sink.get_property("stats")
                        if stats_struct and isinstance(stats_struct, Gst.Structure):
                            parsed_stats = self._extract_stats_from_gstruct(
                                stats_struct
                            )
                            if "error" in parsed_stats:
                                self.logger.warning(
                                    f"Stats parse error leg {leg_num} pair {pair_id}: {parsed_stats['error']}"
                                )
                                return {
                                    "error": f"Parse error: {parsed_stats['error']}",
                                    "raw": parsed_stats.get("raw_string", "N/A"),
                                }
                            else:
                                return parsed_stats
                        elif stats_struct is None:
                            self.logger.warning(
                                f"'stats' property was None for leg {leg_num} pair {pair_id}"
                            )
                            return {"error": "No stats available (property was None)"}
                        else:
                            self.logger.warning(
                                f"'stats' property is not Gst.Structure for leg {leg_num} pair {pair_id}: {type(stats_struct)}"
                            )
                            return {
                                "error": f"Invalid stats type: {type(stats_struct)}"
                            }
                    except Exception as e:
                        self.logger.error(
                            f"Error getting/parsing 'stats' property leg {leg_num} pair {pair_id}: {e}",
                            exc_info=True,
                        )
                        return {"error": f"Error retrieving/parsing stats: {e}"}
                else:
                    self.logger.warning(
                        f"Sink element not found leg {leg_num} pair {pair_id}"
                    )
                    return {"error": "Sink element not found"}

            stats["leg1_stats"] = get_stats_from_sink(sink1, 1)
            stats["leg2_stats"] = get_stats_from_sink(sink2, 2)
            if (
                isinstance(stats["leg1_stats"], dict)
                and "error" in stats["leg1_stats"]
                and isinstance(stats["leg2_stats"], dict)
                and "error" in stats["leg2_stats"]
            ):
                stats["error"] = "Failed to retrieve stats for both legs."
        except ValueError:
            stats["error"] = "Invalid Pair ID format."
            return stats
        except Exception as e:
            stats["error"] = f"Unexpected error getting stats: {e}"
            self.logger.error(f"Error in get_smpte_pair_statistics: {e}", exc_info=True)
        return stats

    def get_smpte_pair_debug_info(self, pair_id_str):
        debug_info = {"error": None}
        pipeline = None  # Define pipeline outside the lock scope
        pair_info = None
        try:
            pair_id = int(pair_id_str)
            with self.lock:
                if pair_id not in self.active_pairs:
                    debug_info["error"] = f"SMPTE Pair {pair_id} not found."
                    return debug_info  # Return early if not found
                pair_info = self.active_pairs[pair_id]
                pipeline = pair_info.get("pipeline")  # Get pipeline object

            config = pair_info.get("config", {}).copy()
            status = pair_info.get("status", "Unknown")
            start_time = pair_info.get("start_time")
            input_detail = pair_info.get("input_detail", "N/A")

            debug_info["pair_id"] = pair_id
            debug_info["config"] = config
            debug_info["status"] = status
            debug_info["start_time_epoch"] = start_time
            debug_info["input_detail"] = input_detail
            if start_time:
                debug_info["uptime"] = self._format_uptime(time.time() - start_time)

            if pipeline:
                try:
                    ret_st, cur_st, pend_st = pipeline.get_state(
                        Gst.CLOCK_TIME_NONE
                    )  # Use timeout
                    debug_info["pipeline_state"] = (
                        Gst.Element.state_get_name(cur_st)
                        if ret_st != Gst.StateChangeReturn.FAILURE
                        else "Error getting state"
                    )
                except Exception as state_e:
                    self.logger.warning(
                        f"Could not get pipeline state for pair {pair_id}: {state_e}"
                    )
                    debug_info["pipeline_state"] = "Error getting state"
            else:
                debug_info["pipeline_state"] = "Pipeline object not found"

            stats_data = self.get_smpte_pair_statistics(pair_id_str)
            debug_info["stats_error"] = stats_data.get(
                "error"
            )  # Overall error from stats function
            debug_info["parsed_stats_leg1"] = stats_data.get(
                "leg1_stats"
            )  # Contains parsed data or error dict
            debug_info["parsed_stats_leg2"] = stats_data.get(
                "leg2_stats"
            )  # Contains parsed data or error dict

            # Add raw stats string if available from stats_data (if parsing failed)
            if (
                isinstance(stats_data.get("leg1_stats"), dict)
                and "raw" in stats_data["leg1_stats"]
            ):
                debug_info["raw_stats_leg1"] = stats_data["leg1_stats"]["raw"]
            if (
                isinstance(stats_data.get("leg2_stats"), dict)
                and "raw" in stats_data["leg2_stats"]
            ):
                debug_info["raw_stats_leg2"] = stats_data["leg2_stats"]["raw"]

        except ValueError:
            debug_info = {
                "error": "Invalid Pair ID format."
            }  # Reset dict on format error
        except Exception as e:
            debug_info = {
                "error": f"Unexpected error getting debug info: {e}"
            }  # Reset dict on other errors
            self.logger.error(f"Error in get_smpte_pair_debug_info: {e}", exc_info=True)

        # Sanitize final dict before returning using the copied helper
        return self._sanitize_for_json(debug_info)

    def _format_uptime(self, seconds):
        # (Remains the same)
        try:
            return str(timedelta(seconds=int(seconds)))
        except:
            return "N/A"

    def shutdown(self):
        self.logger.info("Shutting down SMPTEManager...")
        with self.lock:
            pair_keys = list(self.active_pairs.keys())
        for pair_id in pair_keys:
            self.stop_smpte_stream_pair(str(pair_id))
        time.sleep(0.5)
        self.logger.info("SMPTEManager shutdown complete.")
