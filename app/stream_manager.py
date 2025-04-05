# /opt/mcr-srt-streamer/app/stream_manager.py

import gi
gi.require_version('Gst', '1.0')
gi.require_version('Gio', '2.0')
from gi.repository import Gst, GLib, GObject, Gio
import threading
import logging
import os
import subprocess
import time
import re
import json
from collections import defaultdict
from app.dvb_config import DVB_STANDARD_CONFIG

# Initialize GStreamer
Gst.init(None)

class StreamManager:
    # --- __init__ ---
    def __init__(self, media_folder):
        self.media_folder = media_folder
        self.active_streams = {}
        self.lock = threading.RLock()
        self.mainloop = GLib.MainLoop()
        self.thread = threading.Thread(target=self.mainloop.run)
        self.thread.daemon = True
        self.thread.start()
        self.logger = logging.getLogger(__name__)
        # Ensure logger has handlers if not configured by Flask app __init__
        if not self.logger.hasHandlers():
            log_handler = logging.StreamHandler()
            log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            log_handler.setFormatter(log_formatter)
            self.logger.addHandler(log_handler)
        self.logger.setLevel(logging.INFO) # Ensure level is set
        self.logger.info(f"StreamManager initialized with media folder: {media_folder}")
        try:
            self.logger.info(f"GStreamer version: {Gst.version_string()}")
        except Exception as e:
            self.logger.error(f"Could not get GStreamer version string: {e}")

    # --- Validation Methods ---
    def _validate_listener_port(self, port):
        """Validates listener port is within the allowed range."""
        try: port_int = int(port)
        except (ValueError, TypeError) as e: raise ValueError(f"Invalid listener port: {port}. Must be 10001-10010.") from e
        if not (10001 <= port_int <= 10010): raise ValueError(f"Listener port {port_int} outside allowed range (10001-10010)")
        return port_int

    def _validate_target_port(self, port):
        """Validates target port is within the standard range."""
        try: port_int = int(port)
        except (ValueError, TypeError) as e: raise ValueError(f"Invalid target port: {port}. Must be 1-65535.") from e
        if not (1 <= port_int <= 65535): raise ValueError(f"Target port {port_int} outside valid range (1-65535)")
        return port_int

    # --- Sanitization/Extraction Methods ---
    def _sanitize_for_json(self, obj):
        """Recursively sanitizes data structures for JSON serialization."""
        if isinstance(obj, (str, int, float, bool, type(None))): return obj
        elif isinstance(obj, (list, tuple)): return [self._sanitize_for_json(item) for item in obj]
        elif isinstance(obj, dict): return {str(k): self._sanitize_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, (Gio.SocketAddress, Gio.InetAddress, Gio.InetSocketAddress)): return self._extract_ip_from_socket_address(obj)
        elif isinstance(obj, GLib.Error): return f"GLib.Error: {obj.message} (domain:{obj.domain}, code:{obj.code})"
        elif isinstance(obj, GObject.GObject):
            try:
                if hasattr(obj, 'to_string') and callable(obj.to_string): return obj.to_string()
                elif hasattr(obj, 'get_name') and callable(obj.get_name): return f"{type(obj).__name__}(name='{obj.get_name()}')"
            except Exception: pass
            return str(obj)
        else:
            try: json.dumps(obj); return obj
            except TypeError: return str(obj)

    def _extract_ip_from_socket_address(self, addr):
        """Extracts IP address string from various Gio SocketAddress types."""
        if addr is None: return None
        try:
            if isinstance(addr, Gio.InetSocketAddress):
                inet_addr = addr.get_address(); return inet_addr.to_string() if inet_addr else None
            elif isinstance(addr, Gio.InetAddress): return addr.to_string()
            elif isinstance(addr, Gio.SocketAddress):
                 family = addr.get_family()
                 if family == Gio.SocketFamily.IPV4 or family == Gio.SocketFamily.IPV6:
                     try:
                         inet_sock_addr = addr.cast(Gio.InetSocketAddress)
                         if inet_sock_addr: inet_addr = inet_sock_addr.get_address(); return inet_addr.to_string() if inet_addr else None
                     except TypeError: pass
                 addr_str = addr.to_string(); ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', addr_str); return ip_match.group(1) if ip_match else addr_str
            else: return str(addr)
        except Exception as e: self.logger.error(f"Error extracting IP from address object ({type(addr)}): {str(e)}"); return str(addr)

    # --- GStreamer Bus/Signal Handlers ---
    def _on_bus_message(self, bus, message, key):
        """Handles messages posted on the pipeline's bus."""
        t = message.type
        with self.lock:
            stream_info = self.active_streams.get(key)
            if not stream_info: return True

            mode = stream_info.get('mode', '?'); config_dict = stream_info.get('config', {}); input_type = config_dict.get('input_type', '?'); target_info = stream_info.get('target', '?'); target = f" to {target_info}" if mode == 'caller' else ''; pipeline_description = f"stream {key} ({mode}{target}, input:{input_type})"

            if t == Gst.MessageType.STATE_CHANGED:
                if message.src == stream_info.get('pipeline'):
                    old_state, new_state, pending_state = message.parse_state_changed()
                    self.logger.info(f"BUS_MSG: {pipeline_description} state changed from {Gst.Element.state_get_name(old_state)} to {Gst.Element.state_get_name(new_state)} (pending: {Gst.Element.state_get_name(pending_state)})")
                    if mode == 'caller' and new_state == Gst.State.PLAYING and stream_info['connection_status'] == 'Connecting...':
                        self.logger.info(f"Caller stream {key} reached PLAYING state. Marking as Connected.")
                        stream_info['connection_status'] = 'Connected'
                    if new_state == Gst.State.NULL:
                        self.logger.info(f"BUS_MSG: {pipeline_description} successfully transitioned to NULL state.")
                        if key in self.active_streams and self.active_streams[key]['connection_status'] not in ['Error', 'Disconnected', 'Stopped']:
                             self.active_streams[key]['connection_status'] = 'Stopped'
            elif t == Gst.MessageType.EOS:
                self.logger.info(f"BUS_MSG: EOS received for {pipeline_description}. Stopping.")
                GLib.idle_add(self.stop_stream, key)
            elif t == Gst.MessageType.ERROR:
                err, debug = message.parse_error(); src_name = message.src.get_name() if hasattr(message.src, 'get_name') else '?'; self.logger.error(f"BUS_MSG: GStreamer error on {pipeline_description} from element '{src_name}': {err.message}. Debug: {debug}")
                stream_info['connection_status'] = 'Error: ' + err.message
                GLib.idle_add(self.stop_stream, key)
            elif t == Gst.MessageType.WARNING:
                warn, debug = message.parse_warning(); src_name = message.src.get_name() if hasattr(message.src, 'get_name') else '?'; self.logger.warning(f"BUS_MSG: GStreamer warning on {pipeline_description} from element '{src_name}': {warn.message}. Debug: {debug}")
                current_status = stream_info.get('connection_status', 'Unknown'); new_status = None; msg_lower = warn.message.lower()
                if "failed to authenticate" in msg_lower: new_status = "Auth Error"
                elif "connection timed out" in msg_lower and current_status == 'Connecting...': new_status = "Connection Failed"
                elif "connection was broken" in msg_lower: new_status = "Broken / Reconnecting"
                elif "could not bind" in msg_lower or "address already in use" in msg_lower: new_status = "Bind Error"; self.logger.error(f"BUS_MSG: Detected potential port bind error via warning for stream {key}.")
                if new_status and current_status != new_status: stream_info['connection_status'] = new_status; self.logger.info(f"Updated status for stream {key} to '{new_status}' based on warning.")
        return True

    def _on_caller_added(self, element, socket_id, addr, key):
        ip = self._extract_ip_from_socket_address(addr); self.logger.info(f"SRT signal 'caller-added' for stream {key}: socket_id={socket_id}, client_ip={ip}")
        with self.lock:
            if key in self.active_streams:
                 si = self.active_streams[key]
                 if si.get('mode') == 'listener': si['connection_status'] = 'Connected'; si['connected_client'] = addr; si['socket_id'] = socket_id; self.logger.info(f"Updated LISTENER stream {key} status to Connected, client: {ip}")
                 si.setdefault('connection_history', []).append({'event': 'caller-added', 'time': time.time(), 'ip': ip, 'socket_id': socket_id})
            else: self.logger.warning(f"SRT signal 'caller-added' received for non-existent stream key {key}")

    def _on_caller_removed(self, element, socket_id, addr, key):
        ip = self._extract_ip_from_socket_address(addr); self.logger.info(f"SRT signal 'caller-removed' for stream {key}: socket_id={socket_id}, client_ip={ip}")
        with self.lock:
            if key in self.active_streams:
                si = self.active_streams[key]
                si.setdefault('connection_history', []).append({ 'event': 'caller-removed', 'time': time.time(), 'ip': ip, 'socket_id': socket_id})
                if si.get('mode') == 'listener' and si.get('socket_id') == socket_id:
                    si['connection_status'] = 'Waiting for connection'; si['connected_client'] = None; si['socket_id'] = None; self.logger.info(f"Cleared tracked client for LISTENER stream {key} as socket {socket_id} disconnected.")

    def _on_caller_rejected(self, element, addr, reason, key):
        ip = self._extract_ip_from_socket_address(addr); self.logger.warning(f"SRT signal 'caller-rejected' for stream {key}: client_ip={ip}, reason_code={reason}")
        with self.lock:
            if key in self.active_streams:
                if self.active_streams[key]['mode'] == 'listener': self.active_streams[key]['connection_status'] = 'Rejected Connection'
                self.active_streams[key].setdefault('connection_history', []).append({ 'event': 'rejected', 'time': time.time(), 'ip': ip, 'reason': reason })
            else: self.logger.warning(f"SRT signal 'caller-rejected' received for non-existent stream key {key}")

    # --- start_stream ---
    def start_stream(self, config, use_target_port_as_key=False):
        # Code from response #23 (includes parse_launch error handling)
        key = None; pipeline = None; existing_pipeline = None; pipeline_input_str = None; srt_uri = ""; pipeline_str = ""; DEFAULT_MULTICAST_INTERFACE = "vlan2"
        try:
            mode = config.get('mode', 'listener'); target_port_config = config.get('target_port'); listener_port_config = config.get('port')
            if mode == 'caller': key = self._validate_target_port(target_port_config) # Using target port as key
            else: key = self._validate_listener_port(listener_port_config)

            with self.lock:
                if key in self.active_streams: self.logger.warning(f"Key {key} ({mode}) in use. Stopping existing."); existing_pipeline = self.active_streams.pop(key).get('pipeline')
                else: self.logger.info(f"No existing stream for key {key}.")
            if existing_pipeline: self.logger.info(f"Scheduling NULL state for old pipeline {key}."); GLib.idle_add(existing_pipeline.set_state, Gst.State.NULL, priority=GLib.PRIORITY_DEFAULT); time.sleep(0.5)

            input_type = config.get('input_type', 'multicast'); self.logger.info(f"Starting stream {key} with input type: {input_type}")
            if input_type == 'file':
                file_path = config.get('file_path'); media_dir = os.path.abspath(self.media_folder); base_filename = os.path.basename(file_path)
                if not (file_path and isinstance(file_path, str)): raise ValueError("Missing or invalid 'file_path'.")
                if base_filename != file_path: raise ValueError("Invalid file path format provided.")
                abs_file_path = os.path.abspath(os.path.join(media_dir, base_filename))
                if not abs_file_path.startswith(media_dir + os.sep): raise ValueError("File path is outside allowed media directory.")
                if not os.path.isfile(abs_file_path): raise FileNotFoundError(f"Media file not found: {abs_file_path}")
                if not abs_file_path.lower().endswith('.ts'): raise ValueError("Only .ts files supported.")
                pipeline_input_str = f'filesrc location="{abs_file_path}"'; self.logger.info(f"Using file source: {abs_file_path}")
            elif input_type == 'multicast':
                mc_address=config.get('multicast_address'); mc_port=config.get('multicast_port'); mc_protocol=config.get('protocol','udp')
                if not (mc_address and mc_port): raise ValueError("Missing multicast address or port.")
                if not isinstance(mc_port, int) or not (1 <= mc_port <= 65535): raise ValueError(f"Invalid multicast port: {mc_port}")
                selected_interface = config.get('multicast_interface'); interface_to_use = selected_interface if selected_interface else DEFAULT_MULTICAST_INTERFACE; self.logger.info(f"Multicast interface selected: '{selected_interface}', Using: '{interface_to_use}'")
                if mc_protocol=='udp': pipeline_input_str = f'udpsrc uri="udp://{mc_address}:{mc_port}" multicast-iface="{interface_to_use}" buffer-size=20971520 caps="video/mpegts, systemstream=(boolean)true, packetsize=(int)188"'; self.logger.info(f"Using UDP source: udp://{mc_address}:{mc_port} on {interface_to_use}")
                else: raise ValueError(f"Unsupported multicast protocol: {mc_protocol}")
            else: raise ValueError(f"Unsupported input_type: {input_type}")

            overhead_bandwidth = int(config.get('overhead_bandwidth', 2)); latency_ms = int(config.get('latency', 300)); smoothing_choice = config.get('smoothing_latency_ms', '30')
            try: smoothing_latency_us = int(smoothing_choice) * 1000
            except (ValueError, TypeError): smoothing_latency_us = 30000; self.logger.warning(f"Invalid smoothing latency '{smoothing_choice}', using default 30ms.")
            encryption=config.get('encryption','none'); passphrase=config.get('passphrase',''); qos_enabled=config.get('qos',False); qos_string=str(qos_enabled).lower(); sink_name=f"srtsink_{key}"; tsparse_name=f"tsparse_{key}"
            srt_params = [ f"mode={mode}","transtype=live",f"latency={latency_ms}",f"peerlatency={latency_ms}", f"rcvbuf={DVB_STANDARD_CONFIG.get('rcvbuf',12058624)}", f"sndbuf={DVB_STANDARD_CONFIG.get('sndbuf',12058624)}", f"fc={DVB_STANDARD_CONFIG.get('fc',8000)}", f"tlpktdrop={str(DVB_STANDARD_CONFIG.get('tlpktdrop',True)).lower()}", f"overheadbandwidth={overhead_bandwidth}", "nakreport=true", f"streamid=dvb_stream_{key}", f"qos={qos_string}" ]
            if encryption != 'none':
                if not passphrase or not (10 <= len(passphrase) <= 79): raise ValueError("Passphrase (10-79 chars) required for selected encryption.")
                pbkeylen=16 if encryption=='aes-128' else 32; srt_params.extend([f"passphrase={passphrase}",f"pbkeylen={pbkeylen}"])
            target_address=config.get('target_address'); target_port_for_uri=key; listener_port_for_uri=key
            if mode=='caller':
                if not target_address: raise ValueError("Target address required for caller mode.")
                srt_uri = f"srt://{target_address}:{target_port_for_uri}?{'&'.join(srt_params)}"
            else: srt_uri = f"srt://0.0.0.0:{listener_port_for_uri}?{'&'.join(srt_params)}"
            if not srt_uri: raise ValueError("Internal error: Failed to construct a valid SRT URI.")

            pipeline_str = ( f'{pipeline_input_str} ! ' f'tsparse name="{tsparse_name}" set-timestamps=true alignment=7 smoothing-latency={smoothing_latency_us} parse-private-sections=true ! ' f'srtsink name="{sink_name}" uri="{srt_uri}" async=false sync=false wait-for-connection=false' )
            pipeline_str = " ".join(pipeline_str.split()); self.logger.debug(f"Constructed pipeline string {key}: {pipeline_str}")

            self.logger.info(f"Attempting to parse pipeline for stream {key} (Smoothing:{smoothing_latency_us}us)")
            try: pipeline = Gst.parse_launch(pipeline_str)
            except GLib.Error as e:
                 self.logger.error(f"GStreamer pipeline PARSE error for key {key}: {str(e)}", exc_info=True); self.logger.error(f"Problematic pipeline string: {pipeline_str}")
                 if "Given uri cannot be used" in str(e): return False, f"Pipeline parse error: Invalid SRT URI format or parameters. Check configuration."
                 return False, f"Pipeline parse error: {str(e)}"
            if not pipeline: raise RuntimeError(f"Gst.parse_launch returned None for stream {key}.")

            bus=pipeline.get_bus(); bus.add_signal_watch(); bus.connect("message",self._on_bus_message,key)
            srtsink=pipeline.get_by_name(sink_name)
            if not srtsink: GLib.idle_add(pipeline.set_state, Gst.State.NULL); raise RuntimeError(f"Cannot find '{sink_name}' element.")
            try:
                srtsink.connect('caller-added',self._on_caller_added,key); srtsink.connect('caller-removed',self._on_caller_removed,key); srtsink.connect('caller-rejected',self._on_caller_rejected,key); self.logger.info(f"Connected SRT signals for stream {key}.")
            except Exception as e: self.logger.warning(f"Could not connect SRT signals for stream {key}: {e}")

            stream_info_dict = {'pipeline':pipeline,'bus':bus,'config':config,'srt_uri':srt_uri,'mode':mode,'start_time':time.time(),'connection_status':'Connecting...' if mode=='caller' else 'Waiting for connection','connected_client':None,'socket_id':None,'connection_history':[]}
            if mode == 'caller': stream_info_dict['target'] = f"{target_address}:{target_port_for_uri}"
            with self.lock: self.active_streams[key] = stream_info_dict

            def set_playing_safe(p, k):
                self.logger.info(f"Attempting final state transition to PLAYING for stream {k}...")
                ret = p.set_state(Gst.State.PLAYING)
                s_map = { Gst.StateChangeReturn.FAILURE:"FAIL", Gst.StateChangeReturn.SUCCESS:"OK", Gst.StateChangeReturn.ASYNC:"ASYNC", Gst.StateChangeReturn.NO_PREROLL:"NO_PREROLL" }
                self.logger.info(f"set_state(PLAYING) for stream {k} returned: {s_map.get(ret,'?')}")
                if ret == Gst.StateChangeReturn.FAILURE:
                    self.logger.error(f"Failed to set pipeline state to PLAYING for stream {k}.")
                    with self.lock:
                        if k in self.active_streams: self.active_streams[k]['connection_status'] = 'Start Error'
            GLib.idle_add(set_playing_safe, pipeline, key, priority=GLib.PRIORITY_DEFAULT)
            self.logger.info(f"Scheduled pipeline start for stream {key}.")

            input_detail_log = os.path.basename(config.get('file_path','N/A')) if input_type == 'file' else (f"udp://{config.get('multicast_address','?')}:{config.get('multicast_port','?')}" if input_type == 'multicast' else 'N/A')
            return True, f"Stream {mode} ({key}) starting: {input_type} '{input_detail_log}'"

        except (KeyError, ValueError, FileNotFoundError, RuntimeError) as e:
            self.logger.error(f"Configuration/Runtime error starting stream {key or 'N/A'}: {str(e)}", exc_info=False)
            if pipeline: GLib.idle_add(pipeline.set_state, Gst.State.NULL, priority=GLib.PRIORITY_HIGH)
            return False, f"Stream start error: {str(e)}"
        except Exception as e:
            self.logger.error(f"Unexpected start error for stream {key or 'N/A'}: {str(e)}", exc_info=True)
            if pipeline: GLib.idle_add(pipeline.set_state, Gst.State.NULL, priority=GLib.PRIORITY_HIGH)
            return False, f"Unexpected error: {str(e)}"

    # --- stop_stream ---
    def stop_stream(self, stream_key):
        # Code from response #23 (uses idle_add for safety)
        pipeline_to_stop = None; bus_to_clear = None; key = -1
        try:
            try: key = int(stream_key)
            except (ValueError, TypeError): raise ValueError(f"Invalid stream identifier: '{stream_key}'. Must be a number.")
            with self.lock:
                if key not in self.active_streams: return False, f"Stream {key} not found or already stopped."
                self.logger.info(f"Attempting to stop stream with key: {key}")
                stream_info = self.active_streams.pop(key)
                pipeline_to_stop = stream_info.get('pipeline'); bus_to_clear = stream_info.get('bus')
            if pipeline_to_stop:
                if bus_to_clear:
                    try: bus_to_clear.remove_signal_watch(); self.logger.debug(f"Removing signal watch from bus for stream {key}.")
                    except Exception as bus_e: self.logger.warning(f"Error removing signal watch for stream {key}: {bus_e}")
                self.logger.info(f"Scheduling state change to NULL for stream {key}.")
                def set_null_safe(p, k):
                    ret = p.set_state(Gst.State.NULL)
                    s_map = { Gst.StateChangeReturn.FAILURE:"FAIL", Gst.StateChangeReturn.SUCCESS:"OK", Gst.StateChangeReturn.ASYNC:"ASYNC", Gst.StateChangeReturn.NO_PREROLL:"NO_PREROLL" }
                    self.logger.info(f"Async set_state(NULL) for stream {k} returned: {s_map.get(ret, 'Unknown')}")
                    if ret == Gst.StateChangeReturn.FAILURE: self.logger.error(f"Failed to set pipeline state to NULL for stream {k} via idle_add.")
                GLib.idle_add(set_null_safe, pipeline_to_stop, key, priority=GLib.PRIORITY_DEFAULT)
                return True, f"Stream {key} stop initiated."
            else: self.logger.warning(f"Stream {key} was active but no pipeline object found."); return False, f"Stream {key} active but pipeline missing."
        except ValueError as e: self.logger.error(f"Stop validation error: {str(e)}"); return False, str(e)
        except Exception as e:
            self.logger.error(f"Unexpected error stopping stream {stream_key}: {str(e)}", exc_info=True)
            if pipeline_to_stop:
                try: GLib.idle_add(pipeline_to_stop.set_state, Gst.State.NULL, priority=GLib.PRIORITY_HIGH); self.logger.info(f"Attempted cleanup set_state NULL for {key} after error.")
                except Exception as cleanup_e: self.logger.warning(f"Ignoring error during cleanup NULL scheduling for {key}: {cleanup_e}")
            with self.lock:
                 if isinstance(key, int) and key > 0 and key in self.active_streams: self.logger.warning(f"Stream {key} still in active_streams during exception, removing."); del self.active_streams[key]
            return False, f"An unexpected error occurred stopping stream: {str(e)}"

    # --- _extract_stats_from_gstruct ---
    def _extract_stats_from_gstruct(self, stats_struct):
        # Includes fix to remove walrus operator
        result = {}; raw_stats_string_for_debug = "N/A"
        if not stats_struct or not isinstance(stats_struct, Gst.Structure): self.logger.warning("Invalid Gst.Structure passed to _extract_stats_from_gstruct."); return result
        try:
            raw_stats_string_for_debug = stats_struct.to_string()
            if not raw_stats_string_for_debug: self.logger.warning("Gst.Structure.to_string() returned empty string."); return result
            def parse_value(value_str, value_type):
                value_type = value_type.lower(); value_str = value_str.strip();
                if value_str.endswith('\\'): value_str = value_str[:-1]
                is_quoted = value_str.startswith('"') and value_str.endswith('"')
                if is_quoted: value_str_unquoted = value_str[1:-1].replace('\\"', '"').replace('\\\\', '\\')
                else: value_str_unquoted = value_str
                if value_str_unquoted == "NULL": return None
                if value_str_unquoted == "TRUE": return True
                if value_str_unquoted == "FALSE": return False
                try:
                    if 'int' in value_type: return int(value_str_unquoted)
                    if 'double' in value_type or 'float' in value_type: return round(float(value_str_unquoted), 2)
                except ValueError: self.logger.warning(f"StatsParse: Fail convert '{value_str_unquoted}' as {value_type}"); return 0 if 'int' in value_type else 0.0
                return value_str_unquoted
            inner_listener_pattern = re.compile(r'([a-zA-Z0-9\-]+)\s*\\\=\s*\\\(([^)]+)\\\)\s*("(?:[^"\\]|\\.)*"|[^,]+)')
            top_level_listener_pattern = re.compile(r'([a-zA-Z0-9\-]+)\s*=\s*\(([^)]+)\)\s*("(?:[^"\\]|\\.)*"|[^;]+)')
            caller_pattern = re.compile(r'([a-zA-Z0-9\-]+)\s*=\s*\(([^)]+)\)\s*("(?:[^"\\]|\\.)*"|[^,;]+)')
            def parse_with_finditer(text_to_parse, target_dict, pattern):
                processed_keys = set(target_dict.keys())
                for match in pattern.finditer(text_to_parse):
                    key_raw, value_type, value_part = match.groups()[:3]; key = key_raw.replace('-', '_')
                    if key not in processed_keys: target_dict[key] = parse_value(value_part, value_type); processed_keys.add(key)
            payload_str = raw_stats_string_for_debug
            if ',' in payload_str: payload_str = payload_str.split(',', 1)[1]
            payload_str = payload_str.strip(';{} ')
            if 'callers=' in payload_str:
                inner_kv_string = None; top_level_str = payload_str; callers_match = re.search(r'callers=\(GValueArray\)<(.*?)>', payload_str, re.DOTALL)
                if callers_match:
                    callers_content = callers_match.group(1).strip(); inner_struct_match = re.match(r'\s*"(?:application/x-srt-statistics\\,)?(.*?)\s*;?"\s*', callers_content, re.DOTALL)
                    if inner_struct_match: inner_kv_string = inner_struct_match.group(1).replace('\\,', ',').replace('\\"', '"').replace('\\\\', '\\').strip().lstrip('\\ '); top_level_str = payload_str[:callers_match.start()] + payload_str[callers_match.end():]; top_level_str = top_level_str.strip('; ,')
                    else: self.logger.warning(f"StatsParse: No inner kv: {callers_content[:100]}...")
                else: self.logger.warning("StatsParse: 'callers=' fail.")
                if inner_kv_string: parse_with_finditer(inner_kv_string, result, inner_listener_pattern)
                parse_with_finditer(top_level_str, result, top_level_listener_pattern)
            else: parse_with_finditer(payload_str, result, caller_pattern)
            final_key_map={'bitrate_mbps':['send_rate_mbps'],'rtt_ms':['rtt_ms','link_rtt'],'loss_rate':['pkt_loss_rate'],'packets_sent_total':['pkt_sent_total','packets_sent'],'packets_lost_total':['pkt_lost_total','packets_sent_lost'],'packets_retransmitted_total':['pkt_retransmitted_total','packets_retransmitted'],'bytes_sent_total':['bytes_sent_total'],'estimated_bandwidth_mbps':['bandwidth_mbps','link_bandwidth'],'packets_received_total':['pkt_received_total','packets_received'],'packets_received_lost':['packets_received_lost'],'packets_received_retransmitted':['packets_received_retransmitted'],'packets_received_dropped':['packets_received_dropped'],'bytes_sent':['bytes_sent'],'bytes_received':['bytes_received'],'bytes_retransmitted':['bytes_retransmitted'],'bytes_sent_dropped':['bytes_sent_dropped'],'bytes_received_lost':['bytes_received_lost'],'packet_ack_received':['packet_ack_received'],'packet_nack_received':['packet_nack_received'],'packet_ack_sent':['packet_ack_sent'],'packet_nack_sent':['packet_nack_sent'],'send_buffer_level_ms':['snd_buf_ms'],'recv_buffer_level_ms':['rcv_buf_ms'],'flow_window':['flow_wnd','snd_flow_wnd'],'negotiated_latency_ms':['negotiated_latency_ms']}
            final_result={'bitrate_mbps':0.0,'rtt_ms':0.0,'loss_rate':0.0,'packets_sent_total':0,'packets_lost_total':0,'packets_retransmitted_total':0,'bytes_sent_total':0,'packet_loss_percent':0.0,'estimated_bandwidth_mbps':0.0,'packets_received_total':0,'packets_received_lost':0,'packets_received_retransmitted':0,'packets_received_dropped':0,'bytes_sent':0,'bytes_received':0,'bytes_retransmitted':0,'bytes_sent_dropped':0,'bytes_received_lost':0,'packet_ack_received':0,'packet_nack_received':0,'packet_ack_sent':0,'packet_nack_sent':0,'send_buffer_level_ms':0,'recv_buffer_level_ms':0,'flow_window':0,'negotiated_latency_ms':0}
            # --- Modified loop ---
            for fk, sks in final_key_map.items():
                v = None
                for sk in sks:
                    if sk in result: v = result[sk]; break
                final_key_name = fk.replace('br','bitrate').replace('pkt_','packets_').replace('_s','')
                final_result[final_key_name] = v if v is not None else final_result.get(final_key_name)
            # --- End modification ---
            s,l=final_result.get('packets_sent_total',0),final_result.get('packets_lost_total',0); final_result['packet_loss_percent']=round((l/s)*100,2) if isinstance(s,(int,float)) and isinstance(l,(int,float)) and s>0 else 0.0
            for k,v in result.items(): final_result.setdefault(k,v)
            return final_result
        except Exception as e: self.logger.error(f"CRITICAL Error parsing SRT stats: {e}", exc_info=True); return {'error': f"Parse Fail: {e}", 'raw_string': raw_stats_string_for_debug}

    # --- get_stream_statistics ---
    def get_stream_statistics(self, stream_key):
        # Includes get_state fix
        pipeline = None; stream_info_copy = None
        try:
            key = int(stream_key)
            with self.lock:
                if key not in self.active_streams: self.logger.warning(f"Stats requested for non-existent stream key {key}"); return {'error': f"Stream {key} not found"}
                stream_info = self.active_streams[key]; pipeline = stream_info.get('pipeline')
                stream_info_copy = {'mode': stream_info.get('mode'),'connection_status': stream_info.get('connection_status'),'connected_client': stream_info.get('connected_client'),'start_time': stream_info.get('start_time', time.time()),'config': stream_info.get('config', {})}
            stats = {'connection_status': stream_info_copy.get('connection_status', 'Unknown'),'connected_client': self._extract_ip_from_socket_address(stream_info_copy.get('connected_client')),'uptime': self._format_uptime(time.time() - stream_info_copy.get('start_time', time.time())),'last_updated': time.time(),'config': stream_info_copy.get('config', {})}
            if pipeline:
                ret_state, current_state, pending_state = pipeline.get_state(0) # Corrected unpacking
                if ret_state == Gst.StateChangeReturn.FAILURE: stats['error'] = "Failed to get pipeline state."; self.logger.warning(f"Failed to get pipeline state for stream {key}")
                elif current_state < Gst.State.PAUSED:
                     state_name = Gst.Element.state_get_name(current_state); stats['error'] = f"Pipeline not running (State: {state_name})"
                     if stats['connection_status'] != 'Error': stats['connection_status'] = stream_info_copy.get('connection_status', 'Unknown')
                else:
                    sink_name = f"srtsink_{key}"; srtsink = pipeline.get_by_name(sink_name)
                    if srtsink:
                        try:
                            stats_struct = srtsink.get_property('stats'); parsed_stats = {}
                            if stats_struct and isinstance(stats_struct, Gst.Structure):
                                parsed_stats = self._extract_stats_from_gstruct(stats_struct); stats.update(parsed_stats)
                            elif not stats_struct: self.logger.warning(f"srtsink.get_property('stats') returned None for stream {key}"); stats['error'] = "Failed to retrieve stats structure (returned None)"
                            else: self.logger.warning(f"Stats property for {key} is not a Gst.Structure: {type(stats_struct)}"); stats['error'] = f"Invalid stats structure type: {type(stats_struct)}"
                            if 'error' in parsed_stats: self.logger.warning(f"Stats parse error for stream {key}: {parsed_stats['error']}"); stats['parse_error'] = parsed_stats['error']
                        except Exception as e: self.logger.error(f"Error getting/parsing stats property for {key}: {str(e)}"); stats['error'] = f"Stats fetch/parse error: {str(e)}"
                    else: stats['error'] = f"srtsink '{sink_name}' not found."
            else: stats['error'] = "Pipeline object not found (stream may have stopped)."; stats['connection_status'] = "Stopped"
            return stats
        except ValueError as e: self.logger.error(f"Get stats validation error: {e}"); return {'error': f"Invalid stream key: {stream_key}"}
        except Exception as e: self.logger.error(f"Unexpected error getting stats for {stream_key}: {e}", exc_info=True); return {'error': f"Unexpected error retrieving stats: {str(e)}"}

    # --- get_active_streams (Ensuring this method exists) ---
    def get_active_streams(self):
        """Returns a dictionary of all active streams with basic information."""
        try:
            with self.lock:
                if not self.active_streams: return {}
                streams = {}
                now = time.time() # Get current time once
                for key, stream_info in self.active_streams.items():
                    mode = stream_info.get('mode', 'unknown')
                    config = stream_info.get('config', {})
                    status = stream_info.get('connection_status', 'Unknown')
                    start_time = stream_info.get('start_time', now) # Use now if start_time missing
                    client_addr = stream_info.get('connected_client')
                    target = stream_info.get('target') if mode == 'caller' else None
                    input_type = config.get('input_type', 'unknown'); source_detail = os.path.basename(config.get('file_path','N/A')) if input_type == 'file' else (f"{config.get('multicast_address','?')}:{config.get('multicast_port','?')}" if input_type == 'multicast' else 'N/A')

                    # Handle timeout for 'Connecting...' callers here as well
                    if mode == 'caller' and status == 'Connecting...' and (now - start_time) > 30: # 30 second timeout
                         status = 'Connection Failed' # Update status for the copy
                         # Optionally update the main dict too, but needs care with locking/loops
                         # self.logger.warning(f"Caller {key} timed out in get_active_streams.")
                         # stream_info['connection_status'] = status # Update original dict if needed

                    stream_data = {
                        'key': key, # Include the key itself
                        'mode': mode,
                        'connection_status': status, # Use potentially updated status
                        'uptime': self._format_uptime(now - start_time),
                        'input_type': input_type,
                        'source_detail': source_detail,
                        'latency': config.get('latency', '?'),
                        'overhead_bandwidth': config.get('overhead_bandwidth', '?'),
                        'encryption': config.get('encryption', 'none'),
                        'passphrase_set': bool(config.get('passphrase')) and config.get('encryption', 'none') != 'none',
                        'qos_enabled': config.get('qos', False),
                        'smoothing_latency_ms': config.get('smoothing_latency_ms', '?'),
                        'port': config.get('port') if mode == 'listener' else config.get('target_port'),
                        'target': target,
                        'client_ip': self._extract_ip_from_socket_address(client_addr), # Use helper, handles None
                        'srt_uri': stream_info.get('srt_uri', ''), # Include SRT URI
                        'start_time': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(start_time)) if start_time else 'N/A' # Formatted start time
                    }
                    streams[key] = self._sanitize_for_json(stream_data) # Sanitize final dict
            # self.logger.debug(f"Returning info for {len(streams)} active streams.")
            return streams
        except Exception as e:
            self.logger.error(f"Error retrieving active streams: {str(e)}", exc_info=True)
            return {'error': f"Failed to retrieve active streams: {str(e)}"}

    # --- _format_uptime ---
    def _format_uptime(self, seconds):
        try:
            seconds_int = int(seconds);
            if seconds_int < 0: return "0s"
            days, rem_d = divmod(seconds_int, 86400); hrs, rem_h = divmod(rem_d, 3600); mins, secs = divmod(rem_h, 60)
            parts = [f"{d}d" for d in [days] if d > 0] + [f"{h}h" for h in [hrs] if h > 0] + [f"{m}m" for m in [mins] if m > 0] + [f"{s}s" for s in [secs] if s >= 0 or not parts] # Show seconds >= 0
            return " ".join(parts) if parts else "0s"
        except Exception as e: self.logger.error(f"Error formatting uptime: {e}"); return "Error"

    # --- get_file_info ---
    def get_file_info(self, file_path):
        # Based on user's current version, assumes path validated by caller
        abs_file_path = file_path
        try:
            cmd = ['ffprobe', '-v', 'error', '-show_format', '-show_streams', '-of', 'json', abs_file_path]
            r = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=15)
            return json.dumps(json.loads(r.stdout), indent=2)
        except FileNotFoundError:
            try:
                cmd = ['mediainfo', '--Output=JSON', abs_file_path]
                r = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=20)
                media_info_data = json.loads(r.stdout).get('media', {})
                return json.dumps(media_info_data, indent=2)
            except FileNotFoundError: return json.dumps({"error": "Neither ffprobe nor mediainfo found."}, indent=2)
            except Exception as e_mi: return json.dumps({"error": f"mediainfo failed: {e_mi}"}, indent=2)
        except subprocess.TimeoutExpired: return json.dumps({"error": "ffprobe timed out."}, indent=2)
        except subprocess.CalledProcessError as e_ff: return json.dumps({"error": f"ffprobe failed (Code {e_ff.returncode}): {e_ff.stderr or e_ff.stdout}"}, indent=2)
        except Exception as e: return json.dumps({"error": f"ffprobe execution failed: {str(e)}"}, indent=2)

    # --- get_debug_info ---
    def get_debug_info(self, stream_key):
        # Based on user's current version, includes get_state fix
        si_copy=None; pipeline=None
        try:
            key=int(stream_key)
            with self.lock:
                 si=self.active_streams.get(key)
                 if not si: return {"error": f"Stream {key} not found"}
                 pipeline=si.get('pipeline')
                 cfg_copy = json.loads(json.dumps(si.get('config', {}), default=str))
                 si_copy={'mode':si.get('mode','?'), 'uri':si.get('srt_uri'), 'stat':si.get('connection_status'), 'client':si.get('connected_client'), 'start':si.get('start_time',0), 'cfg':cfg_copy, 'hist':si.get('connection_history',[]).copy()}
            cfg=si_copy['cfg']; i_type=cfg.get('input_type','?'); s_detail = os.path.basename(cfg.get('file_path','N/A')) if i_type == 'file' else (f"udp://{cfg.get('multicast_address','?')}:{cfg.get('multicast_port','?')}" if i_type == 'multicast' else 'N/A')
            debug={'key':key,'mode':si_copy['mode'],'input':i_type,'src':s_detail, 'target':cfg.get('target_address', None) if si_copy['mode'] == 'caller' else None, 'uri':si_copy['uri'],'stat':si_copy['stat'], 'client_ip':self._extract_ip_from_socket_address(si_copy['client']), 'uptime':self._format_uptime(time.time()-si_copy['start']), 'cfg':self._sanitize_for_json(cfg), 'hist':self._sanitize_for_json(si_copy['hist'])}
            if pipeline:
                ret_st, cur_st, pend_st = pipeline.get_state(0) # Corrected unpacking
                debug['pipeline_state'] = Gst.Element.state_get_name(cur_st) if ret_st != Gst.StateChangeReturn.FAILURE else "Error getting state"
                sink=pipeline.get_by_name(f"srtsink_{key}")
                if not sink: debug['stats_error'] = "SRT sink element not found in pipeline."
                else:
                    try:
                        stats_struct = sink.get_property('stats')
                        if stats_struct and isinstance(stats_struct, Gst.Structure):
                             debug['raw_stats'] = stats_struct.to_string()
                             parsed_stats = self._extract_stats_from_gstruct(stats_struct)
                             debug['parsed_stats'] = parsed_stats
                             if 'error' in parsed_stats: debug['parse_error'] = parsed_stats['error']
                        elif stats_struct is None: debug['stats_error'] = "Failed to retrieve stats structure (returned None)."
                        else: debug['stats_error'] = f"Invalid stats structure type: {type(stats_struct)}"
                    except Exception as e: debug['stats_error'] = f"Error getting stats property: {str(e)}"
            else: debug['stats_error']="Pipeline object not found (stream may have stopped)."
            return self._sanitize_for_json(debug)
        except ValueError as e: return {"error": str(e)}
        except Exception as e: self.logger.error(f"Unexpected debug err: {e}", exc_info=True); return {"error": f"Unexpected error: {e}"}

    # --- shutdown ---
    def shutdown(self):
        # Based on user's current version
        self.logger.info("Shutting down StreamManager...")
        with self.lock: active_keys = list(self.active_streams.keys()); self.logger.info(f"Stopping {len(active_keys)} active streams...")
        keys_to_stop = list(active_keys)
        for k in keys_to_stop:
             self.logger.info(f"Requesting stop for stream {k}")
             self.stop_stream(k)
        time.sleep(1.5)
        with self.lock:
             remaining_streams = len(self.active_streams)
             if remaining_streams > 0: self.logger.warning(f"{remaining_streams} streams potentially did not stop cleanly.")
        if self.mainloop.is_running(): self.logger.info("Quitting GLib MainLoop..."); self.mainloop.quit()
        if self.thread.is_alive():
            self.logger.info("Waiting for main loop thread to join...")
            self.thread.join(timeout=5.0)
            if self.thread.is_alive(): self.logger.warning("Main loop thread did not join cleanly!")
            else: self.logger.info("Main loop thread joined.")
        else: self.logger.info("Main loop thread already finished.")
        self.logger.info("StreamManager shutdown complete.")
