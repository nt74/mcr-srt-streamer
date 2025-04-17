# /opt/mcr-srt-streamer/app/stream_manager.py

import gi

gi.require_version("Gst", "1.0")
gi.require_version("Gio", "2.0")
from gi.repository import Gst, GLib, GObject, Gio
import threading
import logging
import os
import subprocess
import time
import re
import json
from collections import defaultdict

# Initialize GStreamer
Gst.init(None)

# Define multicast addresses for internal colorbar streams
COLORBAR_URIS = {"720p50": "udp://224.1.1.1:5004", "1080i25": "udp://224.1.1.1:5005"}


class StreamManager:
    # --- __init__ ---
    def __init__(self, media_folder):
        self.media_folder = media_folder
        self.active_streams = {}
        self.generator_pipelines = (
            {}
        )  # Stores running generator Gst.Pipeline objects {resolution: pipeline}
        self.lock = threading.RLock()
        self.mainloop = GLib.MainLoop()
        self.thread = threading.Thread(target=self.mainloop.run)
        self.thread.daemon = True
        self.thread.start()
        self.logger = logging.getLogger(__name__)
        # Ensure logger has handlers if not configured by Flask app __init__
        if not self.logger.hasHandlers():
            log_handler = logging.StreamHandler()
            log_formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            log_handler.setFormatter(log_formatter)
            self.logger.addHandler(log_handler)
        self.logger.setLevel(logging.INFO)  # Ensure level is set
        self.logger.info(f"StreamManager initialized with media folder: {media_folder}")
        try:
            self.logger.info(f"GStreamer version: {Gst.version_string()}")
        except Exception as e:
            self.logger.error(f"Could not get GStreamer version string: {e}")

    # --- Validation Methods ---
    def _validate_listener_port(self, port):
        try:
            port_int = int(port)
        except (ValueError, TypeError) as e:
            raise ValueError(
                f"Invalid listener port: {port}. Must be 10001-10010."
            ) from e
        if not (10001 <= port_int <= 10010):
            raise ValueError(
                f"Listener port {port_int} outside allowed range (10001-10010)"
            )
        return port_int

    def _validate_target_port(self, port):
        try:
            port_int = int(port)
        except (ValueError, TypeError) as e:
            raise ValueError(f"Invalid target port: {port}. Must be 1-65535.") from e
        if not (1 <= port_int <= 65535):
            raise ValueError(f"Target port {port_int} outside valid range (1-65535)")
        return port_int

    # --- Sanitization/Extraction Methods ---
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
                return obj
            except TypeError:
                return str(obj)

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

    # --- GStreamer Bus/Signal Handlers ---
    def _on_bus_message(self, bus, message, key):
        t = message.type
        with self.lock:
            stream_info = self.active_streams.get(key)
            if not stream_info:
                return True
            mode = stream_info.get("mode", "?")
            config_dict = stream_info.get("config", {})
            input_type = config_dict.get("input_type", "?")
            target_info = stream_info.get("target", "?")
            target = f" to {target_info}" if mode == "caller" else ""
            resolution = config_dict.get("colorbar_resolution", "")
            input_desc = (
                f"{input_type} {resolution}" if input_type == "colorbar" else input_type
            )
            rtp_encap = config_dict.get("rtp_encapsulation", False)  # Get RTP flag
            pipeline_description = f"stream {key} ({mode}{target}, input:{input_desc}{', RTP' if rtp_encap else ''})"

            if t == Gst.MessageType.STATE_CHANGED:
                if message.src == stream_info.get("pipeline"):
                    old_state, new_state, pending_state = message.parse_state_changed()
                    self.logger.info(
                        f"BUS_MSG: {pipeline_description} state changed from {Gst.Element.state_get_name(old_state)} to {Gst.Element.state_get_name(new_state)} (pending: {Gst.Element.state_get_name(pending_state)})"
                    )
                    if (
                        mode == "caller"
                        and new_state == Gst.State.PLAYING
                        and stream_info["connection_status"] == "Connecting..."
                    ):
                        self.logger.info(
                            f"Caller stream {key} reached PLAYING state. Marking as Connected."
                        )
                        stream_info["connection_status"] = "Connected"
                    if new_state == Gst.State.NULL:
                        self.logger.info(
                            f"BUS_MSG: {pipeline_description} successfully transitioned to NULL state."
                        )
                        if key in self.active_streams and self.active_streams[key][
                            "connection_status"
                        ] not in ["Error", "Disconnected", "Stopped"]:
                            self.active_streams[key]["connection_status"] = "Stopped"
            elif t == Gst.MessageType.EOS:
                self.logger.info(
                    f"BUS_MSG: EOS received for {pipeline_description}. Stopping."
                )
                GLib.idle_add(self.stop_stream, key)
            elif t == Gst.MessageType.ERROR:
                err, debug = message.parse_error()
                src_name = (
                    message.src.get_name() if hasattr(message.src, "get_name") else "?"
                )
                self.logger.error(
                    f"BUS_MSG: GStreamer error on {pipeline_description} from element '{src_name}': {err.message}. Debug: {debug}"
                )
                stream_info["connection_status"] = "Error: " + err.message
                GLib.idle_add(self.stop_stream, key)
            elif t == Gst.MessageType.WARNING:
                warn, debug = message.parse_warning()
                src_name = (
                    message.src.get_name() if hasattr(message.src, "get_name") else "?"
                )
                self.logger.warning(
                    f"BUS_MSG: GStreamer warning on {pipeline_description} from element '{src_name}': {warn.message}. Debug: {debug}"
                )
                current_status = stream_info.get("connection_status", "Unknown")
                new_status = None
                msg_lower = warn.message.lower()
                if "failed to authenticate" in msg_lower:
                    new_status = "Auth Error"
                elif (
                    "connection timed out" in msg_lower
                    and current_status == "Connecting..."
                ):
                    new_status = "Connection Failed"
                elif "connection was broken" in msg_lower:
                    new_status = "Broken / Reconnecting"
                elif (
                    "could not bind" in msg_lower
                    or "address already in use" in msg_lower
                ):
                    new_status = "Bind Error"
                    self.logger.error(
                        f"BUS_MSG: Detected potential port bind error via warning for stream {key}."
                    )
                if new_status and current_status != new_status:
                    stream_info["connection_status"] = new_status
                    self.logger.info(
                        f"Updated status for stream {key} to '{new_status}' based on warning."
                    )
        return True

    def _on_caller_added(self, element, socket_id, addr, key):
        ip = self._extract_ip_from_socket_address(addr)
        self.logger.info(
            f"SRT signal 'caller-added' for stream {key}: socket_id={socket_id}, client_ip={ip}"
        )
        with self.lock:
            if key in self.active_streams:
                si = self.active_streams[key]
                if si.get("mode") == "listener":
                    si["connection_status"] = "Connected"
                    si["connected_client"] = addr
                    si["socket_id"] = socket_id
                    self.logger.info(
                        f"Updated LISTENER stream {key} status to Connected, client: {ip}"
                    )
                si.setdefault("connection_history", []).append(
                    {
                        "event": "caller-added",
                        "time": time.time(),
                        "ip": ip,
                        "socket_id": socket_id,
                    }
                )
            else:
                self.logger.warning(
                    f"SRT signal 'caller-added' received for non-existent stream key {key}"
                )

    def _on_caller_removed(self, element, socket_id, addr, key):
        ip = self._extract_ip_from_socket_address(addr)
        self.logger.info(
            f"SRT signal 'caller-removed' for stream {key}: socket_id={socket_id}, client_ip={ip}"
        )
        with self.lock:
            if key in self.active_streams:
                si = self.active_streams[key]
                si.setdefault("connection_history", []).append(
                    {
                        "event": "caller-removed",
                        "time": time.time(),
                        "ip": ip,
                        "socket_id": socket_id,
                    }
                )
                if si.get("mode") == "listener" and si.get("socket_id") == socket_id:
                    si["connection_status"] = "Waiting for connection"
                    si["connected_client"] = None
                    si["socket_id"] = None
                    self.logger.info(
                        f"Cleared tracked client for LISTENER stream {key} as socket {socket_id} disconnected."
                    )

    def _on_caller_rejected(self, element, addr, reason, key):
        ip = self._extract_ip_from_socket_address(addr)
        self.logger.warning(
            f"SRT signal 'caller-rejected' for stream {key}: client_ip={ip}, reason_code={reason}"
        )
        with self.lock:
            if key in self.active_streams:
                if self.active_streams[key]["mode"] == "listener":
                    self.active_streams[key][
                        "connection_status"
                    ] = "Rejected Connection"
                self.active_streams[key].setdefault("connection_history", []).append(
                    {
                        "event": "rejected",
                        "time": time.time(),
                        "ip": ip,
                        "reason": reason,
                    }
                )
            else:
                self.logger.warning(
                    f"SRT signal 'caller-rejected' received for non-existent stream key {key}"
                )

    def _check_gst_element(self, element_name):
        """Checks if a GStreamer element factory exists."""
        factory = Gst.ElementFactory.find(element_name)
        return factory is not None

    def _start_generator_if_needed(self, resolution):
        """Starts the colorbar generator pipeline for the given resolution if not already running."""
        with self.lock:
            if resolution in self.generator_pipelines:
                pipeline = self.generator_pipelines[resolution]
                # Check if pipeline is actually playing (or paused)
                ret, state, pending = pipeline.get_state(0)
                if state >= Gst.State.PAUSED:
                    self.logger.debug(
                        f"Generator pipeline for {resolution} already running."
                    )
                    return True  # Already running or ready
                else:
                    self.logger.warning(
                        f"Generator pipeline for {resolution} exists but is in state {Gst.Element.state_get_name(state)}. Restarting."
                    )
                    self._stop_generator(resolution)  # Stop cleanly before restarting

            self.logger.info(f"Starting generator pipeline for {resolution}...")
            pipeline_str = self._build_generator_pipeline_str(resolution)
            if not pipeline_str:
                self.logger.error(
                    f"Could not build generator pipeline string for {resolution}."
                )
                return False

            try:
                pipeline = Gst.parse_launch(pipeline_str)
            except GLib.Error as e:
                self.logger.error(
                    f"Failed to parse generator pipeline for {resolution}: {e}"
                )
                self.logger.error(
                    f"Problematic generator pipeline string: {pipeline_str}"
                )
                return False

            if not pipeline:
                self.logger.error(
                    f"Gst.parse_launch returned None for generator {resolution}."
                )
                return False

            ret = pipeline.set_state(Gst.State.PLAYING)
            if ret == Gst.StateChangeReturn.FAILURE:
                self.logger.error(
                    f"Failed to set generator pipeline {resolution} to PLAYING."
                )
                pipeline.set_state(Gst.State.NULL)  # Clean up
                return False

            self.logger.info(
                f"Generator pipeline for {resolution} started successfully."
            )
            self.generator_pipelines[resolution] = pipeline
            # We might want a bus watch here too for generator errors, but keeping it simple for now
            return True

    def _build_generator_pipeline_str(self, resolution):
        """Builds the GStreamer pipeline string for the generator."""
        if resolution == "1080i25":
            width, height, framerate = 1920, 1080, "25/1"
            video_caps = f"video/x-raw,width={width},height={height},framerate={framerate},format=I420,interlace-mode=interleaved"
            x264_opts = "tune=zerolatency interlaced=true speed-preset=2 bitrate=4500"
            overlay_text = f"MCR-SRT-STREAMER 1080i25"
            udp_uri = COLORBAR_URIS["1080i25"]
        elif resolution == "720p50":
            width, height, framerate = 1280, 720, "50/1"
            video_caps = f"video/x-raw,width={width},height={height},framerate={framerate},format=I420"
            x264_opts = "tune=zerolatency speed-preset=2 bitrate=4500"
            overlay_text = f"MCR-SRT-STREAMER 720p50"
            udp_uri = COLORBAR_URIS["720p50"]
        else:
            self.logger.error(f"Invalid resolution for generator: {resolution}")
            return None

        video_pipeline_part = (
            f"videotestsrc pattern=smpte-rp-219 is-live=true ! {video_caps} ! "
            f'textoverlay text="{overlay_text}" valignment=bottom halignment=left font-desc="Sans Bold 32" color=0xFFFFFFFF outline-color=0x000000FF shaded-background=true ! '
            f"queue ! x264enc {x264_opts} ! queue ! mux."
        )

        audio_pipeline_part = ""
        audio_src = "audiotestsrc wave=sine freq=1000 volume=0.187 is-live=true ! audio/x-raw,rate=48000,channels=2 ! queue"
        if self._check_gst_element("fdkaacenc"):
            self.logger.info(f"Generator {resolution}: Using fdkaacenc")
            audio_pipeline_part = (
                f"{audio_src} ! fdkaacenc bitrate=384000 ! queue ! mux."
            )
        elif self._check_gst_element("voaacenc"):
            self.logger.info(f"Generator {resolution}: Using voaacenc")
            audio_pipeline_part = f"{audio_src} ! voaacenc bitrate=128000 ! audio/mpeg,mpegversion=4,stream-format=adts ! queue ! mux."
        else:
            self.logger.warning(
                f"Generator {resolution}: No AAC encoder found. Omitting audio."
            )

        # Extract host and port for udpsink
        match = re.match(r"udp://([\d\.]+):(\d+)", udp_uri)
        if not match:
            self.logger.error(f"Invalid UDP URI format for generator: {udp_uri}")
            return None
        udp_host = match.group(1)
        udp_port = match.group(2)

        # Combine with muxer and udpsink
        if audio_pipeline_part:
            pipeline_str = f"{video_pipeline_part} {audio_pipeline_part} mpegtsmux name=mux ! queue ! udpsink host={udp_host} port={udp_port} auto-multicast=true"
        else:
            video_pipeline_no_mux_target = video_pipeline_part.replace(
                "! queue ! mux.", "! queue"
            )
            pipeline_str = f"{video_pipeline_no_mux_target} ! mpegtsmux name=mux ! queue ! udpsink host={udp_host} port={udp_port} auto-multicast=true"

        return pipeline_str

    def _stop_generator(self, resolution):
        """Stops and removes a specific generator pipeline."""
        with self.lock:
            pipeline = self.generator_pipelines.pop(resolution, None)
            if pipeline:
                self.logger.info(f"Stopping generator pipeline for {resolution}...")
                ret = pipeline.set_state(Gst.State.NULL)
                if ret == Gst.StateChangeReturn.FAILURE:
                    self.logger.error(
                        f"Failed to set generator pipeline {resolution} to NULL."
                    )
                else:
                    self.logger.info(f"Generator pipeline {resolution} stopped.")
            else:
                self.logger.debug(
                    f"Generator pipeline for {resolution} not found or already stopped."
                )

    # --- start_stream ---
    def start_stream(self, config, use_target_port_as_key=False):
        key = None
        pipeline = None
        existing_pipeline = None
        srt_uri = ""
        pipeline_str = ""
        DEFAULT_MULTICAST_INTERFACE = "vlan2"  # Default interface if none specified
        try:
            mode = config.get("mode", "listener")
            target_port_config = config.get("target_port")
            listener_port_config = config.get("port")
            rtp_encapsulation = config.get(
                "rtp_encapsulation", False
            )  # Get the new flag

            if mode == "caller":
                key = self._validate_target_port(target_port_config)
            else:
                key = self._validate_listener_port(listener_port_config)

            with self.lock:
                if key in self.active_streams:
                    self.logger.warning(
                        f"Key {key} ({mode}) in use. Stopping existing."
                    )
                    existing_pipeline = self.active_streams.pop(key).get("pipeline")
                else:
                    self.logger.info(f"No existing stream for key {key}.")
            if existing_pipeline:
                self.logger.info(f"Scheduling NULL state for old pipeline {key}.")
                GLib.idle_add(
                    existing_pipeline.set_state,
                    Gst.State.NULL,
                    priority=GLib.PRIORITY_DEFAULT,
                )
                time.sleep(0.5)

            input_type = config.get("input_type", "multicast")
            self.logger.info(
                f"Starting stream {key} with input type: {input_type}, RTP Encapsulation: {rtp_encapsulation}"
            )

            # --- Common SRT Sink Parameters ---
            overhead_bandwidth = int(config.get("overhead_bandwidth", 2))
            latency_ms = int(config.get("latency", 300))
            encryption = config.get("encryption", "none")
            passphrase = config.get("passphrase", "")
            qos_enabled = config.get("qos", False)
            qos_string = str(qos_enabled).lower()
            sink_name = f"srtsink_{key}"
            srt_params = [
                f"mode={mode}",
                "transtype=live",
                f"latency={latency_ms}",
                f"peerlatency={latency_ms}",
                f"rcvbuf={8388608}",
                f"sndbuf={8388608}",
                f"fc={8192}",
                f"tlpktdrop={True}",
                f"overheadbandwidth={overhead_bandwidth}",
                "nakreport=true",
                f"streamid=mcr_stream_{key}",
                f"qos={qos_string}",
            ]
            if encryption != "none":
                if not passphrase or not (10 <= len(passphrase) <= 79):
                    raise ValueError(
                        "Passphrase (10-79 chars) required for selected encryption."
                    )
                pbkeylen = 16 if encryption == "aes-128" else 32
                srt_params.extend([f"passphrase={passphrase}", f"pbkeylen={pbkeylen}"])

            target_address = config.get("target_address")
            target_port_for_uri = key
            listener_port_for_uri = key
            if mode == "caller":
                if not target_address:
                    raise ValueError("Target address required for caller mode.")
                srt_uri = f"srt://{target_address}:{target_port_for_uri}?{'&'.join(srt_params)}"
            else:
                srt_uri = (
                    f"srt://0.0.0.0:{listener_port_for_uri}?{'&'.join(srt_params)}"
                )
            if not srt_uri:
                raise ValueError("Internal error: Failed to construct a valid SRT URI.")
            # --- End Common SRT Sink Parameters ---

            input_detail_log = "N/A"  # Initialize detail log
            rtp_payload_str = ""  # Initialize RTP payload string snippet

            # --- Build pipeline based on input type ---
            if input_type == "file":
                file_path_from_config = config.get("file_path")
                if not (
                    file_path_from_config and isinstance(file_path_from_config, str)
                ):
                    raise ValueError("Missing or invalid 'file_path' in config.")
                media_dir = os.path.abspath(self.media_folder)
                base_filename = os.path.basename(file_path_from_config)
                abs_file_path = os.path.abspath(os.path.join(media_dir, base_filename))
                if not abs_file_path.startswith(media_dir + os.sep):
                    raise ValueError("File path is outside allowed media directory.")
                if not os.path.isfile(abs_file_path):
                    raise FileNotFoundError(f"Media file not found: {abs_file_path}")
                if not abs_file_path.lower().endswith(".ts"):
                    raise ValueError("Only .ts files supported.")
                pipeline_input_str = f'filesrc location="{abs_file_path}"'
                self.logger.info(f"Using file source: {abs_file_path}")
                input_detail_log = base_filename
                # File specific sink settings
                srtsink_sync_param = "true"
                srtsink_wait_param = "true" if mode == "listener" else "false"
                # File specific parse settings
                smoothing_choice = config.get("smoothing_latency_ms", "30")
                try:
                    smoothing_latency_us = int(smoothing_choice) * 1000
                except (ValueError, TypeError):
                    smoothing_latency_us = 30000
                    self.logger.warning(
                        f"Invalid smoothing latency '{smoothing_choice}', using default 30ms."
                    )
                tsparse_name = f"tsparse_{key}"
                pipeline_str = (
                    f"{pipeline_input_str} ! "
                    f'tsparse name="{tsparse_name}" set-timestamps=true alignment=7 smoothing-latency={smoothing_latency_us} parse-private-sections=true ! '
                    f"queue ! "
                    # Note: No rtpmp2tpay here
                    f'srtsink name="{sink_name}" uri="{srt_uri}" async=false sync={srtsink_sync_param} wait-for-connection={srtsink_wait_param}'
                )
            elif input_type == "multicast":
                mc_address = config.get("multicast_address")
                mc_port = config.get("multicast_port")
                mc_protocol = config.get("protocol", "udp")
                if not (mc_address and mc_port):
                    raise ValueError("Missing multicast address or port.")
                if not isinstance(mc_port, int) or not (1 <= mc_port <= 65535):
                    raise ValueError(f"Invalid multicast port: {mc_port}")
                selected_interface = config.get("multicast_interface")
                interface_to_use = (
                    selected_interface
                    if selected_interface
                    else DEFAULT_MULTICAST_INTERFACE
                )
                self.logger.info(
                    f"Multicast interface selected: '{selected_interface}', Using: '{interface_to_use}'"
                )
                if mc_protocol == "udp":
                    if rtp_encapsulation:
                        self.logger.info(f"Enabling RTP encapsulation for stream {key}")
                        rtp_payload_str = "rtpmp2tpay pt=33 mtu=1316 ! queue ! "
                    else:
                        rtp_payload_str = ""  # No RTP encapsulation
                    pipeline_input_str = f'udpsrc uri="udp://{mc_address}:{mc_port}" multicast-iface="{interface_to_use}" buffer-size=20971520 caps="video/mpegts, systemstream=(boolean)true, packetsize=(int)188"'
                    self.logger.info(
                        f"Using UDP source: udp://{mc_address}:{mc_port} on {interface_to_use}"
                    )
                else:
                    raise ValueError(f"Unsupported multicast protocol: {mc_protocol}")
                input_detail_log = f"udp://{mc_address}:{mc_port}"
                # Multicast specific sink settings
                srtsink_sync_param = "false"
                srtsink_wait_param = "true" if mode == "listener" else "false"
                # Multicast specific parse settings
                smoothing_choice = config.get("smoothing_latency_ms", "30")
                try:
                    smoothing_latency_us = int(smoothing_choice) * 1000
                except (ValueError, TypeError):
                    smoothing_latency_us = 30000
                    self.logger.warning(
                        f"Invalid smoothing latency '{smoothing_choice}', using default 30ms."
                    )
                tsparse_name = f"tsparse_{key}"
                pipeline_str = (
                    f"{pipeline_input_str} ! "
                    f'tsparse name="{tsparse_name}" set-timestamps=true alignment=7 smoothing-latency={smoothing_latency_us} parse-private-sections=true ! '
                    f"queue ! "
                    f"{rtp_payload_str}"  # Insert the RTP part (will be empty if not enabled)
                    f'srtsink name="{sink_name}" uri="{srt_uri}" async=false sync={srtsink_sync_param} wait-for-connection={srtsink_wait_param}'
                )
            elif input_type == "colorbar":
                resolution = config.get("colorbar_resolution")
                if not resolution or resolution not in COLORBAR_URIS:
                    raise ValueError(
                        f"Invalid or missing colorbar_resolution: {resolution}"
                    )

                input_detail_log = f"Colorbars {resolution.upper()}"
                self.logger.info(
                    f"Attempting to start/verify generator for {resolution}"
                )
                if not self._start_generator_if_needed(resolution):
                    raise RuntimeError(
                        f"Failed to start required generator pipeline for {resolution}"
                    )

                udp_uri = COLORBAR_URIS[resolution]
                self.logger.info(f"Using UDP source: {udp_uri} for stream {key}")

                # Consumer pipeline settings
                tsparse_name = f"tsparse_{key}"
                srtsink_sync_param = "false"  # Live source from UDP
                srtsink_wait_param = "true" if mode == "listener" else "false"
                if rtp_encapsulation:
                    self.logger.info(
                        f"Enabling RTP encapsulation for colorbar stream {key}"
                    )
                    rtp_payload_str = "rtpmp2tpay pt=33 mtu=1316 ! queue ! "
                else:
                    rtp_payload_str = ""
                pipeline_str = (
                    f'udpsrc uri="{udp_uri}" ! '
                    f'tsparse name="{tsparse_name}" set-timestamps=true ! '  # Removed smoothing here, tsparse defaults are usually ok
                    f"queue ! "
                    f"{rtp_payload_str}"  # Insert RTP part here too
                    f'srtsink name="{sink_name}" uri="{srt_uri}" sync={srtsink_sync_param} wait-for-connection={srtsink_wait_param}'
                )
            else:
                raise ValueError(f"Unsupported input_type: {input_type}")

            pipeline_str = " ".join(pipeline_str.split())
            self.logger.debug(f"Constructed pipeline string {key}: {pipeline_str}")

            self.logger.info(f"Attempting to parse pipeline for stream {key}")
            try:
                pipeline = Gst.parse_launch(pipeline_str)
            except GLib.Error as e:
                self.logger.error(
                    f"GStreamer pipeline PARSE error for key {key}: {str(e)}",
                    exc_info=True,
                )
                self.logger.error(f"Problematic pipeline string: {pipeline_str}")
                if "no element" in str(e).lower():
                    missing_element = str(e).split('"')
                    element_name = (
                        missing_element[1] if len(missing_element) > 1 else "Unknown"
                    )
                    return (
                        False,
                        f"Pipeline parse error: Required GStreamer element '{element_name}' not found. Please install the necessary GStreamer plugin.",
                    )
                elif "Given uri cannot be used" in str(e):
                    return (
                        False,
                        f"Pipeline parse error: Invalid SRT URI format or parameters. Check configuration.",
                    )
                return False, f"Pipeline parse error: {str(e)}"
            if not pipeline:
                raise RuntimeError(f"Gst.parse_launch returned None for stream {key}.")

            bus = pipeline.get_bus()
            bus.add_signal_watch()
            bus.connect("message", self._on_bus_message, key)
            srtsink = pipeline.get_by_name(sink_name)
            if not srtsink:
                GLib.idle_add(pipeline.set_state, Gst.State.NULL)
                raise RuntimeError(f"Cannot find '{sink_name}' element.")
            try:
                srtsink.connect("caller-added", self._on_caller_added, key)
                srtsink.connect("caller-removed", self._on_caller_removed, key)
                srtsink.connect("caller-rejected", self._on_caller_rejected, key)
                self.logger.info(f"Connected SRT signals for stream {key}.")
            except Exception as e:
                self.logger.warning(
                    f"Could not connect SRT signals for stream {key}: {e}"
                )

            stream_info_dict = {
                "pipeline": pipeline,
                "bus": bus,
                "config": config,  # Store the received config including rtp_encapsulation flag
                "srt_uri": srt_uri,
                "mode": mode,
                "start_time": time.time(),
                "connection_status": (
                    "Connecting..." if mode == "caller" else "Waiting for connection"
                ),
                "connected_client": None,
                "socket_id": None,
                "connection_history": [],
            }
            if mode == "caller":
                stream_info_dict["target"] = f"{target_address}:{target_port_for_uri}"
            with self.lock:
                self.active_streams[key] = stream_info_dict

            def set_playing_safe(p, k):
                self.logger.info(
                    f"Attempting final state transition to PLAYING for stream {k}..."
                )
                ret = p.set_state(Gst.State.PLAYING)
                s_map = {
                    Gst.StateChangeReturn.FAILURE: "FAIL",
                    Gst.StateChangeReturn.SUCCESS: "OK",
                    Gst.StateChangeReturn.ASYNC: "ASYNC",
                    Gst.StateChangeReturn.NO_PREROLL: "NO_PREROLL",
                }
                self.logger.info(
                    f"set_state(PLAYING) for stream {k} returned: {s_map.get(ret,'?')}"
                )
                if ret == Gst.StateChangeReturn.FAILURE:
                    self.logger.error(
                        f"Failed to set pipeline state to PLAYING for stream {k}."
                    )
                    with self.lock:
                        if k in self.active_streams:
                            self.active_streams[k]["connection_status"] = "Start Error"

            GLib.idle_add(
                set_playing_safe, pipeline, key, priority=GLib.PRIORITY_DEFAULT
            )
            self.logger.info(f"Scheduled pipeline start for stream {key}.")

            return (
                True,
                f"Stream {mode} ({key}) starting: {input_type} '{input_detail_log}'"
                + (" with RTP" if rtp_encapsulation else ""),
            )

        except (KeyError, ValueError, FileNotFoundError, RuntimeError) as e:
            self.logger.error(
                f"Configuration/Runtime error starting stream {key or 'N/A'}: {str(e)}",
                exc_info=False,  # Set to True for more debug if needed
            )
            if pipeline:
                GLib.idle_add(
                    pipeline.set_state, Gst.State.NULL, priority=GLib.PRIORITY_HIGH
                )
            return False, f"Stream start error: {str(e)}"
        except Exception as e:
            self.logger.error(
                f"Unexpected start error for stream {key or 'N/A'}: {str(e)}",
                exc_info=True,
            )
            if pipeline:
                GLib.idle_add(
                    pipeline.set_state, Gst.State.NULL, priority=GLib.PRIORITY_HIGH
                )
            return False, f"Unexpected error: {str(e)}"

    # --- stop_stream (Unchanged) ---
    def stop_stream(self, stream_key):
        pipeline_to_stop = None
        bus_to_clear = None
        key = -1
        try:
            try:
                key = int(stream_key)
            except (ValueError, TypeError):
                raise ValueError(
                    f"Invalid stream identifier: '{stream_key}'. Must be a number."
                )
            with self.lock:
                if key not in self.active_streams:
                    return False, f"Stream {key} not found or already stopped."
                self.logger.info(f"Attempting to stop stream with key: {key}")
                stream_info = self.active_streams.pop(key)
                pipeline_to_stop = stream_info.get("pipeline")
                bus_to_clear = stream_info.get("bus")
            if pipeline_to_stop:
                if bus_to_clear:
                    try:
                        bus_to_clear.remove_signal_watch()
                        self.logger.debug(
                            f"Removing signal watch from bus for stream {key}."
                        )
                    except Exception as bus_e:
                        self.logger.warning(
                            f"Error removing signal watch for stream {key}: {bus_e}"
                        )
                self.logger.info(f"Scheduling state change to NULL for stream {key}.")

                def set_null_safe(p, k):
                    ret = p.set_state(Gst.State.NULL)
                    s_map = {
                        Gst.StateChangeReturn.FAILURE: "FAIL",
                        Gst.StateChangeReturn.SUCCESS: "OK",
                        Gst.StateChangeReturn.ASYNC: "ASYNC",
                        Gst.StateChangeReturn.NO_PREROLL: "NO_PREROLL",
                    }
                    self.logger.info(
                        f"Async set_state(NULL) for stream {k} returned: {s_map.get(ret, 'Unknown')}"
                    )
                    if ret == Gst.StateChangeReturn.FAILURE:
                        self.logger.error(
                            f"Failed to set pipeline state to NULL for stream {k} via idle_add."
                        )

                GLib.idle_add(
                    set_null_safe, pipeline_to_stop, key, priority=GLib.PRIORITY_DEFAULT
                )
                return True, f"Stream {key} stop initiated."
            else:
                self.logger.warning(
                    f"Stream {key} was active but no pipeline object found."
                )
                return False, f"Stream {key} active but pipeline missing."
        except ValueError as e:
            self.logger.error(f"Stop validation error: {str(e)}")
            return False, str(e)
        except Exception as e:
            self.logger.error(
                f"Unexpected error stopping stream {stream_key}: {str(e)}",
                exc_info=True,
            )
            if pipeline_to_stop:
                try:
                    GLib.idle_add(
                        pipeline_to_stop.set_state,
                        Gst.State.NULL,
                        priority=GLib.PRIORITY_HIGH,
                    )
                    self.logger.info(
                        f"Attempted cleanup set_state NULL for {key} after error."
                    )
                except Exception as cleanup_e:
                    self.logger.warning(
                        f"Ignoring error during cleanup NULL scheduling for {key}: {cleanup_e}"
                    )
            with self.lock:
                if isinstance(key, int) and key > 0 and key in self.active_streams:
                    self.logger.warning(
                        f"Stream {key} still in active_streams during exception, removing."
                    )
                    del self.active_streams[key]
            return False, f"An unexpected error occurred stopping stream: {str(e)}"

    # --- _extract_stats_from_gstruct ---
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
                    self.logger.warning(
                        f"StatsParse: Fail convert '{value_str_unquoted}' as {value_type}"
                    )
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
                for match in pattern.finditer(text_to_parse):
                    key_raw, value_type, value_part = match.groups()[:3]
                    key = key_raw.replace("-", "_")
                    if key not in processed_keys:
                        target_dict[key] = parse_value(value_part, value_type)
                        processed_keys.add(key)

            payload_str = raw_stats_string_for_debug
            if "," in payload_str:
                payload_str = payload_str.split(",", 1)[1]
            payload_str = payload_str.strip(";{} ")
            if "callers=" in payload_str:
                inner_kv_string = None
                top_level_str = payload_str
                callers_match = re.search(
                    r"callers=\(GValueArray\)<(.*?)>", payload_str, re.DOTALL
                )
                if callers_match:
                    callers_content = callers_match.group(1).strip()
                    inner_struct_match = re.match(
                        r'\s*"(?:application/x-srt-statistics\\,)?(.*?)\s*;?"\s*',
                        callers_content,
                        re.DOTALL,
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
                    else:
                        self.logger.warning(
                            f"StatsParse: No inner kv: {callers_content[:100]}..."
                        )
                else:
                    self.logger.warning("StatsParse: 'callers=' fail.")
                if inner_kv_string:
                    parse_with_finditer(inner_kv_string, result, inner_listener_pattern)
                parse_with_finditer(top_level_str, result, top_level_listener_pattern)
            else:
                parse_with_finditer(payload_str, result, caller_pattern)
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
                "bitrate_mbps": 0.0,
                "rtt_ms": 0.0,
                "loss_rate": 0.0,
                "packets_sent_total": 0,
                "packets_lost_total": 0,
                "packets_retransmitted_total": 0,
                "bytes_sent_total": 0,
                "packet_loss_percent": 0.0,
                "estimated_bandwidth_mbps": 0.0,
                "packets_received_total": 0,
                "packets_received_lost": 0,
                "packets_received_retransmitted": 0,
                "packets_received_dropped": 0,
                "bytes_sent": 0,
                "bytes_received": 0,
                "bytes_retransmitted": 0,
                "bytes_sent_dropped": 0,
                "bytes_received_lost": 0,
                "packet_ack_received": 0,
                "packet_nack_received": 0,
                "packet_ack_sent": 0,
                "packet_nack_sent": 0,
                "send_buffer_level_ms": 0,
                "recv_buffer_level_ms": 0,
                "flow_window": 0,
                "negotiated_latency_ms": 0,
            }
            for fk, sks in final_key_map.items():
                v = None
                for sk in sks:
                    if sk in result:
                        v = result[sk]
                        break
                final_key_name = (
                    fk.replace("br", "bitrate")
                    .replace("pkt_", "packets_")
                    .replace("_s", "")
                )
                final_result[final_key_name] = (
                    v if v is not None else final_result.get(final_key_name)
                )
            s, l = final_result.get("packets_sent_total", 0), final_result.get(
                "packets_lost_total", 0
            )
            final_result["packet_loss_percent"] = (
                round((l / s) * 100, 2)
                if isinstance(s, (int, float)) and isinstance(l, (int, float)) and s > 0
                else 0.0
            )
            for k, v in result.items():
                final_result.setdefault(k, v)
            return final_result
        except Exception as e:
            self.logger.error(f"CRITICAL Error parsing SRT stats: {e}", exc_info=True)
            return {
                "error": f"Parse Fail: {e}",
                "raw_string": raw_stats_string_for_debug,
            }

    # --- get_stream_statistics ---
    def get_stream_statistics(self, stream_key):
        pipeline = None
        stream_info_copy = None
        try:
            key = int(stream_key)
            with self.lock:
                if key not in self.active_streams:
                    self.logger.warning(
                        f"Stats requested for non-existent stream key {key}"
                    )
                    return {"error": f"Stream {key} not found"}
                stream_info = self.active_streams[key]
                pipeline = stream_info.get("pipeline")
                stream_info_copy = {
                    "mode": stream_info.get("mode"),
                    "connection_status": stream_info.get("connection_status"),
                    "connected_client": stream_info.get("connected_client"),
                    "start_time": stream_info.get("start_time", time.time()),
                    "config": stream_info.get("config", {}),
                }
            stats = {
                "connection_status": stream_info_copy.get(
                    "connection_status", "Unknown"
                ),
                "connected_client": self._extract_ip_from_socket_address(
                    stream_info_copy.get("connected_client")
                ),
                "uptime": self._format_uptime(
                    time.time() - stream_info_copy.get("start_time", time.time())
                ),
                "last_updated": time.time(),
                "config": stream_info_copy.get("config", {}),
            }
            if pipeline:
                ret_state, current_state, pending_state = pipeline.get_state(
                    0
                )  # Corrected unpacking
                if ret_state == Gst.StateChangeReturn.FAILURE:
                    stats["error"] = "Failed to get pipeline state."
                    self.logger.warning(
                        f"Failed to get pipeline state for stream {key}"
                    )
                elif current_state < Gst.State.PAUSED:
                    state_name = Gst.Element.state_get_name(current_state)
                    stats["error"] = f"Pipeline not running (State: {state_name})"
                    if stats["connection_status"] != "Error":
                        stats["connection_status"] = stream_info_copy.get(
                            "connection_status", "Unknown"
                        )
                else:
                    sink_name = f"srtsink_{key}"
                    srtsink = pipeline.get_by_name(sink_name)
                    if srtsink:
                        try:
                            stats_struct = srtsink.get_property("stats")
                            parsed_stats = {}
                            if stats_struct and isinstance(stats_struct, Gst.Structure):
                                parsed_stats = self._extract_stats_from_gstruct(
                                    stats_struct
                                )
                                stats.update(parsed_stats)
                            elif not stats_struct:
                                self.logger.warning(
                                    f"srtsink.get_property('stats') returned None for stream {key}"
                                )
                                stats["error"] = (
                                    "Failed to retrieve stats structure (returned None)"
                                )
                            else:
                                self.logger.warning(
                                    f"Stats property for {key} is not a Gst.Structure: {type(stats_struct)}"
                                )
                                stats["error"] = (
                                    f"Invalid stats structure type: {type(stats_struct)}"
                                )
                            if "error" in parsed_stats:
                                self.logger.warning(
                                    f"Stats parse error for stream {key}: {parsed_stats['error']}"
                                )
                                stats["parse_error"] = parsed_stats["error"]
                        except Exception as e:
                            self.logger.error(
                                f"Error getting/parsing stats property for {key}: {str(e)}"
                            )
                            stats["error"] = f"Stats fetch/parse error: {str(e)}"
                    else:
                        stats["error"] = f"srtsink '{sink_name}' not found."
            else:
                stats["error"] = "Pipeline object not found (stream may have stopped)."
                stats["connection_status"] = "Stopped"
            return stats
        except ValueError as e:
            self.logger.error(f"Get stats validation error: {e}")
            return {"error": f"Invalid stream key: {stream_key}"}
        except Exception as e:
            self.logger.error(
                f"Unexpected error getting stats for {stream_key}: {e}", exc_info=True
            )
            return {"error": f"Unexpected error retrieving stats: {str(e)}"}

    # --- get_active_streams ---
    def get_active_streams(self):
        try:
            with self.lock:
                if not self.active_streams:
                    return {}
                streams = {}
                now = time.time()
                for key, stream_info in self.active_streams.items():
                    mode = stream_info.get("mode", "unknown")
                    config = stream_info.get("config", {})
                    status = stream_info.get("connection_status", "Unknown")
                    start_time = stream_info.get("start_time", now)
                    client_addr = stream_info.get("connected_client")
                    target = stream_info.get("target") if mode == "caller" else None
                    input_type = config.get("input_type", "unknown")
                    if input_type == "file":
                        source_detail = os.path.basename(config.get("file_path", "N/A"))
                    elif input_type == "multicast":
                        source_detail = f"{config.get('multicast_address','?')}:{config.get('multicast_port','?')}"
                    elif input_type == "colorbar":
                        source_detail = (
                            f"Colorbars {config.get('colorbar_resolution', '?')}"
                        )
                    else:
                        source_detail = "N/A"
                    if (
                        mode == "caller"
                        and status == "Connecting..."
                        and (now - start_time) > 30
                    ):
                        status = "Connection Failed"
                    stream_data = {
                        "key": key,
                        "mode": mode,
                        "connection_status": status,
                        "uptime": self._format_uptime(now - start_time),
                        "input_type": input_type,
                        "source_detail": source_detail,
                        "latency": config.get("latency", "?"),
                        "overhead_bandwidth": config.get("overhead_bandwidth", "?"),
                        "encryption": config.get("encryption", "none"),
                        "passphrase_set": bool(config.get("passphrase"))
                        and config.get("encryption", "none") != "none",
                        "qos_enabled": config.get("qos", False),
                        "smoothing_latency_ms": config.get("smoothing_latency_ms", "?"),
                        "port": (
                            config.get("port")
                            if mode == "listener"
                            else config.get("target_port")
                        ),
                        "target": target,
                        "client_ip": self._extract_ip_from_socket_address(client_addr),
                        "srt_uri": stream_info.get("srt_uri", ""),
                        "start_time": (
                            time.strftime(
                                "%Y-%m-%d %H:%M:%S UTC", time.gmtime(start_time)
                            )
                            if start_time
                            else "N/A"
                        ),
                        "config": config,  # Include full config
                    }
                    streams[key] = self._sanitize_for_json(stream_data)
            return streams
        except Exception as e:
            self.logger.error(
                f"Error retrieving active streams: {str(e)}", exc_info=True
            )
            return {"error": f"Failed to retrieve active streams: {str(e)}"}

    # --- _format_uptime ---
    def _format_uptime(self, seconds):
        try:
            seconds_int = int(seconds)
            if seconds_int < 0:
                return "0s"
            days, rem_d = divmod(seconds_int, 86400)
            hrs, rem_h = divmod(rem_d, 3600)
            mins, secs = divmod(rem_h, 60)
            parts = (
                [f"{d}d" for d in [days] if d > 0]
                + [f"{h}h" for h in [hrs] if h > 0]
                + [f"{m}m" for m in [mins] if m > 0]
                + [f"{s}s" for s in [secs] if s >= 0 or not parts]
            )
            return " ".join(parts) if parts else "0s"
        except Exception as e:
            self.logger.error(f"Error formatting uptime: {e}")
            return "Error"

    # --- get_file_info ---
    def get_file_info(self, file_path):
        media_dir = os.path.abspath(self.media_folder)
        base_filename = os.path.basename(file_path)  # Use base filename
        abs_file_path = os.path.abspath(os.path.join(media_dir, base_filename))
        if not abs_file_path.startswith(media_dir + os.sep):
            return json.dumps(
                {
                    "error": f"Access denied: File path '{base_filename}' is outside the media directory."
                },
                indent=2,
            )
        if not os.path.isfile(abs_file_path):
            return json.dumps({"error": f"File not found: {base_filename}"}, indent=2)
        try:
            cmd = ["mediainfo", "--Output=JSON", abs_file_path]
            r = subprocess.run(
                cmd, capture_output=True, text=True, check=True, timeout=20
            )
            try:
                media_info_data = json.loads(r.stdout).get("media", {})
                return json.dumps(media_info_data, indent=2)
            except json.JSONDecodeError as json_e:
                self.logger.error(
                    f"Failed to decode mediainfo JSON output for {base_filename}: {json_e}"
                )
                return json.dumps(
                    {
                        "error": f"mediainfo returned invalid JSON: {str(json_e)}",
                        "raw_output": r.stdout[:500]
                        + ("..." if len(r.stdout) > 500 else ""),
                    },
                    indent=2,
                )
        except FileNotFoundError:
            self.logger.error(
                "mediainfo command not found. Please ensure it is installed and in the system PATH."
            )
            return json.dumps({"error": "mediainfo command not found."}, indent=2)
        except subprocess.TimeoutExpired:
            self.logger.error(f"mediainfo timed out for file: {base_filename}")
            return json.dumps({"error": "mediainfo timed out."}, indent=2)
        except subprocess.CalledProcessError as e_mi:
            self.logger.error(
                f"mediainfo failed for {base_filename} (Code {e_mi.returncode}): {e_mi.stderr or e_mi.stdout}"
            )
            return json.dumps(
                {
                    "error": f"mediainfo failed (Code {e_mi.returncode}): {e_mi.stderr or e_mi.stdout}"
                },
                indent=2,
            )
        except Exception as e:
            self.logger.error(
                f"An unexpected error occurred during mediainfo execution for {base_filename}: {str(e)}",
                exc_info=True,
            )
            return json.dumps(
                {"error": f"mediainfo execution failed: {str(e)}"}, indent=2
            )

    # --- get_debug_info ---
    def get_debug_info(self, stream_key):
        si_copy = None
        pipeline = None
        try:
            key = int(stream_key)
            with self.lock:
                si = self.active_streams.get(key)
                if not si:
                    return {"error": f"Stream {key} not found"}
                pipeline = si.get("pipeline")
                cfg_copy = json.loads(
                    json.dumps(si.get("config", {}), default=str)
                )  # Use default=str for serialization
                si_copy = {
                    "mode": si.get("mode", "?"),
                    "uri": si.get("srt_uri"),
                    "stat": si.get("connection_status"),
                    "client": si.get("connected_client"),
                    "start": si.get("start_time", 0),
                    "cfg": cfg_copy,
                    "hist": si.get("connection_history", []).copy(),
                }
            cfg = si_copy["cfg"]
            i_type = cfg.get("input_type", "?")
            if i_type == "file":
                s_detail = os.path.basename(cfg.get("file_path", "N/A"))
            elif i_type == "multicast":
                s_detail = f"udp://{cfg.get('multicast_address','?')}:{cfg.get('multicast_port','?')}"
            elif i_type == "colorbar":
                s_detail = f"Colorbars {cfg.get('colorbar_resolution', '?')}"
            else:
                s_detail = "N/A"
            debug = {
                "key": key,
                "mode": si_copy["mode"],
                "input": i_type,
                "src": s_detail,
                "target": (
                    cfg.get("target_address", None)
                    if si_copy["mode"] == "caller"
                    else None
                ),
                "uri": si_copy["uri"],
                "stat": si_copy["stat"],
                "client_ip": self._extract_ip_from_socket_address(si_copy["client"]),
                "uptime": self._format_uptime(time.time() - si_copy["start"]),
                "cfg": self._sanitize_for_json(cfg),
                "hist": self._sanitize_for_json(si_copy["hist"]),
            }
            if pipeline:
                ret_st, cur_st, pend_st = pipeline.get_state(0)  # Corrected unpacking
                debug["pipeline_state"] = (
                    Gst.Element.state_get_name(cur_st)
                    if ret_st != Gst.StateChangeReturn.FAILURE
                    else "Error getting state"
                )
                sink = pipeline.get_by_name(f"srtsink_{key}")
                if not sink:
                    debug["stats_error"] = "SRT sink element not found in pipeline."
                else:
                    try:
                        stats_struct = sink.get_property("stats")
                        if stats_struct and isinstance(stats_struct, Gst.Structure):
                            debug["raw_stats"] = stats_struct.to_string()
                            parsed_stats = self._extract_stats_from_gstruct(
                                stats_struct
                            )
                            debug["parsed_stats"] = parsed_stats
                            if "error" in parsed_stats:
                                debug["parse_error"] = parsed_stats["error"]
                        elif stats_struct is None:
                            debug["stats_error"] = (
                                "Failed to retrieve stats structure (returned None)."
                            )
                        else:
                            debug["stats_error"] = (
                                f"Invalid stats structure type: {type(stats_struct)}"
                            )
                    except Exception as e:
                        debug["stats_error"] = f"Error getting stats property: {str(e)}"
            else:
                debug["stats_error"] = (
                    "Pipeline object not found (stream may have stopped)."
                )
            return self._sanitize_for_json(debug)
        except ValueError as e:
            return {"error": str(e)}
        except Exception as e:
            self.logger.error(f"Unexpected debug err: {e}", exc_info=True)
            return {"error": f"Unexpected error: {e}"}

    # --- shutdown (Modified to stop generators) ---
    def shutdown(self):
        self.logger.info("Shutting down StreamManager...")

        # Stop active SRT streams
        with self.lock:
            active_keys = list(self.active_streams.keys())
            self.logger.info(f"Stopping {len(active_keys)} active SRT streams...")
        keys_to_stop = list(active_keys)
        for k in keys_to_stop:
            self.logger.info(f"Requesting stop for SRT stream {k}")
            self.stop_stream(k)  # This already handles removing from active_streams

        with self.lock:
            generator_keys = list(self.generator_pipelines.keys())
            self.logger.info(f"Stopping {len(generator_keys)} generator pipelines...")
        gen_keys_to_stop = list(generator_keys)
        for res in gen_keys_to_stop:
            self._stop_generator(res)  # This handles removing from generator_pipelines

        time.sleep(1.5)  # Allow time for pipelines to transition to NULL

        with self.lock:
            remaining_streams = len(self.active_streams)
            remaining_generators = len(self.generator_pipelines)
            if remaining_streams > 0:
                self.logger.warning(
                    f"{remaining_streams} SRT streams potentially did not stop cleanly."
                )
            if remaining_generators > 0:
                self.logger.warning(
                    f"{remaining_generators} generator streams potentially did not stop cleanly."
                )

        if self.mainloop.is_running():
            self.logger.info("Quitting GLib MainLoop...")
            self.mainloop.quit()
        if self.thread.is_alive():
            self.logger.info("Waiting for main loop thread to join...")
            self.thread.join(timeout=5.0)
            if self.thread.is_alive():
                self.logger.warning("Main loop thread did not join cleanly!")
            else:
                self.logger.info("Main loop thread joined.")
        else:
            self.logger.info("Main loop thread already finished.")
        self.logger.info("StreamManager shutdown complete.")
