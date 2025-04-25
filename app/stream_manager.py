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
import traceback  # Import traceback for detailed exception logging
from datetime import datetime, timedelta  # Import timedelta for uptime formatting
import socket  # Needed for IP address family check

# Initialize GStreamer
Gst.init(None)

# Define multicast addresses for internal colorbar streams
COLORBAR_URIS = {"720p50": "udp://224.1.1.1:5004", "1080i25": "udp://224.1.1.1:5005"}
DEFAULT_MULTICAST_INTERFACE = "vlan2"  # Default interface if none specified


class StreamManager:
    # --- __init__ ---
    def __init__(self, media_folder):
        self.media_folder = media_folder
        self.active_streams = {}
        self.generator_pipelines = {}
        self.lock = threading.RLock()
        self.logger = logging.getLogger(__name__)
        if not self.logger.hasHandlers():
            log_handler = logging.StreamHandler()
            log_formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            log_handler.setFormatter(log_formatter)
            self.logger.addHandler(log_handler)
            self.logger.setLevel(logging.INFO)

        self.logger.info("Initializing GLib main loop and starting thread...")
        self.mainloop = GLib.MainLoop()
        self.thread = threading.Thread(target=self._run_mainloop, daemon=True)
        self.thread.start()
        self.logger.info("GLib main loop thread started.")

        self.logger.info(f"StreamManager initialized with media folder: {media_folder}")
        try:
            self.logger.info(f"GStreamer version: {Gst.version_string()}")
        except Exception as e:
            self.logger.error(f"Could not get GStreamer version string: {e}")

    # --- Main Loop Runner ---
    def _run_mainloop(self):
        self.logger.info("GLib main loop thread entering run()...")
        try:
            self.mainloop.run()
            self.logger.info("GLib main loop thread exited run().")
        except Exception as e:
            self.logger.error(f"Exception in GLib main loop thread: {e}", exc_info=True)
        finally:
            if self.mainloop and self.mainloop.is_running():
                self.logger.warning(
                    "GLib main loop context still running after thread exit."
                )
            else:
                self.logger.info("GLib main loop thread finished cleanly.")

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
        if isinstance(obj, timedelta):
            # Return total seconds for JSON compatibility
            return obj.total_seconds()
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, (list, tuple)):
            return [self._sanitize_for_json(item) for item in obj]
        if isinstance(obj, dict):
            # Ensure keys are strings and values are sanitized
            return {str(k): self._sanitize_for_json(v) for k, v in obj.items()}
        if isinstance(obj, (Gio.SocketAddress, Gio.InetAddress, Gio.InetSocketAddress)):
            return self._extract_ip_from_socket_address(obj)
        if isinstance(obj, (GObject.GObject, GLib.Error)):
            return str(obj)
        try:
            # Check if serializable directly, use default=str in endpoint jsonify instead
            return obj
        except TypeError:
            # Fallback to string representation only if direct use fails
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
            elif isinstance(addr, Gio.SocketAddress):  # More generic handling
                return str(addr)
            else:
                return str(addr)
        except Exception as e:
            self.logger.warning(
                f"Could not extract IP from address object ({type(addr)}): {e}"
            )
            return str(addr)

    # --- Utility to format uptime ---
    def _format_uptime(self, seconds):
        try:
            td = timedelta(seconds=int(seconds))
            return str(td)
        except (ValueError, TypeError):
            self.logger.error(
                f"Error formatting uptime for seconds: {seconds}", exc_info=False
            )
            return "Error"

    # --- Helper for Resource Cleanup ---
    def _cleanup_stream_resources(self, key, bus_obj):
        self.logger.info(
            f"Performing final cleanup for stream {key} (bus watch, etc.)."
        )
        if bus_obj:
            try:
                bus_obj.remove_signal_watch()
                self.logger.debug(f"Removed signal watch for stream {key}.")
            except Exception as bus_e:
                self.logger.warning(
                    f"Error removing signal watch for stream {key}: {bus_e}"
                )

    # --- Helper to schedule NULL state ---
    def _schedule_null_state(self, pipeline, key):
        if pipeline:
            self.logger.info(
                f"Scheduling state change to NULL for stream key {key} via idle_add."
            )

            def set_null_safe(p, k):
                self.logger.debug(f"Executing async set_state(NULL) for stream {k}...")
                try:
                    ret = p.set_state(Gst.State.NULL)
                    state_map = {
                        Gst.StateChangeReturn.FAILURE: "FAIL",
                        Gst.StateChangeReturn.SUCCESS: "OK",
                        Gst.StateChangeReturn.ASYNC: "ASYNC",
                        Gst.StateChangeReturn.NO_PREROLL: "NO_PREROLL",
                    }
                    self.logger.info(
                        f"Async set_state(NULL) for stream {k} returned: {state_map.get(ret,'?')}"
                    )
                except Exception as e_state:
                    self.logger.error(
                        f"Exception during async set_state(NULL) for stream {k}: {e_state}",
                        exc_info=True,
                    )
                return False  # Remove idle source

            GLib.idle_add(set_null_safe, pipeline, key, priority=GLib.PRIORITY_DEFAULT)
            return True
        else:
            self.logger.warning(
                f"Cannot schedule NULL state for stream key {key}: Pipeline object is None."
            )
            return False

    # --- Bus Message Handler (Handles NULL state after pop) ---
    def _on_bus_message(self, bus, message, key):
        """Handles messages from the standard stream pipeline bus."""
        t = message.type
        msg_src = message.src
        pipeline_obj = None
        bus_obj = None
        is_stopping = False
        should_disconnect_handler = False
        stream_info = None
        self.logger.debug(
            f"Bus handler invoked for key: {key} (type: {type(key)})"
        )  # Keep DEBUG
        try:
            try:
                with self.lock:
                    stream_info = self.active_streams.get(key)
                    if stream_info:
                        pipeline_obj = stream_info.get("pipeline")
                        bus_obj = stream_info.get("bus")
                        is_stopping = stream_info.get("stopping", False)
                    else:
                        self.logger.debug(
                            f"Stream {key} not in active_streams, likely already stopped/popped."
                        )  # Keep DEBUG
                        if t == Gst.MessageType.STATE_CHANGED and isinstance(
                            msg_src, Gst.Pipeline
                        ):
                            pipeline_obj = msg_src

                if t == Gst.MessageType.STATE_CHANGED:
                    if pipeline_obj and msg_src == pipeline_obj:
                        old_state, new_state, _ = message.parse_state_changed()
                        new_state_name = Gst.Element.state_get_name(new_state)
                        old_state_name = Gst.Element.state_get_name(old_state)
                        self.logger.info(
                            f"BUS_MSG: Stream {key} state changed from {old_state_name} to {new_state_name}"
                        )  # Keep INFO

                        if int(new_state) == Gst.State.NULL:
                            self.logger.info(
                                f"Stream {key} NULL state message received. Performing resource cleanup."
                            )  # Keep INFO
                            try:
                                if not bus_obj and stream_info:
                                    bus_obj = stream_info.get("bus")
                                self.logger.debug(
                                    f"Stream {key}: Calling _cleanup_stream_resources..."
                                )  # Keep DEBUG
                                self._cleanup_stream_resources(key, bus_obj)
                                self.logger.debug(
                                    f"Stream {key}: Returned from _cleanup_stream_resources."
                                )  # Keep DEBUG
                                should_disconnect_handler = True
                                self.logger.info(
                                    f"Stream {key}: NULL state resource cleanup complete. Marking handler disconnect."
                                )  # Keep INFO
                            except Exception as cleanup_e:
                                self.logger.error(
                                    f"Stream {key}: Exception during NULL state resource cleanup: {cleanup_e}",
                                    exc_info=True,
                                )  # Keep ERROR
                                should_disconnect_handler = False
                        else:
                            self.logger.debug(
                                f"Stream {key}: State change detected ({old_state_name}->{new_state_name}). Checking if update needed."
                            )  # Keep DEBUG
                            with self.lock:
                                if key in self.active_streams:
                                    if not is_stopping:
                                        current_status = self.active_streams[key].get(
                                            "connection_status", "Unknown"
                                        )
                                        new_status_str = None
                                        mode = self.active_streams[key].get("mode", "?")
                                        if new_state == Gst.State.PLAYING:
                                            # Change status based on context (Caller connecting vs general running)
                                            if (
                                                mode == "caller"
                                                and current_status == "Connecting..."
                                            ):
                                                new_status_str = "Connected"  # Or keep as "Running" if preferred
                                            elif current_status not in [
                                                "Running",
                                                "Connected",
                                            ]:  # Avoid flapping if already Running/Connected
                                                new_status_str = "Running"
                                        elif new_state == Gst.State.PAUSED:
                                            new_status_str = "Paused"
                                        elif new_state == Gst.State.READY:
                                            new_status_str = "Ready"

                                        if (
                                            new_status_str
                                            and new_status_str != current_status
                                            and not current_status.startswith("Error")
                                        ):
                                            self.logger.info(
                                                f"Stream {key}: Updating status '{current_status}' to '{new_status_str}'"
                                            )  # Keep INFO
                                            self.active_streams[key][
                                                "connection_status"
                                            ] = new_status_str
                                    else:
                                        self.logger.debug(
                                            f"Stream {key}: State change to {new_state_name} received but stream is stopping. Ignoring status update."
                                        )  # Keep DEBUG
                                else:
                                    self.logger.debug(
                                        f"Stream {key}: State change to {new_state_name} received but stream already popped. Ignoring status update."
                                    )  # Keep DEBUG
                    elif pipeline_obj:
                        self.logger.warning(
                            f"Stream {key}: STATE_CHANGED source ({msg_src}) != expected ({pipeline_obj}). Ignoring."
                        )  # Keep WARNING
                    else:
                        self.logger.debug(
                            f"Stream {key}: STATE_CHANGED received but pipeline_obj is None (likely already stopped/popped)."
                        )  # Keep DEBUG

                elif t == Gst.MessageType.ERROR:
                    err, debug = message.parse_error()
                    src_name = (
                        msg_src.get_name() if hasattr(msg_src, "get_name") else "?"
                    )
                    pipeline_description = f"stream {key} (details maybe lost)"
                    with self.lock:
                        stream_info = self.active_streams.get(key)
                    if stream_info:
                        config_dict = stream_info.get("config", {})
                        mode = stream_info.get("mode", "?")
                        input_type = config_dict.get("input_type", "?")
                        rtp_encap = config_dict.get("rtp_encapsulation", False)
                        pipeline_description = f"stream {key} ({mode}, input:{input_type}{', RTP' if rtp_encap else ''})"
                    self.logger.error(
                        f"BUS_MSG: GStreamer error on {pipeline_description} from '{src_name}': {err.message}. Debug: {debug}"
                    )  # Keep ERROR
                    # ... (rest of error handling logic remains the same) ...
                    with self.lock:
                        if key in self.active_streams and not self.active_streams[
                            key
                        ].get("stopping", False):
                            self.active_streams[key]["connection_status"] = (
                                "Error: " + err.message
                            )
                            self.active_streams[key]["stopping"] = True
                            self.logger.info(
                                f"Scheduling NULL state for {key} due to error."
                            )
                            current_pipeline = self.active_streams[key].get("pipeline")
                            if current_pipeline:
                                GLib.idle_add(
                                    self._schedule_null_state, current_pipeline, key
                                )
                            else:
                                self.logger.error(
                                    f"Cannot schedule NULL state for {key} on error: pipeline object missing."
                                )
                        elif key in self.active_streams:
                            self.logger.info(
                                f"Bus error for stream {key}, but already stopping."
                            )
                        else:
                            self.logger.warning(
                                f"Bus error for stream {key}, but no longer active."
                            )

                elif t == Gst.MessageType.EOS:
                    pipeline_description = f"stream {key} (details maybe lost)"
                    with self.lock:
                        stream_info = self.active_streams.get(key)
                    if stream_info:
                        config_dict = stream_info.get("config", {})
                        mode = stream_info.get("mode", "?")
                        input_type = config_dict.get("input_type", "?")
                        rtp_encap = config_dict.get("rtp_encapsulation", False)
                        pipeline_description = f"stream {key} ({mode}, input:{input_type}{', RTP' if rtp_encap else ''})"
                    self.logger.info(
                        f"BUS_MSG: EOS received for {pipeline_description}. Initiating stop."
                    )  # Keep INFO
                    # ... (rest of EOS handling logic remains the same) ...
                    with self.lock:
                        if key in self.active_streams and not self.active_streams[
                            key
                        ].get("stopping", False):
                            self.active_streams[key][
                                "connection_status"
                            ] = "Ended (EOS)"
                            self.active_streams[key]["stopping"] = True
                            self.logger.info(
                                f"Scheduling NULL state for stream {key} due to EOS."
                            )
                            current_pipeline = self.active_streams[key].get("pipeline")
                            if current_pipeline:
                                GLib.idle_add(
                                    self._schedule_null_state, current_pipeline, key
                                )
                            else:
                                self.logger.error(
                                    f"Cannot schedule NULL state for {key} on EOS: pipeline object missing."
                                )
                        elif key in self.active_streams:
                            self.logger.info(
                                f"Bus EOS for stream {key}, but already stopping."
                            )
                        else:
                            self.logger.warning(
                                f"Bus EOS for stream {key}, but no longer active."
                            )

                elif t == Gst.MessageType.WARNING:
                    warn, debug = message.parse_warning()
                    src_name = (
                        msg_src.get_name() if hasattr(msg_src, "get_name") else "?"
                    )
                    pipeline_description = f"stream {key} (details maybe lost)"
                    with self.lock:
                        stream_info = self.active_streams.get(key)
                    if stream_info:
                        config_dict = stream_info.get("config", {})
                        mode = stream_info.get("mode", "?")
                        input_type = config_dict.get("input_type", "?")
                        rtp_encap = config_dict.get("rtp_encapsulation", False)
                        pipeline_description = f"stream {key} ({mode}, input:{input_type}{', RTP' if rtp_encap else ''})"
                    self.logger.warning(
                        f"BUS_MSG: GStreamer warning on {pipeline_description} from '{src_name}': {warn.message}. Debug: {debug}"
                    )  # Keep WARNING

            except Exception as e:
                self.logger.error(
                    f"!!! Uncaught exception in bus handler for stream {key} !!!: {e}",
                    exc_info=True,
                )  # Keep ERROR
        finally:
            self.logger.debug(
                f"Stream {key}: Bus handler finishing. Disconnecting handler: {should_disconnect_handler}"
            )  # Keep DEBUG
            return not should_disconnect_handler

    # --- stop_stream ---
    def stop_stream(self, stream_key, force_remove=False):
        # Keep existing logs at INFO/WARNING/ERROR
        """Stops a stream by immediately removing it from the active list and then attempting GStreamer cleanup."""
        pipeline_to_cleanup = None
        bus_obj_to_cleanup = None
        key = -1
        stream_was_active = False

        try:
            key = int(stream_key)
            if key <= 0:
                raise ValueError("Stream key must be positive")

            with self.lock:
                if key in self.active_streams:
                    stream_was_active = True
                    self.logger.info(
                        f"Stop Stream: Request received for active stream {key}. Removing from active list."
                    )
                    stream_info = self.active_streams.get(key)
                    if stream_info:
                        pipeline_to_cleanup = stream_info.get("pipeline")
                        bus_obj_to_cleanup = stream_info.get("bus")
                    else:
                        self.logger.error(
                            f"Stream info unexpectedly missing for key {key} during pop."
                        )
                        pipeline_to_cleanup = None
                        bus_obj_to_cleanup = None
                    self.active_streams.pop(key, None)
                else:
                    self.logger.warning(
                        f"Stop Stream: Request received for stream {key}, but it was not found (already stopped/removed)."
                    )
                    return True, f"Stream {key} already stopped or removed."

            if pipeline_to_cleanup:
                self.logger.info(
                    f"Attempting GStreamer cleanup for removed stream {key}..."
                )
                schedule_success = self._schedule_null_state(pipeline_to_cleanup, key)
                if not schedule_success:
                    self.logger.warning(
                        f"Failed to schedule NULL state for stream {key} during stop cleanup (pipeline might be already NULL or scheduling failed)."
                    )
                    self._cleanup_stream_resources(key, bus_obj_to_cleanup)
                    return (
                        True,
                        f"Stream {key} removed from list; GStreamer stop might have failed or was unnecessary.",
                    )
                else:
                    self.logger.info(
                        f"Stream {key} removed from list and GStreamer stop scheduled via NULL state."
                    )
                    return (
                        True,
                        f"Stream {key} removed from list and GStreamer stop initiated.",
                    )
            else:
                self.logger.warning(
                    f"Stream {key} removed from list, but pipeline object was already missing (likely already NULL/stopped). Performing basic cleanup."
                )
                self._cleanup_stream_resources(key, bus_obj_to_cleanup)
                return (
                    True,
                    f"Stream {key} removed from list (pipeline was already missing).",
                )

        except ValueError as e:
            self.logger.error(f"Stop Stream Error: Invalid ID '{stream_key}'. {e}")
            return False, f"Invalid Stream ID: {str(e)}"
        except Exception as e:
            self.logger.error(
                f"Unexpected error stopping stream {stream_key}: {e}", exc_info=True
            )
            if stream_was_active and key != -1:
                self.logger.error(
                    f"Performing emergency bus cleanup for stream {key} due to unexpected stop error."
                )
                self._cleanup_stream_resources(key, bus_obj_to_cleanup)
            return False, f"An unexpected error occurred during stop: {str(e)}"

    # --- SRT Signal Handlers ---
    # Keep INFO/WARNING/DEBUG logs here as they are infrequent and useful
    def _on_caller_added(self, element, socket_id, addr, key):
        ip = self._extract_ip_from_socket_address(addr)
        self.logger.info(f"SRT 'caller-added' stream {key}: sock={socket_id}, ip={ip}")
        with self.lock:
            if key in self.active_streams:
                si = self.active_streams[key]
                if si.get("mode") == "listener":
                    si["connection_status"] = "Connected"
                    si["connected_client"] = addr
                    si["socket_id"] = socket_id
                    self.logger.info(f"Listener {key} Connected: {ip}")
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
                    f"Stream {key}: Received 'caller-added' signal but stream no longer active."
                )

    def _on_caller_removed(self, element, socket_id, addr, key):
        ip = self._extract_ip_from_socket_address(addr)
        self.logger.info(
            f"SRT 'caller-removed' stream {key}: sock={socket_id}, ip={ip}"
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
                if (
                    si.get("mode") == "listener"
                    and si.get("socket_id") == socket_id
                    and not si.get("stopping", False)
                ):
                    si["connection_status"] = "Waiting for connection"
                    si["connected_client"] = None
                    si["socket_id"] = None
                    self.logger.info(
                        f"Listener {key} client disconnected (stream still active)."
                    )
                elif si.get("stopping", False):
                    self.logger.debug(
                        f"Listener {key} client disconnected during stop sequence. Status remains 'Stopping...'."
                    )
                else:  # This case might indicate an issue if the sockets don't match
                    if si.get("mode") == "listener":  # Only log warning for listeners
                        self.logger.warning(
                            f"Listener {key} client disconnect signal for socket {socket_id} did not match active socket {si.get('socket_id')}"
                        )
            else:
                self.logger.debug(
                    f"Stream {key}: Received 'caller-removed' signal but stream was already popped (likely during stop)."
                )

    def _on_caller_rejected(self, element, addr, reason, key):
        ip = self._extract_ip_from_socket_address(addr)
        self.logger.warning(
            f"SRT 'caller-rejected' stream {key}: ip={ip}, reason={reason}"
        )
        with self.lock:
            if key in self.active_streams:
                if self.active_streams[key]["mode"] == "listener":
                    if not self.active_streams[key].get(
                        "stopping", False
                    ) and not self.active_streams[key].get(
                        "connection_status", ""
                    ).startswith(
                        "Error"
                    ):
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

    # --- Generator Management ---
    # Keep logs as they are (INFO/WARNING/ERROR)
    def _check_gst_element(self, element_name):
        return Gst.ElementFactory.find(element_name) is not None

    def _start_generator_if_needed(self, resolution):
        with self.lock:
            if resolution in self.generator_pipelines:
                pipeline = self.generator_pipelines[resolution]
                ret, state, _ = pipeline.get_state(timeout=50 * Gst.MSECOND)
                if ret == Gst.StateChangeReturn.SUCCESS and state >= Gst.State.PAUSED:
                    self.logger.debug(f"Generator {resolution} already running.")
                    return True
                else:
                    self.logger.warning(
                        f"Generator {resolution} exists but state={Gst.Element.state_get_name(state)}. Restarting."
                    )
                    self._stop_generator(
                        resolution
                    )  # Ensure cleanup before restart attempt

            self.logger.info(f"Starting generator pipeline for {resolution}...")
            pipeline_str = self._build_generator_pipeline_str(resolution)
            if not pipeline_str:
                return False
            try:
                pipeline = Gst.parse_launch(pipeline_str)
            except GLib.Error as e:
                self.logger.error(f"Failed parse generator {resolution}: {e}")
                return False
            if not pipeline:
                self.logger.error(f"parse_launch None for generator {resolution}.")
                return False
            if pipeline.set_state(Gst.State.PLAYING) == Gst.StateChangeReturn.FAILURE:
                self.logger.error(f"Failed set generator {resolution} PLAYING.")
                pipeline.set_state(Gst.State.NULL)  # Attempt cleanup
                return False
            self.logger.info(f"Generator {resolution} started.")
            self.generator_pipelines[resolution] = pipeline
            return True

    def _build_generator_pipeline_str(self, resolution):
        if resolution == "1080i25":
            vcaps, xopts, txt, uri = (
                "video/x-raw,width=1920,height=1080,framerate=25/1,format=I420,interlace-mode=interleaved",
                "tune=zerolatency interlaced=true speed-preset=2 bitrate=4500",
                "MCR-SRT-STREAMER 1080i25",
                COLORBAR_URIS["1080i25"],
            )
        elif resolution == "720p50":
            vcaps, xopts, txt, uri = (
                "video/x-raw,width=1280,height=720,framerate=50/1,format=I420",
                "tune=zerolatency speed-preset=2 bitrate=4500",
                "MCR-SRT-STREAMER 720p50",
                COLORBAR_URIS["720p50"],
            )
        else:
            self.logger.error(f"Invalid resolution for generator: {resolution}")
            return None
        vid_part = f'videotestsrc pattern=smpte-rp-219 is-live=true ! {vcaps} ! textoverlay text="{txt}" valignment=bottom halignment=left font-desc="Sans Bold 32" color=0xFFFFFFFF outline-color=0x000000FF shaded-background=true ! queue ! x264enc {xopts} ! queue ! mux.'
        aud_part = ""
        aud_src = "audiotestsrc wave=sine freq=1000 volume=0.187 is-live=true ! audio/x-raw,rate=48000,channels=2 ! queue"
        if self._check_gst_element("fdkaacenc"):
            aud_part = f"{aud_src} ! fdkaacenc bitrate=384000 ! queue ! mux."
        elif self._check_gst_element("voaacenc"):
            aud_part = f"{aud_src} ! voaacenc bitrate=128000 ! audio/mpeg,mpegversion=4,stream-format=adts ! queue ! mux."
        else:
            self.logger.warning(f"Generator {resolution}: No AAC encoder.")
        match = re.match(r"udp://([\d\.]+):(\d+)", uri)
        if not match:
            self.logger.error(f"Invalid UDP URI: {uri}")
            return None
        host, port = match.groups()
        if aud_part:
            p_str = f"{vid_part} {aud_part} mpegtsmux name=mux ! queue ! udpsink host={host} port={port} auto-multicast=true"
        else:
            vid_part_nomux = vid_part.replace(
                "! queue ! mux.", "! queue"
            )  # Adjust if no audio
            p_str = f"{vid_part_nomux} ! mpegtsmux name=mux ! queue ! udpsink host={host} port={port} auto-multicast=true"
        return p_str

    def _stop_generator(self, resolution):
        with self.lock:
            pipeline = self.generator_pipelines.pop(resolution, None)
            if pipeline:
                self.logger.info(f"Stopping generator pipeline for {resolution}...")
                ret = pipeline.set_state(Gst.State.NULL)
                s_map = {
                    Gst.StateChangeReturn.FAILURE: "FAIL",
                    Gst.StateChangeReturn.SUCCESS: "OK",
                    Gst.StateChangeReturn.ASYNC: "ASYNC",
                    Gst.StateChangeReturn.NO_PREROLL: "NO_PREROLL",
                }
                self.logger.info(
                    f"Generator {resolution} set_state(NULL) returned: {s_map.get(ret,'?')}"
                )
            else:
                self.logger.debug(
                    f"Generator {resolution} not found or already stopped."
                )

    # --- start_stream function ---
    def start_stream(self, config, use_target_port_as_key=False):
        # Keep existing logs at INFO/WARNING/ERROR
        key = None
        pipeline = None
        srt_uri = ""
        pipeline_str = ""
        existing_info = None
        existing_pipeline = None
        input_detail_log = "N/A"
        try:
            mode = config.get("mode", "listener")
            if mode == "caller":
                _port = config.get("target_port")
                key = self._validate_target_port(_port) if _port else None
            else:  # listener
                _port = config.get("port")
                key = self._validate_listener_port(_port) if _port else None
            if key is None:
                raise ValueError(f"Missing port/target_port for mode {mode}")

            rtp_encapsulation = config.get("rtp_encapsulation", False)
            with self.lock:
                if key in self.active_streams:
                    self.logger.warning(
                        f"Key {key} ({mode}) in use. Stopping existing."
                    )
                    existing_info = self.active_streams.pop(key, None)
                if existing_info:
                    existing_pipeline = existing_info.get("pipeline")
            if existing_info and existing_pipeline:
                self.logger.info(
                    f"Scheduling NULL state for old pipeline {key} during restart."
                )
                self._schedule_null_state(existing_pipeline, key)
                time.sleep(0.5)

            input_type = config.get("input_type", "multicast")
            self.logger.info(
                f"Starting stream {key}: mode={mode}, input={input_type}, RTP={rtp_encapsulation}"
            )
            sink_name = f"srtsink_{key}"
            overhead = int(config.get("overhead_bandwidth", 2))
            latency = int(config.get("latency", 300))
            encryption = config.get("encryption", "none")
            passphrase = config.get("passphrase", "")
            qos = str(config.get("qos", False)).lower()
            smoothing_ms = int(config.get("smoothing_latency_ms", 30))
            srt_params = [
                f"mode={mode}",
                "transtype=live",
                f"latency={latency}",
                f"peerlatency={latency}",
                "rcvbuf=8388608",
                "sndbuf=8388608",
                "fc=4096",
                "tlpktdrop=true",
                f"overheadbandwidth={overhead}",
                "nakreport=true",
                f"streamid=mcr_stream_{key}",
                f"qos={qos}",
            ]
            if encryption != "none":
                if not passphrase or not (10 <= len(passphrase) <= 80):
                    raise ValueError("Passphrase required (10-80 chars).")
                pbkeylen = 16 if encryption == "aes-128" else 32
                srt_params.extend([f"passphrase={passphrase}", f"pbkeylen={pbkeylen}"])
            target_addr = config.get("target_address")
            if mode == "caller":
                if not target_addr:
                    raise ValueError("Target address required for caller mode.")
                # --- REMOVED DEBUG LOGGING for URI construction ---
                srt_params_joined = "&".join(srt_params)
                srt_uri = f"srt://{target_addr}:{key}?{srt_params_joined}"
            else:  # listener
                bind_addr = "0.0.0.0"  # Default listener bind address
                srt_uri = f"srt://{bind_addr}:{key}?{'&'.join(srt_params)}"

            rtp_payload_str = ""
            pipeline_input_str = ""
            sync = "false"  # Default sync for live sources
            wait = "true" if mode == "listener" else "false"
            tsparse_part = ""
            if input_type == "file":
                f_path = config.get("file_path")
                media_dir = os.path.abspath(self.media_folder)
                if not (f_path and isinstance(f_path, str)):
                    raise ValueError("Missing 'file_path'.")
                base = os.path.basename(f_path)
                abs_path = os.path.abspath(os.path.join(media_dir, base))
                if not abs_path.startswith(media_dir + os.sep):
                    raise ValueError("File path outside allowed dir.")
                if not os.path.isfile(abs_path):
                    raise FileNotFoundError(f"Media file not found: {base}")
                if not base.lower().endswith(".ts"):
                    raise ValueError("Only .ts files supported.")
                pipeline_input_str = f'filesrc location="{abs_path}"'
                sync = "true"  # Use sync=true for file sources
                input_detail_log = base
                try:
                    smoothing_us = int(config.get("smoothing_latency_ms", 30)) * 1000
                except:
                    smoothing_us = 30000
                tsparse_name = f"tsparse_{key}"
                tsparse_part = f'! tsparse name="{tsparse_name}" set-timestamps=true alignment=7 smoothing-latency={smoothing_us} parse-private-sections=true ! queue'
                if config["rtp_encapsulation"]:
                    raise ValueError(
                        "RTP Encapsulation not supported for file inputs."
                    )  # Should be caught by form/API validation too
            elif input_type == "multicast":
                mc_addr = config.get("multicast_address")
                mc_port = config.get("multicast_port")
                if not (mc_addr and mc_port):
                    raise ValueError("Missing multicast address/port.")
                if not isinstance(mc_port, int) or not (1 <= mc_port <= 65535):
                    raise ValueError(f"Invalid multicast port: {mc_port}")
                mc_iface = (
                    config.get("multicast_interface") or DEFAULT_MULTICAST_INTERFACE
                )
                pipeline_input_str = f'udpsrc uri="udp://{mc_addr}:{mc_port}" multicast-iface="{mc_iface}" buffer-size=20971520 caps="video/mpegts, systemstream=(boolean)true, packetsize=(int)188"'
                input_detail_log = f"udp://{mc_addr}:{mc_port}"
                if rtp_encapsulation:
                    rtp_payload_str = "rtpmp2tpay pt=33 mtu=1316 ! queue ! "
                try:
                    smoothing_us = int(config.get("smoothing_latency_ms", 30)) * 1000
                except:
                    smoothing_us = 30000
                tsparse_name = f"tsparse_{key}"
                tsparse_part = f'! tsparse name="{tsparse_name}" set-timestamps=true alignment=7 smoothing-latency={smoothing_us} parse-private-sections=true ! queue'
            elif input_type == "colorbar":
                resolution = config.get("colorbar_resolution")
                if not resolution or resolution not in COLORBAR_URIS:
                    raise ValueError(
                        f"Invalid or missing colorbar_resolution: {resolution}"
                    )
                if not self._start_generator_if_needed(resolution):
                    raise RuntimeError(
                        f"Failed to start required generator pipeline for {resolution}"
                    )
                udp_uri = COLORBAR_URIS[resolution]
                pipeline_input_str = f'udpsrc uri="{udp_uri}" buffer-size=20971520 caps="video/mpegts, systemstream=(boolean)true, packetsize=(int)188"'
                input_detail_log = f"Colorbars {resolution.upper()}"
                if rtp_encapsulation:
                    rtp_payload_str = "rtpmp2tpay pt=33 mtu=1316 ! queue ! "
                try:
                    smoothing_us = int(config.get("smoothing_latency_ms", 30)) * 1000
                except:
                    smoothing_us = 30000
                tsparse_name = f"tsparse_{key}"
                tsparse_part = f'! tsparse name="{tsparse_name}" set-timestamps=true alignment=7 smoothing-latency={smoothing_us} parse-private-sections=true ! queue'  # Use full version
                sync = "false"
            else:
                raise ValueError(f"Unsupported input_type: {input_type}")

            pipeline_str = f'{pipeline_input_str} {tsparse_part} ! {rtp_payload_str}srtsink name="{sink_name}" uri="{srt_uri}" async=false sync={sync} wait-for-connection={wait}'
            pipeline_str = " ".join(pipeline_str.split())  # Normalize whitespace
            self.logger.debug(
                f"Pipeline {key}: {pipeline_str}"
            )  # Keep DEBUG log for pipeline string

            try:
                pipeline = Gst.parse_launch(pipeline_str)
            except GLib.Error as e:
                self.logger.error(f"Parse error stream {key}: {e}")
                return False, f"Parse error: {e}"
            if not pipeline:
                raise RuntimeError(f"Parse failed for stream {key}")

            bus = pipeline.get_bus()
            bus.add_signal_watch()
            bus.connect("message", self._on_bus_message, key)
            srtsink = pipeline.get_by_name(sink_name)
            if not srtsink:
                raise RuntimeError(f"Cannot find '{sink_name}'")
            try:
                srtsink.connect("caller-added", self._on_caller_added, key)
                srtsink.connect("caller-removed", self._on_caller_removed, key)
                srtsink.connect("caller-rejected", self._on_caller_rejected, key)
                self.logger.info(f"Connected SRT signals for stream {key}.")
            except Exception as e:
                self.logger.warning(f"Could not connect SRT signals for {key}: {e}")

            stream_info_dict = {
                "pipeline": pipeline,
                "bus": bus,
                "config": config.copy(),
                "srt_uri": srt_uri,
                "mode": mode,
                "start_time": time.time(),
                "stopping": False,
                "connection_status": (
                    "Connecting..." if mode == "caller" else "Waiting for connection"
                ),
                "connected_client": None,
                "socket_id": None,
                "connection_history": [],
                "input_detail": input_detail_log,
            }
            if mode == "caller":
                stream_info_dict["target"] = f"{target_addr}:{key}"
            with self.lock:
                self.active_streams[key] = stream_info_dict

            def set_playing_safe(p, k):
                ret = p.set_state(Gst.State.PLAYING)
                s_map = {
                    Gst.StateChangeReturn.FAILURE: "FAIL",
                    Gst.StateChangeReturn.SUCCESS: "OK",
                    Gst.StateChangeReturn.ASYNC: "ASYNC",
                    Gst.StateChangeReturn.NO_PREROLL: "NO_PREROLL",
                }
                self.logger.info(
                    f"set_state(PLAYING) {k} returned: {s_map.get(ret,'?')}"
                )  # Keep INFO
                if ret == Gst.StateChangeReturn.FAILURE:
                    with self.lock:
                        if k in self.active_streams and not self.active_streams[k].get(
                            "stopping", False
                        ):
                            self.active_streams[k][
                                "connection_status"
                            ] = "Start Error (Set P->R Failed)"
                            self.logger.error(
                                f"Stream {k} failed to transition from READY to PAUSED/PLAYING."
                            )
                return False  # Remove idle source

            GLib.idle_add(
                set_playing_safe, pipeline, key, priority=GLib.PRIORITY_DEFAULT
            )
            return True, f"Stream {mode} ({key}) starting: {input_type}..."

        except (KeyError, ValueError, FileNotFoundError, RuntimeError) as e:
            self.logger.error(
                f"Start stream config/runtime error {key or 'N/A'}: {e}", exc_info=False
            )
            if pipeline:
                GLib.idle_add(pipeline.set_state, Gst.State.NULL)
            with self.lock:
                self.active_streams.pop(key, None)
            return False, f"Stream start error: {str(e)}"
        except Exception as e:
            self.logger.error(
                f"Unexpected start error {key or 'N/A'}: {e}", exc_info=True
            )
            if pipeline:
                GLib.idle_add(pipeline.set_state, Gst.State.NULL)
            with self.lock:
                self.active_streams.pop(key, None)
            return False, f"Unexpected error: {str(e)}"

    # --- ROBUST Stats Parsing Function ---
    # Keep this function as is
    def _extract_stats_from_gstruct(self, stats_struct):
        stats = {
            "timestamp": time.time(),
            "error": None,
            "_raw_stats_string": None,
            "packets_sent": 0,
            "packets_sent_lost": 0,
            "packets_retransmitted": 0,
            "packets_received": 0,
            "packets_received_lost": 0,
            "packets_received_retransmitted": 0,
            "packets_received_dropped": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "bytes_sent_dropped": 0,
            "send_rate_mbps": 0.0,
            "recv_rate_mbps": 0.0,
            "rtt_ms": 0.0,
            "bandwidth_mbps": 0.0,
            "negotiated_latency_ms": 0,
            "packet_loss_percent": 0.0,
            "retransmitted_pkts_percent": 0.0,
        }
        if not stats_struct:
            stats["error"] = "Stats structure is None"
            return stats

        stats["_raw_stats_string"] = stats_struct.to_string()
        source_struct = None
        try:
            if stats_struct.has_field("callers"):
                callers_array = stats_struct.get_value("callers")
                if (
                    callers_array
                    and hasattr(callers_array, "__len__")
                    and len(callers_array) > 0
                ):
                    nested_struct = callers_array[0]
                    if isinstance(nested_struct, Gst.Structure):
                        self.logger.debug(
                            "Parsing stats from nested 'callers' structure (Listener)."
                        )  # Keep DEBUG
                        source_struct = nested_struct
                    else:
                        stats["error"] = "Nested caller stats has unexpected type."
                else:
                    stats["error"] = (
                        "Listener mode, but no active callers connected."  # Error if empty callers array
                    )
            else:
                self.logger.debug(
                    "Parsing stats from top-level structure (Caller?)."
                )  # Keep DEBUG
                source_struct = stats_struct

            if source_struct:
                stats["packets_sent"] = source_struct.get_value("packets-sent") or 0
                stats["packets_sent_lost"] = (
                    source_struct.get_value("packets-sent-lost") or 0
                )
                stats["packets_retransmitted"] = (
                    source_struct.get_value("packets-retransmitted") or 0
                )
                stats["bytes_sent"] = source_struct.get_value("bytes-sent") or 0
                stats["send_rate_mbps"] = (
                    source_struct.get_value("send-rate-mbps") or 0.0
                )
                stats["rtt_ms"] = source_struct.get_value("rtt-ms") or 0.0
                stats["bandwidth_mbps"] = (
                    source_struct.get_value("bandwidth-mbps") or 0.0
                )
                stats["negotiated_latency_ms"] = (
                    source_struct.get_value("negotiated-latency-ms") or 0
                )
                stats["packets_received"] = (
                    source_struct.get_value("packets-received") or 0
                )
                stats["packets_received_lost"] = (
                    source_struct.get_value("packets-received-lost") or 0
                )
                stats["packets_received_retransmitted"] = (
                    source_struct.get_value("packets-received-retransmitted") or 0
                )
                stats["packets_received_dropped"] = (
                    source_struct.get_value("packets-received-dropped") or 0
                )
                stats["bytes_received"] = source_struct.get_value("bytes-received") or 0
                stats["recv_rate_mbps"] = (
                    source_struct.get_value("receive-rate-mbps")
                    or source_struct.get_value("recv-rate-mbps")
                    or 0.0
                )
                stats["bytes_sent_dropped"] = (
                    source_struct.get_value("bytes-sent-dropped") or 0
                )

                pkts_sent = stats["packets_sent"]
                pkts_lost = stats["packets_sent_lost"]
                pkts_retrans = stats["packets_retransmitted"]
                if isinstance(pkts_sent, (int, float)) and pkts_sent > 0:
                    if isinstance(pkts_lost, (int, float)):
                        stats["packet_loss_percent"] = (pkts_lost / pkts_sent) * 100
                    if isinstance(pkts_retrans, (int, float)):
                        stats["retransmitted_pkts_percent"] = (
                            pkts_retrans / pkts_sent
                        ) * 100
                else:
                    stats["packet_loss_percent"] = 0.0
                    stats["retransmitted_pkts_percent"] = 0.0

                if (
                    stats.get("error")
                    != "Listener mode, but no active callers connected."
                ):
                    stats["error"] = None

        except Exception as e:
            self.logger.error(
                f"Unexpected error during SRT stats parsing: {e}", exc_info=True
            )  # Keep ERROR
            stats["error"] = f"Internal parsing error: {str(e)}"
        return stats

    # --- get_stream_statistics ---
    def get_stream_statistics(self, stream_key):
        # Keep existing logs at INFO/WARNING/ERROR
        stats = {"error": None}
        pipeline = None
        key = -1
        info = None
        try:
            key = int(stream_key)
            with self.lock:
                info = self.active_streams.get(key)
                pipeline = info.get("pipeline") if info else None

            if not info:
                # self.logger.debug(f"Info dict missing for stream {key} in get_stream_statistics (likely stopped).") # DEBUG REMOVED
                return {"error": f"Stream {key} stopped or removed."}
            if not pipeline:
                # self.logger.debug(f"Pipeline object missing for stream {key} in get_stream_statistics (likely stopped).") # DEBUG REMOVED
                return {
                    "error": f"Stream {key} stopped or stopping (pipeline missing)."
                }

            sink = pipeline.get_by_name(f"srtsink_{key}")
            if not sink:
                return {"error": f"srtsink element not found for {key}"}

            _ret, current_state, _ = pipeline.get_state(timeout=10 * Gst.MSECOND)
            if current_state < Gst.State.PAUSED:
                # self.logger.debug(f"Stats request for {key} skipped, pipeline state is {Gst.Element.state_get_name(current_state)}.") # DEBUG REMOVED
                return {
                    "error": f"Stream {key} pipeline state is {Gst.Element.state_get_name(current_state)}, cannot get stats."
                }

            stats_struct = sink.get_property("stats")
            if stats_struct:
                stats = self._extract_stats_from_gstruct(stats_struct)
            else:
                stats = {"error": "Stats structure was None from srtsink"}
                # self.logger.debug(f"Stats structure was None for stream {key}") # DEBUG REMOVED

            with self.lock:
                info = self.active_streams.get(key)
                if info:
                    stats["connection_status"] = info.get(
                        "connection_status", "Unknown"
                    )
                    stats["uptime"] = self._format_uptime(
                        time.time() - info.get("start_time", time.time())
                    )
                    stats["config_latency"] = info.get("config", {}).get("latency")
                    stats["config_overhead"] = info.get("config", {}).get(
                        "overhead_bandwidth"
                    )
                else:
                    stats["connection_status"] = "Stopped/Removed"
                    stats["uptime"] = "N/A"
                    if not stats.get("error"):
                        stats["error"] = f"Stream {key} removed during stats fetch."

            stats["last_updated"] = time.time()

        except ValueError:
            stats = {"error": f"Invalid stream key: {stream_key}"}
        except AttributeError as ae:
            stats = {
                "error": f"Error accessing pipeline/sink for stats (likely stopping): {ae}"
            }
            self.logger.warning(
                f"AttributeError getting stats for {key}: {ae}", exc_info=False
            )  # Keep WARNING
        except Exception as e:
            stats = {"error": f"Unexpected error getting stats: {e}"}
            self.logger.error(f"Err get stats {key}: {e}", exc_info=True)  # Keep ERROR
        return self._sanitize_for_json(stats)

    # --- get_active_streams ---
    def get_active_streams(self):
        # Keep existing logs at INFO/WARNING/ERROR
        """Gets a summary of active streams including key stats for the UI dashboard."""
        streams = {}
        now = time.time()
        with self.lock:
            keys_to_process = list(self.active_streams.keys())
            for key in keys_to_process:
                info = self.active_streams.get(key)
                if not info:
                    self.logger.warning(
                        f"Stream info for key {key} disappeared during get_active_streams iteration."
                    )
                    continue

                status = info.get("connection_status", "Unknown")
                cfg = info.get("config", {})
                mode = info.get("mode", "?")
                input_type = cfg.get("input_type", "?")
                start_time = info.get("start_time", now)
                pipeline = info.get("pipeline")
                stopping = info.get("stopping", False)

                source_detail = "N/A"
                if input_type == "file":
                    source_detail = os.path.basename(cfg.get("file_path", "N/A"))
                elif input_type == "multicast":
                    source_detail = f"{cfg.get('multicast_address','?')}:{cfg.get('multicast_port','?')}"
                elif input_type == "colorbar":
                    source_detail = (
                        f"Colorbars {cfg.get('colorbar_resolution', '?').upper()}"
                    )

                stream_stats_subset = {
                    "rtt_ms": None,
                    "packet_loss_percent": None,
                    "send_rate_mbps": None,
                    "error": None,
                }

                if (
                    pipeline
                    and not stopping
                    and (status == "Connected" or status == "Running")
                ):
                    try:
                        sink = pipeline.get_by_name(f"srtsink_{key}")
                        if sink:
                            _ret, current_state, _ = pipeline.get_state(
                                timeout=10 * Gst.MSECOND
                            )
                            if current_state >= Gst.State.PAUSED:
                                stats_struct = sink.get_property("stats")
                                if stats_struct:
                                    parsed_stats = self._extract_stats_from_gstruct(
                                        stats_struct
                                    )
                                    if not parsed_stats.get("error"):
                                        stream_stats_subset["rtt_ms"] = (
                                            parsed_stats.get("rtt_ms")
                                        )
                                        stream_stats_subset["packet_loss_percent"] = (
                                            parsed_stats.get("packet_loss_percent")
                                        )
                                        stream_stats_subset["send_rate_mbps"] = (
                                            parsed_stats.get("send_rate_mbps")
                                        )
                                    else:
                                        stream_stats_subset["error"] = parsed_stats.get(
                                            "error"
                                        )
                                        # self.logger.debug(f"Stats parsing error for dashboard stream {key}: {stream_stats_subset['error']}") # DEBUG REMOVED
                                else:
                                    stream_stats_subset["error"] = (
                                        "Stats structure None from sink"
                                    )
                                    # self.logger.debug(f"Stats structure was None for dashboard stream {key}") # DEBUG REMOVED
                            else:
                                stream_stats_subset["error"] = (
                                    f"Pipeline not ready ({Gst.Element.state_get_name(current_state)})"
                                )
                                # self.logger.debug(f"Pipeline not ready for stats for dashboard stream {key}: {stream_stats_subset['error']}") # DEBUG REMOVED
                        else:
                            stream_stats_subset["error"] = "Sink not found"
                            self.logger.warning(
                                f"Sink srtsink_{key} not found for dashboard stats."
                            )  # Keep WARNING
                    except Exception as stats_e:
                        self.logger.warning(
                            f"Could not get stats for dashboard stream {key}: {stats_e}",
                            exc_info=False,
                        )  # Keep WARNING
                        stream_stats_subset["error"] = (
                            f"Exception: {type(stats_e).__name__}"
                        )
                elif stopping:
                    stream_stats_subset["error"] = "Stream stopping"
                elif not pipeline:
                    stream_stats_subset["error"] = "Pipeline missing"
                elif status not in [
                    "Connected",
                    "Running",
                ]:  # Only set error if status is neither
                    stream_stats_subset["error"] = (
                        f"Status not Connected/Running ({status})"
                    )

                streams[key] = {
                    "key": key,
                    "mode": mode,
                    "connection_status": status,
                    "uptime": self._format_uptime(now - start_time),
                    "input_type": input_type,
                    "source_detail": source_detail,
                    "latency": cfg.get("latency", "?"),
                    "overhead_bandwidth": cfg.get("overhead_bandwidth", "?"),
                    "encryption": cfg.get("encryption", "none"),
                    "passphrase_set": bool(cfg.get("passphrase"))
                    and cfg.get("encryption", "none") != "none",
                    "qos_enabled": cfg.get("qos", False),
                    "port": (
                        cfg.get("port")
                        if mode == "listener"
                        else cfg.get("target_port")
                    ),
                    "target": info.get("target") if mode == "caller" else None,
                    "client_ip": self._extract_ip_from_socket_address(
                        info.get("connected_client")
                    ),
                    "config": cfg,
                    "stats": stream_stats_subset,
                }
        return self._sanitize_for_json(streams)

    # --- get_debug_info ---
    def get_debug_info(self, stream_key):
        # Removed specific debug logs, keeping essential warnings/errors
        debug = {"error": None}
        key = -1
        pipeline = None
        info = None
        try:
            key = int(stream_key)
            with self.lock:
                info = self.active_streams.get(key)

            # === START DEBUG LOGGING REMOVAL ===
            # Original debug logging commented out:
            # if not info: self.logger.warning(f"DEBUG_GET_INFO ({key}): Stream info dict NOT FOUND in active_streams.")
            # else:
            #     self.logger.info(f"DEBUG_GET_INFO ({key}): Stream info dict FOUND. Keys: {list(info.keys())}")
            #     pipeline = info.get("pipeline")
            #     if pipeline: self.logger.info(f"DEBUG_GET_INFO ({key}): Pipeline object reference FOUND in info dict.")
            #     else: self.logger.warning(f"DEBUG_GET_INFO ({key}): Pipeline object reference IS MISSING (None/False) in info dict! Info dict dump: {info}")
            # === END DEBUG LOGGING REMOVAL ===

            # Need to get pipeline ref here now if info exists
            if info:
                pipeline = info.get("pipeline")
            else:
                return {"error": f"Stream {key} not found or already stopped."}

            config_data = info.get("config", {})
            debug["config"] = (
                config_data.copy() if isinstance(config_data, dict) else {}
            )
            debug["srt_uri"] = info.get("srt_uri")
            debug["mode"] = info.get("mode")
            debug["status"] = info.get("connection_status")
            debug["start_time"] = info.get("start_time")
            debug["stopping"] = info.get("stopping", False)
            debug["connected_client"] = self._extract_ip_from_socket_address(
                info.get("connected_client")
            )
            debug["socket_id"] = info.get("socket_id")
            history_data = info.get("connection_history", [])
            debug["connection_history"] = (
                history_data.copy() if isinstance(history_data, list) else []
            )
            debug["input_detail"] = info.get("input_detail")

            if pipeline:
                try:
                    _, state, _ = pipeline.get_state(timeout=100 * Gst.MSECOND)
                    debug["pipeline_state"] = Gst.Element.state_get_name(state)
                    # self.logger.info(f"DEBUG_GET_INFO ({key}): Successfully got pipeline state: {debug['pipeline_state']}") # DEBUG REMOVED
                except Exception as state_e:
                    debug["pipeline_state"] = f"Error querying state: {state_e}"
                    # self.logger.warning(f"DEBUG_GET_INFO ({key}): Exception querying pipeline state: {state_e}") # DEBUG REMOVED
            else:
                debug["pipeline_state"] = "Pipeline missing (already stopped?)"

            stats_data = self.get_stream_statistics(stream_key)
            if isinstance(stats_data, dict) and stats_data.get("error"):
                debug["stats_error"] = stats_data["error"]
                debug["stats"] = {}
            else:
                debug["stats"] = stats_data if isinstance(stats_data, dict) else {}

        except ValueError:
            debug = {"error": f"Invalid stream key: {stream_key}"}
        except Exception as e:
            self.logger.error(
                f"Error getting debug info for stream {key}: {e}", exc_info=True
            )  # Keep ERROR
            debug = {"error": f"Unexpected error getting debug info: {e}"}

        return self._sanitize_for_json(debug)

    # --- shutdown ---
    def shutdown(self):
        # Keep existing logs
        self.logger.info("Shutting down StreamManager...")
        keys_to_stop = []
        gen_keys_to_stop = []
        with self.lock:
            keys_to_stop = list(self.active_streams.keys())
            gen_keys_to_stop = list(self.generator_pipelines.keys())
        self.logger.info(
            f"Requesting stop for {len(keys_to_stop)} streams, {len(gen_keys_to_stop)} generators..."
        )
        for k in keys_to_stop:
            self.stop_stream(str(k), force_remove=True)
        for res in gen_keys_to_stop:
            self._stop_generator(res)
        self.logger.info("Waiting briefly for streams to reach NULL state...")
        time.sleep(1.0)
        with self.lock:
            if self.active_streams:
                self.logger.warning(
                    f"Streams still active after shutdown: {list(self.active_streams.keys())}"
                )
            if self.generator_pipelines:
                self.logger.warning(
                    f"Generators still active after shutdown: {list(self.generator_pipelines.keys())}"
                )
        if self.mainloop and self.mainloop.is_running():
            self.logger.info("Quitting GLib MainLoop...")
            self.mainloop.quit()
        if self.thread and self.thread.is_alive():
            self.logger.info("Waiting for main loop thread to join...")
            self.thread.join(timeout=5.0)
            if self.thread.is_alive():
                self.logger.warning("Main loop thread did not join cleanly!")
            else:
                self.logger.info("Main loop thread joined.")
        self.logger.info("StreamManager shutdown complete.")
