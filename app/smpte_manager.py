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
from datetime import datetime, timedelta
import traceback

try:
    from app.utils import get_network_interfaces
except ImportError:

    def get_network_interfaces():
        _logger = logging.getLogger(__name__)
        _logger.warning("utils.get_network_interfaces not found, using basic fallback.")
        return {}


# Import gevent for the non-blocking loop
try:
    import gevent
except ImportError:
    logging.getLogger(__name__).critical(
        "gevent is not installed, which is required for the Gunicorn worker. Please install it."
    )
    gevent = None

COLORBAR_URIS = {"720p50": "udp://224.1.1.1:5004", "1080i25": "udp://224.1.1.1:5005"}
DEFAULT_MULTICAST_INTERFACE = "vlan2"


class SMPTEManager:
    def __init__(self, main_stream_manager_ref=None):
        self.active_pairs = {}
        self.lock = threading.RLock()
        self.logger = logging.getLogger(__name__)
        self.main_stream_manager = main_stream_manager_ref
        if not self.logger.hasHandlers():
            log_handler = logging.StreamHandler()
            log_formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            log_handler.setFormatter(log_formatter)
            self.logger.addHandler(log_handler)
            self.logger.setLevel(logging.INFO)
        self.network_interfaces = self._get_interface_ips()
        self.logger.info(
            "SMPTEManager Initialized and ready for non-blocking GLib loop."
        )

    def _run_glib_loop_non_blocking(self):
        """
        Runs in a gevent greenlet. It iteratively processes the GLib main context
        without blocking, allowing the Gunicorn worker to remain responsive.
        """
        self.logger.info(
            "Starting non-blocking GLib main context loop for SMPTEManager..."
        )
        context = GLib.MainContext.default()
        while True:
            try:
                context.iteration(False)
                gevent.sleep(0.01)  # Yield control
            except Exception as e:
                self.logger.error(
                    f"Error in SMPTEManager's non-blocking GLib loop: {e}",
                    exc_info=True,
                )
                gevent.sleep(1)

    def start_glib_loop(self):
        """Public method to be called from wsgi.py to start the non-blocking loop."""
        if not gevent:
            self.logger.critical(
                "Cannot start GLib loop because gevent is not available."
            )
            return
        self.logger.info("Spawning gevent greenlet for SMPTEManager's GLib loop.")
        gevent.spawn(self._run_glib_loop_non_blocking)

    def _get_interface_ips(self):
        interfaces = {}
        try:
            import psutil

            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            for name, snics in addrs.items():
                if (
                    name == "lo"
                    or not stats.get(name)
                    or not stats[name].isup
                    or name.startswith(("docker", "virbr", "veth", "lo"))
                ):
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
            self.logger.error(f"Failed to get interface IPs using psutil: {e}")
        self.logger.info(f"Detected network interfaces: {interfaces}")
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
                return str(addr)
            else:
                return str(addr)
        except Exception as e:
            self.logger.warning(
                f"Could not extract IP from address object ({type(addr)}): {e}"
            )
            return str(addr)

    def _sanitize_for_json(self, obj):
        if isinstance(obj, (str, int, float, bool, type(None))):
            return obj
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, timedelta):
            return obj.total_seconds()
        if isinstance(obj, (list, tuple)):
            return [self._sanitize_for_json(item) for item in obj]
        if isinstance(obj, dict):
            return {str(k): self._sanitize_for_json(v) for k, v in obj.items()}
        if isinstance(obj, (Gio.SocketAddress, Gio.InetAddress, Gio.InetSocketAddress)):
            return self._extract_ip_from_socket_address(obj)
        if isinstance(obj, (GObject.GObject, GLib.Error)):
            return str(obj)
        try:
            return obj
        except TypeError:
            return str(obj)

    def _format_uptime(self, seconds):
        try:
            td = timedelta(seconds=int(seconds))
            return str(td)
        except (ValueError, TypeError):
            self.logger.error(
                f"Error formatting uptime for seconds: {seconds}", exc_info=False
            )
            return "Error"

    def _build_srt_uri(self, leg_config, shared_config):
        port = leg_config["port"]
        mode = leg_config["mode"]
        pair_id = shared_config.get("pair_id", "unknown")
        leg_num = leg_config.get("leg_num", "?")
        srt_params = [
            f"mode={mode}",
            "transtype=live",
            f"latency={shared_config['latency']}",
            f"peerlatency={shared_config['latency']}",
            "rcvbuf=8388608",
            "sndbuf=8388608",
            "fc=4096",
            "tlpktdrop=true",
            "nakreport=true",
            f"overheadbandwidth={shared_config['overhead_bandwidth']}",
            f"streamid=smpte_pair_{pair_id}_leg{leg_num}",
            f"qos={'true' if shared_config.get('qos', False) else 'false'}",
        ]
        encryption = shared_config.get("encryption", "none").lower()
        if encryption != "none":
            passphrase = shared_config.get("passphrase", "")
            if passphrase:
                pbkeylen = 16 if encryption == "aes-128" else 32
                srt_params.extend([f"passphrase={passphrase}", f"pbkeylen={pbkeylen}"])
            else:
                self.logger.warning(
                    f"Encryption '{encryption}' requested for pair {pair_id} leg {leg_num} but no passphrase."
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
            if not target_addr:
                raise ValueError(f"Missing target address for caller leg {leg_num}")
            uri_base = f"srt://{target_addr}:{port}"

            if interface_ip:
                srt_params.append(f"localaddress={interface_ip}")

        return f"{uri_base}?{'&'.join(srt_params)}"

    def _schedule_null_state(self, pipeline, pair_id):
        if pipeline:
            self.logger.info(
                f"Scheduling state change to NULL for pair {pair_id} via idle_add."
            )

            def set_null_safe(p, k):
                self.logger.debug(f"Executing async set_state(NULL) for pair {k}...")
                try:
                    ret = p.set_state(Gst.State.NULL)
                    state_map = {
                        Gst.StateChangeReturn.FAILURE: "FAIL",
                        Gst.StateChangeReturn.SUCCESS: "OK",
                        Gst.StateChangeReturn.ASYNC: "ASYNC",
                        Gst.StateChangeReturn.NO_PREROLL: "NO_PREROLL",
                    }
                    self.logger.info(
                        f"Async set_state(NULL) for pair {k} returned: {state_map.get(ret,'?')}"
                    )
                except Exception as e_state:
                    self.logger.error(
                        f"Exception during async set_state(NULL) for pair {k}: {e_state}",
                        exc_info=True,
                    )
                return False

            GLib.idle_add(
                set_null_safe, pipeline, pair_id, priority=GLib.PRIORITY_DEFAULT
            )
            return True
        else:
            self.logger.warning(
                f"Cannot schedule NULL state for pair {pair_id}: Pipeline object is None."
            )
            return False

    def _cleanup_smpte_pair_resources(self, pair_id, bus_obj):
        self.logger.info(
            f"Performing final cleanup for SMPTE Pair {pair_id} (bus watch, etc.)."
        )
        if bus_obj:
            try:
                bus_obj.remove_signal_watch()
                self.logger.debug(f"Removed signal watch for SMPTE Pair {pair_id}.")
            except Exception as bus_e:
                self.logger.warning(
                    f"Error removing signal watch for SMPTE Pair {pair_id}: {bus_e}"
                )

    def _on_smpte_bus_message(self, bus, message, pair_id):
        t = message.type
        msg_src = message.src
        pipeline_obj = None
        bus_obj = None
        is_stopping = False
        should_disconnect_handler = False
        pair_info = None

        try:
            with self.lock:
                pair_info = self.active_pairs.get(pair_id)
                if pair_info:
                    pipeline_obj = pair_info.get("pipeline")
                    bus_obj = pair_info.get("bus")
                    is_stopping = pair_info.get("stopping", False)
                elif t == Gst.MessageType.STATE_CHANGED and isinstance(
                    msg_src, Gst.Pipeline
                ):
                    pipeline_obj = msg_src

            if not pipeline_obj:
                self.logger.debug(
                    f"Bus message for pair {pair_id} ignored: no active pipeline found."
                )
                return True

            src_name = msg_src.get_name() if hasattr(msg_src, "get_name") else "?"

            if t == Gst.MessageType.STATE_CHANGED:
                old_state, new_state, _ = message.parse_state_changed()
                new_state_name = Gst.Element.state_get_name(new_state)
                old_state_name = Gst.Element.state_get_name(old_state)
                self.logger.info(
                    f"BUS_MSG: SMPTE Pair {pair_id}, Element '{src_name}' state changed from {old_state_name} to {new_state_name}"
                )

                if msg_src == pipeline_obj:
                    if int(new_state) == Gst.State.NULL:
                        self.logger.info(
                            f"SMPTE Pair {pair_id} pipeline reached NULL state. Performing resource cleanup."
                        )
                        self._cleanup_smpte_pair_resources(pair_id, bus_obj)
                        should_disconnect_handler = True
                    else:
                        with self.lock:
                            if pair_id in self.active_pairs and not is_stopping:
                                current_status = self.active_pairs[pair_id].get(
                                    "status", "Unknown"
                                )
                                new_status_str = None
                                if new_state == Gst.State.PLAYING:
                                    new_status_str = "Running"
                                elif new_state == Gst.State.PAUSED:
                                    new_status_str = "Paused"
                                elif new_state == Gst.State.READY:
                                    new_status_str = "Ready"

                                if new_status_str and new_status_str != current_status:
                                    self.logger.info(
                                        f"SMPTE Pair {pair_id}: Updating overall status to '{new_status_str}'"
                                    )
                                    self.active_pairs[pair_id][
                                        "status"
                                    ] = new_status_str

            elif t == Gst.MessageType.ERROR:
                err, debug = message.parse_error()
                self.logger.error(
                    f"BUS_MSG: GStreamer error on SMPTE Pair {pair_id} from '{src_name}': {err.message}. Debug: {debug}"
                )
                with self.lock:
                    if pair_id in self.active_pairs and not is_stopping:
                        self.active_pairs[pair_id]["status"] = "Error: " + err.message
                        self.active_pairs[pair_id]["stopping"] = True
                        self._schedule_null_state(pipeline_obj, pair_id)

            elif t == Gst.MessageType.EOS:
                self.logger.info(
                    f"BUS_MSG: EOS received for SMPTE Pair {pair_id} from '{src_name}'. Initiating stop."
                )
                with self.lock:
                    if pair_id in self.active_pairs and not is_stopping:
                        self.active_pairs[pair_id]["status"] = "Ended (EOS)"
                        self.active_pairs[pair_id]["stopping"] = True
                        self._schedule_null_state(pipeline_obj, pair_id)

            elif t == Gst.MessageType.WARNING:
                warn, debug = message.parse_warning()
                self.logger.warning(
                    f"BUS_MSG: GStreamer warning on SMPTE Pair {pair_id} from '{src_name}': {warn.message}. Debug: {debug}"
                )

        except Exception as e:
            self.logger.error(
                f"!!! Uncaught exception in SMPTE bus handler for pair {pair_id} !!!: {e}",
                exc_info=True,
            )

        return not should_disconnect_handler

    def start_smpte_stream_pair(self, config):
        pair_id = None
        pipeline = None
        pipeline_str = ""
        input_detail_log = "N/A"
        try:
            try:
                pair_id = min(int(config["port_1"]), int(config["port_2"]))
            except (ValueError, TypeError, KeyError):
                raise ValueError("Invalid port configuration for determining pair ID.")
            config["pair_id"] = pair_id

            stop_needed = False
            with self.lock:
                if pair_id in self.active_pairs:
                    self.logger.warning(
                        f"Pair ID {pair_id} already active. Requesting stop for existing."
                    )
                    stop_needed = True

            if stop_needed:
                stop_success, stop_msg = self.stop_smpte_stream_pair(str(pair_id))
                self.logger.info(
                    f"Stop result for existing pair {pair_id}: {stop_success}, {stop_msg}"
                )
                time.sleep(0.5)

            with self.lock:
                if pair_id in self.active_pairs:
                    self.logger.error(
                        f"Pair {pair_id} still found in active_pairs after stop attempt during start."
                    )
                    return (
                        False,
                        f"Failed to clean up previous instance of pair {pair_id} before restart.",
                    )

            input_type = config["input_type"]
            pipeline_input_str = ""
            if input_type == "multicast":
                mc_address = config.get("multicast_address")
                mc_port = config.get("multicast_port")
                mc_interface = (
                    config.get("multicast_interface") or DEFAULT_MULTICAST_INTERFACE
                )
                if not mc_address or not mc_port:
                    raise ValueError("Missing multicast address or port.")
                pipeline_input_str = f'udpsrc uri="udp://{mc_address}:{mc_port}" multicast-iface="{mc_interface}" buffer-size=2097152 caps="video/mpegts, systemstream=(boolean)true, packetsize=(int)188"'
                input_detail_log = f"udp://{mc_address}:{mc_port} via {mc_interface}"
            elif input_type.startswith("colorbar"):
                resolution = config.get("colorbar_resolution")
                udp_uri = COLORBAR_URIS.get(resolution)
                if not udp_uri:
                    raise ValueError(f"Invalid colorbar resolution: {resolution}")
                if self.main_stream_manager:
                    if not self.main_stream_manager._start_generator_if_needed(
                        resolution
                    ):
                        raise RuntimeError(
                            f"Failed to start generator for {resolution}"
                        )
                else:
                    self.logger.warning(
                        "Main Stream Manager ref not available, cannot ensure generator running."
                    )
                pipeline_input_str = f'udpsrc uri="{udp_uri}" buffer-size=2097152 caps="video/mpegts, systemstream=(boolean)true, packetsize=(int)188"'
                input_detail_log = f"Colorbars {resolution.upper()}"
            else:
                raise ValueError(f"Unsupported input_type: {input_type}")

            tsparse_name = f"tsparse_smpte_{pair_id}"
            try:
                smoothing_latency_us = (
                    int(config.get("smoothing_latency_ms", 30)) * 1000
                )
            except (ValueError, TypeError):
                smoothing_latency_us = 30000
            tsparse_part = f'tsparse name="{tsparse_name}" set-timestamps=true alignment=7 smoothing-latency={smoothing_latency_us} parse-private-sections=true'

            try:
                ssrc_hex = config["ssrc"].lower().replace("0x", "")
                ssrc_int = int(ssrc_hex, 16)
                ssrc_str = f"{ssrc_int}"
                ssrc_property_val = f"ssrc={ssrc_str}"
            except (ValueError, KeyError, AttributeError) as e:
                raise ValueError(
                    f"Invalid SSRC format: {config.get('ssrc')}. Error: {e}"
                )

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

            pipeline_str = f'{pipeline_input_str} ! queue ! {tsparse_part} ! queue ! {rtp_part} ! {tee_part} t. ! queue ! srtsink name="{sink_1_name}" uri="{uri_1}" {sink_common_params} t. ! queue ! srtsink name="{sink_2_name}" uri="{uri_2}" {sink_common_params}'
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
            bus.connect("message", self._on_smpte_bus_message, pair_id)
            self.logger.info(f"Connected bus message handler for SMPTE Pair {pair_id}")

            pair_info = {
                "pipeline": pipeline,
                "bus": bus,
                "config": config.copy(),
                "pair_id": pair_id,
                "status": "Starting",
                "stopping": False,
                "start_time": time.time(),
                "input_detail": input_detail_log,
                "connection_history": [],
            }
            with self.lock:
                self.active_pairs[pair_id] = pair_info

            ret = pipeline.set_state(Gst.State.PLAYING)
            state_map = {
                Gst.StateChangeReturn.FAILURE: "FAIL",
                Gst.StateChangeReturn.SUCCESS: "OK",
                Gst.StateChangeReturn.ASYNC: "ASYNC",
                Gst.StateChangeReturn.NO_PREROLL: "NO_PREROLL",
            }
            self.logger.info(
                f"SMPTE Pair {pair_id} set_state(PLAYING) returned: {state_map.get(ret, 'UNKNOWN')}"
            )

            with self.lock:
                if pair_id in self.active_pairs:
                    if ret == Gst.StateChangeReturn.FAILURE:
                        self.active_pairs[pair_id][
                            "status"
                        ] = "Start Error (PLAYING failed)"
                        self.logger.error(
                            f"Failed to set SMPTE Pair {pair_id} to PLAYING."
                        )
                        self.active_pairs.pop(pair_id, None)
                        self._cleanup_smpte_pair_resources(pair_id, bus)
                        return (
                            False,
                            f"Failed start SMPTE Pair {pair_id} (set_state PLAYING failed).",
                        )
                    elif ret == Gst.StateChangeReturn.ASYNC:
                        self.active_pairs[pair_id]["status"] = "Starting (Async)"
                    else:
                        self.active_pairs[pair_id]["status"] = "Running"
                else:
                    self.logger.warning(
                        f"SMPTE Pair {pair_id} removed during PLAYING state transition."
                    )
                    if pipeline:
                        GLib.idle_add(pipeline.set_state, Gst.State.NULL)
                    return (
                        False,
                        f"Failed to start pair {pair_id} (removed during startup).",
                    )

            return pair_id, f"SMPTE Pair {pair_id} ({input_detail_log}) starting."

        except (ValueError, FileNotFoundError, RuntimeError) as e:
            self.logger.error(
                f"Config/Runtime error starting SMPTE pair {pair_id or 'N/A'}: {e}",
                exc_info=False,
            )
            if pipeline:
                GLib.idle_add(pipeline.set_state, Gst.State.NULL)
            with self.lock:
                self.active_pairs.pop(pair_id, None)
            return False, f"Stream start error: {str(e)}"
        except Exception as e:
            self.logger.error(
                f"Unexpected start error for SMPTE pair {pair_id or 'N/A'}: {e}",
                exc_info=True,
            )
            if pipeline:
                GLib.idle_add(pipeline.set_state, Gst.State.NULL)
            with self.lock:
                self.active_pairs.pop(pair_id, None)
            return False, f"Unexpected start error: {str(e)}"

    def stop_smpte_stream_pair(self, pair_id_str, force_remove=False):
        pipeline_to_schedule_stop = None
        pair_id = -1
        bus_obj_to_cleanup = None
        pair_exists_at_start = False
        try:
            pair_id = int(pair_id_str)
            if pair_id <= 0:
                raise ValueError("Pair ID must be positive")

            with self.lock:
                if pair_id not in self.active_pairs:
                    self.logger.warning(f"Stop SMPTE Pair: Pair {pair_id} not found.")
                    if force_remove:
                        self.logger.info(
                            f"Force remove requested for already missing pair {pair_id}."
                        )
                        self._cleanup_smpte_pair_resources(pair_id, None)
                        return True, f"Pair {pair_id} already removed."
                    else:
                        return False, f"SMPTE Pair {pair_id} not found."

                pair_info = self.active_pairs.get(pair_id)
                pair_exists_at_start = True
                if not pair_info:
                    self.logger.error(
                        f"Stop SMPTE Pair: Pair info disappeared unexpectedly for key {pair_id}."
                    )
                    return False, f"Internal error: Pair {pair_id} info missing."
                if pair_info.get("stopping", False) and not force_remove:
                    self.logger.info(
                        f"Stop SMPTE Pair: Pair {pair_id} already stopping (force={force_remove})."
                    )
                    return True, f"Stop already in progress."

                self.logger.info(
                    f"Stop SMPTE Pair: Marking pair {pair_id} as stopping and removing from active list (force={force_remove})."
                )
                pipeline_to_schedule_stop = pair_info.get("pipeline")
                bus_obj_to_cleanup = pair_info.get("bus")
                self.active_pairs.pop(pair_id, None)

            if pipeline_to_schedule_stop and not force_remove:
                if self._schedule_null_state(pipeline_to_schedule_stop, pair_id):
                    return True, f"SMPTE Pair {pair_id} stop initiated."
                else:
                    self.logger.error(
                        f"Failed schedule NULL state {pair_id}. Cleaning up bus watch."
                    )
                    self._cleanup_smpte_pair_resources(pair_id, bus_obj_to_cleanup)
                    return False, f"Pair {pair_id} stop failed (scheduling error)."
            elif force_remove or not pipeline_to_schedule_stop:
                if not pipeline_to_schedule_stop:
                    self.logger.warning(
                        f"Pair {pair_id} pipeline missing during stop/force_remove."
                    )
                else:
                    self.logger.info(
                        f"Forcing immediate NULL state and cleanup for pair {pair_id}."
                    )
                    try:
                        pipeline_to_schedule_stop.set_state(Gst.State.NULL)
                    except Exception as direct_null_e:
                        self.logger.warning(
                            f"Error setting NULL directly during force_remove: {direct_null_e}"
                        )
                self._cleanup_smpte_pair_resources(pair_id, bus_obj_to_cleanup)
                status_msg = (
                    f"Pipeline missing."
                    if not pipeline_to_schedule_stop
                    else f"Forced remove successful."
                )
                return True, status_msg

        except ValueError as e:
            self.logger.error(f"Stop SMPTE Pair Error: Invalid ID '{pair_id_str}'. {e}")
            return False, f"Invalid Pair ID: {str(e)}"
        except Exception as e:
            self.logger.error(
                f"Unexpected error stopping SMPTE pair {pair_id_str}: {e}",
                exc_info=True,
            )
            if pair_exists_at_start:
                with self.lock:
                    self.active_pairs.pop(pair_id, None)
                if "bus_obj_to_cleanup" in locals() and bus_obj_to_cleanup:
                    self._cleanup_smpte_pair_resources(pair_id, bus_obj_to_cleanup)
            return False, f"An unexpected error occurred stopping pair: {str(e)}"

    def get_active_smpte_pairs(self):
        pairs_data = {}
        now = time.time()
        with self.lock:
            for pair_id in list(self.active_pairs.keys()):
                pair_info = self.active_pairs.get(pair_id)
                if not pair_info:
                    continue

                config = pair_info.get("config", {})
                status = pair_info.get("status", "Unknown")
                start_time = pair_info.get("start_time", now)
                input_detail = pair_info.get("input_detail", "N/A")
                pipeline = pair_info.get("pipeline")
                pipeline_state_name = "N/A"

                if (
                    pipeline
                    and status
                    not in ["Starting", "Stopping...", "Start Error", "Ended (EOS)"]
                    and not status.startswith("Error")
                ):
                    try:
                        _ret, current_state, _ = pipeline.get_state(
                            timeout=50 * Gst.MSECOND
                        )
                        pipeline_state_name = Gst.Element.state_get_name(current_state)
                        if current_state < Gst.State.PAUSED:
                            self.logger.warning(
                                f"Correcting status for pair {pair_id}. Was '{status}', pipeline state '{pipeline_state_name}'."
                            )
                            status = f"Error (Pipeline State: {pipeline_state_name})"
                            pair_info["status"] = status
                    except Exception as e:
                        self.logger.warning(
                            f"Error getting state for pair {pair_id}: {e}"
                        )
                        pipeline_state_name = "Error Querying"

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
        return self._sanitize_for_json(pairs_data)

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

        try:
            stats["_raw_stats_string"] = stats_struct.to_string()
        except Exception as e_str:
            stats["_raw_stats_string"] = f"Error getting raw string: {e_str}"
            self.logger.warning(f"Failed to get raw stats string: {e_str}")

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
                            "Parsing SMPTE stats from nested 'callers' structure (Listener - Connected)."
                        )
                        source_struct = nested_struct
                    else:
                        stats["error"] = "Nested caller stats has unexpected type."
                        self.logger.warning(
                            f"SMPTE Stats: First element in 'callers' array was not a Gst.Structure. Type: {type(nested_struct).__name__}"
                        )
                else:
                    self.logger.debug(
                        "SMPTE Stats: 'callers' array empty (Listener - Not Connected). Parsing yields zeros."
                    )
                    source_struct = None
            else:
                self.logger.debug(
                    "Parsing SMPTE stats from top-level structure (Caller?)."
                )
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
                stats["error"] = None

        except Exception as e:
            self.logger.error(
                f"Unexpected error during SMPTE SRT stats parsing: {e}", exc_info=True
            )
            stats["error"] = f"Internal parsing error: {str(e)}"

        return stats

    def get_smpte_pair_statistics(self, pair_id_str):
        stats_dict = {
            "pair_id": pair_id_str,
            "leg1_stats": None,
            "leg2_stats": None,
            "error": None,
            "status": "Unknown",
        }
        pipeline = None
        pair_info = None
        pair_id = -1
        leg_errors = False
        now = time.time()

        try:
            pair_id = int(pair_id_str)
            if pair_id <= 0:
                raise ValueError("Pair ID must be positive")

            with self.lock:
                pair_info = self.active_pairs.get(pair_id)

            if not pair_info:
                stats_dict["error"] = f"Pair ID {pair_id_str} not found or inactive."
                stats_dict["status"] = "Not Found"
                return stats_dict

            stats_dict["status"] = pair_info.get("status", "Unknown")

            pipeline = pair_info.get("pipeline")
            if not pipeline:
                stats_dict["error"] = (
                    f"Pipeline not found for SMPTE Pair {pair_id_str} (likely stopped or failed)."
                )
                return stats_dict

            pipeline_ready_for_stats = False
            pipeline_state_name = "Unknown"
            try:
                _ret, current_state, _ = pipeline.get_state(timeout=20 * Gst.MSECOND)
                pipeline_state_name = Gst.Element.state_get_name(current_state)
                if current_state >= Gst.State.PAUSED:
                    pipeline_ready_for_stats = True
                else:
                    stats_dict["error"] = (
                        f"Pipeline state not ready ({pipeline_state_name})"
                    )
                    leg_errors = True
            except Exception as state_e:
                pipeline_state_name = f"Error ({type(state_e).__name__})"
                self.logger.warning(
                    f"STATS ({pair_id_str}): Error getting pipeline state: {state_e}"
                )
                stats_dict["error"] = (
                    f"Error getting pipeline state: {type(state_e).__name__}"
                )
                leg_errors = True

            def get_stats_from_sink(sink_name, leg_num):
                leg_stat_data = {"error": None, "timestamp": now}
                if not pipeline_ready_for_stats:
                    leg_stat_data["error"] = stats_dict.get(
                        "error", "Pipeline not ready"
                    )
                    return leg_stat_data, True

                sink = pipeline.get_by_name(sink_name)
                if sink:
                    stats_struct = None
                    try:
                        stats_struct = sink.get_property("stats")
                        if stats_struct:
                            try:
                                struct_string = stats_struct.to_string()
                                self.logger.debug(
                                    f"STATS ({pair_id_str}) Leg {leg_num}: Raw stats structure: {struct_string}"
                                )
                            except Exception as to_string_e:
                                self.logger.warning(
                                    f"STATS ({pair_id_str}) Leg {leg_num}: Failed to convert stats_struct to string: {to_string_e}"
                                )

                            parsed_stats = self._extract_stats_from_gstruct(
                                stats_struct
                            )
                            if parsed_stats.get("error"):
                                leg_stat_data = parsed_stats
                                return leg_stat_data, True
                            else:
                                return parsed_stats, False
                        else:
                            leg_stat_data["error"] = "Stats structure None from sink"
                            return leg_stat_data, True
                    except Exception as e:
                        self.logger.error(
                            f"STATS ({pair_id_str}) Leg {leg_num}: Exception getting/parsing stats property for {sink_name}: {e}",
                            exc_info=True,
                        )
                        leg_stat_data["error"] = (
                            f"Exception getting stats: {type(e).__name__} - {e}"
                        )
                        return leg_stat_data, True
                else:
                    leg_stat_data["error"] = f"Sink element '{sink_name}' not found"
                    self.logger.error(
                        f"STATS ({pair_id_str}) Leg {leg_num}: Sink element '{sink_name}' NOT FOUND."
                    )
                    return leg_stat_data, True

            leg1_stats_result, leg1_had_error = get_stats_from_sink(
                f"srtsink_smpte_{pair_id}_1", 1
            )
            stats_dict["leg1_stats"] = leg1_stats_result
            leg_errors = leg_errors or leg1_had_error

            leg2_stats_result, leg2_had_error = get_stats_from_sink(
                f"srtsink_smpte_{pair_id}_2", 2
            )
            stats_dict["leg2_stats"] = leg2_stats_result
            leg_errors = leg_errors or leg2_had_error

            if leg_errors and not stats_dict.get("error"):
                stats_dict["error"] = "Failed to get valid stats for one or both legs."

        except ValueError as e:
            stats_dict["error"] = f"Invalid Pair ID format: {str(e)}"
            stats_dict["status"] = "Error"
            self.logger.error(f"Error getting SMPTE stats for '{pair_id_str}': {e}")
        except AttributeError as ae:
            stats_dict["error"] = (
                f"Error accessing data for stats (likely stopping): {str(ae)}"
            )
            stats_dict["status"] = "Error"
            self.logger.warning(
                f"AttributeError getting SMPTE stats for {pair_id_str}: {ae}",
                exc_info=False,
            )
        except Exception as e:
            stats_dict["error"] = f"Unexpected error getting stats: {str(e)}"
            stats_dict["status"] = "Error"
            self.logger.error(
                f"Unexpected error getting SMPTE stats {pair_id_str}: {e}",
                exc_info=True,
            )

        return self._sanitize_for_json(stats_dict)

    def get_smpte_pair_debug_info(self, pair_id_str):
        debug_info = {"error": None}
        pipeline = None
        pair_info = None
        pair_id = -1
        if not pair_id_str or not pair_id_str.isdigit():
            return {"error": f"Invalid Pair ID format: '{pair_id_str}'."}
        try:
            pair_id = int(pair_id_str)
            if pair_id <= 0:
                raise ValueError("Pair ID must be positive")
            with self.lock:
                pair_info = self.active_pairs.get(pair_id)
            if not pair_info:
                return {"error": f"SMPTE Pair {pair_id} not found (likely stopped)."}

            pipeline = pair_info.get("pipeline")
            config_data = pair_info.get("config", {})
            cfg_copy = config_data.copy() if isinstance(config_data, dict) else {}

            status = pair_info.get("status", "Unknown")
            start_time = pair_info.get("start_time")
            input_detail = pair_info.get("input_detail", "N/A")
            history_data = pair_info.get("connection_history", [])
            hist_copy = history_data.copy() if isinstance(history_data, list) else []

            debug_info.update(
                {
                    "pair_id": pair_id,
                    "config": cfg_copy,
                    "status": status,
                    "start_time_epoch": start_time,
                    "input_detail": input_detail,
                    "hist": hist_copy,
                }
            )
            if start_time:
                debug_info["uptime"] = self._format_uptime(time.time() - start_time)

            if pipeline:
                try:
                    _ret, state, _ = pipeline.get_state(timeout=100 * Gst.MSECOND)
                    debug_info["pipeline_state"] = Gst.Element.state_get_name(state)
                except Exception as state_e:
                    debug_info["pipeline_state"] = f"Error querying state: {state_e}"
            else:
                debug_info["pipeline_state"] = "Pipeline missing (already stopped?)"

            stats_data = self.get_smpte_pair_statistics(pair_id_str)
            if isinstance(stats_data, dict) and stats_data.get("error"):
                debug_info["stats_error"] = stats_data["error"]
                debug_info["parsed_stats_leg1"] = {}
                debug_info["parsed_stats_leg2"] = {}
            else:
                if isinstance(stats_data, dict):
                    leg1_stats = stats_data.get("leg1_stats")
                    leg2_stats = stats_data.get("leg2_stats")
                    debug_info["parsed_stats_leg1"] = (
                        leg1_stats if isinstance(leg1_stats, dict) else {}
                    )
                    debug_info["parsed_stats_leg2"] = (
                        leg2_stats if isinstance(leg2_stats, dict) else {}
                    )

                    if isinstance(leg1_stats, dict):
                        debug_info["raw_stats_leg1"] = leg1_stats.get(
                            "_raw_stats_string"
                        )
                    if isinstance(leg2_stats, dict):
                        debug_info["raw_stats_leg2"] = leg2_stats.get(
                            "_raw_stats_string"
                        )
                else:
                    debug_info["parsed_stats_leg1"] = {}
                    debug_info["parsed_stats_leg2"] = {}

        except ValueError as e:
            debug_info = {"error": f"Invalid Pair ID: {str(e)}"}
        except Exception as e:
            debug_info = {"error": f"Unexpected error getting debug info: {e}"}
            self.logger.error(f"Err get debug {pair_id_str}: {e}", exc_info=True)

        return self._sanitize_for_json(debug_info)

    def shutdown(self):
        self.logger.info("Shutting down SMPTEManager...")
        pair_keys_to_stop = []
        gen_keys_to_stop = []
        with self.lock:
            pair_keys_to_stop = list(self.active_pairs.keys())

        self.logger.info(f"Requesting stop for active pairs: {pair_keys_to_stop}")
        for pair_id in pair_keys_to_stop:
            self.stop_smpte_stream_pair(str(pair_id), force_remove=True)

        self.logger.info(
            "SMPTE Pair stop sequence initiated. Allow brief time for cleanup..."
        )
        time.sleep(1.0)

        with self.lock:
            if self.active_pairs:
                self.logger.warning(
                    f"Pairs still active after shutdown: {list(self.active_pairs.keys())}"
                )

        self.logger.info("SMPTEManager shutdown sequence complete.")
