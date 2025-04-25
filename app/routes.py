# /opt/mcr-srt-streamer/app/routes.py

from flask import (
    render_template,
    request,
    jsonify,
    send_from_directory,
    redirect,
    url_for,
    flash,
    current_app as app,  # Use current_app for accessing managers
    session,
    Blueprint,
)

import json
import logging
import os
import re
import time
import subprocess
from datetime import datetime, timedelta
from typing import Tuple, Dict, Any, Optional, List, Union
import socket

from app.forms import (  # Import required forms
    StreamForm,
    CallerForm,
    NetworkTestForm,
    MediaUploadForm,
    SettingsForm,
)
from app.utils import (
    get_system_info,
    get_network_interfaces,
    get_external_ip_and_location,
)
from app.network_test import NetworkTester, NETWORK_TEST_MECHANISM

logger_routes = logging.getLogger(__name__)

# Initialize network tester
try:
    network_tester = NetworkTester()
    logger_routes.info("NetworkTester initialized successfully for routes.")
except Exception as e:
    logger_routes.error(
        f"Failed to initialize NetworkTester for routes: {e}", exc_info=True
    )
    network_tester = None


# --- Helper Functions ---
def load_iptv_channels():
    iptv_channels = []
    data_dir = os.path.join(os.path.dirname(__file__), "data")
    json_path = os.path.join(data_dir, "iptv_channels.json")
    try:
        if os.path.exists(json_path):
            with open(json_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if not content:
                iptv_channels = []
            else:
                try:
                    iptv_channels = json.loads(content)
                    if not isinstance(iptv_channels, list):
                        logger_routes.error(
                            f"IPTV channel file does not contain a valid JSON list: {json_path}"
                        )
                        iptv_channels = []
                except json.JSONDecodeError as json_e:
                    logger_routes.error(
                        f"Error decoding JSON from {json_path}: {json_e}"
                    )
                    iptv_channels = []
        else:
            logger_routes.warning(f"IPTV channel file not found: {json_path}")
    except Exception as e:
        logger_routes.error(
            f"Error reading IPTV channels file {json_path}: {e}", exc_info=True
        )
        iptv_channels = []
    return iptv_channels


def populate_multicast_choices(form_field):
    channels = load_iptv_channels()
    choices = [("", "-- Select Multicast Channel --")]
    if isinstance(channels, list):
        for channel in channels:
            if (
                isinstance(channel, dict)
                and "name" in channel
                and "address" in channel
                and "port" in channel
            ):
                value = f"{channel['address']}:{channel['port']}"
                label = channel["name"]
                choices.append((value, label))
            else:
                logger_routes.warning(f"Skipping invalid channel entry: {channel}")
    else:
        logger_routes.error(
            "IPTV channels data is not a list, cannot populate choices."
        )
    if hasattr(form_field, "choices"):
        form_field.choices = choices
    else:
        logger_routes.warning(
            f"Field {getattr(form_field, 'name', 'UNKNOWN')} has no 'choices' attribute."
        )
    return choices


def populate_interface_choices(form_field):
    interfaces_list, error_msg = get_network_interfaces()
    if error_msg:
        logger_routes.error(f"Failed to get interfaces for form: {error_msg}")
        interfaces = []
    else:
        interfaces = interfaces_list or []
    choices = [("", "-- Auto --")]
    for interface_name in interfaces:
        choices.append((interface_name, interface_name))
    if hasattr(form_field, "choices"):
        form_field.choices = choices
    else:
        logger_routes.warning(
            f"Field {getattr(form_field, 'name', 'UNKNOWN')} has no 'choices' attribute."
        )
    return choices


# --- Core Configuration Building Logic ---
def _build_stream_config_from_dict(
    data: dict, mode: str
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    config = {"mode": mode}
    error_message = None
    required_fields_common = [
        "input_type",
        "latency",
        "overhead_bandwidth",
        "encryption",
    ]
    required_fields_listener = ["port"]
    required_fields_caller = ["target_address", "target_port"]
    try:
        if mode not in ["listener", "caller"]:
            raise ValueError(f"Invalid mode specified: {mode}")
        missing_common = [f for f in required_fields_common if data.get(f) is None]
        if missing_common:
            raise ValueError(f"Missing required fields: {', '.join(missing_common)}")
        if mode == "listener":
            missing_mode = [f for f in required_fields_listener if data.get(f) is None]
            if missing_mode:
                raise ValueError(f"Missing listener fields: {', '.join(missing_mode)}")
            port_int = int(data["port"])
            if not (10001 <= port_int <= 10010):
                raise ValueError("Listener port must be 10001-10010.")
            config["port"] = port_int
        elif mode == "caller":
            missing_mode = [f for f in required_fields_caller if data.get(f) is None]
            if missing_mode:
                raise ValueError(f"Missing caller fields: {', '.join(missing_mode)}")
            port_int = int(data["target_port"])
            if not (1 <= port_int <= 65535):
                raise ValueError("Target port must be 1-65535.")
            target_addr = data.get("target_address")
            if (
                not target_addr
                or not isinstance(target_addr, str)
                or len(target_addr) > 255
                or not re.match(r"^[a-zA-Z0-9\.\-\_]+$", target_addr)
                or ("." not in target_addr and target_addr != "localhost")
            ):
                raise ValueError("Invalid or missing target address format.")
            config["target_address"] = target_addr
            config["target_port"] = port_int
        latency = int(data["latency"])
        overhead = int(data["overhead_bandwidth"])
        if not (20 <= latency <= 8000):
            raise ValueError("Latency must be 20-8000ms.")
        if not (1 <= overhead <= 99):
            raise ValueError("Overhead must be 1-99%.")
        config["latency"] = latency
        config["overhead_bandwidth"] = overhead
        config["encryption"] = str(data.get("encryption", "none")).lower()
        config["passphrase"] = data.get("passphrase", "")
        config["qos"] = bool(data.get("qos", False))
        config["smoothing_latency_ms"] = int(data.get("smoothing_latency_ms", 30))
        config["rtp_encapsulation"] = bool(data.get("rtp_encapsulation", False))
        if config["encryption"] not in ["none", "aes-128", "aes-256"]:
            raise ValueError("Invalid encryption type.")
        if config["encryption"] != "none":
            if not config["passphrase"] or not (10 <= len(config["passphrase"]) <= 80):
                raise ValueError(
                    "Valid passphrase (10-80 chars) required for encryption."
                )
        else:
            config["passphrase"] = ""
        input_type = data["input_type"]
        if input_type == "file":
            config["input_type"] = "file"
            file_path_from_data = data.get("file_path")
            if not file_path_from_data:
                raise ValueError("Missing file_path for file input.")
            media_dir = os.path.abspath(app.config["MEDIA_FOLDER"])
            base_filename = os.path.basename(file_path_from_data)
            if (
                base_filename != file_path_from_data
                or ".." in base_filename
                or base_filename.startswith("/")
            ):
                raise ValueError("Invalid characters or format in file path.")
            abs_file_path = os.path.abspath(os.path.join(media_dir, base_filename))
            if not abs_file_path.startswith(media_dir + os.sep):
                raise ValueError("File path outside allowed media directory.")
            if not os.path.isfile(abs_file_path):
                raise FileNotFoundError(f"Media file not found: {base_filename}")
            if not base_filename.lower().endswith(".ts"):
                raise ValueError("Only .ts files supported.")
            config["file_path"] = base_filename  # Store only the filename
            if config["rtp_encapsulation"]:
                raise ValueError("RTP Encapsulation not supported for file inputs.")
        elif input_type == "multicast":
            config["input_type"] = "multicast"
            mc_address = data.get("multicast_address")
            mc_port = data.get("multicast_port")
            if not mc_address or mc_port is None:
                raise ValueError("Multicast address and port required.")
            mc_port = int(mc_port)
            if not (1 <= mc_port <= 65535):
                raise ValueError("Invalid multicast port.")
            if not isinstance(mc_address, str) or not re.match(
                r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", mc_address
            ):
                if not re.match(r"^[a-zA-Z0-9\.\-]+$", mc_address):
                    raise ValueError("Invalid multicast address format.")
            config["multicast_address"] = mc_address
            config["multicast_port"] = mc_port
            config["protocol"] = "udp"
            config["multicast_interface"] = data.get("multicast_interface") or None
        elif input_type.startswith("colorbar_"):
            config["input_type"] = "colorbar"
            resolution = input_type.split("_", 1)[1]
            if resolution not in ["720p50", "1080i25"]:
                raise ValueError("Invalid colorbar resolution.")
            config["colorbar_resolution"] = resolution
        else:
            raise ValueError(f"Unsupported input_type received: {input_type}")
    except (ValueError, FileNotFoundError, TypeError, KeyError) as e:
        error_message = str(e)
        logger_routes.warning(
            f"Error building stream config from dict: {error_message}"
        )
        return None, error_message
    except Exception as e:
        error_message = (
            f"An unexpected error occurred during config validation: {str(e)}"
        )
        logger_routes.error(
            f"Unexpected validation error: {error_message}", exc_info=True
        )
        return None, error_message
    return config, None


def _build_stream_config_from_form(form, mode):
    data_from_form = {}
    try:
        data_from_form["input_type"] = (
            getattr(form, "input_type", None).data
            if hasattr(form, "input_type")
            else None
        )
        data_from_form["latency"] = (
            getattr(form, "latency", None).data if hasattr(form, "latency") else None
        )
        data_from_form["overhead_bandwidth"] = (
            getattr(form, "overhead_bandwidth", None).data
            if hasattr(form, "overhead_bandwidth")
            else None
        )
        data_from_form["encryption"] = (
            getattr(form, "encryption", None).data
            if hasattr(form, "encryption")
            else "none"
        )
        data_from_form["passphrase"] = (
            getattr(form, "passphrase", None).data
            if hasattr(form, "passphrase")
            else None
        )
        data_from_form["qos"] = (
            getattr(form, "qos", None).data if hasattr(form, "qos") else False
        )
        data_from_form["smoothing_latency_ms"] = (
            getattr(form, "smoothing_latency_ms", None).data
            if hasattr(form, "smoothing_latency_ms")
            else None
        )
        data_from_form["rtp_encapsulation"] = (
            getattr(form, "rtp_encapsulation", None).data
            if hasattr(form, "rtp_encapsulation")
            else False
        )
        if mode == "listener":
            data_from_form["port"] = (
                getattr(form, "port", None).data if hasattr(form, "port") else None
            )
        elif mode == "caller":
            data_from_form["target_address"] = (
                getattr(form, "target_address", None).data
                if hasattr(form, "target_address")
                else None
            )
            data_from_form["target_port"] = (
                getattr(form, "target_port", None).data
                if hasattr(form, "target_port")
                else None
            )
        if hasattr(form, "input_type") and form.input_type.data == "file":
            data_from_form["file_path"] = (
                getattr(form, "file_path", None).data
                if hasattr(form, "file_path")
                else None
            )
        elif hasattr(form, "input_type") and form.input_type.data == "multicast":
            selected_channel_value = (
                getattr(form, "multicast_channel", None).data
                if hasattr(form, "multicast_channel")
                else None
            )
            match = re.match(r"(.+):(\d+)$", selected_channel_value or "")
            if match:
                data_from_form["multicast_address"] = match.group(1)
                data_from_form["multicast_port"] = int(match.group(2))
            else:
                return None, (
                    "Invalid multicast channel value passed from form."
                    if selected_channel_value
                    else "Multicast channel selection is required."
                )
            data_from_form["multicast_interface"] = (
                getattr(form, "multicast_interface", None).data
                if hasattr(form, "multicast_interface")
                else None
            )
        if (
            data_from_form.get("input_type") == "file"
            and data_from_form.get("file_path") is None
        ):
            return None, "File path is missing."
    except AttributeError as e:
        logger_routes.error(f"Error accessing form field data: {e}", exc_info=True)
        return None, f"Internal error accessing form data: {e}"
    return _build_stream_config_from_dict(data_from_form, mode)


# Wrap route definitions in a function called by __init__
# Routes are defined INSIDE this function so they have access to app_instance
def register_routes(app_instance):

    # --- Main Dashboard ---
    @app_instance.route("/")
    def index():
        form = StreamForm()
        populate_multicast_choices(form.multicast_channel)
        populate_interface_choices(form.multicast_interface)
        error_message = request.args.get("error")
        if request.args.get("apply_network_test"):
            try:
                latency_arg = request.args.get("latency")
                overhead_arg = request.args.get("overhead")
                applied = False
                if latency_arg is not None:
                    form.latency.data = min(max(int(latency_arg), 20), 8000)
                    applied = True
                if overhead_arg is not None:
                    form.overhead_bandwidth.data = min(max(int(overhead_arg), 1), 99)
                    applied = True
                if applied:
                    flash(
                        f"Net test settings applied: Latency={form.latency.data}ms, Overhead={form.overhead_bandwidth.data}%",
                        "success",
                    )
            except Exception as e:
                logger_routes.warning(
                    f"Failed to apply network settings from args: {e}"
                )
                flash("Error applying network settings.", "danger")

        system_info = get_system_info()
        active_streams_initial = {}
        error_getting_streams = None
        try:
            if hasattr(app_instance, "stream_manager") and app_instance.stream_manager:
                standard_streams = app_instance.stream_manager.get_active_streams()
                if isinstance(standard_streams, dict):
                    for key, stream_data in standard_streams.items():
                        stream_data["stream_type"] = "standard"
                        active_streams_initial[f"standard_{key}"] = stream_data
                elif isinstance(standard_streams, dict) and "error" in standard_streams:
                    error_getting_streams = (
                        f"Main Manager Error: {standard_streams['error']}"
                    )
                else:
                    logger_routes.warning(
                        f"Main stream manager get_active_streams returned unexpected format: {type(standard_streams)}"
                    )
                    error_getting_streams = (
                        "Unexpected format from main stream manager."
                        if standard_streams is not None and standard_streams != {}
                        else None
                    )
            else:
                error_getting_streams = "Main stream manager service unavailable."
                logger_routes.error("Main stream manager not found on app instance.")

            if hasattr(app_instance, "smpte_manager") and app_instance.smpte_manager:
                smpte_pairs = app_instance.smpte_manager.get_active_smpte_pairs()
                if isinstance(smpte_pairs, dict):
                    for key, pair_data in smpte_pairs.items():
                        pair_data["stream_type"] = "smpte_pair"
                        active_streams_initial[f"smpte_{key}"] = pair_data
                elif isinstance(smpte_pairs, dict) and "error" in smpte_pairs:
                    if error_getting_streams:
                        error_getting_streams += (
                            f"; SMPTE Manager Error: {smpte_pairs['error']}"
                        )
                    else:
                        error_getting_streams = (
                            f"SMPTE Manager Error: {smpte_pairs['error']}"
                        )
                else:
                    logger_routes.warning(
                        f"SMPTE manager get_active_smpte_pairs returned unexpected format: {type(smpte_pairs)}"
                    )
                    error_getting_streams = (
                        "Unexpected format from SMPTE manager."
                        if not error_getting_streams
                        and smpte_pairs is not None
                        and smpte_pairs != {}
                        else error_getting_streams
                    )
            elif not error_getting_streams:
                error_getting_streams = "SMPTE manager service unavailable."
                logger_routes.error(
                    "SMPTE manager not found on app instance (in index)."
                )
        except Exception as e:
            error_getting_streams = f"Error retrieving initial stream list: {e}"
            logger_routes.error(error_getting_streams, exc_info=True)
        if error_getting_streams:
            flash(error_getting_streams, "danger")
        return render_template(
            "index.html",
            form=form,
            system_info=system_info,
            active_streams=active_streams_initial,
            error=error_message,
            current_year=datetime.utcnow().year,
        )

    # --- Start Listener ---
    @app_instance.route("/start_listener_stream", methods=["POST"])
    def start_listener_stream():
        form = StreamForm()
        populate_multicast_choices(form.multicast_channel)
        populate_interface_choices(form.multicast_interface)
        system_info = get_system_info()
        active_streams = {}
        error = None
        try:
            active_streams = app_instance.stream_manager.get_active_streams()
        except Exception as e:
            logger_routes.error(
                f"Error getting streams for re-render in start_listener: {e}"
            )
        if form.validate_on_submit():
            config, error_msg = _build_stream_config_from_form(form, "listener")
            if error_msg:
                flash(f"Configuration error: {error_msg}", "danger")
                error = error_msg
            elif config:
                logger_routes.info(
                    f"Attempting start LISTENER (port {config.get('port')}) with built config: {config}"
                )
                if (
                    not hasattr(app_instance, "stream_manager")
                    or not app_instance.stream_manager
                ):
                    flash("Stream Manager is not available.", "danger")
                    error = "Stream Manager unavailable"
                else:
                    success, message = app_instance.stream_manager.start_stream(
                        config=config
                    )
                    if success:
                        flash(
                            f"Listener stream started on port {config.get('port')}.",
                            "success",
                        )
                        return redirect(url_for("index"))  # Corrected endpoint
                    else:
                        flash(f"Failed to start stream: {message}", "danger")
                        error = message
            else:
                flash("Unknown error processing stream configuration.", "danger")
                error = "Unknown configuration error."
        else:
            form_errors = {f: e[0] for f, e in form.errors.items() if f != "csrf_token"}
            error_list_str = "; ".join([f"{k}: {v}" for k, v in form_errors.items()])
            flash(f"Please correct the errors: {error_list_str}", "warning")
            error = f"Form validation failed: {error_list_str}"
        try:
            active_streams = app_instance.stream_manager.get_active_streams()
        except:
            pass
        return render_template(
            "index.html",
            form=form,
            system_info=system_info,
            active_streams=active_streams,
            error=error,
            current_year=datetime.utcnow().year,
        )

    # --- Start Caller ---
    @app_instance.route("/caller", methods=["GET", "POST"])
    def caller_page():
        form = CallerForm()
        populate_multicast_choices(form.multicast_channel)
        populate_interface_choices(form.multicast_interface)
        error_message = None
        if form.validate_on_submit():
            config, error_msg = _build_stream_config_from_form(form, "caller")
            if error_msg:
                error_message = f"Configuration error: {error_msg}"
                flash(error_message, "danger")
            elif config:
                logger_routes.info(
                    f"Attempting start CALLER to {config['target_address']}:{config['target_port']} with built config: {config}"
                )
                if (
                    not hasattr(app_instance, "stream_manager")
                    or not app_instance.stream_manager
                ):
                    flash("Stream Manager is not available.", "danger")
                    error_message = "Stream Manager unavailable"
                else:
                    success, message = app_instance.stream_manager.start_stream(
                        config=config, use_target_port_as_key=True
                    )
                    if success:
                        flash(
                            f"Caller stream to {config.get('target_address')}:{config.get('target_port')} started.",
                            "success",
                        )
                        return redirect(url_for("index"))  # Corrected endpoint
                    else:
                        error_message = f"Failed to start stream: {message}"
                        flash(error_message, "danger")
            else:
                error_message = "Unknown configuration error."
                flash(error_message, "danger")
        elif request.method == "POST":
            form_errors = {f: e[0] for f, e in form.errors.items() if f != "csrf_token"}
            error_list_str = "; ".join([f"{k}: {v}" for k, v in form_errors.items()])
            flash(f"Please correct the errors: {error_list_str}", "warning")
            error_message = f"Form validation failed: {error_list_str}"
        return render_template(
            "caller.html",
            form=form,
            error=error_message,
            current_year=datetime.utcnow().year,
        )

    # --- UI Data Endpoints ---
    @app_instance.route("/ui/active_streams_data")
    def ui_active_streams_data():
        combined_streams = {}
        error_messages = []
        try:
            if hasattr(app_instance, "stream_manager") and app_instance.stream_manager:
                standard_streams = app_instance.stream_manager.get_active_streams()
                if isinstance(standard_streams, dict):
                    for key, stream_data in standard_streams.items():
                        stream_data["stream_type"] = "standard"
                        combined_streams[f"standard_{key}"] = stream_data
                elif isinstance(standard_streams, dict) and "error" in standard_streams:
                    error_messages.append(
                        f"Main Manager Error: {standard_streams['error']}"
                    )
                else:
                    logger_routes.warning(
                        f"Main stream manager get_active_streams returned unexpected format: {type(standard_streams)}"
                    )
                    (
                        error_messages.append(
                            "Unexpected format from main stream manager."
                        )
                        if standard_streams is not None and standard_streams != {}
                        else None
                    )
            else:
                error_messages.append("Main stream manager service unavailable.")
                logger_routes.error("Main stream manager not found on app instance.")
        except Exception as e:
            logger_routes.error(f"Error getting standard streams: {e}", exc_info=True)
            error_messages.append("Failed to retrieve standard streams.")
        try:
            if hasattr(app_instance, "smpte_manager") and app_instance.smpte_manager:
                smpte_pairs = app_instance.smpte_manager.get_active_smpte_pairs()
                if isinstance(smpte_pairs, dict):
                    for key, pair_data in smpte_pairs.items():
                        pair_data["stream_type"] = "smpte_pair"
                        combined_streams[f"smpte_{key}"] = pair_data
                elif isinstance(smpte_pairs, dict) and "error" in smpte_pairs:
                    error_messages.append(
                        f"SMPTE Manager Error: {smpte_pairs['error']}"
                    )
                else:
                    logger_routes.warning(
                        f"SMPTE manager get_active_smpte_pairs returned unexpected format: {type(smpte_pairs)}"
                    )
                    (
                        error_messages.append("Unexpected format from SMPTE manager.")
                        if smpte_pairs is not None and smpte_pairs != {}
                        else None
                    )
            elif not any(
                "SMPTE manager service unavailable" in msg for msg in error_messages
            ):
                error_messages.append("SMPTE manager service unavailable.")
                logger_routes.error(
                    "SMPTE manager not found on app instance (in /ui/active_streams_data)."
                )
        except Exception as e:
            logger_routes.error(f"Error getting SMPTE pairs: {e}", exc_info=True)
            error_messages.append("Failed to retrieve SMPTE pairs.")
        if not combined_streams and error_messages:
            logger_routes.error(
                f"No streams found and errors occurred: {error_messages}"
            )
            return jsonify({"error": error_messages[0]}), 500
        elif error_messages:
            logger_routes.warning(
                f"Errors encountered fetching stream data for UI: {'; '.join(error_messages)}"
            )
        try:
            return jsonify({"data": combined_streams})
        except Exception as e:
            logger_routes.critical(
                f"Critical JSON serialization error for combined streams: {e}"
            )
            return jsonify({"error": "Failed to serialize stream data"}), 500

    @app_instance.route("/ui/stats/<stream_key>")
    def ui_stream_stats(stream_key):
        try:
            key_int = int(stream_key)
            if not (0 < key_int < 65536):
                raise ValueError("Invalid key range")
            if (
                not hasattr(app_instance, "stream_manager")
                or not app_instance.stream_manager
            ):
                return jsonify({"error": "Stream manager service unavailable."}), 503
            stats = app_instance.stream_manager.get_stream_statistics(str(key_int))
            if stats is None:
                return (
                    jsonify({"error": f"Stream {key_int} not found or stopped."}),
                    404,
                )
            if isinstance(stats, dict) and stats.get("error"):
                status_code = (
                    404
                    if "not found" in str(stats["error"]).lower()
                    or "stopped" in str(stats["error"]).lower()
                    else 500
                )
                return jsonify(stats), status_code
            else:
                stats["timestamp_api"] = time.time()
                return jsonify(stats)  # Already sanitized
        except ValueError:
            return jsonify({"error": "Invalid stream key format."}), 400
        except Exception as e:
            logger_routes.error(f"Error in /ui/stats/{stream_key}: {e}", exc_info=True)
            return jsonify({"error": "Failed to retrieve stream stats for UI"}), 500

    @app_instance.route("/ui/debug/<int:stream_key>")
    def ui_stream_debug(stream_key):
        """Returns raw debug info for a specific stream as JSON."""
        if (
            not hasattr(app_instance, "stream_manager")
            or not app_instance.stream_manager
        ):
            return jsonify({"error": "Stream Manager service unavailable."}), 503

        debug_info = app_instance.stream_manager.get_debug_info(stream_key)
        error_message = debug_info.get("error")
        if error_message:
            error_lower = str(error_message).lower() if error_message else ""
            status_code = (
                404
                if "not found" in error_lower
                or "missing" in error_lower
                or "stopped" in error_lower
                else 500
            )
            return jsonify({"error": error_message}), status_code

        # Return the sanitized debug info directly as JSON
        return jsonify(debug_info)

    # --- Stop Stream, Media List, Media Info, Details ---
    @app_instance.route("/stop_stream/<stream_key>", methods=["POST"])
    def stop_stream(stream_key):
        try:
            key_int = int(stream_key)
            assert 0 < key_int < 65536
        except (ValueError, AssertionError):
            flash("Invalid stream identifier.", "danger")
            return redirect(url_for("index"))
        if (
            not hasattr(app_instance, "stream_manager")
            or not app_instance.stream_manager
        ):
            flash("Stream manager service unavailable.", "danger")
            return redirect(url_for("index"))
        success, message = app_instance.stream_manager.stop_stream(str(key_int))
        if success:
            logger_routes.info(f"Stream stopped via UI: {message}")
            flash(f"Stream ({stream_key}) stopped.", "success")
        else:
            logger_routes.error(f"Stream stop fail UI: {message}")
            flash(f"Failed stop ({stream_key}): {message}", "danger")
        referrer = request.referrer
        is_safe_url = referrer and (
            referrer.startswith("/") or request.host_url in referrer
        )
        return redirect(referrer) if is_safe_url else redirect(url_for("index"))

    @app_instance.route("/media")
    def list_media():
        media_files = []
        media_dir = app_instance.config.get(
            "MEDIA_FOLDER", "/opt/mcr-srt-streamer/media"
        )
        try:
            if not os.path.isdir(media_dir):
                raise FileNotFoundError(
                    "Media directory not found or is not accessible."
                )
            for f in os.listdir(media_dir):
                if f.startswith(".") or not f.lower().endswith(".ts"):
                    continue
                try:
                    fp = os.path.join(media_dir, f)
                    if os.path.isfile(fp):
                        media_files.append({"name": f, "size": os.path.getsize(fp)})
                except OSError as fe:
                    logger_routes.warning(f"Error stating file '{f}': {fe}")
            media_files.sort(key=lambda x: x["name"])
        except FileNotFoundError as fnfe:
            logger_routes.error(f"Media directory error: {fnfe}")
            return jsonify({"error": str(fnfe)}), 404
        except Exception as e:
            logger_routes.error(f"Failed list media: {e}", exc_info=True)
            return jsonify({"error": "Failed list media files"}), 500
        return jsonify(media_files)

    @app_instance.route("/media_info/<path:filename>")
    def media_info(filename):
        # Basic validation to prevent directory traversal
        if (
            ".." in filename
            or filename.startswith("/")
            or not filename.lower().endswith(".ts")
        ):
            flash("Invalid filename.", "danger")
            return redirect(url_for("index"))

        media_dir = os.path.abspath(app.config["MEDIA_FOLDER"])
        abs_file_path = os.path.abspath(os.path.join(media_dir, filename))

        # Security check: Ensure the path is still within the media folder
        if not abs_file_path.startswith(media_dir + os.sep):
            flash("Access denied.", "danger")
            return redirect(url_for("index"))

        if not os.path.isfile(abs_file_path):
            flash(f"Media file not found: {filename}", "danger")
            return redirect(url_for("index"))

        try:
            # Ensure mediainfo command exists and is executable
            cmd = [
                "mediainfo",
                "--Output=JSON",
                abs_file_path,
            ]  # Use JSON output
            logger_routes.info(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,  # Raise CalledProcessError on non-zero exit
                timeout=15,  # Add a timeout
            )
            info_json_str = result.stdout
            # Attempt to parse to ensure it's valid JSON before passing
            try:
                # Pass the raw JSON string to the template
                # The template can then decide how to display it (e.g., pre-formatted)
                # Or parse it here if needed for specific fields
                json.loads(info_json_str)  # Validate JSON structure
                info_display = info_json_str
            except json.JSONDecodeError as json_e:
                logger_routes.error(
                    f"Failed to parse mediainfo JSON output for {filename}: {json_e}"
                )
                info_display = f"Error: Could not parse mediainfo output.\n\nRaw Output:\n{info_json_str}"

        except FileNotFoundError:
            logger_routes.error(
                "mediainfo command not found. Please ensure it's installed and in PATH."
            )
            info_display = "Error: 'mediainfo' command not found on the server."
        except subprocess.CalledProcessError as e:
            logger_routes.error(f"mediainfo command failed for {filename}: {e.stderr}")
            info_display = f"Error running mediainfo: {e.stderr}"
        except subprocess.TimeoutExpired:
            logger_routes.error(f"mediainfo command timed out for {filename}")
            info_display = "Error: mediainfo command timed out."
        except Exception as e:
            logger_routes.error(
                f"Error getting media info for {filename}: {e}", exc_info=True
            )
            info_display = f"Error: An unexpected error occurred ({type(e).__name__})."

        return render_template("media_info.html", filename=filename, info=info_display)

    @app_instance.route("/stream/<stream_key>")
    def stream_details(stream_key):
        try:
            key_as_int = int(stream_key)
            assert 0 < key_as_int < 65536
        except (ValueError, AssertionError):
            flash("Invalid stream identifier.", "danger")
            return redirect(url_for("index"))

        debug_info = None
        error_msg = None

        if hasattr(app_instance, "stream_manager") and app_instance.stream_manager:
            try:
                # *** FETCH FULL DEBUG INFO INSTEAD OF JUST STATS/BASIC INFO ***
                debug_info = app_instance.stream_manager.get_debug_info(str(key_as_int))
                error_msg = debug_info.get(
                    "error"
                )  # Check for errors within debug info

            except Exception as e:
                logger_routes.error(
                    f"Error getting debug info for details page key={key_as_int}: {e}",
                    exc_info=True,
                )
                error_msg = f"Error fetching details for stream {stream_key}."
                flash(error_msg, "danger")
                return redirect(url_for("index"))
        else:
            error_msg = "Stream Manager service unavailable."
            flash(error_msg, "danger")
            return redirect(url_for("index"))

        # --- Check if stream was found or if there was an error getting info ---
        if error_msg:
            # Handle errors like "not found" gracefully
            error_lower = str(error_msg).lower()
            if (
                "not found" in error_lower
                or "missing" in error_lower
                or "stopped" in error_lower
            ):
                flash(
                    f"Stream ({stream_key}) not found or is stopped. Error: {error_msg}",
                    "warning",
                )
            else:
                flash(
                    f"Error getting stream details ({stream_key}): {error_msg}",
                    "danger",
                )
            return redirect(url_for("index"))

        # If we got here, debug_info should be valid (though stats might be empty if not connected)
        # The dynamic stats will STILL be loaded by stream_details.js, but now using the same debug endpoint.
        dummy_form = StreamForm()  # Keep for compatibility if template needs it
        return render_template(
            "stream_details.html",
            stream_key=key_as_int,
            # *** PASS THE FULL DEBUG INFO OBJECT ***
            debug_info=debug_info,  # Pass the entire debug info dict
            form=dummy_form,
            current_year=datetime.utcnow().year,
        )

    @app_instance.route("/health")
    def health_check():
        return "OK", 200

    # --- Network Test Routes ---
    @app_instance.route("/network_test")
    def network_test_page():
        form = NetworkTestForm()
        location_info = None
        location_error = None
        regions = []
        global network_tester
        if network_tester:
            try:
                location_data_dict, location_error_msg = get_external_ip_and_location()
                if location_data_dict:
                    location_info = location_data_dict
                if location_error_msg:
                    location_error = location_error_msg
                    logger_routes.warning(
                        f"Error getting location info for network test page: {location_error}"
                    )
                regions = network_tester.get_server_regions()
                form.region.choices = [("", "-- Select Region --")] + [
                    (r, r) for r in regions if r
                ]
            except Exception as e:
                logger_routes.error(
                    f"Error preparing network test page: {e}", exc_info=True
                )
                flash("Error preparing network test page.", "danger")
                location_error = str(e)
        else:
            flash("Network testing service unavailable.", "warning")
        base_form = StreamForm()
        return render_template(
            "network_test.html",
            form=form,
            base_form=base_form,
            location_info=location_info,
            regions=regions,
            current_year=datetime.utcnow().year,
            network_test_mechanism=(
                NETWORK_TEST_MECHANISM if network_tester else "unknown"
            ),
        )

    @app_instance.route("/api/network_test", methods=["POST"])
    def network_test_api():
        form = NetworkTestForm(request.form)
        global network_tester
        if not network_tester:
            try:
                network_tester = NetworkTester()
                logger_routes.info("Re-initialized NetworkTester for API request.")
            except Exception as e:
                logger_routes.error(
                    f"Failed to re-initialize NetworkTester for API request: {e}"
                )
                return jsonify({"error": "Network test service unavailable."}), 503
        try:
            regions = network_tester.get_server_regions()
            form.region.choices = [("", "-- Select Region --")] + [
                (r, r) for r in regions if r
            ]
        except Exception as e:
            logger_routes.error(
                f"API Net Test: Failed to populate regions for validation: {e}"
            )
        if form.validate():
            try:
                location_data, location_error = get_external_ip_and_location()
                if location_error:
                    logger_routes.warning(
                        f"Issue getting location info for network test API: {location_error}"
                    )
                result_dict, error_msg = network_tester.run_network_test(
                    mode=form.mode.data,
                    region=form.region.data,
                    manual_host=form.manual_host.data or None,
                    manual_port=form.manual_port.data,
                    manual_protocol=form.manual_protocol.data,
                    duration=form.duration.data,
                    bitrate=form.bitrate.data,
                    location_info_dict_from_caller=location_data,
                )
                if error_msg:
                    logger_routes.error(f"Network test execution failed: {error_msg}")
                    return (
                        jsonify(
                            {"error": f"Network test execution failed: {error_msg}"}
                        ),
                        500,
                    )
                elif result_dict:
                    return jsonify(result_dict)
                else:
                    logger_routes.error(
                        "Network test returned None result without error message."
                    )
                    return (
                        jsonify({"error": "Test completed but returned no data."}),
                        500,
                    )
            except Exception as e:
                logger_routes.error(
                    f"Unexpected error during network test execution: {e}",
                    exc_info=True,
                )
                return (
                    jsonify({"error": f"Network test execution failed: {str(e)}"}),
                    500,
                )
        else:
            errors = {f: e[0] for f, e in form.errors.items() if f != "csrf_token"}
            msg = next(iter(errors.values()), "Invalid input")
            logger_routes.warning(f"Net test API validation fail: {errors}")
            return (
                jsonify({"error": f"Validation failed: {msg}", "details": errors}),
                400,
            )


# --- End of register_routes function ---
