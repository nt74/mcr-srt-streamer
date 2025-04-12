# /opt/mcr-srt-streamer/app/routes.py
# *** MODIFIED: Added rtp_encapsulation handling from forms ***

from flask import (
    render_template,
    request,
    jsonify,  # Keep jsonify for potential future use or error handling if needed
    send_from_directory,
    redirect,
    url_for,
    flash,
    current_app as app,
    session,
)

# Import ALL needed forms from the updated app/forms.py
from app.forms import (
    StreamForm,
    CallerForm,
    NetworkTestForm,
    MediaUploadForm,
    SettingsForm,
)

# *** IMPORT new function from utils ***
from app.utils import (
    get_system_info,
    get_network_interfaces,
)  # Added get_network_interfaces

# *** MODIFIED: Import NetworkTester AND the constant ***
from app.network_test import NetworkTester, NETWORK_TEST_MECHANISM

# *** END MODIFIED ***
import os
import logging
from datetime import datetime
import json  # For loading channel list and handling JSON errors
import re  # For parsing multicast value

logger = logging.getLogger(__name__)

# Initialize network tester (remains the same)
try:
    network_tester = NetworkTester()
    logger.info("NetworkTester initialized successfully.")
except Exception as e:
    logger.error(f"Failed to initialize NetworkTester: {e}", exc_info=True)
    network_tester = None


# --- Helper Function to Load IPTV Channels (Handles Empty File) ---
def load_iptv_channels():
    """Loads channel data from the JSON file, handling empty or missing file."""
    iptv_channels = []
    data_dir = os.path.join(os.path.dirname(__file__), "data")
    json_path = os.path.join(data_dir, "iptv_channels.json")
    try:
        if os.path.exists(json_path):
            with open(json_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                # *** ADDED CHECK: If content is empty, treat as empty list ***
                if not content:
                    logger.info(f"IPTV channel file is empty: {json_path}")
                    iptv_channels = []
                else:
                    # Try parsing only if content exists
                    try:
                        iptv_channels = json.loads(
                            content
                        )  # Use json.loads on read content
                        if not isinstance(iptv_channels, list):  # Ensure it's a list
                            logger.error(
                                f"IPTV channel file does not contain a valid JSON list: {json_path}"
                            )
                            iptv_channels = []
                        else:
                            logger.info(
                                f"Loaded {len(iptv_channels)} channels from {json_path}"
                            )
                    except json.JSONDecodeError as json_e:
                        logger.error(f"Error decoding JSON from {json_path}: {json_e}")
                        iptv_channels = []  # Return empty list on parse error
        else:
            logger.warning(f"IPTV channel file not found: {json_path}")
    except Exception as e:
        # Catch other potential errors like permission issues
        logger.error(
            f"Error reading IPTV channels file {json_path}: {e}", exc_info=True
        )
        iptv_channels = []  # Ensure empty list on any error
    return iptv_channels


# --- End Helper ---


# --- Helper Function to Populate Multicast Choices ---
def populate_multicast_choices(form_field):
    """Populates the choices for a SelectField from the loaded channels."""
    channels = load_iptv_channels()  # Now safely handles empty/invalid file
    choices = [("", "-- Select Multicast Channel --")]
    # Check if channels is indeed a list before iterating
    if isinstance(channels, list):
        for channel in channels:
            # Ensure channel is a dictionary and has needed keys
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
                logger.warning(f"Skipping invalid channel entry: {channel}")
    else:
        logger.error("IPTV channels data is not a list, cannot populate choices.")

    form_field.choices = choices
    return choices


# *** NEW HELPER: Populate Network Interface Choices ***
def populate_interface_choices(form_field):
    """Populates the choices for the network interface SelectField."""
    interfaces = get_network_interfaces()  # Call the function from utils.py
    # Start with 'Auto' option, value is empty string
    choices = [("", "-- Auto --")]
    for interface_name in interfaces:
        choices.append((interface_name, interface_name))  # Value and Label are the same
    form_field.choices = choices
    logger.debug(f"Populated interface choices: {choices}")
    return choices


# *** END NEW HELPER ***


# Wrap route definitions in a function called by __init__
def register_routes(app_instance):

    # --- Main Dashboard ---
    @app_instance.route("/")
    def index():
        """Renders the main dashboard page with listener form and active streams."""
        form = StreamForm()
        populate_multicast_choices(form.multicast_channel)
        populate_interface_choices(form.multicast_interface)  # Populate interfaces
        error_message = request.args.get("error")
        if request.args.get("apply_network_test"):
            try:  # Apply Network Test settings logic remains the same
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
            except:
                flash("Error applying network settings.", "danger")
        system_info = get_system_info()
        # Ensure stream_manager exists before calling methods
        active_streams = {}
        if hasattr(app_instance, "stream_manager") and app_instance.stream_manager:
            try:
                # Use the API endpoint conceptually, but call the manager directly here
                active_streams = app_instance.stream_manager.get_active_streams()
            except AttributeError as ae:
                logger.error(f"Error accessing stream_manager methods: {ae}")
                flash("Error communicating with stream manager service.", "danger")
            except Exception as e:
                logger.error(
                    f"Unexpected error getting active streams: {e}", exc_info=True
                )
                flash("Unexpected error retrieving stream list.", "danger")
        else:
            logger.error("Stream manager not initialized on app_instance.")
            flash("Stream manager service not available.", "danger")

        return render_template(
            "index.html",
            form=form,
            system_info=system_info,
            active_streams=active_streams,
            error=error_message,
            current_year=datetime.utcnow().year,
        )

    @app_instance.route("/start_listener_stream", methods=["POST"])
    def start_listener_stream():
        """Handles submission of the Listener stream form from the index page."""
        form = StreamForm()
        populate_multicast_choices(form.multicast_channel)
        populate_interface_choices(
            form.multicast_interface
        )  # Repopulate choices before validation
        system_info = get_system_info()
        active_streams = {}
        if hasattr(app_instance, "stream_manager") and app_instance.stream_manager:
            try:
                active_streams = app_instance.stream_manager.get_active_streams()
            except Exception as e:
                logger.error(f"Error getting active streams for form render: {e}")
                flash("Error getting current stream status.", "warning")
        else:
            flash("Stream manager service not available.", "danger")
            # Render immediately if manager isn't available
            return render_template(
                "index.html",
                form=form,
                system_info=system_info,
                active_streams=active_streams,
                error="Stream manager unavailable",
                current_year=datetime.utcnow().year,
            )

        if form.validate_on_submit():
            # *** MODIFIED: Add rtp_encapsulation to config ***
            config = {
                "port": form.port.data,
                "latency": form.latency.data,
                "overhead_bandwidth": form.overhead_bandwidth.data,
                "mode": "listener",
                "encryption": form.encryption.data,
                "passphrase": form.passphrase.data,
                "qos": form.qos.data,
                "input_type": form.input_type.data,  # Initial input type from form
                "smoothing_latency_ms": form.smoothing_latency_ms.data,
                "rtp_encapsulation": form.rtp_encapsulation.data,  # <<< ADDED
            }
            # *** END MODIFIED ***
            input_type = config["input_type"]  # Get initial input type
            media_source_detail = "N/A"

            # *** ADDED: Handle Colorbar Input ***
            if input_type.startswith("colorbar_"):
                resolution = input_type.split("_", 1)[
                    1
                ]  # Extract '720p50' or '1080i25'
                config["input_type"] = "colorbar"  # Set generic type for stream_manager
                config["colorbar_resolution"] = resolution
                media_source_detail = f"Colorbars {resolution.upper()}"
                # No need for file or multicast checks below
            # *** END ADDED ***
            elif input_type == "file":
                try:  # File handling - Use base filename
                    file_to_check = form.file_path.data
                    media_dir = os.path.abspath(app_instance.config["MEDIA_FOLDER"])
                    base_filename = os.path.basename(
                        file_to_check
                    )  # Ensure we only use the filename part
                    if not base_filename or base_filename != file_to_check:
                        raise ValueError(
                            "Invalid characters in filename."
                        )  # Basic check
                    file_path = os.path.abspath(
                        os.path.join(media_dir, base_filename)
                    )  # Construct full path for checking
                    if not file_path.startswith(
                        media_dir + os.sep
                    ) or not os.path.isfile(file_path):
                        raise ValueError("Invalid file path or file not found.")
                    config["file_path"] = (
                        base_filename  # Store only filename in config for stream manager
                    )
                    media_source_detail = base_filename
                except Exception as e:
                    flash(f"Invalid media file: {e}", "danger")
                    logger.error(f"Listener file fail: {e}")
                    return render_template(
                        "index.html",
                        form=form,
                        system_info=system_info,
                        active_streams=active_streams,
                        error=str(e),
                        current_year=datetime.utcnow().year,
                    )
            elif input_type == "multicast":
                selected_channel_value = form.multicast_channel.data
                match = re.match(r"(.+):(\d+)$", selected_channel_value)
                if match:
                    config["multicast_address"] = match.group(1)
                    config["multicast_port"] = int(match.group(2))
                    config["protocol"] = "udp"
                    media_source_detail = (
                        f"{config['multicast_address']}:{config['multicast_port']}"
                    )
                    config["multicast_interface"] = form.multicast_interface.data
                else:
                    flash("Invalid multicast channel selection.", "danger")
                    logger.error(f"Listener mcast fail: {selected_channel_value}")
                    return render_template(
                        "index.html",
                        form=form,
                        system_info=system_info,
                        active_streams=active_streams,
                        error="Invalid channel value.",
                        current_year=datetime.utcnow().year,
                    )

            # *** MODIFIED: Check original input_type for logging ***
            interface_log = (
                f", Interface: {config.get('multicast_interface') or 'Auto'}"
                if form.input_type.data == "multicast"
                else ""
            )
            rtp_log = ", RTP" if config.get("rtp_encapsulation") else ""
            # *** END MODIFIED ***

            logger.info(
                f"Attempting to start LISTENER stream (port {config.get('port')}) with config: {config}"
            )
            success, message = app_instance.stream_manager.start_stream(config=config)
            if success:
                # *** MODIFIED: Use generic config['input_type'] in log message ***
                logger.info(
                    f"Listener stream start initiated (Port: {config.get('port')}, Input: {config['input_type']} [{media_source_detail}]{interface_log}{rtp_log}, Smoothing: {config.get('smoothing_latency_ms')}ms): {message}"
                )
                # *** END MODIFIED ***
                flash(
                    f"Listener stream started on port {config.get('port')}.", "success"
                )
                return redirect(url_for("index"))
            else:
                logger.error(f"Listener stream start failed: {message}")
                flash(f"Failed start: {message}", "danger")
                return render_template(
                    "index.html",
                    form=form,
                    system_info=system_info,
                    active_streams=active_streams,
                    error=message,
                    current_year=datetime.utcnow().year,
                )
        else:  # Validation failed
            flash("Please correct the errors in the listener form.", "warning")
            return render_template(
                "index.html",
                form=form,
                system_info=system_info,
                active_streams=active_streams,
                error=None,
                current_year=datetime.utcnow().year,
            )

    # --- Caller Page ---
    @app_instance.route("/caller", methods=["GET", "POST"])
    def caller_page():
        """Renders the Caller stream configuration page and handles form submission."""
        form = CallerForm()
        populate_multicast_choices(form.multicast_channel)
        populate_interface_choices(form.multicast_interface)
        error_message = None

        if form.validate_on_submit():
            # *** MODIFIED: Add rtp_encapsulation to config ***
            config = {
                "mode": "caller",
                "target_address": form.target_address.data,
                "target_port": form.target_port.data,
                "latency": form.latency.data,
                "overhead_bandwidth": form.overhead_bandwidth.data,
                "encryption": form.encryption.data,
                "passphrase": form.passphrase.data,
                "qos": form.qos.data,
                "input_type": form.input_type.data,  # Initial input type from form
                "smoothing_latency_ms": form.smoothing_latency_ms.data,
                "rtp_encapsulation": form.rtp_encapsulation.data,  # <<< ADDED
            }
            # *** END MODIFIED ***
            input_type = config["input_type"]  # Get initial input type
            media_source_detail = "N/A"

            # *** ADDED: Handle Colorbar Input ***
            if input_type.startswith("colorbar_"):
                resolution = input_type.split("_", 1)[
                    1
                ]  # Extract '720p50' or '1080i25'
                config["input_type"] = "colorbar"  # Set generic type for stream_manager
                config["colorbar_resolution"] = resolution
                media_source_detail = f"Colorbars {resolution.upper()}"
                # No need for file or multicast checks below
            # *** END ADDED ***
            elif input_type == "file":
                try:  # File handling
                    file_to_check = form.file_path.data
                    media_dir = os.path.abspath(app_instance.config["MEDIA_FOLDER"])
                    base_filename = os.path.basename(file_to_check)
                    if base_filename != file_to_check:
                        raise ValueError("Invalid characters in filename.")
                    file_path = os.path.abspath(os.path.join(media_dir, base_filename))
                    if not file_path.startswith(
                        media_dir + os.sep
                    ) or not os.path.isfile(file_path):
                        raise ValueError("Invalid file path or file not found.")
                    config["file_path"] = base_filename
                    media_source_detail = base_filename
                except Exception as e:
                    error_message = f"Invalid file: {e}"
                    logger.error(f"Caller file fail: {e}")
                    return render_template(
                        "caller.html",
                        form=form,
                        error=error_message,
                        current_year=datetime.utcnow().year,
                    )
            elif input_type == "multicast":
                selected_channel_value = form.multicast_channel.data
                match = re.match(r"(.+):(\d+)$", selected_channel_value)
                if match:
                    config["multicast_address"] = match.group(1)
                    config["multicast_port"] = int(match.group(2))
                    config["protocol"] = "udp"
                    media_source_detail = (
                        f"{config['multicast_address']}:{config['multicast_port']}"
                    )
                    config["multicast_interface"] = form.multicast_interface.data
                else:
                    error_message = "Invalid multicast channel."
                    logger.error(f"Caller mcast fail: {selected_channel_value}")
                    return render_template(
                        "caller.html",
                        form=form,
                        error=error_message,
                        current_year=datetime.utcnow().year,
                    )

            # *** MODIFIED: Check original input_type for logging ***
            interface_log = (
                f", Interface: {config.get('multicast_interface') or 'Auto'}"
                if form.input_type.data == "multicast"
                else ""
            )
            rtp_log = ", RTP" if config.get("rtp_encapsulation") else ""
            # *** END MODIFIED ***

            logger.info(
                f"Attempting to start CALLER stream to {config['target_address']}:{config['target_port']} with config: {config}"
            )
            success, message = app_instance.stream_manager.start_stream(
                config=config, use_target_port_as_key=True
            )  # Caller uses target port as key
            if success:
                # *** MODIFIED: Use generic config['input_type'] in log message ***
                logger.info(
                    f"Caller stream start initiated (Target: {config['target_address']}:{config['target_port']}, Input: {config['input_type']} [{media_source_detail}]{interface_log}{rtp_log}, Smoothing: {config.get('smoothing_latency_ms')}ms): {message}"
                )
                # *** END MODIFIED ***
                flash(
                    f"Caller stream to {config.get('target_address')}:{config.get('target_port')} started.",
                    "success",
                )
                return redirect(url_for("index"))
            else:
                logger.error(f"Caller stream start failed: {message}")
                error_message = f"Failed start: {message}"

        return render_template(
            "caller.html",
            form=form,
            error=error_message,
            current_year=datetime.utcnow().year,
        )

    # --- Other Web UI Routes (Unchanged) ---
    @app_instance.route("/stop_stream/<stream_key>", methods=["POST"])
    def stop_stream(stream_key):
        try:
            key_int = int(stream_key)
            assert 0 < key_int < 65536
        except:
            flash("Invalid stream identifier.", "danger")
            return redirect(url_for("index"))
        success, message = app_instance.stream_manager.stop_stream(stream_key)
        if success:
            logger.info(f"Stream stopped via UI: {message}")
            flash(f"Stream ({stream_key}) stopped.", "success")
        else:
            logger.error(f"Stream stop fail UI: {message}")
            flash(f"Failed stop ({stream_key}): {message}", "danger")
        referrer = request.referrer
        return (
            redirect(referrer)
            if referrer and request.host_url in referrer
            else redirect(url_for("index"))
        )

    @app_instance.route("/media")
    def list_media():
        media_files = []
        media_dir = app_instance.config.get(
            "MEDIA_FOLDER", "/opt/mcr-srt-streamer/media"
        )
        try:
            if not os.path.isdir(media_dir):
                raise FileNotFoundError("Media dir missing")
            for f in os.listdir(media_dir):
                if f.startswith(".") or not f.lower().endswith(".ts"):
                    continue
                try:
                    fp = os.path.join(media_dir, f)
                    if os.path.isfile(fp):
                        media_files.append({"name": f, "size": os.path.getsize(fp)})
                except Exception as fe:
                    logger.warning(f"Err stat file '{f}': {fe}")
            media_files.sort(key=lambda x: x["name"])
        except Exception as e:
            logger.error(f"Failed list media: {e}")
            # Return JSON error for AJAX call
            return jsonify({"error": "Failed list media"}), 500
        return jsonify(media_files)  # Return JSON for AJAX call

    @app_instance.route("/media_info/<path:filename>")
    def media_info(filename):
        if (
            ".." in filename
            or filename.startswith("/")
            or not filename.lower().endswith(".ts")
        ):
            flash("Invalid filename.", "danger")
            return redirect(url_for("index"))
        info = None
        file_path = None
        try:
            media_dir = os.path.abspath(app_instance.config["MEDIA_FOLDER"])
            base_filename = os.path.basename(filename)
            file_path = os.path.abspath(os.path.join(media_dir, base_filename))
            if not file_path.startswith(media_dir + os.sep) or not os.path.isfile(
                file_path
            ):
                raise FileNotFoundError("Access error.")
            # Call get_file_info which now returns a JSON *string* or dict with error
            info_str_or_dict = app_instance.stream_manager.get_file_info(
                base_filename
            )  # Pass only base filename
            # Try to parse if it's a string, otherwise use as is (assuming error dict)
            if isinstance(info_str_or_dict, str):
                info = info_str_or_dict  # Keep as string for pre tag
            else:
                info = json.dumps(
                    info_str_or_dict, indent=2
                )  # Format error dict nicely
        except Exception as e:
            info = json.dumps(
                {"error": f"Error getting info for '{filename}': {e}"}, indent=2
            )
            flash(f"Error processing file info: {e}", "danger")

        dummy_form = StreamForm()
        populate_multicast_choices(dummy_form.multicast_channel)
        populate_interface_choices(dummy_form.multicast_interface)
        return render_template(
            "media_info.html",
            filename=filename,
            info=info,
            form=dummy_form,
            current_year=datetime.utcnow().year,
        )

    @app_instance.route("/stream/<stream_key>")
    def stream_details(stream_key):
        try:
            key = int(stream_key)
            assert 0 < key < 65536
        except:
            flash("Invalid stream identifier.", "danger")
            return redirect(url_for("index"))
        stream_data = {}
        # Get basic info first
        if hasattr(app_instance, "stream_manager") and app_instance.stream_manager:
            try:
                active_streams = app_instance.stream_manager.get_active_streams()
                stream_data = active_streams.get(key)
            except Exception as e:
                logger.error(f"Error getting stream data for details page {key}: {e}")

        if not stream_data:
            flash(f"Stream ({key}) not found.", "warning")
            return redirect(url_for("index"))
        form = StreamForm()  # Need form context for template rendering base layout
        populate_multicast_choices(form.multicast_channel)
        populate_interface_choices(form.multicast_interface)
        return render_template(
            "stream_details.html",
            stream_key=key,
            stream=stream_data,
            form=form,  # Pass the form
            current_year=datetime.utcnow().year,
        )

    # --- Health Check (kept) ---
    @app_instance.route("/health")
    def health_check():
        return "OK", 200

    # --- Network Test Route (UI part, kept here) ---
    @app_instance.route("/network_test")
    def network_test_page():
        form = NetworkTestForm()
        location_info = None
        regions = []
        if network_tester:
            try:
                location_info = network_tester.get_external_ip_and_location()
                regions = network_tester.get_server_regions()
                form.region.choices = [("", "-- Select Region --")] + [
                    (r, r) for r in regions if r
                ]
            except Exception as e:
                logger.error(f"Error prep network test: {e}")
        else:
            flash("Network testing service unavailable.", "warning")
        dummy_form = StreamForm()  # For base template
        populate_multicast_choices(dummy_form.multicast_channel)
        populate_interface_choices(dummy_form.multicast_interface)
        return render_template(
            "network_test.html",
            form=form,
            base_form=dummy_form,
            location_info=location_info,
            regions=regions,
            current_year=datetime.utcnow().year,
            # *** FIXED: Access constant correctly ***
            network_test_mechanism=(
                NETWORK_TEST_MECHANISM if network_tester else "unknown"
            ),
        )

    # --- RE-ADDED: Network Test API Endpoint (from Script 2) ---
    @app_instance.route('/api/network_test', methods=['POST'])
    def network_test_api():
        """ Executes a network test based on POST form data. """
        form = NetworkTestForm(request.form)
        if network_tester:
            try:
                # Attempt to populate region choices - needed for validation if mode is regional
                form.region.choices = [("", "-- Select Region --")] + [
                    (r, r) for r in network_tester.get_server_regions() if r
                ]
            except Exception as e:
                logger.error(f"Net Test Route: Fail populate region API: {e}")
                # Continue, validation might still pass if mode isn't regional

            if form.validate(): # Use WTForms validation on the POST data
                try:
                    if not network_tester: # Double check after potential init failure
                        return jsonify({"error": "Network test service unavailable."}), 503
                    location_info = network_tester.get_external_ip_and_location()
                    result = network_tester.run_network_test(
                        mode=form.mode.data, region=form.region.data,
                        manual_host=form.manual_host.data or None, manual_port=form.manual_port.data,
                        manual_protocol=form.manual_protocol.data, duration=form.duration.data,
                        bitrate=form.bitrate.data, location_info=location_info,
                    )
                    return jsonify(result or network_tester.get_fallback_results("Test returned None."))
                except Exception as e:
                    logger.error(f"Net test execution error: {e}", exc_info=True)
                    return jsonify({"error": f"Network test execution failed: {str(e)}"}), 500
            else:
                # Validation failed
                errors = {f: e[0] for f, e in form.errors.items() if f != 'csrf_token'}
                msg = next(iter(errors.values()), "Invalid input")
                logger.warning(f"Net test validation fail: {errors}")
                return jsonify({"error": f"Validation failed: {msg}", "details": errors}), 400
        else:
            logger.error("Net test route called but network_tester not initialized.")
            return jsonify({"error": "Network test service unavailable."}), 503
    # --- END RE-ADDED ---

# --- End of register_routes function ---
