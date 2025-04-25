# /opt/mcr-srt-streamer/app/api_routes.py

from flask import (
    Blueprint,
    jsonify,
    request,
    current_app as app,
    Response,
    abort,
)
import logging
import re
import os
import json
import time

# Import utilities needed (ensure utils.py exists and defines get_system_info)
# If get_system_info isn't defined in app.utils, adjust this import
try:
    from app.utils import get_system_info
except ImportError:
    # Define a dummy function or handle the error appropriately if utils is optional
    def get_system_info():
        logger.error("app.utils or get_system_info not found!")
        return {"error": "System info utility not available"}


# Import the shared authentication decorator (ensure auth.py exists)
try:
    from .auth import require_api_auth
except ImportError:
    # Define a dummy decorator if auth.py is missing, allowing app to load but API calls will fail
    logger.error("app.auth or require_api_auth not found! API calls will fail.")
    import functools

    def require_api_auth(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            abort(Response("Authentication module not configured.", 500))

        return wrapper


logger = logging.getLogger(__name__)
api_bp = Blueprint("api", __name__, url_prefix="/api")


# --- API Routes ---


@api_bp.route("/streams", methods=["GET"])
# @require_api_auth # Optional: Protect GET requests if needed
def api_get_streams():
    """Returns a list of active streams."""
    try:
        if not hasattr(app, "stream_manager") or not app.stream_manager:
            logger.error("API GET /streams: Stream manager not available.")
            return jsonify({"error": "Stream manager not available"}), 503
        streams = app.stream_manager.get_active_streams()
        serializable_streams = json.loads(json.dumps(streams, default=str))
        return jsonify(
            {
                "data": (
                    serializable_streams
                    if isinstance(serializable_streams, dict)
                    else {}
                )
            }
        )
    except Exception as e:
        logger.error(f"API GET /streams error: {e}", exc_info=True)
        return jsonify({"error": "Failed to retrieve streams"}), 500


@api_bp.route("/stats/<stream_key>")
# @require_api_auth # Optional: Protect GET requests if needed
def get_stats(stream_key):
    """Returns live statistics for a specific stream."""
    try:
        key_int = int(stream_key)
        if not (0 < key_int < 65536):
            raise ValueError("Invalid key range")
    except ValueError:
        logger.warning(
            f"API GET /stats: Invalid key format/range requested: {stream_key}"
        )
        return jsonify({"error": f"Invalid key format or range: {stream_key}"}), 400

    if not hasattr(app, "stream_manager") or not app.stream_manager:
        logger.error(f"API GET /stats/{stream_key}: Stream manager not available.")
        return jsonify({"error": "Stream manager not available"}), 503

    stats = app.stream_manager.get_stream_statistics(stream_key)

    if stats is None:
        logger.info(
            f"API GET /stats/{stream_key}: Stats unavailable or stream not found."
        )
        return (
            jsonify(
                {
                    "error": f"Stream ({stream_key}) stats unavailable or stream not found"
                }
            ),
            404,
        )
    elif isinstance(stats, dict) and "error" in stats:
        error_msg = stats["error"]
        logger.error(
            f"Stream manager error getting stats for {stream_key}: {error_msg}"
        )
        status_code = 404 if "not found" in error_msg.lower() else 500
        return jsonify(stats), status_code
    else:
        stats["timestamp_api"] = time.time()
        try:
            serializable_stats = json.loads(json.dumps(stats, default=str))
            return jsonify(serializable_stats)
        except (TypeError, json.JSONDecodeError) as e:
            logger.error(f"API GET /stats/{stream_key}: Serialization error: {e}")
            return jsonify({"error": "Error serializing stream statistics"}), 500


@api_bp.route("/debug/<stream_key>")
# @require_api_auth # Optional: Protect GET requests if needed
def get_debug_info(stream_key):
    """Returns raw debug information for a specific stream."""
    try:
        key_int = int(stream_key)
        if not (0 < key_int < 65536):
            raise ValueError("Invalid key range")
    except ValueError:
        logger.warning(
            f"API GET /debug: Invalid key format/range requested: {stream_key}"
        )
        return jsonify({"error": f"Invalid key format or range: {stream_key}"}), 400

    if not hasattr(app, "stream_manager") or not app.stream_manager:
        logger.error(f"API GET /debug/{stream_key}: Stream manager not available.")
        return jsonify({"error": "Stream manager not available"}), 503

    debug_info = app.stream_manager.get_debug_info(stream_key)

    if debug_info is None:
        logger.error(f"API GET /debug/{stream_key}: Manager returned None.")
        return (
            jsonify(
                {
                    "error": f"Debug info unavailable or stream not found for {stream_key}"
                }
            ),
            404,
        )
    elif isinstance(debug_info, dict) and "error" in debug_info:
        error_msg = debug_info["error"]
        logger.error(
            f"Stream manager error getting debug info for {stream_key}: {error_msg}"
        )
        status_code = 404 if "not found" in error_msg.lower() else 500
        return jsonify(debug_info), status_code
    else:
        try:
            serializable_debug = json.loads(json.dumps(debug_info, default=str))
            return jsonify(serializable_debug)
        except (TypeError, json.JSONDecodeError) as e:
            logger.error(f"API GET /debug/{stream_key}: Serialization error: {e}")
            return jsonify({"error": "Error serializing debug information"}), 500


@api_bp.route("/streams/<stream_key>", methods=["GET"])
# @require_api_auth # Optional: Protect GET requests if needed
def api_get_stream_detail(stream_key):
    """Returns combined details and stats for a specific stream (currently same as stats)."""
    return get_stats(stream_key)


@api_bp.route("/streams", methods=["POST"])
@require_api_auth  # Apply the decorator
def api_start_stream():
    """Starts a new stream (listener or caller) based on JSON payload."""
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 415
    config_data = request.get_json()
    if not config_data:
        return jsonify({"error": "No JSON data provided"}), 400

    logger.info(f"API request received to start stream: {config_data}")

    # --- Stage 1: Validation and Variable Extraction ---
    errors = {}
    validated_params = {}  # Store validated parameters here

    # Mode
    mode = config_data.get("mode", "listener").lower()
    if mode not in ["listener", "caller"]:
        errors["mode"] = "Mode must be 'listener' or 'caller'."
    else:
        validated_params["mode"] = mode

    # Input Type
    input_type = config_data.get("input_type")
    allowed_inputs = ["multicast", "file", "colorbar_720p50", "colorbar_1080i25"]
    if not input_type or input_type not in allowed_inputs:
        errors["input_type"] = (
            f"Missing or invalid input_type. Allowed: {', '.join(allowed_inputs)}"
        )
    # We store the validated input type later based on specific checks

    # RTP Encapsulation
    rtp_encapsulation = config_data.get("rtp_encapsulation", False)
    if not isinstance(rtp_encapsulation, bool):
        errors["rtp_encapsulation"] = (
            "rtp_encapsulation must be a boolean (true/false)."
        )
    elif rtp_encapsulation and input_type not in [
        "multicast",
        "colorbar_720p50",
        "colorbar_1080i25",
    ]:
        if "input_type" not in errors:
            errors["rtp_encapsulation"] = (
                "RTP encapsulation only supported for Multicast or Colorbar inputs via API."
            )
    else:
        validated_params["rtp_encapsulation"] = rtp_encapsulation

    # SRT Parameters
    latency = config_data.get("latency", 300)
    if not isinstance(latency, int) or not (20 <= latency <= 8000):
        errors["latency"] = "SRT Latency must be an integer between 20 and 8000."
    else:
        validated_params["latency"] = latency

    overhead = config_data.get("overhead_bandwidth", 2)
    if not isinstance(overhead, int) or not (1 <= overhead <= 99):
        errors["overhead_bandwidth"] = (
            "Overhead bandwidth must be an integer between 1 and 99."
        )
    else:
        validated_params["overhead_bandwidth"] = overhead

    encryption = config_data.get("encryption", "none").lower()
    passphrase = config_data.get("passphrase")
    if encryption not in ["none", "aes-128", "aes-256"]:
        errors["encryption"] = (
            "Invalid encryption type. Allowed: none, aes-128, aes-256."
        )
    elif encryption != "none":
        if not passphrase:
            errors["passphrase"] = "Passphrase is required when encryption is enabled."
        elif not isinstance(passphrase, str) or not (10 <= len(passphrase) <= 80):
            errors["passphrase"] = (
                "Passphrase must be a string between 10 and 80 characters."
            )
        else:
            validated_params["passphrase"] = passphrase
    validated_params["encryption"] = encryption
    if encryption == "none":
        validated_params["passphrase"] = ""

    # Optional SRT Params
    validated_params["qos"] = config_data.get("qos", False)
    if not isinstance(validated_params["qos"], bool):
        errors["qos"] = "qos must be a boolean (true/false) if provided."

    validated_params["smoothing_latency_ms"] = config_data.get(
        "smoothing_latency_ms", 30
    )
    if not isinstance(validated_params["smoothing_latency_ms"], int):
        errors["smoothing_latency_ms"] = (
            "smoothing_latency_ms must be an integer if provided."
        )

    # --- Mode-specific Validation (Handles string->int conversion) ---
    if mode == "listener":
        port_str = config_data.get("port")
        try:
            port = int(port_str)
            if not (1 <= port <= 65535):
                errors["port"] = "Listener requires a 'port' between 1 and 65535."
            else:
                validated_params["port"] = port
        except (ValueError, TypeError):
            errors["port"] = (
                "Listener requires a valid integer 'port' between 1 and 65535."
            )

    elif mode == "caller":
        target_address = config_data.get("target_address")
        target_port_str = config_data.get("target_port")

        if (
            not target_address
            or not isinstance(target_address, str)
            or len(target_address) > 255
        ):
            errors["target_address"] = (
                "Caller requires a valid 'target_address' (string, max 255)."
            )
        elif not re.match(r"^[a-zA-Z0-9.\-]+$", target_address) or (
            "." not in target_address and target_address != "localhost"
        ):
            errors["target_address"] = (
                "Invalid target address format (use hostname or IP)."
            )
        else:
            validated_params["target_address"] = target_address

        try:
            target_port = int(target_port_str)
            if not (1 <= target_port <= 65535):
                errors["target_port"] = (
                    "Caller requires a 'target_port' between 1 and 65535."
                )
            else:
                validated_params["target_port"] = target_port
        except (ValueError, TypeError):
            errors["target_port"] = (
                "Caller requires a valid integer 'target_port' between 1 and 65535."
            )
    # --- End Mode-specific Validation ---

    # Input-specific Validation (Only if input_type itself was valid initially)
    if "input_type" not in errors:
        if input_type == "file":
            file_path = config_data.get("file_path")
            if not file_path or not isinstance(file_path, str):
                errors["file_path"] = "File input requires a 'file_path' (string)."
            elif ".." in file_path or os.path.isabs(file_path):
                errors["file_path"] = (
                    "Invalid file path format (must be relative, no '..')."
                )
            elif not file_path.lower().endswith(".ts"):
                errors["file_path"] = "Only .ts files are supported."
            else:
                try:
                    media_dir = os.path.abspath(app.config["MEDIA_FOLDER"])
                    safe_file_path = os.path.normpath(file_path)
                    if os.path.isabs(safe_file_path):
                        errors["file_path"] = (
                            "Invalid file path format (must be relative)."
                        )
                    else:
                        abs_path = os.path.abspath(
                            os.path.join(media_dir, safe_file_path)
                        )
                        if not abs_path.startswith(media_dir + os.sep):
                            errors["file_path"] = (
                                "File path is outside the allowed media directory."
                            )
                        elif not os.path.isfile(abs_path):
                            errors["file_path"] = (
                                f"File does not exist: {safe_file_path}"
                            )
                        else:
                            validated_params["file_path"] = safe_file_path
                except KeyError:
                    logger.error("MEDIA_FOLDER not configured in app config.")
                    errors["file_path"] = "Server configuration error (media folder)."
                except Exception as e:
                    logger.error(f"Error validating file path {file_path}: {e}")
                    errors["file_path"] = "Server error validating file path."
            if "file_path" not in errors:
                validated_params["input_type"] = "file"

        elif input_type == "multicast":
            mc_address = config_data.get("multicast_address")
            mc_port_str = config_data.get("multicast_port")  # Get as string first
            mc_interface = config_data.get("multicast_interface")

            if not mc_address or not isinstance(mc_address, str):
                errors["multicast_address"] = (
                    "Multicast input requires 'multicast_address'."
                )
            elif not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", mc_address):
                errors["multicast_address"] = "Invalid multicast address format."
            else:
                validated_params["multicast_address"] = mc_address

            try:
                mc_port = int(mc_port_str)
                if not (1 <= mc_port <= 65535):
                    errors["multicast_port"] = (
                        "Multicast input requires 'multicast_port' (1-65535)."
                    )
                else:
                    validated_params["multicast_port"] = mc_port
            except (ValueError, TypeError):
                errors["multicast_port"] = (
                    "Multicast input requires a valid integer 'multicast_port'."
                )

            if mc_interface and not isinstance(mc_interface, str):
                errors["multicast_interface"] = (
                    "Multicast interface must be a string if provided."
                )
            elif mc_interface:
                validated_params["multicast_interface"] = mc_interface

            if "multicast_address" not in errors and "multicast_port" not in errors:
                validated_params["input_type"] = "multicast"
                validated_params["protocol"] = "udp"

        elif input_type.startswith("colorbar_"):
            resolution = input_type.split("_", 1)[1]
            if resolution not in ["720p50", "1080i25"]:
                errors["input_type"] = (
                    "Invalid colorbar resolution (use colorbar_720p50 or colorbar_1080i25)."
                )
            else:
                validated_params["input_type"] = "colorbar"
                validated_params["colorbar_resolution"] = resolution

    # --- Final Validation Check ---
    if errors:
        logger.warning(f"API stream config validation failed: {errors}")
        return jsonify({"error": "Validation failed", "details": errors}), 400

    # --- Stage 2: Construct final_config from validated_params ---
    final_config = validated_params.copy()
    final_config.setdefault("port", None)
    final_config.setdefault("target_address", None)
    final_config.setdefault("target_port", None)
    final_config.setdefault("file_path", None)
    final_config.setdefault("multicast_address", None)
    final_config.setdefault("multicast_port", None)
    final_config.setdefault("multicast_interface", None)
    final_config.setdefault("protocol", None)
    final_config.setdefault("colorbar_resolution", None)
    if final_config["encryption"] == "none":
        final_config["passphrase"] = ""
    final_config.setdefault("passphrase", None)

    # --- Stage 3: Start Stream ---
    logger.info(
        f"API validated config, attempting start_stream: {json.dumps(final_config)}"
    )  # Log complete config as JSON
    try:
        if not hasattr(app, "stream_manager") or not app.stream_manager:
            logger.error("API start stream failed: Stream manager not available.")
            return jsonify({"error": "Stream manager not available"}), 503

        use_target_key = final_config["mode"] == "caller"
        success, message = app.stream_manager.start_stream(
            config=final_config, use_target_port_as_key=use_target_key
        )

        if success:
            started_key = (
                final_config.get("target_port")
                if use_target_key
                else final_config.get("port")
            )
            logger.info(
                f"API successfully initiated stream start for key {started_key}"
            )
            response_data = {
                "message": message or "Stream creation initiated.",
                "stream_key": started_key,
                "status": "starting",
            }
            return jsonify(response_data), 201
        else:
            logger.error(f"API start_stream failed: {message}")
            status_code = (
                409
                if "in use" in str(message).lower()
                or "conflict" in str(message).lower()
                else 400
            )
            return jsonify({"error": message or "Failed to start stream"}), status_code
    except Exception as e:
        logger.exception("API POST /streams internal error during start_stream call")
        return (
            jsonify({"error": f"Internal server error starting stream: {str(e)}"}),
            500,
        )


@api_bp.route("/streams/<stream_key>", methods=["DELETE"])
@require_api_auth  # Apply the decorator
def api_stop_stream(stream_key):
    """Stops a specific stream."""
    logger.info(f"API request received to stop stream {stream_key}")
    try:
        key_int = int(stream_key)
        if not (0 < key_int < 65536):
            raise ValueError("Invalid key range")

        if not hasattr(app, "stream_manager") or not app.stream_manager:
            logger.error(
                f"API DELETE /streams/{stream_key}: Stream manager not available."
            )
            return jsonify({"error": "Stream manager not available"}), 503

        success, message = app.stream_manager.stop_stream(stream_key)

        if success:
            logger.info(
                f"API stop request for stream {stream_key} successful: {message}"
            )
            return (
                jsonify(
                    {
                        "message": message or "Stream stopping initiated.",
                        "status": "stopping",
                    }
                ),
                200,
            )
        else:
            logger.warning(
                f"API stop request failed for stream {stream_key}: {message}"
            )
            status_code = 404 if "not found" in str(message).lower() else 400
            return jsonify({"error": message or "Failed to stop stream."}), status_code
    except ValueError:
        logger.warning(
            f"API DELETE /streams: Invalid key format/range requested: {stream_key}"
        )
        return jsonify({"error": "Invalid stream key format or value"}), 400
    except Exception as e:
        logger.exception(f"API DELETE /streams/{stream_key} internal error")
        return (
            jsonify({"error": f"Internal server error stopping stream: {str(e)}"}),
            500,
        )


# --- System Status Route (existing) ---
@api_bp.route("/system/status", methods=["GET"])
# @require_api_auth # Optional: Protect GET requests if needed
def api_get_system_status():
    """Returns current system status information."""
    try:
        # Call the imported function directly
        info = get_system_info()
        serializable_info = json.loads(json.dumps(info, default=str))
        return jsonify(serializable_info)
    except ImportError:
        logger.exception(
            "API GET /system/status: Failed to import get_system_info from app.utils"
        )
        return (
            jsonify({"error": "Server configuration error (utility unavailable)."}),
            500,
        )
    except Exception as e:
        logger.exception("API GET /system/status error")
        return jsonify({"error": "Failed to retrieve system status"}), 500
