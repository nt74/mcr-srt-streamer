# /opt/mcr-srt-streamer/app/api_routes.py

from flask import Blueprint, jsonify, request, current_app as app
import logging
import re # For parsing multicast if needed again
import os # For file path validation if implementing file source via API
import json # For network test results parsing
import time # For stats update time

# Import utilities needed by remaining routes
from app.utils import get_system_info # Used by api_get_system_status

logger = logging.getLogger(__name__)
api_bp = Blueprint('api', __name__, url_prefix='/api')

# --- IMPORTANT: API Authentication ---
def require_api_auth():
    # ... (placeholder or your actual implementation) ...
    # logger.warning("API Authentication not implemented! Endpoints are unprotected.")
    return None

@api_bp.before_request
def before_api_request():
    auth_error = require_api_auth()
    if auth_error:
        return auth_error

# --- API Routes ---

@api_bp.route('/streams', methods=['GET'])
def api_get_streams():
    """ Returns a list of active streams. """
    try:
        if not hasattr(app, 'stream_manager') or not app.stream_manager:
             return jsonify({"error": "Stream manager not available"}), 503
        streams = app.stream_manager.get_active_streams()
        return jsonify({"data": streams if isinstance(streams, dict) else {}})
    except Exception as e:
        logger.error(f"API GET /streams error: {e}", exc_info=True)
        return jsonify({"error": "Failed to retrieve streams"}), 500

@api_bp.route('/stats/<stream_key>')
def get_stats(stream_key):
    """ Returns live statistics for a specific stream. """
    try:
        key = int(stream_key)
        assert 0 < key < 65536
    except:
        return jsonify({"error": f"Invalid key format: {stream_key}"}), 400

    if not hasattr(app, 'stream_manager') or not app.stream_manager:
        return jsonify({"error": "Stream manager not available"}), 503

    stats = app.stream_manager.get_stream_statistics(stream_key)
    if isinstance(stats, dict) and "error" in stats:
        if "not found" in stats["error"].lower():
            return jsonify(stats), 404
        else:
            return jsonify(stats), 500
    elif stats is None:
        return jsonify({"error": f"Stream ({stream_key}) stats unavailable"}), 404
    else:
        stats['timestamp_api'] = time.time()
        return jsonify(stats)

@api_bp.route('/debug/<stream_key>')
def get_debug_info(stream_key):
    """ Returns raw debug information for a specific stream. """
    try:
        key = int(stream_key)
        assert 0 < key < 65536
    except:
        return jsonify({"error": f"Invalid key format: {stream_key}"}), 400

    if not hasattr(app, 'stream_manager') or not app.stream_manager:
        return jsonify({"error": "Stream manager not available"}), 503

    debug_info = app.stream_manager.get_debug_info(stream_key)
    if debug_info is None:
        return jsonify({"error": f"Error fetching info for {stream_key}"}), 500
    if "error" in debug_info:
        status_code = 404 if "not found" in debug_info["error"].lower() else 500
        return jsonify(debug_info), status_code
    try:
        return jsonify(debug_info)
    except TypeError as e:
        logger.error(f"Serialization error debug info {stream_key}: {e}")
        return jsonify({"error": f"Serialization error preparing debug info"}), 500

@api_bp.route('/streams/<stream_key>', methods=['GET'])
def api_get_stream_detail(stream_key):
    """ Returns combined details and stats for a specific stream. """
    return get_stats(stream_key)


@api_bp.route('/streams', methods=['POST'])
def api_start_stream():
    """ Starts a new stream (listener or caller) based on JSON payload. """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 415
    config_data = request.get_json()
    if not config_data:
         return jsonify({"error": "No JSON data provided"}), 400
    logger.info(f"API request received to start stream: {config_data}")
    # --- Basic Payload Validation ---
    errors = {}
    mode = config_data.get('mode', 'listener').lower()
    if mode not in ['listener', 'caller']:
        errors['mode'] = "Mode must be 'listener' or 'caller'."
    input_type = config_data.get('input_type')
    allowed_inputs = ['multicast', 'file', 'colorbar_720p50', 'colorbar_1080i25']
    if not input_type or input_type not in allowed_inputs:
        errors['input_type'] = f"Missing or invalid input_type. Allowed: {', '.join(allowed_inputs)}"
    rtp_encapsulation = config_data.get('rtp_encapsulation', False)
    if not isinstance(rtp_encapsulation, bool):
         errors['rtp_encapsulation'] = "rtp_encapsulation must be a boolean (true/false)."
    elif rtp_encapsulation and input_type not in ['multicast', 'colorbar_720p50', 'colorbar_1080i25']:
         if 'input_type' not in errors:
             errors['rtp_encapsulation'] = "RTP encapsulation only supported for Multicast or Colorbar inputs via API."
    if mode == 'listener':
        port = config_data.get('port')
        if not port or not isinstance(port, int) or not (10001 <= port <= 10010):
             errors['port'] = "Listener requires a 'port' between 10001 and 10010."
    else: # caller
        target_address = config_data.get('target_address')
        target_port = config_data.get('target_port')
        if not target_address or not isinstance(target_address, str) or len(target_address) > 255:
             errors['target_address'] = "Caller requires a valid 'target_address' (string, max 255)."
        elif not re.match(r"^[a-zA-Z0-9\.\-]+$", target_address) or '.' not in target_address:
             errors['target_address'] = "Invalid target address format."
        if not target_port or not isinstance(target_port, int) or not (1 <= target_port <= 65535):
            errors['target_port'] = "Caller requires a 'target_port' between 1 and 65535."
    if input_type == 'file':
        file_path = config_data.get('file_path')
        if not file_path or not isinstance(file_path, str):
            errors['file_path'] = "File input requires a 'file_path' (string)."
        elif ".." in file_path or file_path.startswith("/"):
             errors['file_path'] = "Invalid file path format."
        elif not file_path.lower().endswith(".ts"):
             errors['file_path'] = "Only .ts files are supported."
        else:
             try:
                 media_dir = os.path.abspath(app.config['MEDIA_FOLDER'])
                 abs_path = os.path.abspath(os.path.join(media_dir, os.path.basename(file_path)))
                 if not abs_path.startswith(media_dir + os.sep):
                      errors['file_path'] = "File path is outside the allowed media directory."
                 elif not os.path.isfile(abs_path):
                      errors['file_path'] = f"File does not exist: {os.path.basename(file_path)}"
             except Exception as e:
                  logger.error(f"Error accessing app config or checking file path: {e}")
                  errors['file_path'] = "Server error validating file path."
    elif input_type == 'multicast':
         mc_address = config_data.get('multicast_address')
         mc_port = config_data.get('multicast_port')
         mc_interface = config_data.get('multicast_interface')
         if not mc_address or not isinstance(mc_address, str):
             errors['multicast_address'] = "Multicast input requires 'multicast_address'."
         elif not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", mc_address):
              errors['multicast_address'] = "Invalid multicast address format."
         if not mc_port or not isinstance(mc_port, int) or not (1 <= mc_port <= 65535):
             errors['multicast_port'] = "Multicast input requires 'multicast_port' (1-65535)."
         if mc_interface and not isinstance(mc_interface, str):
              errors['multicast_interface'] = "Multicast interface must be a string if provided."
    latency = config_data.get('latency', 300)
    overhead = config_data.get('overhead_bandwidth', 2)
    if not isinstance(latency, int) or not (20 <= latency <= 8000):
         errors['latency'] = "SRT Latency must be an integer between 20 and 8000."
    if not isinstance(overhead, int) or not (1 <= overhead <= 99):
        errors['overhead_bandwidth'] = "Overhead bandwidth must be an integer between 1 and 99."
    encryption = config_data.get('encryption', 'none').lower()
    passphrase = config_data.get('passphrase')
    if encryption not in ['none', 'aes-128', 'aes-256']:
        errors['encryption'] = "Invalid encryption type. Allowed: none, aes-128, aes-256."
    elif encryption != 'none':
        if not passphrase:
            errors['passphrase'] = "Passphrase is required when encryption is enabled."
        elif not isinstance(passphrase, str) or not (10 <= len(passphrase) <= 79):
            errors['passphrase'] = "Passphrase must be a string between 10 and 79 characters."
    if errors:
        logger.warning(f"API stream config validation failed: {errors}")
        return jsonify({"error": "Validation failed", "details": errors}), 400
    # --- End Validation ---
    final_config = {
        "mode": mode, "latency": latency, "overhead_bandwidth": overhead,
        "encryption": encryption, "passphrase": passphrase if encryption != 'none' else "",
        "qos": config_data.get('qos', False),
        "smoothing_latency_ms": config_data.get('smoothing_latency_ms', 30),
        "rtp_encapsulation": rtp_encapsulation
    }
    if mode == 'listener': final_config['port'] = config_data['port']
    else: final_config['target_address'] = config_data['target_address']; final_config['target_port'] = config_data['target_port']
    if input_type == 'file':
        final_config['input_type'] = 'file'; final_config['file_path'] = os.path.basename(config_data['file_path'])
    elif input_type == 'multicast':
        final_config['input_type'] = 'multicast'; final_config['multicast_address'] = config_data['multicast_address']
        final_config['multicast_port'] = config_data['multicast_port']; final_config['protocol'] = 'udp'
        final_config['multicast_interface'] = config_data.get('multicast_interface')
    elif input_type.startswith('colorbar_'):
        final_config['input_type'] = 'colorbar'; final_config['colorbar_resolution'] = input_type.split("_", 1)[1]
    # --- Start Stream ---
    logger.info(f"API validated config, attempting start_stream: {final_config}")
    try:
        if not hasattr(app, 'stream_manager') or not app.stream_manager:
             return jsonify({"error": "Stream manager not available"}), 503
        use_target_key = (mode == 'caller')
        success, message = app.stream_manager.start_stream(config=final_config, use_target_port_as_key=use_target_key)
        if success:
            started_key = final_config.get('target_port') if use_target_key else final_config.get('port')
            logger.info(f"API successfully initiated stream start for key {started_key}")
            return jsonify({"message": message, "stream_key": started_key, "status": "starting"}), 201
        else:
            logger.error(f"API start_stream failed: {message}")
            return jsonify({"error": message}), 400
    except Exception as e:
        logger.error(f"API POST /streams internal error: {e}", exc_info=True)
        return jsonify({"error": f"Internal server error starting stream: {str(e)}"}), 500

@api_bp.route('/streams/<stream_key>', methods=['DELETE'])
def api_stop_stream(stream_key):
    """ Stops a specific stream. """
    logger.info(f"API request received to stop stream {stream_key}")
    try:
        key_int = int(stream_key)
        if not (0 < key_int < 65536): raise ValueError("Invalid port range")
        if not hasattr(app, 'stream_manager') or not app.stream_manager:
             return jsonify({"error": "Stream manager not available"}), 503
        success, message = app.stream_manager.stop_stream(stream_key)
        if success:
            logger.info(f"API stop request for stream {stream_key} successful: {message}")
            return jsonify({"message": message, "status": "stopping"}), 200
        else:
            logger.warning(f"API stop request failed for stream {stream_key}: {message}")
            status_code = 404 if "not found" in message.lower() else 400
            return jsonify({"error": message}), status_code
    except ValueError:
         logger.warning(f"API stop request received invalid stream key: {stream_key}")
         return jsonify({"error": "Invalid stream key format or value"}), 400
    except Exception as e:
        logger.error(f"API DELETE /streams/{stream_key} internal error: {e}", exc_info=True)
        return jsonify({"error": f"Internal server error stopping stream: {str(e)}"}), 500


# --- System Status Route (existing) ---
@api_bp.route('/system/status', methods=['GET'])
def api_get_system_status():
    """ Returns current system status information. """
    try:
        from app.utils import get_system_info
        info = get_system_info()
        return jsonify(info)
    except Exception as e:
        logger.error(f"API GET /system/status error: {e}", exc_info=True)
        return jsonify({"error": "Failed to retrieve system status"}), 500
