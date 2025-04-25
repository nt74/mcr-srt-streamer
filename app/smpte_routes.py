# /opt/mcr-srt-streamer/app/smpte_routes.py

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    current_app as app,
    Response,  # Ensure imported
    abort,  # Ensure imported
)

# Assuming smpte_forms.py exists and defines these
try:
    from .smpte_forms import SMPTEPairForm, _populate_shared_choices
except ImportError:
    logger.error(
        "Failed to import SMPTE forms from .smpte_forms - UI will likely fail."
    )

    # Define dummy classes/functions if needed for app to load, but UI will break
    class SMPTEPairForm:
        pass

    def _populate_shared_choices(form):
        pass


import logging
from datetime import datetime
import re
import json

# Import the shared authentication decorator (ensure auth.py exists)
try:
    from .auth import require_api_auth
except ImportError:
    logger.error(
        "app.auth or require_api_auth not found! API calls requiring auth will fail."
    )
    import functools

    def require_api_auth(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            abort(Response("Authentication module not configured.", 500))

        return wrapper


logger = logging.getLogger(__name__)
smpte_bp = Blueprint("smpte", __name__, url_prefix="/smpte2022_7")


# --- Helper Function: Build Config from Form ---
# Based on previous context, assuming this function exists and is correct
def _build_smpte_config_from_form(form):
    """Builds the config dictionary from a validated SMPTEPairForm."""
    config = {
        "input_type": form.input_type.data,
        "ssrc": form.ssrc.data,
        "latency": form.latency.data,
        "overhead_bandwidth": form.overhead_bandwidth.data,
        "encryption": form.encryption.data,
        "passphrase": form.passphrase.data if form.encryption.data != "none" else "",
        "qos": form.qos.data,
        "smoothing_latency_ms": form.smoothing_latency_ms.data,
        "port_1": form.port_1.data,
        "mode_1": form.mode_1.data,
        "output_interface_1": form.output_interface_1.data or None,
        "port_2": form.port_2.data,
        "mode_2": form.mode_2.data,
        "output_interface_2": form.output_interface_2.data or None,
    }
    if form.mode_1.data == "caller":
        config["target_address_1"] = form.target_address_1.data
    if form.mode_2.data == "caller":
        config["target_address_2"] = form.target_address_2.data

    if form.input_type.data == "multicast":
        # Use the validated multicast_channel data which should be address:port
        multicast_channel = form.multicast_channel.data
        match = re.match(r"(.+):(\d+)$", multicast_channel or "")
        if match:
            config["multicast_address"] = match.group(1)
            config["multicast_port"] = int(match.group(2))
            config["multicast_interface"] = (
                form.multicast_interface.data or None
            )  # From separate field
        else:
            # This case should ideally be caught by form validation
            logger.error(
                f"Invalid multicast channel format in form processing: {multicast_channel}"
            )
            raise ValueError("Invalid multicast channel format processing form.")
    elif form.input_type.data.startswith("colorbar_"):
        config["colorbar_resolution"] = form.input_type.data.split("_", 1)[1]
    return config


# --- Helper Function: Validate API Config (Corrected Version) ---
def validate_smpte_api_config(data):
    """
    Validates the JSON data received for creating an SMPTE pair via API.
    Returns a validated config dictionary or raises ValueError with JSON details.
    """
    errors = {}
    validated_params = {}  # Store validated parameters here

    # --- Field Type and Basic Presence Validation ---
    input_type = data.get("input_type")
    if not input_type or not isinstance(input_type, str):
        errors["input_type"] = "Missing or invalid 'input_type' (string)."

    ssrc = data.get("ssrc")
    if not ssrc or not isinstance(ssrc, str):
        errors["ssrc"] = "Missing or invalid 'ssrc' (string)."
    else:
        validated_params["ssrc"] = ssrc

    for field in ["latency", "overhead_bandwidth", "smoothing_latency_ms"]:
        value_str = data.get(field)
        try:
            value = int(value_str)
            validated_params[field] = value
        except (ValueError, TypeError):
            errors[field] = f"Missing or invalid '{field}' (integer required)."

    qos = data.get("qos")
    if not isinstance(qos, bool):
        errors["qos"] = "Invalid 'qos' (boolean true/false required)."
    else:
        validated_params["qos"] = qos

    encryption = str(data.get("encryption", "none")).lower()
    if encryption not in ["none", "aes-128", "aes-256"]:
        errors["encryption"] = "Invalid 'encryption' type (none, aes-128, aes-256)."
    else:
        validated_params["encryption"] = encryption
        if encryption != "none":
            passphrase = data.get("passphrase")
            if not passphrase:
                errors["passphrase"] = (
                    "Passphrase is required when encryption is enabled."
                )
            elif not isinstance(passphrase, str) or not (10 <= len(passphrase) <= 80):
                errors["passphrase"] = (
                    "Passphrase must be a string between 10 and 80 characters."
                )
            else:
                validated_params["passphrase"] = passphrase
        else:
            validated_params["passphrase"] = ""

    for i in [1, 2]:
        port_key = f"port_{i}"
        mode_key = f"mode_{i}"
        target_addr_key = f"target_address_{i}"
        output_intf_key = f"output_interface_{i}"

        port_str = data.get(port_key)
        try:
            port = int(port_str)
            if not (1 <= port <= 65535):
                errors[port_key] = f"Port_{i} must be between 1 and 65535."
            else:
                validated_params[port_key] = port
        except (ValueError, TypeError):
            errors[port_key] = f"Missing or invalid integer 'port_{i}'."

        mode = str(data.get(mode_key, "")).lower()
        if mode not in ["listener", "caller"]:
            errors[mode_key] = f"Mode_{i} must be 'listener' or 'caller'."
        else:
            validated_params[mode_key] = mode
            if mode == "caller":
                target_address = data.get(target_addr_key)
                if not target_address or not isinstance(target_address, str):
                    errors[target_addr_key] = (
                        f"Target_address_{i} required for caller mode."
                    )
                else:
                    validated_params[target_addr_key] = target_address
            else:
                validated_params[target_addr_key] = None

        output_interface = data.get(output_intf_key)
        if output_interface is not None and not isinstance(output_interface, str):
            errors[output_intf_key] = (
                f"Output_interface_{i} must be a string or null/absent."
            )
        else:
            validated_params[output_intf_key] = output_interface

    # --- Specific Value Range Checks ---
    if "latency" in validated_params and not (
        20 <= validated_params["latency"] <= 8000
    ):
        errors["latency"] = "Must be between 20 and 8000."
    if "overhead_bandwidth" in validated_params and not (
        1 <= validated_params["overhead_bandwidth"] <= 99
    ):
        errors["overhead_bandwidth"] = "Must be between 1 and 99."

    if (
        "port_1" in validated_params
        and "port_2" in validated_params
        and validated_params["port_1"] == validated_params["port_2"]
    ):
        errors.setdefault("port_1", []).append("Port 1 and Port 2 cannot be the same.")
        errors.setdefault("port_2", []).append("Port 1 and Port 2 cannot be the same.")

    # --- Input Type Specific Checks ---
    if "input_type" not in errors:
        if input_type == "multicast":
            mc_address = data.get("multicast_address")
            mc_port_str = data.get("multicast_port")
            mc_interface = data.get("multicast_interface")

            if not mc_address or not isinstance(mc_address, str):
                errors["multicast_address"] = "Required string for multicast input."
            elif not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", mc_address):
                errors["multicast_address"] = "Invalid multicast address format."
            else:
                validated_params["multicast_address"] = mc_address

            try:
                mc_port = int(mc_port_str)
                if not (1 <= mc_port <= 65535):
                    errors["multicast_port"] = "Invalid port range (1-65535)."
                else:
                    validated_params["multicast_port"] = mc_port
            except (ValueError, TypeError):
                errors["multicast_port"] = "Integer port required for multicast input."

            if mc_interface is not None and not isinstance(mc_interface, str):
                errors["multicast_interface"] = "Must be a string or null/absent."
            else:
                validated_params["multicast_interface"] = mc_interface

            if "multicast_address" not in errors and "multicast_port" not in errors:
                validated_params["input_type"] = "multicast"

        elif input_type.startswith("colorbar_"):
            resolution = input_type.split("_", 1)[-1]
            if resolution not in ["720p50", "1080i25"]:
                errors["input_type"] = (
                    "Invalid colorbar resolution (720p50 or 1080i25)."
                )
            else:
                validated_params["input_type"] = "colorbar"
                validated_params["colorbar_resolution"] = resolution
        else:
            # Add other valid input types if supported by the manager via API
            # e.g., if "file" is supported:
            # if input_type == "file": ... validation ...
            # else:
            errors["input_type"] = f"Unsupported input_type via API: {input_type}"

    # --- Final Error Check and Return ---
    if errors:
        final_errors = {}
        for k, v in errors.items():
            final_errors[k] = "; ".join(v) if isinstance(v, list) else v
        raise ValueError(json.dumps(final_errors))

    # Add default None for keys that might not have been set
    validated_params.setdefault("multicast_address", None)
    validated_params.setdefault("multicast_port", None)
    validated_params.setdefault("multicast_interface", None)
    validated_params.setdefault("colorbar_resolution", None)

    return validated_params


# --- Web UI Routes ---
@smpte_bp.route("/", methods=["GET", "POST"])
def smpte_config_page():
    """Renders the SMPTE 2022-7 configuration page and handles form submission."""
    try:
        form = SMPTEPairForm()
        _populate_shared_choices(form)  # Populate dynamic choices if needed
    except NameError:
        flash("SMPTE Forms not available. UI configuration disabled.", "danger")
        return render_template(
            "smpte2022_7.html",
            form=None,
            error="Forms unavailable.",
            current_year=datetime.utcnow().year,
        )

    if form.validate_on_submit():
        if not hasattr(app, "smpte_manager") or not app.smpte_manager:
            flash("SMPTE Manager unavailable.", "danger")
            return render_template(
                "smpte2022_7.html",
                form=form,
                error="SMPTE manager unavailable.",
                current_year=datetime.utcnow().year,
            )
        try:
            config = _build_smpte_config_from_form(form)
            logger.info(f"Attempting to start SMPTE pair via UI with config: {config}")
            pair_id_or_success, message = app.smpte_manager.start_smpte_stream_pair(
                config
            )

            if pair_id_or_success:
                pair_id_display = (
                    pair_id_or_success
                    if isinstance(pair_id_or_success, (str, int))
                    else "N/A"
                )
                flash(
                    f"SMPTE Pair ({pair_id_display}) started successfully: {message}",
                    "success",
                )
                return redirect(url_for("index"))
            else:
                flash(f"Failed to start SMPTE Pair: {message}", "danger")
        except ValueError as ve:
            flash(f"Configuration Error: {ve}", "danger")
            logger.warning(f"Error building SMPTE config from form: {ve}")
        except Exception as e:
            flash(f"Unexpected error starting SMPTE pair: {e}", "danger")
            logger.error(f"Error starting SMPTE pair from UI: {e}", exc_info=True)
    elif request.method == "POST":
        form_errors = {f: e[0] for f, e in form.errors.items() if f != "csrf_token"}
        error_list_str = "; ".join([f"{k}: {v}" for k, v in form_errors.items()])
        flash(f"Please correct the errors: {error_list_str}", "warning")

    return render_template(
        "smpte2022_7.html", form=form, current_year=datetime.utcnow().year
    )


@smpte_bp.route("/stop/<pair_id_str>", methods=["POST"])
def stop_smpte_pair(pair_id_str):
    """Handles stopping an SMPTE pair via a POST request from the UI."""
    # Note: CSRF protection is handled by Flask-WTF via form's hidden_tag()
    if not hasattr(app, "smpte_manager") or not app.smpte_manager:
        flash("SMPTE Manager unavailable.", "danger")
        return redirect(request.referrer or url_for("index"))

    try:
        success, message = app.smpte_manager.stop_smpte_stream_pair(pair_id_str)
        if success:
            logger.info(f"SMPTE Pair stopped via UI: {pair_id_str} - {message}")
            flash(f"SMPTE Pair ({pair_id_str}) stopped.", "success")
        else:
            logger.error(f"SMPTE Pair stop failed via UI: {pair_id_str} - {message}")
            flash(f"Failed to stop SMPTE Pair ({pair_id_str}): {message}", "danger")
    except Exception as e:
        logger.error(
            f"Error stopping SMPTE pair {pair_id_str} from UI: {e}", exc_info=True
        )
        flash(f"Error stopping pair {pair_id_str}: {e}", "danger")

    referrer = request.referrer
    is_safe_url = referrer and (
        referrer.startswith("/") or request.host_url in referrer
    )
    return redirect(referrer) if is_safe_url else redirect(url_for("index"))


@smpte_bp.route("/<int:pair_id>")
def smpte_details_page(pair_id):
    """Renders the details page for a specific SMPTE pair."""
    pair_info = None
    if hasattr(app, "smpte_manager") and app.smpte_manager:
        try:
            pair_info = app.smpte_manager.get_smpte_pair_debug_info(str(pair_id))
        except Exception as e:
            logger.error(
                f"Error getting debug info for pair {pair_id} for details page: {e}",
                exc_info=True,
            )
            flash(f"Error retrieving details for pair {pair_id}.", "danger")
            return redirect(url_for("index"))

    if not pair_info or (isinstance(pair_info, dict) and pair_info.get("error")):
        error_msg = (
            pair_info.get("error")
            if isinstance(pair_info, dict)
            else "Pair not found or inactive."
        )
        logger.warning(f"Details page access failed for pair ID {pair_id}: {error_msg}")
        flash(f"SMPTE Pair ({pair_id}) not found or is inactive.", "warning")
        return redirect(url_for("index"))

    try:
        # Ensure config is serializable before passing to template
        pair_config_serializable = json.loads(
            json.dumps(pair_info.get("config", {}), default=str)
        )
        return render_template(
            "smpte_details.html",
            pair_id=pair_id,
            pair_config=pair_config_serializable,
            current_year=datetime.utcnow().year,
        )
    except Exception as e:
        logger.error(
            f"Error rendering SMPTE details page for {pair_id}: {e}", exc_info=True
        )
        flash("Error displaying pair details.", "danger")
        return redirect(url_for("index"))


# --- API Endpoints for SMPTE Pairs ---


@smpte_bp.route("/api/pairs", methods=["GET"])
# @require_api_auth # Optional: Apply decorator if GET needs protection
def api_smpte_list_pairs():
    """API endpoint to list active SMPTE pairs."""
    if not hasattr(app, "smpte_manager") or not app.smpte_manager:
        logger.error("API list pairs failed: SMPTE manager unavailable.")
        return jsonify({"error": "SMPTE manager service unavailable."}), 503
    try:
        pairs_data = app.smpte_manager.get_active_smpte_pairs()
        if isinstance(pairs_data, dict) and "error" in pairs_data:
            logger.error(
                f"SMPTE manager error on get_active_smpte_pairs: {pairs_data['error']}"
            )
            return jsonify(pairs_data), 500
        serializable_data = json.loads(json.dumps(pairs_data, default=str))
        return jsonify({"data": serializable_data})
    except Exception as e:
        logger.error(f"Error listing SMPTE pairs via API: {e}", exc_info=True)
        return jsonify({"error": "Failed to retrieve SMPTE pair list"}), 500


@smpte_bp.route("/api/pairs", methods=["POST"])
@require_api_auth  # Apply decorator
def api_smpte_create_pair():
    """API endpoint to create/start a new SMPTE pair."""
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 415
    config_data = request.get_json()
    if not config_data:
        return jsonify({"error": "No JSON data provided"}), 400

    if not hasattr(app, "smpte_manager") or not app.smpte_manager:
        return jsonify({"error": "SMPTE manager service unavailable."}), 503

    try:
        # Use the corrected validation helper function
        validated_config = validate_smpte_api_config(config_data)

        logger.info(f"API attempting start SMPTE pair: {json.dumps(validated_config)}")
        pair_id_or_success, message = app.smpte_manager.start_smpte_stream_pair(
            validated_config
        )

        if pair_id_or_success:
            pair_id = validated_config.get(
                "pair_id",
                (
                    pair_id_or_success
                    if isinstance(pair_id_or_success, (str, int))
                    else None
                ),
            )
            if pair_id is None:
                # Fallback logic for pair_id if manager doesn't add it to config
                pair_id = min(validated_config["port_1"], validated_config["port_2"])
            return (
                jsonify(
                    {
                        "message": message or "Pair creation initiated",
                        "pair_id": pair_id,
                        "status": "starting",
                    }
                ),
                201,
            )
        else:
            logger.error(f"API start_smpte_stream_pair failed: {message}")
            status_code = (
                409
                if "in use" in str(message).lower()
                or "conflict" in str(message).lower()
                else 400
            )
            return jsonify({"error": message or "Failed to start pair"}), status_code

    except ValueError as ve:
        # Catch validation errors from validate_smpte_api_config
        try:
            error_details = json.loads(str(ve))
            logger.warning(f"API SMPTE Pair validation failed: {error_details}")
            return (
                jsonify({"error": "Validation failed", "details": error_details}),
                400,
            )
        except json.JSONDecodeError:
            logger.warning(f"API SMPTE Pair validation error (non-JSON): {ve}")
            return jsonify({"error": f"Validation Error: {ve}"}), 400
    except Exception as e:
        logger.exception("API Error starting SMPTE pair")  # Use exception logger
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500


@smpte_bp.route("/api/pairs/<int:pair_id>", methods=["DELETE"])
@require_api_auth  # Apply decorator
def api_smpte_delete_pair(pair_id):
    """API endpoint to stop/delete a specific SMPTE pair."""
    if not hasattr(app, "smpte_manager") or not app.smpte_manager:
        logger.error(f"API DELETE /pairs/{pair_id}: SMPTE manager unavailable.")
        return jsonify({"error": "SMPTE manager service unavailable."}), 503
    try:
        pair_id_str = str(pair_id)
        success, message = app.smpte_manager.stop_smpte_stream_pair(pair_id_str)
        if success:
            logger.info(f"API stopped SMPTE Pair {pair_id_str}: {message}")
            return (
                jsonify(
                    {
                        "message": message or "Pair stopping initiated.",
                        "status": "stopping",
                    }
                ),
                200,
            )
        else:
            logger.warning(f"API stop failed for SMPTE Pair {pair_id_str}: {message}")
            status_code = 404 if "not found" in str(message).lower() else 400
            return jsonify({"error": message or "Failed to stop pair."}), status_code
    except Exception as e:
        logger.exception(
            f"API Error stopping SMPTE pair {pair_id}"
        )  # Use exception logger
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500


@smpte_bp.route("/api/stats/<int:pair_id>")
# @require_api_auth # Optional: Apply decorator if GET needs protection
def api_smpte_stats(pair_id):
    """API endpoint to get SRT statistics for a specific SMPTE pair."""
    if not hasattr(app, "smpte_manager") or not app.smpte_manager:
        logger.error(f"API GET /stats/{pair_id}: SMPTE manager unavailable.")
        return jsonify({"error": "SMPTE manager service unavailable."}), 503
    try:
        pair_id_str = str(pair_id)
        stats_data = app.smpte_manager.get_smpte_pair_statistics(pair_id_str)

        # *** MODIFIED HANDLING ***
        # Check only for "not found" errors to return 404.
        # Otherwise, return 200 OK and let the JS handle errors inside the data.
        if isinstance(stats_data, dict) and stats_data.get("error"):
            error_msg = stats_data.get("error", "")
            if "not found" in error_msg.lower():
                logger.warning(f"API GET /stats/{pair_id}: Pair not found.")
                # Return 404 only if pair itself doesn't exist
                return jsonify({"error": error_msg}), 404
            else:
                # Log the partial error but proceed to return 200 OK with the data
                logger.warning(
                    f"API GET /stats/{pair_id}: Manager reported partial error: {error_msg}. Returning data anyway."
                )

        # Attempt to serialize and return with 200 OK
        serializable_stats = json.loads(json.dumps(stats_data, default=str))
        return jsonify(serializable_stats), 200  # Always return 200 if pair exists

    except Exception as e:
        logger.exception(f"Error in /api/smpte/stats/{pair_id}")  # Use exception logger
        # Return 500 only for unexpected exceptions in the route itself
        return (
            jsonify(
                {"error": "Failed to retrieve SMPTE pair stats due to server error."}
            ),
            500,
        )


@smpte_bp.route("/api/debug/<int:pair_id>")
# @require_api_auth # Optional: Apply decorator if GET needs protection
def api_smpte_debug(pair_id):
    """API endpoint to get debug info (config, status) for a specific SMPTE pair."""
    if not hasattr(app, "smpte_manager") or not app.smpte_manager:
        logger.error(f"API GET /debug/{pair_id}: SMPTE manager unavailable.")
        return jsonify({"error": "SMPTE manager service unavailable."}), 503
    try:
        pair_id_str = str(pair_id)
        debug_data = app.smpte_manager.get_smpte_pair_debug_info(pair_id_str)

        if isinstance(debug_data, dict) and debug_data.get("error"):
            error_msg = debug_data.get("error", "")
            logger.warning(f"API GET /debug/{pair_id}: Manager error: {error_msg}")
            status_code = 404 if "not found" in error_msg.lower() else 500
            return jsonify(debug_data), status_code
        else:
            serializable_debug = json.loads(json.dumps(debug_data, default=str))
            return jsonify(serializable_debug)
    except Exception as e:
        logger.exception(f"Error in /api/smpte/debug/{pair_id}")  # Use exception logger
        return jsonify({"error": "Failed to retrieve SMPTE pair debug info"}), 500
