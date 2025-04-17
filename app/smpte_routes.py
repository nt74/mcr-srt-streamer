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
)
from app.smpte_forms import SMPTEPairForm, _populate_shared_choices
import logging
from datetime import datetime
import re
import json

logger = logging.getLogger(__name__)
smpte_bp = Blueprint("smpte", __name__, url_prefix="/smpte2022_7")


def _build_smpte_config_from_form(form):
    config = {
        "input_type": form.input_type.data,
        "ssrc": form.ssrc.data,
        "latency": form.latency.data,
        "overhead_bandwidth": form.overhead_bandwidth.data,
        "encryption": form.encryption.data,
        "passphrase": form.passphrase.data if form.encryption.data != "none" else "",
        "qos": form.qos.data,
        "smoothing_latency_ms": form.smoothing_latency_ms.data,  # Added previously
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
        match = re.match(r"(.+):(\d+)$", form.multicast_channel.data or "")
        if match:
            config["multicast_address"] = match.group(1)
            config["multicast_port"] = int(match.group(2))
            config["multicast_interface"] = form.multicast_interface.data or None
        else:
            raise ValueError("Invalid multicast channel data in form.")
    elif form.input_type.data.startswith("colorbar_"):
        config["colorbar_resolution"] = form.input_type.data.split("_", 1)[1]
    return config


# --- Web UI Routes ---
@smpte_bp.route("/", methods=["GET", "POST"])
def smpte_config_page():
    form = SMPTEPairForm()
    _populate_shared_choices(form)
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
            logger.info(f"Attempting to start SMPTE pair with config: {config}")
            success, message = app.smpte_manager.start_smpte_stream_pair(config)
            if success:
                flash(
                    f"SMPTE Pair ({config.get('pair_id', 'N/A')}) started successfully: {message}",
                    "success",
                )
                return redirect(url_for("index"))
            else:
                flash(f"Failed to start SMPTE Pair: {message}", "danger")
        except ValueError as ve:
            flash(f"Configuration Error: {ve}", "danger")
            logger.warning(f"Error building SMPTE config: {ve}")
        except Exception as e:
            flash(f"Unexpected error: {e}", "danger")
            logger.error(f"Error starting SMPTE pair: {e}", exc_info=True)
    elif request.method == "POST":
        form_errors = {f: e[0] for f, e in form.errors.items() if f != "csrf_token"}
        error_list_str = "; ".join([f"{k}: {v}" for k, v in form_errors.items()])
        flash(f"Please correct the errors: {error_list_str}", "warning")
    return render_template(
        "smpte2022_7.html", form=form, current_year=datetime.utcnow().year
    )


@smpte_bp.route("/stop/<pair_id_str>", methods=["POST"])
def stop_smpte_pair(pair_id_str):
    if not hasattr(app, "smpte_manager") or not app.smpte_manager:
        flash("SMPTE Manager unavailable.", "danger")
        return redirect(url_for("index"))
    success, message = app.smpte_manager.stop_smpte_stream_pair(pair_id_str)
    if success:
        logger.info(f"SMPTE Pair stopped UI: {message}")
        flash(f"SMPTE Pair ({pair_id_str}) stopped.", "success")
    else:
        logger.error(f"SMPTE Pair stop fail UI: {message}")
        flash(f"Failed stop SMPTE Pair ({pair_id_str}): {message}", "danger")
    referrer = request.referrer
    is_safe_url = referrer and (
        referrer.startswith("/") or request.host_url in referrer
    )
    return redirect(referrer) if is_safe_url else redirect(url_for("index"))


@smpte_bp.route("/<int:pair_id>")
def smpte_details_page(pair_id):
    pair_info = None
    if hasattr(app, "smpte_manager") and app.smpte_manager:
        pair_info = app.smpte_manager.get_smpte_pair_debug_info(str(pair_id))
    if not pair_info or pair_info.get("error"):
        logger.warning(f"Details page access for non-existent pair ID: {pair_id}")
        flash(f"SMPTE Pair ({pair_id}) not found or is inactive.", "warning")
        return redirect(url_for("index"))
    return render_template(
        "smpte_details.html",
        pair_id=pair_id,
        pair_config=pair_info.get("config", {}),
        current_year=datetime.utcnow().year,
    )


# --- API Endpoints for SMPTE Pairs ---


@smpte_bp.route("/api/stats/<int:pair_id>")
def api_smpte_stats(pair_id):
    """API endpoint to get SRT statistics for a specific SMPTE pair."""
    if not hasattr(app, "smpte_manager") or not app.smpte_manager:
        return jsonify({"error": "SMPTE manager service unavailable."}), 503
    try:
        stats_data = app.smpte_manager.get_smpte_pair_statistics(str(pair_id))
        if stats_data.get("error"):
            status_code = 404 if "not found" in stats_data["error"].lower() else 500
            return jsonify(stats_data), status_code
        else:
            serializable_stats = json.loads(json.dumps(stats_data, default=str))
            return jsonify(serializable_stats)
    except ValueError:
        return jsonify({"error": "Invalid Pair ID format."}), 400
    except Exception as e:
        logger.error(f"Error in /api/smpte/stats/{pair_id}: {e}", exc_info=True)
        return jsonify({"error": "Failed to retrieve SMPTE pair stats"}), 500


@smpte_bp.route("/api/debug/<int:pair_id>")
def api_smpte_debug(pair_id):
    """API endpoint to get debug info (config, status) for a specific SMPTE pair."""
    if not hasattr(app, "smpte_manager") or not app.smpte_manager:
        return jsonify({"error": "SMPTE manager service unavailable."}), 503
    try:
        debug_data = app.smpte_manager.get_smpte_pair_debug_info(
            str(pair_id)
        )  # Call the enhanced debug method
        if debug_data.get("error"):
            status_code = 404 if "not found" in debug_data["error"].lower() else 500
            return jsonify(debug_data), status_code
        else:
            serializable_debug = json.loads(json.dumps(debug_data, default=str))
            return jsonify(serializable_debug)
    except ValueError:
        return jsonify({"error": "Invalid Pair ID format."}), 400
    except Exception as e:
        logger.error(f"Error in /api/smpte/debug/{pair_id}: {e}", exc_info=True)
        return jsonify({"error": "Failed to retrieve SMPTE pair debug info"}), 500
