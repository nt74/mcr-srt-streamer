# /opt/mcr-srt-streamer/app/__init__.py

from flask import Flask
import os
import logging
from logging.handlers import RotatingFileHandler
from app.stream_manager import StreamManager

# Import CSRFProtect
from flask_wtf.csrf import CSRFProtect

# Import SMPTE2022-7 components and other blueprints
from app.smpte_routes import smpte_bp
from app.smpte_manager import SMPTEManager
from app.routes import register_routes
from app.api_routes import api_bp

# Configure logging
log_dir_standard = "/var/log/srt-streamer"  # Standard log directory
logging.basicConfig(level=logging.INFO)  # Basic config for root logger
logger = logging.getLogger()  # Get root logger

# --- File Handler using standard path ---
try:
    # Create log directory if it doesn't exist
    if not os.path.exists(log_dir_standard):
        try:
            # Set permissions appropriate for the directory
            os.makedirs(log_dir_standard, mode=0o755, exist_ok=True)
            logger.info(f"Created log directory: {log_dir_standard}")
        except Exception as dir_e:
            logger.error(
                f"Failed to create log directory {log_dir_standard}: {dir_e}. Logging to file might fail."
            )

    log_file_path = os.path.join(log_dir_standard, "srt_streamer.log")

    # Use RotatingFileHandler for log rotation
    file_handler = RotatingFileHandler(
        log_file_path,
        maxBytes=10 * 1024 * 1024,  # 10MB per file
        backupCount=5,  # Keep 5 backup files
    )
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]"
        )
    )
    file_handler.setLevel(logging.INFO)  # Set level for file handler
    logger.addHandler(file_handler)  # Add handler to the root logger
    logger.info(f"Logging to file: {log_file_path}")

except Exception as log_e:
    logger.error(f"Failed to set up file logging to {log_dir_standard}: {log_e}")
    logger.warning("File logging setup failed. Check permissions and path.")


# --- Initialize Flask App ---
app = Flask(__name__)


# ** IMPORTANT: Load SECRET_KEY from environment variable for production **
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
if not app.config["SECRET_KEY"]:
    logger.critical(
        "FATAL ERROR: SECRET_KEY environment variable is not set. Application will not start securely."
    )
    raise ValueError(
        "SECRET_KEY environment variable must be set for the application to run."
    )
elif (
    app.config["SECRET_KEY"] == "a5458bf94a5181014e17836e8af327ec479b236bf393d089"
):  # Check against example
    logger.warning(
        "SECURITY WARNING: Using the example default SECRET_KEY. Generate a new strong key and set it via environment variable."
    )


app.config["API_KEY"] = os.environ.get("API_KEY")
if not app.config["API_KEY"]:
    # Log a warning, but allow app to start. Auth decorator will block API calls.
    logger.warning(
        "CONFIG WARNING: API_KEY environment variable is not set. API endpoints will be inaccessible until it is set and the service is restarted."
    )
# Optional: Check for a known weak/default key
# elif app.config["API_KEY"] == "your_insecure_default_key":
#     logger.warning("SECURITY WARNING: Using a default/weak API_KEY.")


# Load Media Folder from environment variable
app.config["MEDIA_FOLDER"] = os.environ.get(
    "MEDIA_FOLDER",
    "/opt/mcr-srt-streamer/media",  # Default path
)
if not os.path.isdir(app.config["MEDIA_FOLDER"]):
    logger.warning(
        f"Media folder '{app.config['MEDIA_FOLDER']}' does not exist or is not a directory. File streaming inputs may fail."
    )
    # Consider creating it if it doesn't exist, if desired:
    # try:
    #     os.makedirs(app.config["MEDIA_FOLDER"], mode=0o755, exist_ok=True)
    #     logger.info(f"Created media folder: {app.config['MEDIA_FOLDER']}")
    # except Exception as media_dir_e:
    #      logger.error(f"Failed to create media directory {app.config['MEDIA_FOLDER']}: {media_dir_e}")


# --- Initialize Managers ---
# Ensure Managers are initialized *after* app config is set
# Check if classes are imported before using them
if "StreamManager" in globals():
    app.stream_manager = StreamManager(app.config["MEDIA_FOLDER"])
else:
    logger.error("StreamManager class not imported correctly.")
    # Handle error appropriately, maybe raise an exception or exit
    raise ImportError("StreamManager could not be initialized.")

if "SMPTEManager" in globals() and "app" in locals() and hasattr(app, "stream_manager"):
    app.smpte_manager = SMPTEManager(main_stream_manager_ref=app.stream_manager)
    logger.info("Initialized StreamManager and SMPTEManager.")
elif "SMPTEManager" not in globals():
    logger.error("SMPTEManager class not imported correctly.")
    raise ImportError("SMPTEManager could not be initialized.")
else:
    logger.error(
        "Could not initialize SMPTEManager due to missing dependencies (app or stream_manager)."
    )
    raise RuntimeError("Could not initialize SMPTEManager.")
# ------------------------------------------------------


# --- Register Blueprints ---
# Register all blueprints before initializing CSRF
# Ensure functions/blueprints are imported before use
if "register_routes" in globals():
    register_routes(app)  # Register your standard web routes
else:
    logger.error("register_routes function not imported correctly.")

if "api_bp" in globals():
    app.register_blueprint(api_bp)  # Register the API blueprint (prefix is /api)
else:
    logger.error("api_bp blueprint not imported correctly.")

if "smpte_bp" in globals():
    app.register_blueprint(
        smpte_bp
    )  # Register the SMPTE blueprint (prefix is /smpte2022_7)
    logger.info("Registered web routes, API blueprint, and SMPTE blueprint.")
else:
    logger.error("smpte_bp blueprint not imported correctly.")


# --- Initialize CSRF Protection AFTER blueprints are registered ---
csrf = CSRFProtect()
csrf.init_app(app)  # Initialize CSRF protection with the app instance FIRST
logger.info("CSRF protection initialized.")


# --- Set Exemptions AFTER initializing CSRF with the app ---
# Exclude the API blueprints from CSRF protection by name if they exist
if "api_bp" in globals():
    csrf.exempt(api_bp)
if "smpte_bp" in globals():
    csrf.exempt(smpte_bp)  # Exempt SMPTE blueprint as it contains API endpoints
logger.info("Exempted API and SMPTE blueprints (if registered) from CSRF protection.")


# --- Application Initialization Complete ---
# Use app.logger which should now have the handlers configured earlier
app.logger.info(
    "SRT Streamer Enhanced Application initialized successfully (with API and SMPTE)."
)

# Add any other application-level setup here if needed
