# /opt/mcr-srt-streamer/app/auth.py

import os
from functools import wraps
from flask import request, abort, current_app, Response


def require_api_auth(func):
    """Decorator to enforce API key authentication."""

    @wraps(func)
    def decorated_function(*args, **kwargs):
        api_key = current_app.config.get("API_KEY")
        if not api_key:
            current_app.logger.error("API Key is not configured on the server.")
            abort(
                Response("API access requires server-side API_KEY configuration.", 500)
            )

        provided_key = request.headers.get("X-API-Key")
        if not provided_key:
            current_app.logger.warning("API request missing X-API-Key header.")
            abort(Response("Missing API Key.", 401))

        # Consider using hmac.compare_digest(provided_key, api_key) for added security if needed
        if provided_key != api_key:
            current_app.logger.warning("Invalid API Key provided.")
            abort(Response("Invalid API Key.", 401))

        return func(*args, **kwargs)

    return decorated_function
