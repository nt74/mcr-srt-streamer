# MCR SRT Streamer

## Description

`mcr-srt-streamer` is a tool for testing SRT (Secure Reliable Transport) listeners and callers, optimized for professional broadcast workflows (e.g., DVB transport streams). Built with Python, Flask, GStreamer, and Bootstrap 5 (with SVT color theme), it provides a web interface to manage and monitor multiple SRT streams originating from local Transport Stream (`.ts`) files, UDP multicast inputs, or internally generated test patterns.

The application configures GStreamer pipelines (`filesrc/udpsrc/videotestsrc ! ... ! srtsink`) for robust TS-over-SRT streaming. It includes integrated network testing tools (`ping`, optionally `iperf3`) to recommend optimal SRT parameters (Latency, Overhead) derived from the Haivision SRT Deployment Guide[cite: 679]. Recent refactoring has centralized configuration logic, standardized internal error reporting (using tuples), and separated frontend JavaScript into external files for improved maintainability and robustness. The interface uses Bootstrap 5, jQuery, and Chart.js, designed for air-gapped or firewall-restricted operation with no external CDN dependencies.

---

## Features

### Streaming

-   **Multi-Stream Hosting:** Run multiple concurrent SRT streams (default simultaneous streams limit configurable).
-   **Listener and Caller Modes:** Launch streams as SRT Listener (server) or Caller (client) with easy web configuration.
-   **Multiple Input Sources:**
    -   **File:** Stream local `.ts` files from the `media/` directory.
    -   **UDP Multicast:** Ingest streams from IPTV multicast sources declared in `app/data/iptv_channels.json`[cite: 1], with selectable network interface (`Auto` chooses OS default).
    -   **Colorbar Generator:** Stream internally generated 720p50 or 1080i25 PAL color bars (SMPTE pattern) with a 1000Hz sine audio tone, suitable for testing SRT links without an external source.
-   **GStreamer Pipeline Details:**
    -   Inputs from local files or multicast via `filesrc` or `udpsrc`. For Colorbars, `videotestsrc` and `audiotestsrc` are used, outputting to an internal UDP multicast relay.
    -   Transport Stream parsing via `tsparse` (for file/multicast/colorbar inputs before SRT sink) with timestamps enabled (`set-timestamps=true`) and DVB alignment (`alignment=7`)[cite: 3].
    -   Configurable smoothing latency (to reduce PCR jitter, mainly for file/multicast).
    -   **Colorbar Generation:** Uses `videotestsrc` (pattern smpte-rp-219) and `audiotestsrc` (sine wave 1000Hz). Audio encoded to AAC (`fdkaacenc` preferred, `voaacenc` fallback). Video encoded using `x264enc`. Multiplexed into MPEG-TS before SRT[cite: 3].
    -   SRT transmission via `srtsink` with:
        -   Adjustable latency (20-8000ms, accepts any integer).
        -   Bandwidth overhead (1-99%).
        -   Optional encryption: AES-128 or AES-256 (10-79 character passphrase).
        -   **Hardcoded DVB-Optimized Parameters:** Includes `tlpktdrop=true` and conservative buffer sizes (`rcvbuf`/`sndbuf`/`fc` defaulting to 8MB/8192pkts) applied directly in the URI builder for stability (see `app/stream_manager.py`). The `dvb_config.py` file is obsolete.
        -   Quality-of-service DSCP flag (`qos=true|false`).
        -   **Optional RTP Encapsulation:** Apply `rtpmp2tpay pt=33 mtu=1316` for UDP/Colorbar inputs, useful for SMPTE 2022-7 testing (selectable in UI/API).
-   **Refactored Logic:** Centralized configuration validation (`_build_stream_config_from_dict`) shared between Web UI and API routes for consistency.

### Network Testing & Recommendations

-   **Configurable Network Test Mechanisms:** (`NETWORK_TEST_MECHANISM` env var)
    -   **`ping_only` (default):** Uses ICMP `ping` to assess RTT. Estimates recommendations using RTT + fixed fallback loss (`ASSUMED_LOSS_FOR_TCP_FALLBACK`).
    -   **`iperf`:** Requires `iperf3` binary & optional background service. Uses UDP `iperf3` tests against a safe list (`app/data/udp_safe_servers.json`) for measured RTT, bandwidth, loss, jitter, providing more accurate recommendations.
    -   **In Both Modes:** GeoIP lookup (cached) used for closer server selection. Tests: Closest, Regional, Manual. Results can auto-fill Listener form.
-   **System Info Dashboard:** Host stats (CPU, RAM, disk, IP, uptime, user).
-   **Stream Status:** Live updates with:
    -   Real-time charts for bitrate, RTT, loss (on detail page).
    -   SRT packet statistics, including **Negotiated Latency** (on detail page).
    -   Per-stream details page with advanced debug data access (via separate UI endpoint).
-   **Media Browser & Info:** AJAX modal file selector; `mediainfo` integration.
-   **Security:** NGINX frontend (optional Basic Auth), CSRF protection (Flask-WTF), `SECRET_KEY` required, REST API requires `X-API-Key`.
-   **Designed for Air-Gapped Deployments:** All CSS/JS assets (Bootstrap, jQuery, Chart.js, Font Awesome) are local. JavaScript separated into external files (`app/static/js/`).

---

## Technology Stack

-   **Backend:** Python 3, Flask, Flask-WTF, Waitress, GStreamer (PyGObject), requests, psutil.
-   **Frontend:** Bootstrap 5, jQuery, Chart.js, Font Awesome (local assets), Jinja2 templates, custom styles. External JS files.
-   **Supporting Tools:** `curl`, `ping`, `dig`, `ffmpeg`, `mediainfo`, **Optional:** `iperf3`, `systemd`, `nginx`.

---

## Architecture Overview

### Backend (`app/` directory)

-   `stream_manager.py`: Manages GStreamer pipelines, hardcodes buffer/tlpktdrop params. Returns `(success, message)` tuples.
-   `network_test.py`: Manages ping/iperf3 tests. Returns `(result, error)` tuples.
-   `test_iperf_servers.py`: Background script for UDP server list.
-   `utils.py`: System info, network utils, GeoIP caching. Uses `(result, error)` tuples for some functions.
-   `forms.py`: WTForms definitions.
-   `routes.py`: Flask routes for web UI. Includes `/ui/...` endpoints for AJAX. Calls helper functions.
-   `api_routes.py`: Flask Blueprint routes for the REST API. Calls config helper.
-   `dvb_config.py`: *(Removed/Obsolete)*
-   `ts_analyzer.py`: *(Currently placeholder/unused)*
-   `data/`: Config files (`iptv_channels.json`), server lists, caches.
-   `static/`: Local CSS, JS (including `app.js`, `forms.js`, `dashboard.js`, `caller.js`, `stream_details.js`, `network_test.js`), fonts, images.
-   `templates/`: HTML templates (`index.html`, `caller.html`, `stream_details.html`, `network_test.html`, `media_info.html`).

**Logs**: `/var/log/srt-streamer/srt_streamer.log` (default)

### Frontend (via recommended NGINX proxy)

-   Serves static assets from `/static`.
-   Optional Basic Auth for `/` via `.htpasswd`.
-   Reverse proxies `/` and `/api/` to Waitress (port 5000). (Note: `/api/` location block in Nginx should *not* have Basic Auth if API key is used).

### System Services (default install)

-   **`network-tuning.service`**: Runs `network-tuning.sh` (optional).
-   **`mcr-srt-streamer.service`**: Runs Waitress Flask server (env vars: `SECRET_KEY`, `API_KEY`, `NETWORK_TEST_MECHANISM`, etc.).
-   **`iperf-server-check.service` & `.timer`**: Optional background timer for UDP server list update (`iperf` mode only).

---

## System Requirements

-   **OS:** Debian / Ubuntu, or RHEL 9+ / Rocky Linux 9+.
-   **RAM:** ~1 GB / active stream recommended. Default buffer settings reduced (~8MB/stream) for lower memory usage.
-   **CPU:** Minimal (more if using Colorbar encoding).
-   **GPU:** Not required.
-   **Network:** Stable bandwidth + overhead. Network tuning recommended.
-   **Dependencies:** Python 3+venv+pip, GStreamer 1.0+plugins (gst-python, base, good, bad, ugly, libav, x264enc, fdkaacenc/voaacenc), `ping`, `curl`, `dig`, `mediainfo`, `ffmpeg`, **Optional:** `iperf3`.

---

## Installation Guide

*(Ensure SECRET_KEY and API_KEY steps are clear, Nginx config reflects separation)*

### 1. Obtain the source code

```bash
sudo git clone https://your-github-repo/mcr-srt-streamer.git /opt/mcr-srt-streamer
cd /opt/mcr-srt-streamer
```

### 2. System Packages

*(Package lists remain the same - ensure required gstreamer plugins like x264/aac are installed)*

### 3. Python Environment

```bash
sudo python3 -m venv /opt/venv
source /opt/venv/bin/activate
cd /opt/mcr-srt-streamer
pip install -r requirements.txt
deactivate
```

### 4. Initial Configuration

-   **Media Content:** `sudo mkdir -p /opt/mcr-srt-streamer/media && sudo chown -R nginx:nginx /opt/mcr-srt-streamer/media`
-   **Multicast Channels (`app/data/iptv_channels.json`):** Edit/create.
-   **Log & Data Dirs:** `sudo mkdir -p /var/log/srt-streamer /opt/mcr-srt-streamer/app/data && sudo chown -R nginx:nginx /var/log/srt-streamer /opt/mcr-srt-streamer/app/data`
-   **Flask Secret Key & API Key:** Generate and save for systemd file:
    ```bash
    openssl rand -hex 32 # For SECRET_KEY
    openssl rand -hex 32 # For API_KEY
    ```
-   **NGINX Reverse Proxy:** Configure `/etc/nginx/conf.d/mcr-srt-streamer.conf` (or similar):
    ```nginx
    server {
      listen 80; # Add SSL config later if needed
      server_name your-streamer-hostname.domain.com;

      # Basic Auth ONLY for Web UI root
      location / {
        # Uncomment and configure if needed
        # auth_basic "Restricted Access";
        # auth_basic_user_file /etc/nginx/.htpasswd;

        proxy_pass [http://127.0.0.1:5000](http://127.0.0.1:5000);
        proxy_set_header Host $host; # Pass original host
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 600s; proxy_send_timeout 600s;
      }

      # API Location - NO Basic Auth (relies on X-API-Key)
      location /api/ {
        proxy_pass [http://127.0.0.1:5000](http://127.0.0.1:5000);
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 600s; proxy_send_timeout 600s;
      }

      # Static Files - NO Basic Auth
      location /static {
        alias /opt/mcr-srt-streamer/app/static; # Ensure path is correct
        expires 7d; # Add caching headers
      }
    }
    ```
    Create htpasswd if using Basic Auth: `sudo htpasswd -c /etc/nginx/.htpasswd your_user && sudo chown nginx:nginx /etc/nginx/.htpasswd && sudo chmod 600 /etc/nginx/.htpasswd`
    Test & Reload: `sudo nginx -t && sudo systemctl reload nginx`

-   **Systemd Services:** Ensure scripts executable: `sudo chmod +x network-tuning.sh test_iperf_servers.py`

#### Main App Service (`/etc/systemd/system/mcr-srt-streamer.service`)
```ini
[Unit]
Description=MCR SRT Streamer
After=network.target network-tuning.service nginx.service
Wants=network-tuning.service

[Service]
Type=simple
WorkingDirectory=/opt/mcr-srt-streamer
User=nginx Group=nginx # Recommended user

# === CRITICAL: Set these environment variables ===
Environment="SECRET_KEY=PASTE_YOUR_GENERATED_SECRET_KEY"
Environment="API_KEY=PASTE_YOUR_GENERATED_API_KEY"
# ================================================

Environment="HOST=127.0.0.1" Environment="PORT=5000" Environment="THREADS=8"
Environment="MEDIA_FOLDER=/opt/mcr-srt-streamer/media"
Environment="FLASK_ENV=production"
Environment="NETWORK_TEST_MECHANISM=ping_only" # Or "iperf"

ExecStart=/opt/venv/bin/python3 /opt/mcr-srt-streamer/wsgi.py
Restart=on-failure RestartSec=5

[Install]
WantedBy=multi-user.target
```
Reload & enable: `sudo systemctl daemon-reload && sudo systemctl enable --now mcr-srt-streamer`

#### Optional: Background iperf3 UDP Server Check (`iperf` mode only)
*(Service and Timer definitions remain the same)*
Enable: `sudo systemctl daemon-reload && sudo systemctl enable --now iperf-server-check.timer`
Run initially: `sudo systemctl start iperf-server-check.service`

### SELinux (RHEL/Rocky):
Allow Nginx <-> Waitress: `sudo setsebool -P httpd_can_network_connect 1 && sudo systemctl restart nginx`

---

## Usage Workflow

*(Added Negotiated Latency and RTP toggle)*

1.  **Login** via Basic Auth (if configured).
2.  **Dashboard:** Monitor system, Launch **Listener** (select source, params, smoothing, SRT latency, overhead, encryption, QoS, **RTP Encapsulation**).
3.  **Caller:** Launch Caller (target IP/port, select source, params, smoothing, SRT latency, overhead, encryption, QoS, **RTP Encapsulation**).
4.  **Network Testing:** View mechanism, select mode, run test, view results (RTT, BW, Loss, Jitter), apply recommended Latency/Overhead. View SRT Parameter Reference.
5.  **Stream Details:** Monitor stats, charts (including **Negotiated Latency**). Toggle Raw Stats display.
6.  **Stop Streams** via UI or API.

---

## REST API Usage

*(Keeping the detailed section provided by user, ensuring accuracy)*

The application provides a RESTful API for programmatic control, accessible under the `/api/` prefix.

**Authentication:**

-   All API requests **MUST** include a valid API key in the `X-API-Key` header.
-   The expected API key is set via the `API_KEY` environment variable.
-   If Nginx Basic Auth is enabled *on the `/api/` location* (not recommended if using API keys), include the `-u USERNAME:PASSWORD` flag.

**Endpoints:**

### 1. List Active Streams

-   **Endpoint:** `GET /api/streams`
-   **Method:** `GET`
-   **Auth:** `X-API-Key` header required.
-   **Success Response (200 OK):**
    ```json
    {
      "data": {
        "10001": { // Key is listener port or target port for caller
          "key": 10001, // Key here is integer type
          "mode": "listener",
          "connection_status": "Connected",
          // ... other summary fields as shown before ...
          "config": { /* full config dict */ }
        },
        "10002": { /* ... */ }
      }
    }
    ```
-   **Error Response:** `500` or `503`.

### 2. Get Stream Details/Statistics

-   **Endpoint:** `GET /api/stats/<stream_key>` (or alias `GET /api/streams/<stream_key>`)
-   **Method:** `GET`
-   **Auth:** `X-API-Key` header required.
-   **URL Params:** `<stream_key>` (listener port or target port).
-   **Success Response (200 OK):** Returns detailed SRT statistics dictionary.
    ```json
    {
        // Note: No top-level "data" key here, stats dict is root
        "connection_status": "Connected",
        // ... many SRT stats fields ...
        "negotiated_latency_ms": 120,
        "rtt_ms": 45.5,
        "packet_loss_percent": 0.01,
        "packets_sent": 123456,
        // ...
        "timestamp_api": 1712860023.456
    }
    ```
-   **Error Responses:** `400`, `404`, `500`, `503`.

### 3. Get Debug Info

-   **Endpoint:** `GET /api/debug/<stream_key>`
-   **Method:** `GET`
-   **Auth:** `X-API-Key` header required.
-   **URL Params:** `<stream_key>`.
-   **Success Response (200 OK):** Returns a dictionary containing config, status, history, parsed stats, and raw stats string.
-   **Error Responses:** `400`, `404`, `500`, `503`.

### 4. Start a New Stream

-   **Endpoint:** `POST /api/streams`
-   **Method:** `POST`
-   **Auth:** `X-API-Key` header required.
-   **Request Body (JSON):** See structure detailed in user's original README (mode, input_type, latency, overhead_bandwidth, encryption, passphrase, qos, rtp_encapsulation, port/target_address/target_port, multicast_address/multicast_port/multicast_interface, file_path).
-   **Success Response (201 Created):**
    ```json
    { "message": "Stream started...", "stream_key": 10001, "status": "starting" }
    ```
-   **Error Responses:** `400`, `415`, `500`, `503`.

### 5. Stop a Stream

-   **Endpoint:** `DELETE /api/streams/<stream_key>`
-   **Method:** `DELETE`
-   **Auth:** `X-API-Key` header required.
-   **URL Params:** `<stream_key>`.
-   **Success Response (200 OK):**
    ```json
    { "message": "Stream stop initiated.", "status": "stopping" }
    ```
-   **Error Responses:** `400`, `404`, `500`, `503`.

### 6. Get System Status

-   **Endpoint:** `GET /api/system/status`
-   **Method:** `GET`
-   **Auth:** `X-API-Key` header required.
-   **Success Response (200 OK):** Returns system info dictionary (CPU, Mem, Disk, IP, etc.).
-   **Error Response:** `500`.

### Example `curl` Usage (Listener with Multicast & RTP Encapsulation):
*(Keep existing example)*
```bash
# Replace placeholders
API_KEY="..." NGINX_USER="..." NGINX_PASS="..." STREAMER_URL="http://..."
curl -X POST -u "${NGINX_USER}:${NGINX_PASS}" -H "X-API-Key: ${API_KEY}" -H "Content-Type: application/json" \
 -d '{ "mode": "listener", "port": 10003, "input_type": "multicast", "multicast_address": "239.1.1.2", "multicast_port": 5000, "multicast_interface": "", "latency": 300, "overhead_bandwidth": 10, "smoothing_latency_ms": 30, "encryption": "none", "qos": false, "rtp_encapsulation": true }' \
 "${STREAMER_URL}/api/streams"
```

---

## Configuration & Network Tuning Tips

-   **SRT Latency & Overhead:** Base `latency` on measured RTT (3-4x RTT, min ~120ms). Base `overheadbandwidth` on measured loss (use Network Test). Defaults (300ms, 2%) are starting points.
-   **TSParse smoothing latency:** 20-50ms for file/multicast.
-   **QoS (DSCP):** Enable if network honors tags.
-   **RTP Encapsulation:** Enable for UDP/Multicast/Colorbar inputs if needed (e.g., for SMPTE 2022-7).
-   **Network Test Mode:** `iperf` recommended if UDP tests work; `ping_only` otherwise.
-   **Linux Tuning:** Use `network-tuning.sh`. Default buffer sizes reduced (~8MB) in `stream_manager.py`.

---

## License

*(Updated to match new footer format)*

MCR SRT Streamer is released under the <a href="https://opensource.org/licenses/BSD-2-Clause" target="_blank" rel="noopener noreferrer">BSD-2-Clause License</a>. See the `LICENSE` file.

---

## References

*(Keep existing references)*
-   Haivision SRT Protocol Deployment Guide v1.5.x (included in `/docs/`)
-   [SRT Alliance](https://www.srtalliance.org/)
-   [SRT GitHub](https://github.com/Haivision/srt)
-   [GStreamer Documentation](https://gstreamer.freedesktop.org/documentation/)

---

