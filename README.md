# MCR SRT Streamer

## Description

`mcr-srt-streamer` is a tool for testing SRT (Secure Reliable Transport) listeners and callers, optimized for professional broadcast workflows (e.g., DVB transport streams). Built with Python, Flask, GStreamer, and Bootstrap 5 (with SVT color theme), it provides a web interface to manage and monitor multiple SRT streams originating from local Transport Stream (`.ts`) files, UDP multicast inputs, internally generated test patterns, or SMPTE 2022-7 redundant streams.

The application configures GStreamer pipelines (`filesrc/udpsrc/videotestsrc ! ... ! srtsink`) for robust TS-over-SRT streaming and includes integrated network testing tools (`ping`, optionally `iperf3`) to recommend optimal SRT parameters (Latency, Overhead) derived from the Haivision SRT Deployment Guide. Recent improvements include fixes for SMPTE 2022-7 caller mode statistics and source binding, enhanced dashboard statistics display, improved form validation, and making passphrase fields visible for easier use. The interface is implemented with Bootstrap 5, jQuery, and Chart.js, designed for air-gapped or firewall-restricted operation with no external CDN dependencies.

---

## Features

### Streaming

-   **Multi-Stream Hosting:** Run multiple concurrent SRT streams (default simultaneous streams limit configurable).
-   **Listener and Caller Modes:** Launch streams as SRT Listener (server) or Caller (client) with easy web configuration.
-   **Multiple Input Sources:**
    -   **File:** Stream local `.ts` files from the `media/` directory.
    -   **UDP Multicast:** Ingest streams from IPTV multicast sources declared in `app/data/iptv_channels.json`, with selectable network interface (`Auto` chooses OS default).
    -   **Colorbar Generator:** Stream internally generated 720p50 or 1080i25 PAL color bars (SMPTE pattern) with a 1000Hz sine audio tone, suitable for testing SRT links without an external source.
-   **SMPTE 2022-7 Seamless Protection Output:** Create redundant RTP streams sent via SRT with identical SSRC and timestamps for seamless protection (see dedicated section below for details).
-   **GStreamer Pipeline Details:**
    -   Inputs from local files or multicast via `filesrc` or `udpsrc`. For Colorbars, `videotestsrc` and `audiotestsrc` are used, outputting to an internal UDP multicast relay.
    -   Transport Stream parsing via `tsparse` (for file/multicast/colorbar inputs before SRT sink) with:
        -   timestamps enabled (`set-timestamps=true`)
        -   DVB alignment (`alignment=7`)
        -   configurable smoothing latency (to reduce PCR jitter, mainly for file/multicast)
    -   **Colorbar Generation:** Uses `videotestsrc` (pattern smpte-rp-219) and `audiotestsrc` (sine wave 1000Hz) for test signals. Audio is encoded to AAC, prioritizing `fdkaacenc` if available on the system, otherwise falling back to `voaacenc`. Video is encoded using `x264enc`. The generated streams are multiplexed into an MPEG-TS stream before being sent via SRT (using an internal UDP multicast relay).
    -   SRT transmission via `srtsink` with:
        -   adjustable latency (20-8000ms)
        -   bandwidth overhead (1-99%)
        -   optional encryption: AES-128 or AES-256 (10-80 character **visible** passphrase field)
        -   **Hardcoded DVB-Optimized Parameters:** Includes `tlpktdrop=true` and conservative buffer sizes (`rcvbuf`/`sndbuf`/`fc` defaulting to 8MB/4096pkts) applied directly in the URI builder.
        -   quality-of-service DSCP flag (`qos=true|false`)
        -   **Optional RTP Encapsulation:** Apply `rtpmp2tpay pt=33 mtu=1316` for UDP/Colorbar inputs, useful for SMPTE 2022-7 testing (selectable in UI/API). Standard SMPTE 2022-7 streams always use RTP encapsulation.
-   **Refactored Logic:** Centralized configuration validation shared between Web UI and API routes. Robust statistics parsing handles both Listener and Caller modes correctly.
-   **Detailed DVB Compliance:** Pipeline settings (`tsparse alignment=7`, `rtpmp2tpay mtu=1316`) aimed at broadcast/DVB workflows.

### Network Testing & Recommendations

-   **Configurable Network Test Mechanisms:** Controlled via `NETWORK_TEST_MECHANISM` env var (`ping_only` or `iperf`).
    -   **`ping_only` mode (default):** Uses ICMP `ping` to assess RTT. Estimates loss for recommendations. Useful in restricted environments.
    -   **`iperf` mode:** Requires `iperf3` binary and optional background server check service. Performs `ping` + UDP `iperf3` tests for measured RTT, bandwidth, loss, jitter. Provides more accurate recommendations.
    -   **In Both Modes:** GeoIP used for server selection. Tests: Closest, Regional, Manual. Results auto-fill Latency/Overhead fields.
-   **System Info Dashboard:** Host stats (CPU, RAM, disk, IP, uptime, user).
-   **Stream Status:** Live updates with:
    -   **Improved Dashboard Display:** Key stats (Bitrate, RTT, Loss) shown directly on dashboard cards for active streams (when status is "Running" or "Connected"). Consistent color coding for status indicators (Green/Checkmark for Running/Connected).
    -   Real-time charts for bitrate, RTT, loss (on detail page).
    -   SRT packet statistics, counters, and **Negotiated Latency** (on detail page).
    -   Per-stream details page with advanced debug data (client IPs, connection state, raw stats string).
-   **Media Browser & Info:**
    -   AJAX modal file selector for `.ts` media in `media/`.
    -   File analysis via `mediainfo` (requires `mediainfo` binary).
-   **Security:**
    -   NGINX frontend with optional Basic Auth.
    -   CSRF protection via Flask-WTF.
    -   Requires strong `SECRET_KEY` (env var).
    -   REST API Authentication via `X-API-Key` header (env var `API_KEY`).
-   **Designed for Air-Gapped Deployments:**
    -   No external CDNs. All Bootstrap, jQuery, Chart.js & Font Awesome assets are local.
    -   JavaScript separated into external files.

---

## SMPTE 2022-7 Seamless Protection Output

This feature adds support for creating SMPTE 2022-7 style redundant RTP streams sent via SRT. It takes a single input source (Multicast UDP or internal Colorbars) and creates two identical RTP streams (same SSRC, timestamps) that are then sent out via two configurable SRT outputs (legs).

### Design Approach

This feature is implemented separately from the standard Listener/Caller stream management:

- **Separate Management:** `SMPTEManager` class (`app/smpte_manager.py`) handles SMPTE pair GStreamer pipelines.
- **Separate UI:** Dedicated configuration page (`/smpte2022_7`) and details page (`/smpte2022_7/<id>`).
- **Separate Routes:** Flask Blueprint (`smpte_bp` in `app/smpte_routes.py`) handles UI and dedicated API endpoints.

### New Components

**Backend:**
- `app/smpte_manager.py`: Contains `SMPTEManager` class to build `(input -> tsparse -> rtpmp2tpay -> tee -> 2x srtsink)` and manage pipelines. Includes methods for getting statistics and debug info, correctly parsing stats for both listener and caller modes (returning zeros for unconnected legs).
- `app/smpte_routes.py`: Defines routes for the config page (`/`), stopping pairs (`/stop/<id>`), the details page (`/<id>`), and API endpoints (`/api/pairs`, `/api/pairs/<id>`, `/api/stats/<id>`, `/api/debug/<id>`).
- `app/smpte_forms.py`: Defines `SMPTEPairForm` for web UI configuration. Includes **validation preventing the use of the same Port and selected Interface combination for both legs**. Passphrase input uses a standard text field for visibility.

**Frontend:**
- `app/templates/smpte2022_7.html`: Web form for configuring a new SMPTE pair.
- `app/templates/smpte_details.html`: Page to display detailed statistics (tables and charts) for both legs of an active SMPTE pair.
- `app/static/js/smpte2022_7.js`: JavaScript for the configuration page.
- `app/static/js/smpte_details.js`: JavaScript for the details page; fetches stats from the API (`/smpte2022_7/api/stats/<id>`) periodically and updates tables and charts for both legs.

### Modifications to Existing Files

- `app/__init__.py`: Initialized `SMPTEManager` and registered the `smpte_bp` Blueprint.
- `app/routes.py`: Modified `/ui/active_streams_data` to query both managers and return combined data. Modified index route to fetch initial data from both managers.
- `app/static/js/dashboard.js`: Updated to handle combined data, render distinct cards, include correct links, and display stats/status correctly for standard streams.
- `app/stream_manager.py`: Updated `get_active_streams` to fetch dashboard stats for "Running" status. Cleaned up debug logging in `get_debug_info`. Updated stats parsing.
- `app/forms.py`: Changed `passphrase` field from `PasswordField` to `StringField`.

### Key Functionality Details

- **Pipeline:** `(input -> tsparse -> rtpmp2tpay -> tee -> 2x srtsink)`. Includes `tsparse` with `alignment=7` and configurable `smoothing-latency`. `rtpmp2tpay` uses `pt=33`, `mtu=1316`, and the configured SSRC.
- **Configuration:** UI allows configuration of input, shared SRT/RTP params, and per-leg SRT settings (Mode, Port, Interface, Target Address).
- **Caller Mode Binding:** Uses `localaddress=IP` parameter in SRT URI for source IP binding when a specific interface is selected. The OS assigns the source port (localport is not forced).
- **API:** Dedicated API endpoints under `/smpte2022_7/api/`.
- **UI Integration:** SMPTE pairs shown on dashboard, have own details page.

---

## Technology Stack

-   **Backend:** Python 3 with Flask, Flask-WTF, Waitress WSGI, GStreamer via PyGObject, requests, psutil.
-   **Frontend:** Bootstrap 5, jQuery, Chart.js, Font Awesome (all local), Jinja2 templates, custom styles.
-   **Supporting Tools:** `curl`, `ping`, `dig`, `ffmpeg`, `mediainfo`, **optionally**: `iperf3`, `systemd`, `nginx`.

---

## Architecture Overview

### Backend (`app/` directory)

-   `stream_manager.py`: Manages standard SRT streams (listener/caller) and colorbar generators.
-   `smpte_manager.py`: Manages SMPTE 2022-7 redundant stream pairs.
-   `network_test.py`: Manages ping/iperf3 tests.
-   `test_iperf_servers.py`: Background script for iperf server validation.
-   `utils.py`: System info, network interfaces, GeoIP functions.
-   `forms.py`: WTForms for standard streams.
-   `smpte_forms.py`: WTForms for SMPTE 2022-7 configuration.
-   `routes.py`: Flask routes for main web UI and standard stream AJAX/debug endpoints.
-   `api_routes.py`: Flask Blueprint routes for the REST API (standard streams).
-   `smpte_routes.py`: Flask Blueprint routes for SMPTE 2022-7 UI and API.
-   `auth.py`: Authentication helpers (API Key / Basic Auth potentially).
-   `ts_analyzer.py`: *(Placeholder/unused)*
-   `data/`: Config files (`iptv_channels.json`), server lists, caches.
-   `static/`: Local CSS, JS (including `app.js`, `forms.js`, `dashboard.js`, `caller.js`, `stream_details.js`, `network_test.js`, `smpte2022_7.js`, `smpte_details.js`), fonts, images.
-   `templates/`: HTML templates (`index.html`, `caller.html`, `stream_details.html`, `network_test.html`, `media_info.html`, `smpte2022_7.html`, `smpte_details.html`).

**Logs**: `/var/log/srt-streamer/srt_streamer.log` (default)
**Data:** `app/data/`

### Frontend (via recommended NGINX proxy)

-   Serves static assets from `/opt/mcr-srt-streamer/app/static/`.
-   Protects with optional Basic Auth.
-   Reverse proxies to Python Waitress server (default port 5000).
-   API endpoints (`/api/`, `/smpte2022_7/api/`) can be configured without Basic Auth when using API keys.

### System Services (default install)

-   **`network-tuning.service`**: Optional OS network tuning.
-   **`mcr-srt-streamer.service`**: Runs the Waitress Flask server.
-   **`iperf-server-check.service` & `.timer`**: Optional background UDP server check for `iperf` mode.

---

## System Requirements

-   **OS:**
    Debian / Ubuntu, or RHEL 9+ / Rocky Linux 9+ (other distros with recent GStreamer/Python should work with adjustments).
-   **RAM:**
    Approximately **1 GB / active stream** (e.g., ~10 GB for 10 streams). Plus resources for background generator pipelines if using Colorbars. Default buffer settings reduced (~8MB/stream) for lower memory usage.
-   **CPU:**
    Minimal, but encoding for Colorbars will consume some CPU resources.
-   **GPU:**
    Not required.
-   **Network:**
    Sufficient stable bandwidth plus overhead (> stream bitrate × (1 + overhead%)). Network tuning is recommended.
-   **Dependencies:**
    -   Python 3 + pip & venv
    -   GStreamer 1.0 with good, bad, ugly, libav, gst-python bindings (ensure plugins for H.264 (`x264enc`) and AAC (`fdkaacenc`, `voaacenc`) encoding are available).
    -   `ping` (iputils), `curl`, `dig` (dnsutils/bind-utils), `mediainfo`, and `ffmpeg`
    -   **Optional:** `iperf3` (only if full UDP tests needed)

---

## Installation Guide

Assuming installation under `/opt/mcr-srt-streamer`. Adapt as needed.

### 1. Obtain the source code

```bash
sudo git clone https://your-github-repo/mcr-srt-streamer.git /opt/mcr-srt-streamer
cd /opt/mcr-srt-streamer
```

### 2. System Packages

#### Debian / Ubuntu:

```bash
sudo apt update && sudo apt install -y \
 python3 python3-pip python3-venv python3-gi gir1.2-gobject-2.0 gir1.2-glib-2.0 \
 libgirepository1.0-dev gcc libcairo2-dev pkg-config python3-dev \
 gir1.2-gstreamer-1.0 gir1.2-gst-plugins-base-1.0 \
 gstreamer1.0-plugins-base gstreamer1.0-plugins-good gstreamer1.0-plugins-bad \
 gstreamer1.0-plugins-ugly gstreamer1.0-tools gstreamer1.0-libav gstreamer1.0-x264 \
 nginx curl iperf3 iputils-ping dnsutils ffmpeg mediainfo apache2-utils
```
*(Note: Added gstreamer1.0-x264 explicitly, ensure relevant AAC packages like gstreamer1.0-fdkaac or similar are installed if needed and not covered by bad/ugly)*

#### RHEL 9+ / Rocky 9:

```bash
# Enable RPM Fusion or other repo providing gstreamer1.0-plugins-ugly/bad containing x264enc, fdkaacenc/voaacenc if not in base/epel
sudo dnf update && sudo dnf install -y \
 python3 python3-pip python3-gobject gobject-introspection-devel cairo-gobject-devel \
 python3-devel pkgconf-pkg-config gcc \
 gstreamer1 gstreamer1-plugins-base gstreamer1-plugins-good \
 gstreamer1-plugins-bad-free gstreamer1-plugins-ugly-free gstreamer1-libav \
 # Add packages for x264enc, fdkaacenc, voaacenc if not included above (e.g., gstreamer1-plugin-x264 gstreamer1-plugins-bad-freeworld) \
 nginx curl iperf3 iputils bind-utils ffmpeg mediainfo httpd-tools
```

*(Adjust packages and commands for other distros.)*

### 3. Python Environment

```bash
sudo python3 -m venv /opt/venv
source /opt/venv/bin/activate
cd /opt/mcr-srt-streamer
pip install -r requirements.txt
deactivate
```

### 4. Initial Configuration

-   **Media Content:**

    Place `.ts` files under:

    ```bash
    sudo mkdir -p /opt/mcr-srt-streamer/media
    sudo chown -R nginx:nginx /opt/mcr-srt-streamer/media  # Or desired user
    # Copy your .ts files inside
    ```

-   **Multicast Channels JSON (`app/data/iptv_channels.json`):**

    ```json
    [
      {
        "name": "Channel 1 HD",
        "address": "239.1.1.1",
        "port": 1234,
        "protocol": "udp",
        "source_ip": "10.0.0.1"  // optional
      }
    ]
    ```

-   **Log & Data Directories:**

    ```bash
    sudo mkdir -p /var/log/srt-streamer /opt/mcr-srt-streamer/app/data
    sudo touch /opt/mcr-srt-streamer/app/data/external_ip_cache.json
    sudo touch /opt/mcr-srt-streamer/app/data/iperf3_export_servers.json
    sudo touch /opt/mcr-srt-streamer/app/data/iptv_channels.json # if not yet created
    sudo chown -R nginx:nginx /var/log/srt-streamer /opt/mcr-srt-streamer/app/data
    ```

-   **Flask Secret Key & API Key:**

    Generate strong keys:
    ```bash
    openssl rand -hex 32 # Generate SECRET_KEY
    openssl rand -hex 32 # Generate API_KEY
    # save both outputs for the systemd service file
    ```

-   **NGINX Reverse Proxy:**

    Configure a server block (e.g., `/etc/nginx/conf.d/mcr-srt-streamer.conf`):

    ```nginx
    server {
      listen 80;
      server_name your-streamer-hostname.domain.com; # or IP

      # Optional: Basic Auth for Web UI
      location / {
        # Uncomment if needed:
        # auth_basic "Restricted Area";
        # auth_basic_user_file /etc/nginx/.htpasswd;

        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 600s;
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
      }

      # API Location - NO Basic Auth (relies on X-API-Key)
      location /api/ {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 600s;
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
      }

      location /static {
        alias /opt/mcr-srt-streamer/app/static;
        expires 7d;
        add_header Cache-Control "public";
      }
    }
    ```

    Create htpasswd (if using Basic Auth):

    ```bash
    sudo htpasswd -c /etc/nginx/.htpasswd your_chosen_username
    sudo chown nginx:nginx /etc/nginx/.htpasswd
    sudo chmod 600 /etc/nginx/.htpasswd
    sudo nginx -t && sudo systemctl reload nginx
    ```

-   **Systemd Services**

    Ensure scripts are executable:

    ```bash
    sudo chmod +x /opt/mcr-srt-streamer/network-tuning.sh
    sudo chmod +x /opt/mcr-srt-streamer/test_iperf_servers.py
    ```

#### Main App Service (`/etc/systemd/system/mcr-srt-streamer.service`)

```ini
[Unit]
Description=MCR SRT Streamer
After=network.target network-tuning.service nginx.service
Wants=network-tuning.service

[Service]
Type=simple
WorkingDirectory=/opt/mcr-srt-streamer
User=nginx # Or user running Nginx/Waitress
Group=nginx # Or group running Nginx/Waitress

# === CRITICAL: Set these environment variables ===
Environment="SECRET_KEY=PASTE_YOUR_GENERATED_SECRET_KEY"
Environment="API_KEY=PASTE_YOUR_GENERATED_API_KEY"
# ================================================

Environment="HOST=127.0.0.1" # Listen only locally if behind Nginx
Environment="PORT=5000"
Environment="THREADS=8"
Environment="MEDIA_FOLDER=/opt/mcr-srt-streamer/media"
Environment="FLASK_ENV=production"

# Choose ONE mechanism:
Environment="NETWORK_TEST_MECHANISM=ping_only"  # Safe default
# Environment="NETWORK_TEST_MECHANISM=iperf"     # Enable UDP iperf3 tests if background script running

ExecStart=/opt/venv/bin/python3 /opt/mcr-srt-streamer/wsgi.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Reload daemon & enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mcr-srt-streamer
```

---

### Optional: Background iperf3 UDP Server Validation Service (if using `iperf` mode)

-   **`/etc/systemd/system/iperf-server-check.service`:**

```ini
[Unit]
Description=Refresh Good UDP iperf3 Servers List
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/opt/mcr-srt-streamer
User=root # Needs permissions to write to app/data potentially, or adjust ownership
Group=root
ExecStart=/opt/venv/bin/python3 /opt/mcr-srt-streamer/test_iperf_servers.py

[Install]
WantedBy=multi-user.target
```

-   **`/etc/systemd/system/iperf-server-check.timer`:**

```ini
[Unit]
Description=Run UDP iperf3 servers check daily

[Timer]
OnCalendar=*-*-* 03:00:00 # Run daily at 3 AM
RandomizedDelaySec=3600 # Spread the load
Persistent=true # Run on next boot if missed

[Install]
WantedBy=timers.target
```

Enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now iperf-server-check.timer
```

Run once initially:

```bash
sudo systemctl start iperf-server-check.service
```

---

### SELinux (RHEL/Rocky):

Allow nginx <-> Waitress if blocked:

```bash
sudo setsebool -P httpd_can_network_connect 1
sudo systemctl restart nginx
```

---

## Usage Workflow

1.  **Login** to the web UI (via Basic Auth if configured).
2.  **Dashboard:**
    -   Monitor system status.
    -   Launch **Listener** streams: select source (**File**, **Multicast UDP**, or **Colorbars 720p50/1080i25**), input params, smoothing latency (if applicable), SRT latency, overhead, encryption, QoS, **RTP Encapsulation** (for UDP/Colorbar).
3.  **Caller:**
    -   Launch as SRT Caller, specifying target IP and port, select input source (**File**, **Multicast UDP**, or **Colorbars 720p50/1080i25**), configure SRT parameters, QoS, **RTP Encapsulation** (for UDP/Colorbar).
4.  **SMPTE 2022-7:**
    -   Configure redundant streams with identical RTP payloads
    -   Set shared parameters (SSRC, SRT settings) and per-leg configurations
    -   Monitor both legs simultaneously in the details view
5.  **Network Testing:**
    -   View mechanism active (Ping or iperf+Ping).
    -   Select mode (Closest, Regional, Manual).
    -   Run test to measure RTT, bandwidth, loss (depending on mechanism).
    -   Click to auto-fill SRT recommended latency/overhead.
6.  **Per-Stream Detail Pages:**
    -   Monitor bitrates, stats, charts including **Negotiated Latency**.
    -   View debug info including client addresses.
7.  **Stop Streams** anytime from dashboard or via API.

---

## REST API Usage

The application provides a RESTful API for programmatic control, accessible under the `/api/` prefix.

**Authentication:**

-   All API requests **MUST** include a valid API key in the `X-API-Key` header.
-   The expected API key is set via the `API_KEY` environment variable in the application's systemd service file.
-   If Nginx Basic Auth is enabled, include the `-u USERNAME:PASSWORD` flag in your `curl` requests.

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
          "key": 10001,
          "mode": "listener",
          "connection_status": "Connected",
          "uptime": "5m 10s",
          "input_type": "multicast",
          "source_detail": "239.1.1.1:1234",
          "latency": 300,
          "overhead_bandwidth": 5,
          "encryption": "aes-128",
          "passphrase_set": true,
          "qos_enabled": false,
          "smoothing_latency_ms": 30,
          "port": 10001,
          "target": null,
          "client_ip": "192.168.1.50",
          "srt_uri": "srt://0.0.0.0:10001?...",
          "start_time": "2025-04-11 19:01:00 UTC",
          "config": {
             "mode": "listener",
             "port": 10001,
             "input_type": "multicast",
             "multicast_address": "239.1.1.1",
             "multicast_port": 1234,
             "multicast_interface": "eth0",
             "latency": 300,
             "overhead_bandwidth": 5,
             "smoothing_latency_ms": 30,
             "encryption": "aes-128",
             "passphrase": "********", // Passphrase not included in GET response
             "qos": false,
             "rtp_encapsulation": false // Included here
          }
        },
        "10002": { ... }
      }
    }
    ```
-   **Error Response:** `500 Internal Server Error` if retrieval fails.

### 2. Get Stream Details/Statistics

-   **Endpoint:** `GET /api/streams/<stream_key>`
-   **Method:** `GET`
-   **Auth:** `X-API-Key` header required.
-   **URL Params:**
    -   `<stream_key>`: The listener port (listener mode) or target port (caller mode) of the stream.
-   **Success Response (200 OK):**
    Returns detailed statistics including SRT metrics (bitrate, RTT, loss, packets sent/received/lost/retransmitted etc.) as provided by `stream_manager.get_stream_statistics()`. The exact structure depends on the stats available from `srtsink`.
    ```json
    {
        "data": {
            "connection_status": "Connected",
            "connected_client": "192.168.1.50",
            "uptime": "6m 2s",
            "last_updated": 1712860022.123,
            "timestamp_api": 1712860023.456,
            "config": { ... full config, including rtp_encapsulation ... },
            "bitrate_mbps": 8.50,
            "rtt_ms": 45.5,
            "loss_rate": 0.01,
            "packets_sent_total": 123456,
            "packets_lost_total": 12,
            "packets_retransmitted_total": 15,
            "bytes_sent_total": 123456789,
            "packet_loss_percent": 0.01,
            "negotiated_latency_ms": 120,
            // ... many more potential SRT stats ...
        }
    }
    ```
-   **Error Responses:**
    -   `400 Bad Request`: Invalid stream key format.
    -   `404 Not Found`: Stream with the given key does not exist.
    -   `500 Internal Server Error`: Failed to retrieve statistics.

### 3. Get Debug Info

-   **Endpoint:** `GET /api/debug/<stream_key>`
-   **Method:** `GET`
-   **Auth:** `X-API-Key` header required.
-   **URL Params:**
    -   `<stream_key>`: The listener port (listener mode) or target port (caller mode) of the stream.
-   **Success Response (200 OK):**
    Returns a dictionary containing config, status, history, parsed stats, and raw stats string.
-   **Error Responses:**
    -   `400 Bad Request`: Invalid stream key format.
    -   `404 Not Found`: Stream with the given key does not exist.
    -   `500 Internal Server Error`: Failed to retrieve debug info.

### 4. Start a New Stream

-   **Endpoint:** `POST /api/streams`
-   **Method:** `POST`
-   **Auth:** `X-API-Key` header required.
-   **Request Body (JSON):**
    Requires a JSON object defining the stream configuration. Fields generally mirror the web forms:
    * `mode`: `"listener"` or `"caller"` (required).
    * `input_type`: `"multicast"`, `"file"`, `"colorbar_720p50"`, or `"colorbar_1080i25"` (required).
    * `latency`: Integer, 20-8000 (required).
    * `overhead_bandwidth`: Integer, 1-99 (required).
    * `smoothing_latency_ms`: Integer (e.g., 20, 30), defaults to 30 if omitted.
    * `encryption`: `"none"`, `"aes-128"`, `"aes-256"` (defaults to "none").
    * `passphrase`: String (10-79 chars), **required** if `encryption` is not `"none"`.
    * `qos`: Boolean (`true` or `false`), defaults to `false`.
    * **`rtp_encapsulation`**: Boolean (`true` or `false`), defaults to `false`. If `true`, encapsulates UDP or Colorbar input using `rtpmp2tpay pt=33 mtu=1316`. (Optional)
    * **If `mode` is "listener":**
        * `port`: Integer, 10001-10010 (required).
    * **If `mode` is "caller":**
        * `target_address`: String (required).
        * `target_port`: Integer, 1-65535 (required).
    * **If `input_type` is "multicast":**
        * `multicast_address`: String (required).
        * `multicast_port`: Integer, 1-65535 (required).
        * `multicast_interface`: String (optional, e.g., `"eth1"`, `""` for auto).
    * **If `input_type` is "file":**
        * `file_path`: String (filename within media folder, required).
    * **If `input_type` starts with "colorbar_":**
        * No extra fields needed besides `input_type`.
-   **Success Response (201 Created):**
    ```json
    {
      "message": "Listener stream started on port 10001.", // Or caller message
      "stream_key": 10001, // The key used for the stream
      "status": "starting"
    }
    ```
-   **Error Responses:**
    -   `400 Bad Request`: Invalid JSON, missing required fields, or validation failed (check `details` field).
    -   `415 Unsupported Media Type`: Request body was not JSON.
    -   `500 Internal Server Error`: Failed to start the stream process.
    -   `503 Service Unavailable`: Stream manager not ready.

### 5. Stop a Stream

-   **Endpoint:** `DELETE /api/streams/<stream_key>`
-   **Method:** `DELETE`
-   **Auth:** `X-API-Key` header required.
-   **URL Params:**
    -   `<stream_key>`: The listener port (listener mode) or target port (caller mode) of the stream to stop.
-   **Success Response (200 OK):**
    ```json
    {
      "message": "Stream 10001 stop initiated.",
      "status": "stopping"
    }
    ```
-   **Error Responses:**
    -   `400 Bad Request`: Invalid stream key format or other failure.
    -   `404 Not Found`: Stream with the given key does not exist.
    -   `500 Internal Server Error`: Failed to stop the stream process.
    -   `503 Service Unavailable`: Stream manager not ready.

### 6. Get System Status

-   **Endpoint:** `GET /api/system/status`
-   **Method:** `GET`
-   **Auth:** `X-API-Key` header required.
-   **Success Response (200 OK):** Returns system info dictionary (CPU, Mem, Disk, IP, etc.).
-   **Error Response:** `500`.

### Example `curl` Usage (Listener with Multicast & RTP Encapsulation):

*(Assumes Nginx Basic Auth is also configured)*

```bash
# Replace placeholders with actual values
API_KEY="YOUR_ACTUAL_API_KEY"
NGINX_USER="YOUR_NGINX_USERNAME"
NGINX_PASS="YOUR_NGINX_PASSWORD"
STREAMER_URL="http://your-streamer-address" # e.g., http://10.0.0.5 or http://streamer.example.com

curl -X POST \
     -u "${NGINX_USER}:${NGINX_PASS}" \
     -H "X-API-Key: ${API_KEY}" \
     -H "Content-Type: application/json" \
     -d '{
          "mode": "listener",
          "port": 10003,
          "input_type": "multicast",
          "multicast_address": "239.1.1.2",
          "multicast_port": 5000,
          "multicast_interface": "",
          "latency": 300,
          "overhead_bandwidth": 10,
          "smoothing_latency_ms": 30,
          "encryption": "none",
          "qos": false,
          "rtp_encapsulation": true
     }' \
     "${STREAMER_URL}/api/streams"

# Example to delete the stream later
# curl -X DELETE -u "${NGINX_USER}:${NGINX_PASS}" -H "X-API-Key: ${API_KEY}" "${STREAMER_URL}/api/streams/10003"
```

---

## SMPTE 2022-7 Pairs API (`/smpte2022_7/api/...`)

(Review and update API examples/descriptions, ensuring `localport` is not shown as a required input for caller mode, and stats responses are accurate)

---

## Configuration & Network Tuning Tips

-   **SRT Latency & Overhead:**
    -   Increased latency buffers for jitter and recovery; typical recommendation = 4×RTT or more, plus safety margin.
    -   Overhead % covers recovery bandwidth; Haivision suggests >25-30% in lossy environments.
-   **TSParse smoothing latency:**
    -   PCR smoothing (for file/multicast inputs): try 20-50ms. Not applicable to Colorbar source.
-   **QoS (DSCP):**
    -   Enable if your network honors DSCP tags.
-   **RTP Encapsulation:**
    -   Enable for UDP/Multicast/Colorbar inputs when testing compatibility with SMPTE 2022-7 receivers that expect RTP encapsulation. Adds `rtpmp2tpay pt=33 mtu=1316`.
-   **SMPTE 2022-7 Configuration:**
    -   Use identical SRT parameters for both legs except for network interfaces/targets
    -   Ensure sufficient network bandwidth for redundant streams
    -   Ensure destination ports are different if mirroring `localport` (though this is no longer default)
    -   Ensure unique Port+Interface combination if selecting specific interfaces for both legs
-   **Choose test mode carefully:**
    -   Use `iperf` mode and background job if internet UDP allowed and accurate tuning critical.
    -   Use `ping_only` in secure or restricted environments.
-   **Adjust Linux sysctl via `network-tuning.sh`:**
    -   Increase socket buffers, tune net.filter parameters, etc.

---

## License

MCR SRT Streamer is released under the <a href="https://opensource.org/licenses/BSD-2-Clause" target="_blank" rel="noopener noreferrer">BSD-2-Clause License</a>. See the `LICENSE` file.

---

## References

-   Haivision SRT Protocol Deployment Guide v1.5.x (included in `/docs/`)
-   [SRT Alliance](https://www.srtalliance.org/)
-   [SRT GitHub](https://github.com/Haivision/srt)
-   [GStreamer Documentation](https://gstreamer.freedesktop.org/documentation/)
-   [SMPTE 2022-7 Standard](https://www.smpte.org/)

