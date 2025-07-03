# MCR SRT Streamer

## Description

`mcr-srt-streamer` is a tool for testing SRT (Secure Reliable Transport) listeners and callers, optimized for professional broadcast workflows (e.g., DVB transport streams). Built with Python, Flask, GStreamer, and Bootstrap 5 (with SVT color theme), it provides a web interface to manage and monitor multiple SRT streams originating from local Transport Stream (`.ts`) files, UDP multicast inputs, internally generated test patterns, or SMPTE 2022-7 redundant streams.

The application configures GStreamer pipelines (`filesrc/udpsrc/videotestsrc ! ... ! srtsink`) for robust TS-over-SRT streaming and includes integrated network testing tools (`ping`, optionally `iperf3`) to recommend optimal SRT parameters (Latency, Overhead) derived from the Haivision SRT Deployment Guide. Recent improvements include fixes for SMPTE 2022-7 caller mode statistics and source binding, enhanced dashboard statistics display, improved form validation, and making passphrase fields visible for easier use. The interface is implemented with Bootstrap 5, jQuery, and Chart.js, designed for air-gapped or firewall-restricted operation with no external CDN dependencies.

## Screenshots

A showcase of the `mcr-srt-streamer` user interface.

### Main Dashboard
The main dashboard provides an at-a-glance view of all active SRT streams.
<p align="center">
  <img src="./images/main-dashboard.png" alt="Main Dashboard of MCR SRT Streamer" width="85%">
</p>

### Stream Details & Monitoring
Each stream has a detailed view with real-time charts for bitrate, RTT, and packet loss, along with detailed SRT statistics.
<p align="center">
  <img src="./images/stream-details-page.png" alt="Stream Details Page with Monitoring Graphs" width="85%">
</p>

### SMPTE 2022-7 Seamless Protection
The application has dedicated support for configuring and monitoring SMPTE 2022-7 redundant stream pairs.
<p align="center">
  <img src="./images/smpte-2022-7-config.png" alt="SMPTE 2022-7 Configuration Page" width="48%">
  <img src="./images/smpte-2022-7-stream-details-page.png" alt="SMPTE 2022-7 Details Page" width="48%">
</p>

### Utility Features
Includes a built-in network testing tool to recommend SRT parameters and a media browser for selecting local `.ts` files.
<p align="center">
  <img src="./images/network-test-modal.png" alt="Network Test Modal" width="48%">
  <img src="./images/media-browser.png" alt="Media Browser Modal" width="48%">
</p>

-----

## Features

### Streaming

  - **Multi-Stream Hosting:** Run multiple concurrent SRT streams (default simultaneous streams limit configurable).
  - **Listener and Caller Modes:** Launch streams as SRT Listener (server) or Caller (client) with easy web configuration.
  - **Multiple Input Sources:**
      - **File:** Stream local `.ts` files from the `media/` directory.
      - **UDP Multicast:** Ingest streams from IPTV multicast sources declared in `app/data/iptv_channels.json`, with selectable network interface (`Auto` chooses OS default).
      - **Colorbar Generator:** Stream internally generated 720p50 or 1080i25 PAL color bars (SMPTE pattern) with a 1000Hz sine audio tone, suitable for testing SRT links without an external source.
  - **SMPTE 2022-7 Seamless Protection Output:** Create redundant RTP streams sent via SRT with identical SSRC and timestamps for seamless protection (see dedicated section below for details).
  - **GStreamer Pipeline Details:**
      - Inputs from local files or multicast via `filesrc` or `udpsrc`. For Colorbars, `videotestsrc` and `audiotestsrc` are used, outputting to an internal UDP multicast relay.
      - Transport Stream parsing via `tsparse` (for file/multicast/colorbar inputs before SRT sink) with:
          - timestamps enabled (`set-timestamps=true`)
          - DVB alignment (`alignment=7`)
          - configurable smoothing latency (to reduce PCR jitter, mainly for file/multicast)
      - **Colorbar Generation:** Uses `videotestsrc` (pattern smpte-rp-219) and `audiotestsrc` (sine wave 1000Hz) for test signals. Audio is encoded to AAC, prioritizing `fdkaacenc` if available on the system, otherwise falling back to `voaacenc`. Video is encoded using `x264enc`. The generated streams are multiplexed into an MPEG-TS stream before being sent via SRT (using an internal UDP multicast relay).
      - SRT transmission via `srtsink` with:
          - adjustable latency (20-8000ms)
          - bandwidth overhead (1-99%)
          - optional encryption: AES-128 or AES-256 (10-80 character **visible** passphrase field)
          - **Hardcoded DVB-Optimized Parameters:** Includes `tlpktdrop=true` and conservative buffer sizes (`rcvbuf`/`sndbuf`/`fc` defaulting to 8MB/4096pkts) applied directly in the URI builder.
          - quality-of-service DSCP flag (`qos=true|false`)
          - **Optional RTP Encapsulation:** Apply `rtpmp2tpay pt=33 mtu=1316` for UDP/Colorbar inputs, useful for SMPTE 2022-7 testing (selectable in UI/API). Standard SMPTE 2022-7 streams always use RTP encapsulation.
  - **Refactored Logic:** Centralized configuration validation shared between Web UI and API routes. Robust statistics parsing handles both Listener and Caller modes correctly.
  - **Detailed DVB Compliance:** Pipeline settings (`tsparse alignment=7`, `rtpmp2tpay mtu=1316`) aimed at broadcast/DVB workflows.

### Network Testing & Recommendations

  - **Configurable Network Test Mechanisms:** Controlled via `NETWORK_TEST_MECHANISM` env var (`ping_only` or `iperf`).
      - **`ping_only` mode (default):** Uses ICMP `ping` to assess RTT. Estimates loss for recommendations. Useful in restricted environments.
      - **`iperf` mode:** Requires `iperf3` binary and optional background server check service. Performs `ping` + UDP `iperf3` tests for measured RTT, bandwidth, loss, jitter. Provides more accurate recommendations.
      - **In Both Modes:** GeoIP used for server selection. Tests: Closest, Regional, Manual. Results auto-fill Latency/Overhead fields.
  - **System Info Dashboard:** Host stats (CPU, RAM, disk, IP, uptime, user).
  - **Stream Status:** Live updates with:
      - **Improved Dashboard Display:** Key stats (Bitrate, RTT, Loss) shown directly on dashboard cards for active streams (when status is "Running" or "Connected"). Consistent color coding for status indicators (Green/Checkmark for Running/Connected).
      - Real-time charts for bitrate, RTT, loss (on detail page).
      - SRT packet statistics, counters, and **Negotiated Latency** (on detail page).
      - Per-stream details page with advanced debug data (client IPs, connection state, raw stats string).
  - **Media Browser & Info:**
      - AJAX modal file selector for `.ts` media in `media/`.
      - File analysis via `mediainfo` (requires `mediainfo` binary).
  - **Security:**
      - NGINX frontend with optional Basic Auth.
      - CSRF protection via Flask-WTF.
      - Requires strong `SECRET_KEY` (env var).
      - REST API Authentication via `X-API-Key` header (env var `API_KEY`).
  - **Designed for Air-Gapped Deployments:**
      - No external CDNs. All Bootstrap, jQuery, Chart.js & Font Awesome assets are local.
      - JavaScript separated into external files.

-----

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

-----

## Technology Stack

  - **Backend:** Python 3 with Flask, Flask-WTF, Gunicorn with Gevent, GStreamer via PyGObject, requests, psutil.
  - **Frontend:** Bootstrap 5, jQuery, Chart.js, Font Awesome (all local), Jinja2 templates, custom styles.
  - **Supporting Tools:** `curl`, `ping`, `dig`, `ffmpeg`, `mediainfo`, **optionally**: `iperf3`, `systemd`, `nginx`.

-----

## Architecture Overview

### Backend (`app/` directory)

  - `stream_manager.py`: Manages standard SRT streams (listener/caller) and colorbar generators.
  - `smpte_manager.py`: Manages SMPTE 2022-7 redundant stream pairs.
  - `network_test.py`: Manages ping/iperf3 tests.
  - `test_iperf_servers.py`: Background script for iperf server validation.
  - `utils.py`: System info, network interfaces, GeoIP functions.
  - `forms.py`: WTForms for standard streams.
  - `smpte_forms.py`: WTForms for SMPTE 2022-7 configuration.
  - `routes.py`: Flask routes for main web UI and standard stream AJAX/debug endpoints.
  - `api_routes.py`: Flask Blueprint routes for the REST API (standard streams).
  - `smpte_routes.py`: Flask Blueprint routes for SMPTE 2022-7 UI and API.
  - `auth.py`: Authentication helpers (API Key / Basic Auth potentially).
  - `ts_analyzer.py`: *(Placeholder/unused)*
  - `data/`: Config files (`iptv_channels.json`), server lists, caches.
  - `static/`: Local CSS, JS (including `app.js`, `forms.js`, `dashboard.js`, `caller.js`, `stream_details.js`, `network_test.js`, `smpte2022_7.js`, `smpte_details.js`), fonts, images.
  - `templates/`: HTML templates (`index.html`, `caller.html`, `stream_details.html`, `network_test.html`, `media_info.html`, `smpte2022_7.html`, `smpte_details.html`).

**Logs**: `/var/log/srt-streamer/srt_streamer.log` (default)
**Data:** `app/data/`

### Frontend (via recommended NGINX proxy)

  - Serves static assets from `/opt/mcr-srt-streamer/app/static/`.
  - Protects with optional Basic Auth.
  - Reverse proxies to Python Gunicorn server (default port 5000).
  - API endpoints (`/api/`, `/smpte2022_7/api/`) can be configured without Basic Auth when using API keys.

### System Services (default install)

  - **`network-tuning.service`**: Optional OS network tuning.
  - **`mcr-srt-streamer.service`**: Runs the Gunicorn Flask server.
  - **`iperf-server-check.service` & `.timer`**: Optional background UDP server check for `iperf` mode.

-----

## System Requirements

  - **OS:**
    Debian / Ubuntu, or RHEL 9+ / Rocky Linux 9+ (other distros with recent GStreamer/Python should work with adjustments).
  - **RAM:**
    Minimal. Approximately **20-30 MB / active stream**. Plus resources for background generator pipelines if using Colorbars.
  - **CPU:**
    Minimal, but encoding for Colorbars will consume some CPU resources.
  - **GPU:**
    Not required.
  - **Network:**
    Sufficient stable bandwidth plus overhead (\> stream bitrate × (1 + overhead%)). Network tuning is recommended.
  - **Dependencies:**
      - Python 3 + pip & venv
      - GStreamer 1.0 with good, bad, ugly, libav, gst-python bindings (ensure plugins for H.264 (`x264enc`) and AAC (`fdkaacenc`, `voaacenc`) encoding are available).
      - `ping` (iputils), `curl`, `dig` (dnsutils/bind-utils), `mediainfo`, and `ffmpeg`
      - **Optional:** `iperf3` (only if full UDP tests needed)

-----

## Installation Guide

Assuming installation under `/opt/mcr-srt-streamer`. Adapt as needed.

### 1\. Obtain the source code

```bash
sudo git clone https://your-github-repo/mcr-srt-streamer.git /opt/mcr-srt-streamer
cd /opt/mcr-srt-streamer
```

### 2\. System Packages

#### Debian / Ubuntu

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

#### RHEL 9+ / Rocky Linux 9

For RHEL-based systems, the recommended installation method is to use DNF to install system-level dependencies and available Python packages, followed by `pip` to install the remaining Python requirements system-wide. This avoids the use of a virtual environment (`venv`).

A more advanced method of building GStreamer from source is also provided for users who require the latest versions.

##### Method 1: DNF and Pip Installation (Recommended)

1.  **Enable Repositories:**

    ```bash
    sudo dnf install -y epel-release
    sudo dnf install -y https://download1.rpmfusion.org/free/el/rpmfusion-free-release-$(rpm -E %rhel).noarch.rpm https://download1.rpmfusion.org/nonfree/el/rpmfusion-nonfree-release-$(rpm -E %rhel).noarch.rpm
    sudo dnf config-manager --set-enabled crb
    ```

2.  **Install System Dependencies and Python Packages via DNF:**
    Install core dependencies, GStreamer plugins from the repositories, and all available Python modules.

    ```bash
    sudo dnf install -y \
     python3 python3-pip python3-gobject gobject-introspection-devel cairo-gobject-devel \
     python3-devel pkgconf-pkg-config gcc gcc-c++ make cmake meson ninja-build git \
     gstreamer1 gstreamer1-plugins-base gstreamer1-plugins-good \
     gstreamer1-plugins-bad-free gstreamer1-plugins-ugly-free gstreamer1-libav \
     gstreamer1-plugin-x264 gstreamer1-plugin-openh264 \
     nginx curl iperf3 iputils bind-utils ffmpeg mediainfo httpd-tools \
     [cite_start]python3-chardet [cite: 411] [cite_start]python3-click [cite: 412] [cite_start]python3-flask [cite: 417] [cite_start]python3-flask-wtf [cite: 417] \
     [cite_start]python3-idna [cite: 423] [cite_start]python3-itsdangerous [cite: 424] [cite_start]python3-jinja2 [cite: 427] [cite_start]python3-markupsafe [cite: 428] \
     [cite_start]python3-psutil [cite: 431] [cite_start]python3-cairo python3-pytz [cite: 433] python3-requests \
     [cite_start]python3-six [cite: 437] [cite_start]python3-urllib3 [cite: 438] [cite_start]python3-werkzeug [cite: 440] [cite_start]python3-wtforms [cite: 442] \
     [cite_start]python3-gunicorn [cite: 422] [cite_start]python3-gevent [cite: 418]
    ```

    *Note: The `gstreamer1-plugins-bad-free` package in some repos may not include `srtsink`. If it's missing, you must use Method 2.*

3.  **Install Remaining Python Packages via Pip:**
    Use `pip` to install the remaining application-specific Python packages that are not available in the DNF repositories.

    ```bash
    cd /opt/mcr-srt-streamer
    sudo pip3 install -r requirements.txt
    ```

##### Method 2: Build from Source (Advanced)

This method ensures you have the latest versions of SRT and GStreamer with all necessary plugins.

1.  **Install Build Dependencies:**
    Install the core development tools and libraries needed for compilation.

    ```bash
    sudo dnf groupinstall -y "Development Tools"
    sudo dnf install -y \
        python3-devel python3-pip python3-gobject gobject-introspection-devel cairo-gobject-devel \
        pkgconf-pkg-config cmake meson ninja-build git openssl-devel \
        libtool automake autoconf yasm nasm \
        nginx curl iperf3 iputils bind-utils ffmpeg mediainfo httpd-tools
    ```

2.  **Build and Install `srt` library:**

    ```bash
    cd /usr/local/src
    sudo git clone https://github.com/Haivision/srt.git
    cd srt
    sudo ./configure --prefix=/usr
    sudo make -j$(nproc)
    sudo make install
    ```

3.  **Build and Install `x264` library:**

    ```bash
    cd /usr/local/src
    sudo git clone https://code.videolan.org/videolan/x264.git
    cd x264
    sudo ./configure --prefix=/usr --libdir=/usr/lib64 --enable-shared --disable-static
    sudo make -j$(nproc)
    sudo make install
    ```

4.  **Build and Install `GStreamer` and Plugins:**
    This process involves building several modules in order. After each `make install`, run `ldconfig` to update the library cache.

    ```bash
    # Set PKG_CONFIG_PATH for the build process
    export PKG_CONFIG_PATH=/usr/lib64/pkgconfig:/usr/share/pkgconfig

    # GStreamer Core (installs all modules like ugly, bad etc)
    cd /usr/local/src
    sudo git clone https://gitlab.freedesktop.org/gstreamer/gstreamer.git
    cd gstreamer
    sudo meson build --prefix=/usr --libdir=/usr/lib64
    sudo ninja -C build
    sudo ninja -C build install
    sudo ldconfig
    ```

### 3\. Python Environment

  - **For Debian/Ubuntu (venv recommended):**
    A virtual environment is recommended to isolate dependencies.
    ```bash
    sudo python3 -m venv /opt/venv
    source /opt/venv/bin/activate
    cd /opt/mcr-srt-streamer
    pip install -r requirements.txt
    deactivate
    ```
  - **For RHEL 9+ / Rocky Linux 9:**
    The Python packages were installed system-wide in the previous steps, so no separate environment setup is needed.

### 4\. Initial Configuration

  - **Media Content:**
    ```bash
    sudo mkdir -p /opt/mcr-srt-streamer/media
    sudo chown -R root:root /opt/mcr-srt-streamer/media
    # Copy your .ts files inside
    ```
  - **Log & Data Directories:**
    ```bash
    sudo mkdir -p /var/log/srt-streamer /opt/mcr-srt-streamer/app/data
    sudo touch /opt/mcr-srt-streamer/app/data/external_ip_cache.json
    sudo touch /opt/mcr-srt-streamer/app/data/iperf3_export_servers.json
    sudo touch /opt/mcr-srt-streamer/app/data/iptv_channels.json
    sudo chown -R root:root /var/log/srt-streamer /opt/mcr-srt-streamer/app/data
    ```
  - **Flask Secret Key & API Key:**
    Generate strong keys and save them for the systemd service file.
    ```bash
    openssl rand -hex 32
    openssl rand -hex 32
    ```

### 5\. NGINX Reverse Proxy

Configure a server block (e.g., `/etc/nginx/conf.d/mcr-srt-streamer.conf`). This example includes WebSocket support and optional Basic Auth.

```nginx
server {
    listen 80;
    server_name _;

    access_log /var/log/nginx/srt-streamer-access.log;
    error_log /var/log/nginx/srt-streamer-error.log;

    location / {
        # Optional: Basic Authentication for Web UI
        # auth_basic "Restricted Access";
        # auth_basic_user_file /etc/nginx/auth/htpasswd;

        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # API endpoints without authentication (if using API keys)
    location ~ ^/(api|smpte2022_7/api)/ {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

*To enable Basic Auth, uncomment the `auth_basic` lines and create the password file:*

```bash
# sudo mkdir -p /etc/nginx/auth
# sudo htpasswd -c /etc/nginx/auth/htpasswd your_username
```

*Then test and reload NGINX:*

```bash
sudo nginx -t && sudo systemctl reload nginx
```

### 6\. Systemd Service

Create the service file at `/etc/systemd/system/mcr-srt-streamer.service`.

```ini
[Unit]
Description=MCR SRT Streamer
After=network.target network-tuning.service nginx.service
Wants=network-tuning.service

[Service]
Type=simple
WorkingDirectory=/opt/mcr-srt-streamer
User=root   # or nginx
Group=root  # or nginx

# === CRITICAL: Set these environment variables ===
Environment="SECRET_KEY=PASTE_YOUR_GENERATED_SECRET_KEY"
Environment="API_KEY=PASTE_YOUR_GENERATED_API_KEY"
# ================================================

Environment="THREADS=8"
Environment="MEDIA_FOLDER=/opt/mcr-srt-streamer/media"
Environment="FLASK_ENV=production"
Environment="NETWORK_TEST_MECHANISM=ping_only"

# Use --workers 1 to prevent issues with GLib loops in a multi-process environment.
# Use --worker-class gevent for WebSocket/async support.
# Use a longer timeout to prevent the master from killing the worker during startup.
# The path to gunicorn might be different; find it with 'which gunicorn'.
# For Debian/Ubuntu with venv:
# ExecStart=/opt/venv/bin/gunicorn --workers 1 --worker-class gevent --bind 127.0.0.1:5000 --timeout 90 --log-level=info wsgi:app
# For RHEL/Rocky Linux (system install):
ExecStart=/usr/bin/gunicorn --workers 1 --worker-class gevent --bind 127.0.0.1:5000 --timeout 90 --log-level=info wsgi:app
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

*Note: I have adjusted the `ExecStart` line to show examples for both Debian (with `venv`) and Rocky Linux (system path). You will need to uncomment the correct one for your OS.*

Reload the daemon and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mcr-srt-streamer
```

### 7\. Note on Professional Use (Genlock)

For professional broadcast environments, feeding the input of this streamer from a source that is genlocked (or PTP-locked) is highly recommended. While the streamer attempts to smooth PCR jitter from file or multicast sources, a stable input signal is the best way to ensure a stable, compliant output for professional receivers.
