#!/bin/bash
# /opt/srt-streamer-enhanced/network-tuning.sh
# Apply Network Settings for SRT Streamer Enhanced

# --- BEGIN ADDED CODE ---
# Check if sysctl command exists
if ! command -v sysctl &> /dev/null
then
    echo "ERROR: sysctl command not found. Cannot apply network tuning." | systemd-cat -p err -t network-tuning
    exit 1 # Exit if sysctl is missing
fi
# --- END ADDED CODE ---

echo "Applying SRT/DVB network optimizations..." | systemd-cat -p info -t network-tuning

# Function to apply sysctl setting and log
apply_sysctl() {
    local key="$1"
    local value="$2"
    if sysctl -w "${key}=${value}" &>/dev/null; then
        echo "✓ Set ${key} to ${value}" | systemd-cat -p info -t network-tuning
    else
        # Check if the key exists at all
        if sysctl -n "${key}" &>/dev/null; then
             echo "WARN: Failed to set ${key} to ${value}, but key exists. Check permissions or value." | systemd-cat -p warning -t network-tuning
        else
             echo "- Skip ${key} (Not available in this kernel/environment)" | systemd-cat -p notice -t network-tuning
        fi
    fi
}

# Apply settings using the function
apply_sysctl net.core.rmem_max 26214400
apply_sysctl net.core.wmem_max 26214400
apply_sysctl net.core.rmem_default 8388608
apply_sysctl net.core.wmem_default 8388608
apply_sysctl net.ipv4.udp_rmem_min 8192
apply_sysctl net.ipv4.udp_wmem_min 8192
apply_sysctl net.ipv4.tcp_window_scaling 1
apply_sysctl net.ipv4.tcp_timestamps 1
apply_sysctl net.ipv4.tcp_sack 1
apply_sysctl net.ipv4.tcp_fastopen 3
apply_sysctl vm.swappiness 10

# Example: Add a small delay if needed for settings to fully apply (usually not necessary)
# sleep 1

echo "Network tuning script finished." | systemd-cat -p info -t network-tuning

exit 0
