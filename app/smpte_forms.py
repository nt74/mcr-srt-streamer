# /opt/mcr-srt-streamer/app/smpte_forms.py

import os
import json
import re
import socket
from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    IntegerField,
    SelectField,
    BooleanField,
    HiddenField,
    PasswordField,
)
from wtforms.validators import (
    DataRequired,
    Length,
    NumberRange,
    Optional,
    Regexp,
    ValidationError,
)

try:
    from app.forms import PercentageInput
except ImportError:
    # Placeholder if PercentageInput is not available in app.forms:
    from wtforms.widgets import Input, html_params
    from markupsafe import Markup

    class PercentageInput(Input):
        def __call__(self, field, **kwargs):
            kwargs.setdefault("id", field.id)
            kwargs.setdefault("type", "number")
            value_str = field._value() if field._value() is not None else ""
            try:
                formatted_value = format(int(value_str), ".0f") if value_str else ""
            except (ValueError, TypeError):
                formatted_value = value_str
            return Markup(
                f'<div class="input-group"><input {html_params(name=field.name, value=formatted_value, **kwargs)}><span class="input-group-text">%</span></div>'
            )


from app.utils import get_network_interfaces
import logging

logger_forms = logging.getLogger(__name__)


# --- Helper to populate choices ---
def _populate_shared_choices(form):
    """Populates choices shared between forms (multicast, interfaces)."""
    interfaces_list, error_msg = get_network_interfaces()
    if error_msg:
        interfaces = []
        logger_forms.error(f"SMPTE Form: Error getting interfaces: {error_msg}")
    else:
        interfaces = interfaces_list or []
    # Store the list of actual interfaces for validation later
    form._available_interfaces = interfaces  # Store interface names
    interface_choices = [("", "-- Auto --")] + [(iface, iface) for iface in interfaces]
    try:
        if hasattr(form, "output_interface_1"):
            form.output_interface_1.choices = interface_choices
        if hasattr(form, "output_interface_2"):
            form.output_interface_2.choices = interface_choices
        if hasattr(form, "multicast_interface"):
            form.multicast_interface.choices = interface_choices
    except AttributeError as e:
        logger_forms.warning(f"Could not set interface choices on form fields: {e}")

    if hasattr(form, "multicast_channel"):
        try:
            from app.routes import load_iptv_channels

            channels = load_iptv_channels()
            mc_choices = [("", "-- Select Multicast Channel --")]
            if isinstance(channels, list):
                for channel in channels:
                    if (
                        isinstance(channel, dict)
                        and "name" in channel
                        and "address" in channel
                        and "port" in channel
                    ):
                        mc_choices.append(
                            (f"{channel['address']}:{channel['port']}", channel["name"])
                        )
            form.multicast_channel.choices = mc_choices
        except ImportError:
            logger_forms.warning("Could not import load_iptv_channels in smpte_forms.")
            form.multicast_channel.choices = [("", "-- Check Import/Utils --")]
        except Exception as e:
            logger_forms.error(
                f"Error populating multicast channels for SMPTE form: {e}"
            )
            form.multicast_channel.choices = [("", "-- Error Loading Channels --")]


# --- SMPTE Pair Form (Simplified + Smoothing + NIC Validation) ---
class SMPTEPairForm(FlaskForm):
    """Form for configuring one SMPTE 2022-7 stream pair."""

    # Field definitions remain the same as the previous version
    # --- Input Source ---
    input_type = SelectField(
        "Input Source Type",
        choices=[
            ("multicast", "Multicast UDP"),
            ("colorbar_720p50", "Colorbars 720p50"),
            ("colorbar_1080i25", "Colorbars 1080i25"),
        ],
        default="multicast",
        validators=[DataRequired()],
        render_kw={"class": "form-select", "aria-describedby": "smpteInputTypeHelp"},
    )
    multicast_channel = SelectField(
        "Multicast Channel (if input=Multicast)",
        choices=[("", "-- Select Multicast Channel --")],
        validators=[Optional()],
        render_kw={"class": "form-select", "aria-describedby": "smpteMulticastHelp"},
    )
    multicast_interface = SelectField(
        "Multicast Input Interface (if input=Multicast)",
        choices=[("", "-- Auto --")],
        validators=[Optional()],
        description="Network interface for receiving multicast ('Auto' = OS default).",
        render_kw={"class": "form-select"},
    )
    # --- Shared SRT Parameters ---
    ssrc = StringField(
        "Shared SSRC (Hex)",
        validators=[
            DataRequired(),
            Regexp(
                r"^[0-9a-fA-F]{8}$",
                message="Must be 8 hexadecimal characters (0-9, A-F).",
            ),
        ],
        default="ABBACAFE",
        render_kw={
            "placeholder": "e.g., ABBACAFE",
            "class": "form-control",
            "maxlength": "8",
        },
        description="Shared Synchronization Source Identifier (SSRC) for both RTP streams.",
    )
    latency = IntegerField(
        "SRT Latency (ms)",
        validators=[DataRequired(), NumberRange(min=20, max=8000)],
        default=300,
        render_kw={"class": "form-control", "min": "20", "max": "8000", "step": "1"},
        description="SRT latency buffer for both streams (ms).",
    )
    overhead_bandwidth = IntegerField(
        "Overhead Bandwidth (%)",
        validators=[DataRequired(), NumberRange(min=1, max=99)],
        default=2,
        widget=PercentageInput(),
        render_kw={"class": "form-control", "min": "1", "max": "99", "step": "1"},
        description="SRT overhead for packet recovery (%) for both streams.",
    )
    smoothing_latency_ms = IntegerField(
        "Smoothing Latency (ms)",
        validators=[DataRequired(), NumberRange(min=0, max=5000)],
        default=30,
        render_kw={"class": "form-control", "min": "0", "max": "5000", "step": "1"},
        description="tsparse smoothing latency (jitter buffer) in milliseconds. Applied before RTP encapsulation.",
    )
    encryption = SelectField(
        "Encryption",
        choices=[("none", "None"), ("aes-128", "AES-128"), ("aes-256", "AES-256")],
        default="none",
        render_kw={"class": "form-select", "id": "encryption_smpte"},
        description="SRT encryption type for both streams.",
    )
    passphrase = PasswordField(
        "Passphrase",
        validators=[Optional(), Length(min=10, max=79)],
        render_kw={
            "placeholder": "Required if encryption enabled (10-79 chars)",
            "class": "form-control",
        },
        description="SRT encryption passphrase for both streams (if enabled).",
    )
    qos = BooleanField(
        "Enable QoS",
        default=False,
        render_kw={"class": "form-check-input"},
        description="Enable Quality of Service flag (qos=true) for both SRT URIs.",
    )
    # --- Pair Leg 1 ---
    output_interface_1 = SelectField(
        "Leg 1: Output Interface",
        choices=[("", "-- Auto --")],
        validators=[Optional()],
        description="Network interface for SRT output (Listener bind IP or Caller adapter IP). 'Auto' uses 0.0.0.0 for Listener.",
        render_kw={"class": "form-select"},
    )
    port_1 = IntegerField(
        "Leg 1: SRT Port",
        validators=[DataRequired(), NumberRange(min=10000, max=65535)],
        description="Local port for Listener mode, Target port for Caller mode.",
        render_kw={
            "placeholder": "e.g., 10201",
            "class": "form-control",
            "min": "10000",
            "max": "65535",
        },
    )
    mode_1 = SelectField(
        "Leg 1: SRT Mode",
        choices=[("listener", "Listener"), ("caller", "Caller")],
        default="listener",
        validators=[DataRequired()],
        render_kw={"class": "form-select", "id": "mode_1"},
    )
    target_address_1 = StringField(
        "Leg 1: Target Host/IP (Caller Mode)",
        validators=[Optional(), Length(max=255)],
        render_kw={
            "placeholder": "Required if Mode is Caller",
            "class": "form-control",
        },
    )
    # --- Pair Leg 2 ---
    output_interface_2 = SelectField(
        "Leg 2: Output Interface",
        choices=[("", "-- Auto --")],
        validators=[Optional()],
        description="Network interface for SRT output (Listener bind IP or Caller adapter IP). 'Auto' uses 0.0.0.0 for Listener.",
        render_kw={"class": "form-select"},
    )
    port_2 = IntegerField(
        "Leg 2: SRT Port",
        validators=[DataRequired(), NumberRange(min=10000, max=65535)],
        description="Local port for Listener mode, Target port for Caller mode.",
        render_kw={
            "placeholder": "e.g., 10202",
            "class": "form-control",
            "min": "10000",
            "max": "65535",
        },
    )
    mode_2 = SelectField(
        "Leg 2: SRT Mode",
        choices=[("listener", "Listener"), ("caller", "Caller")],
        default="listener",
        validators=[DataRequired()],
        render_kw={"class": "form-select", "id": "mode_2"},
    )
    target_address_2 = StringField(
        "Leg 2: Target Host/IP (Caller Mode)",
        validators=[Optional(), Length(max=255)],
        render_kw={
            "placeholder": "Required if Mode is Caller",
            "class": "form-control",
        },
    )
    pair_id = HiddenField()

    # --- Custom Validation (Adds NIC Check) ---
    def validate(self, extra_validators=None):
        # Run initial validators from WTForms
        initial_validation = super(SMPTEPairForm, self).validate(extra_validators)
        if not initial_validation:
            return False

        # Assume _populate_shared_choices stored the list
        available_interfaces = getattr(self, "_available_interfaces", [])
        multiple_nics_available = len(available_interfaces) > 1

        # Input type validation
        input_type_valid = True
        if self.input_type.data == "multicast":
            if not self.multicast_channel.data:
                self.multicast_channel.errors.append(
                    "Multicast channel selection is required."
                )
                input_type_valid = False
            if multiple_nics_available and not self.multicast_interface.data:
                self.multicast_interface.errors.append(
                    "Please select a specific input interface when multiple NICs are available."
                )
                input_type_valid = False
            elif self.multicast_interface.data and not re.match(
                r"^[a-zA-Z0-9\.\-\_]+$", self.multicast_interface.data
            ):
                self.multicast_interface.errors.append(
                    "Invalid characters in multicast interface name."
                )
                input_type_valid = False

        # Encryption validation
        encryption_valid = True
        if self.encryption.data != "none":
            if not self.passphrase.data:
                self.passphrase.errors.append(
                    "Passphrase is required when encryption is enabled."
                )
                encryption_valid = False
            elif not (10 <= len(self.passphrase.data) <= 79):
                self.passphrase.errors.append(
                    "Passphrase must be 10-79 characters long."
                )
                encryption_valid = False

        # Port validation
        ports_valid = True
        if (
            self.port_1.data is not None
            and self.port_2.data is not None
            and self.port_1.data == self.port_2.data
        ):
            self.port_2.errors.append("Leg 1 and Leg 2 ports must be different.")
            ports_valid = False

        # Caller mode validation
        caller_1_valid = True
        if self.mode_1.data == "caller":
            if not self.target_address_1.data:
                self.target_address_1.errors.append(
                    "Target Host/IP is required for Caller mode."
                )
                caller_1_valid = False
            elif not re.match(r"^[a-zA-Z0-9\.\-\_]+$", self.target_address_1.data):
                self.target_address_1.errors.append(
                    "Invalid target address format for Leg 1."
                )
                caller_1_valid = False
            if self.port_1.data is None:
                self.port_1.errors.append(
                    "SRT Port is required for Caller mode target."
                )
                caller_1_valid = False

        caller_2_valid = True
        if self.mode_2.data == "caller":
            if not self.target_address_2.data:
                self.target_address_2.errors.append(
                    "Target Host/IP is required for Caller mode."
                )
                caller_2_valid = False
            elif not re.match(r"^[a-zA-Z0-9\.\-\_]+$", self.target_address_2.data):
                self.target_address_2.errors.append(
                    "Invalid target address format for Leg 2."
                )
                caller_2_valid = False
            if self.port_2.data is None:
                self.port_2.errors.append(
                    "SRT Port is required for Caller mode target."
                )
                caller_2_valid = False

        output_nic_valid = True
        if multiple_nics_available:
            if not self.output_interface_1.data:  # Check if 'Auto' ('') was selected
                self.output_interface_1.errors.append(
                    "Please select a specific output interface when multiple NICs are available."
                )
                output_nic_valid = False
            if not self.output_interface_2.data:  # Check if 'Auto' ('') was selected
                self.output_interface_2.errors.append(
                    "Please select a specific output interface when multiple NICs are available."
                )
                output_nic_valid = False

        # Return True only if all checks pass
        return (
            input_type_valid
            and encryption_valid
            and ports_valid
            and caller_1_valid
            and caller_2_valid
            and output_nic_valid
        )
