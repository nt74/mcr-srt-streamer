# /opt/mcr-srt-streamer/app/forms.py

from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    IntegerField,
    SelectField,
    RadioField,  # Kept for NetworkTestForm
    PasswordField,  # Kept in case used elsewhere
    BooleanField,
    FileField,  # Kept for MediaUploadForm
)
from wtforms.validators import (
    DataRequired,
    Length,
    NumberRange,
    Optional,
    ValidationError,
    InputRequired,  # Needed for conditional validation
)
from wtforms.widgets import html_params, Input
from markupsafe import Markup
from flask_wtf.file import FileAllowed
import re  # Import re for validation if needed


# --- Custom Widget for Percentage Input ---
class PercentageInput(Input):
    """
    Custom input widget that adds a percentage sign after the input field
    """

    def __call__(self, field, **kwargs):
        kwargs.setdefault("id", field.id)
        kwargs.setdefault("type", "number")
        if "required" not in kwargs and "required" in getattr(field, "flags", []):
            kwargs["required"] = True
        value_str = field._value()
        if value_str is None or value_str == "":
            value_str = ""
        else:
            try:
                value_str = (
                    format(field._value(), ".0f")
                    if isinstance(field._value(), (int, float))
                    else field._value()
                )
            except (ValueError, TypeError):
                value_str = field._value()
        return Markup(
            '<div class="input-group"><input %s><span class="input-group-text">%%</span></div>'
            % html_params(name=field.name, value=value_str, **kwargs)
        )


# --- StreamForm (for Listener) ---
class StreamForm(FlaskForm):
    """
    Form for configuring and starting SRT streams (Listener mode).
    Includes input type, multicast interface, and tsparse smoothing selection.
    """

    input_type = SelectField(
        "Input Source Type",
        choices=[
            ("multicast", "Multicast UDP"),
            ("file", "File"),
            ("colorbar_720p50", "Colorbars 720p50"),
            ("colorbar_1080i25", "Colorbars 1080i25"),
        ],
        default="multicast",
        validators=[DataRequired()],
        render_kw={"class": "form-select", "aria-describedby": "inputTypeHelp"},
    )

    # --- Conditional Inputs ---
    file_path = StringField(
        "File Path",
        validators=[Optional()],
        render_kw={
            "placeholder": "Select media file (if Input Type is File)",
            "class": "form-control",
            "aria-describedby": "fileHelp",
        },
    )
    multicast_channel = SelectField(
        "Multicast Channel",
        choices=[("", "-- Select Multicast Channel --")],  # Populated by route
        validators=[Optional()],
        render_kw={"class": "form-select", "aria-describedby": "multicastHelp"},
    )
    multicast_interface = SelectField(
        "Multicast Interface",
        choices=[("", "-- Auto --")],  # Populated by route, '' = Auto/Default
        validators=[Optional()],  # Optional for now, routes.py can handle default if ''
        render_kw={
            "class": "form-select",
            "aria-describedby": "multicastInterfaceHelp",
        },
        description="Network interface for multicast input ('Auto' = OS default).",
    )
    # --- End Conditional Inputs ---

    port = SelectField(
        "Listener Port",
        choices=[(str(port), str(port)) for port in range(10001, 10011)],
        default="10001",
        validators=[DataRequired()],
        render_kw={"class": "form-select", "aria-describedby": "portHelp"},
    )
    smoothing_latency_ms = SelectField(
        "Smoothing Latency",
        choices=[("20", "20 ms"), ("30", "30 ms (Recommended)")],
        default="30",
        validators=[DataRequired()],
        render_kw={"class": "form-select", "aria-describedby": "smoothingHelp"},
        description="Smoothing latency (PCR stabilization buffer).",
    )
    latency = IntegerField(
        "SRT Latency (ms)",
        validators=[DataRequired(), NumberRange(min=20, max=8000)],
        default=300,
        render_kw={"class": "form-control", "min": "20", "max": "8000", "step": "1"},
    )
    overhead_bandwidth = IntegerField(
        "Overhead Bandwidth",
        validators=[DataRequired(), NumberRange(min=1, max=99)],
        default=2,
        widget=PercentageInput(),
        render_kw={"class": "form-control", "min": "1", "max": "99", "step": "1"},
        description="SRT overhead for packet recovery (%). Range: 1-99%. Default: 2%.",
    )
    encryption = SelectField(
        "Encryption",
        choices=[("none", "None"), ("aes-128", "AES-128"), ("aes-256", "AES-256")],
        default="none",
        render_kw={"class": "form-select"},
    )
    passphrase = StringField(
        "Passphrase",
        validators=[Optional(), Length(min=10, max=79)],
        render_kw={
            "placeholder": "Required if encryption enabled (10-79 chars)",
            "class": "form-control",
        },
    )
    rtp_encapsulation = BooleanField(
        "RTP Encapsulation (SMPTE 2022-7)",
        default=False,
        render_kw={"class": "form-check-input"},
        description="Encapsulate UDP input into RTP (mtu=1316). Only for UDP/Multicast inputs.",
    )
    qos = BooleanField(
        "Enable QoS",
        default=False,
        render_kw={"class": "form-check-input"},
        description="Enable Quality of Service flag (qos=true) for SRT URI",
    )

    def validate(self, extra_validators=None):
        initial_validation = super(StreamForm, self).validate(extra_validators)
        if not initial_validation:
            return False  # Basic validation failed

        input_type_valid = True
        input_type_value = self.input_type.data
        if input_type_value == "file":
            if not self.file_path.data:
                self.file_path.errors.append("Media file path is required.")
                input_type_valid = False
        elif input_type_value == "multicast":
            if not self.multicast_channel.data:
                self.multicast_channel.errors.append(
                    "A multicast channel must be selected."
                )
                input_type_valid = False
        elif input_type_value.startswith("colorbar_"):
            pass  # No specific validation needed for file/multicast fields here

        encryption_valid = True
        if self.encryption.data != "none":
            if not self.passphrase.data:
                self.passphrase.errors.append("Passphrase is required.")
                encryption_valid = False
            elif not (10 <= len(self.passphrase.data) <= 79):
                self.passphrase.errors.append("Passphrase must be 10-79 characters.")
                encryption_valid = False

        rtp_valid = True
        if self.rtp_encapsulation.data and input_type_value not in ["multicast", "colorbar_720p50", "colorbar_1080i25"]:
             self.rtp_encapsulation.errors.append("RTP encapsulation only supported for Multicast or Colorbar inputs.")
             rtp_valid = False

        return input_type_valid and encryption_valid and rtp_valid


# --- CallerForm ---
class CallerForm(FlaskForm):
    """
    Form for configuring and starting SRT streams (Caller mode).
    Includes input type, multicast interface, and tsparse smoothing selection.
    """

    input_type = SelectField(
        "Input Source Type",
        choices=[
            ("multicast", "Multicast UDP"),
            ("file", "File"),
            ("colorbar_720p50", "Colorbars 720p50"),
            ("colorbar_1080i25", "Colorbars 1080i25"),
        ],
        default="multicast",
        validators=[DataRequired()],
        render_kw={"class": "form-select", "aria-describedby": "inputTypeHelpCaller"},
    )

    # --- Conditional Inputs ---
    file_path = StringField(
        "File Path",
        validators=[Optional()],
        render_kw={"placeholder": "Select media file", "class": "form-control"},
    )
    multicast_channel = SelectField(
        "Multicast Channel",
        choices=[("", "-- Select Multicast Channel --")],
        validators=[Optional()],
        render_kw={"class": "form-select"},
    )
    multicast_interface = SelectField(
        "Multicast Interface",
        choices=[("", "-- Auto --")],  # Populated by route, '' = Auto/Default
        validators=[Optional()],
        render_kw={
            "class": "form-select",
            "aria-describedby": "multicastInterfaceHelpCaller",
        },
        description="Select network interface for receiving multicast. 'Auto' uses OS default.",
    )
    # --- End Conditional Inputs ---

    target_address = StringField(
        "Target Host/IP",
        validators=[DataRequired(), Length(max=255)],
        render_kw={"placeholder": "e.g., 192.168.1.100", "class": "form-control"},
    )
    target_port = IntegerField(
        "Target Port",
        validators=[DataRequired(), NumberRange(min=1, max=65535)],
        default=10001,
        render_kw={"class": "form-control", "min": "1", "max": "65535"},
    )

    smoothing_latency_ms = SelectField(
        "Smoothing Latency",
        choices=[("20", "20 ms"), ("30", "30 ms (Recommended)")],
        default="30",
        validators=[DataRequired()],
        render_kw={"class": "form-select", "aria-describedby": "smoothingHelpCaller"},
        description="Smoothing latency (PCR stabilization buffer).",
    )
    latency = IntegerField(
        "SRT Latency (ms)",
        validators=[DataRequired(), NumberRange(min=20, max=8000)],
        default=300,
        render_kw={"class": "form-control", "min": "20", "max": "8000", "step": "1"},
    )
    overhead_bandwidth = IntegerField(
        "Overhead Bandwidth",
        validators=[DataRequired(), NumberRange(min=1, max=99)],
        default=2,
        widget=PercentageInput(),
        render_kw={"class": "form-control", "min": "1", "max": "99", "step": "1"},
        description="SRT overhead for packet recovery (%). Range: 1-99%. Default: 2%.",
    )
    encryption = SelectField(
        "Encryption",
        choices=[("none", "None"), ("aes-128", "AES-128"), ("aes-256", "AES-256")],
        default="none",
        render_kw={"class": "form-select"},
    )
    passphrase = StringField(
        "Passphrase",
        validators=[Optional(), Length(min=10, max=79)],
        render_kw={
            "placeholder": "Required if encryption enabled (10-79 chars)",
            "class": "form-control",
        },
    )
    rtp_encapsulation = BooleanField(
        "RTP Encapsulation (SMPTE 2022-7)",
        default=False,
        render_kw={"class": "form-check-input"},
        description="Encapsulate UDP input into RTP (mtu=1316). Only for UDP/Multicast inputs.",
    )
    qos = BooleanField(
        "Enable QoS",
        default=False,
        render_kw={"class": "form-check-input"},
        description="Enable Quality of Service flag (qos=true) for SRT URI",
    )

    def validate(self, extra_validators=None):
        initial_validation = super(CallerForm, self).validate(extra_validators)
        if not initial_validation:
            return False

        input_type_valid = True
        input_type_value = self.input_type.data
        if input_type_value == "file":
            if not self.file_path.data:
                self.file_path.errors.append("Media file path is required.")
                input_type_valid = False
        elif input_type_value == "multicast":
            if not self.multicast_channel.data:
                self.multicast_channel.errors.append(
                    "A multicast channel must be selected."
                )
                input_type_valid = False
        elif input_type_value.startswith("colorbar_"):
            pass  # No specific validation needed for file/multicast fields here

        encryption_valid = True
        if self.encryption.data != "none":
            if not self.passphrase.data:
                self.passphrase.errors.append("Passphrase is required.")
                encryption_valid = False
            elif not (10 <= len(self.passphrase.data) <= 79):
                self.passphrase.errors.append("Passphrase must be 10-79 characters.")
                encryption_valid = False

        target_valid = True
        if not self._validate_target_address(self.target_address.data):
            self.target_address.errors.append("Invalid target address format.")
            target_valid = False

        rtp_valid = True
        if self.rtp_encapsulation.data and input_type_value not in ["multicast", "colorbar_720p50", "colorbar_1080i25"]:
            self.rtp_encapsulation.errors.append("RTP encapsulation only supported for Multicast or Colorbar inputs.")
            rtp_valid = False

        return input_type_valid and encryption_valid and target_valid and rtp_valid

    def _validate_target_address(self, address):
        if address == "127.0.0.1":
            return True
        if address and len(address) <= 255 and not any(c.isspace() for c in address):
            if re.match(r"^[a-zA-Z0-9\.\-]+$", address) and "." in address:
                return True
        return False


# --- NetworkTestForm, MediaUploadForm, SettingsForm ---
class NetworkTestForm(FlaskForm):
    # ... (keep existing implementation) ...
    mode = RadioField(
        "Test Mode",
        choices=[
            ("closest", "Auto (Closest)"),
            ("regional", "Auto (Regional)"),
            ("manual", "Manual"),
        ],
        default="closest",
        validators=[DataRequired()],
    )
    region = SelectField(
        "Select Region",
        choices=[("", "-- Select Region --")],
        validators=[Optional()],
        render_kw={"class": "form-select"},
    )
    manual_host = StringField(
        "Server IP / URL",
        validators=[Optional(), Length(min=3, max=255)],
        render_kw={"placeholder": "e.g., iperf.example.com", "class": "form-control"},
    )
    manual_port = IntegerField(
        "Port",
        validators=[Optional(), NumberRange(min=1, max=65535)],
        render_kw={"placeholder": "e.g., 5201", "class": "form-control"},
    )
    manual_protocol = SelectField(
        "Protocol (Manual Only)",
        choices=[("udp", "UDP"), ("tcp", "TCP")],
        default="udp",
        validators=[Optional()],
        render_kw={"class": "form-select"},
    )
    duration = IntegerField(
        "Test Duration (sec)",
        default=5,
        validators=[DataRequired(), NumberRange(min=3, max=10)],
        render_kw={"class": "form-control", "min": "3", "max": "10"},
    )
    bitrate = SelectField(
        "Test Bitrate (UDP)",
        choices=[
            ("5M", "5 Mbps"),
            ("10M", "10 Mbps"),
            ("20M", "20 Mbps"),
            ("50M", "50 Mbps"),
        ],
        default="10M",
        validators=[DataRequired()],
        render_kw={"class": "form-select"},
    )

    def validate(self, extra_validators=None):
        valid = super(NetworkTestForm, self).validate(extra_validators=extra_validators)
        if not valid:
            return False
        if self.mode.data == "manual" and not self.manual_host.data:
            self.manual_host.errors.append(
                "Manual host/IP is required when Mode is set to Manual."
            )
            return False
        if self.mode.data == "regional":
            if len(self.region.choices) > 1 and not self.region.data:
                self.region.errors.append(
                    "Region selection is required when Mode is set to Auto (Regional)."
                )
                return False
            elif len(self.region.choices) <= 1:
                pass
        return True


class MediaUploadForm(FlaskForm):
    media_file = FileField(
        "Media File",
        validators=[
            DataRequired(),
            FileAllowed(["ts"], "Only TS files (.ts) are supported"),
        ],
        render_kw={"class": "form-control", "accept": ".ts"},
    )
    description = StringField(
        "Description",
        validators=[Optional(), Length(max=255)],
        render_kw={"placeholder": "Optional file description", "class": "form-control"},
    )


class SettingsForm(FlaskForm):
    max_streams = IntegerField(
        "Maximum Concurrent Streams",
        validators=[DataRequired(), NumberRange(min=1, max=10)],
        default=5,
        render_kw={"class": "form-control", "min": "1", "max": "10"},
    )
    auto_restart = BooleanField(
        "Auto-restart Failed Streams",
        default=True,
        render_kw={"class": "form-check-input"},
    )
    log_level = SelectField(
        "Logging Level",
        choices=[
            ("DEBUG", "Debug"),
            ("INFO", "Info"),
            ("WARNING", "Warning"),
            ("ERROR", "Error"),
        ],
        default="INFO",
        render_kw={"class": "form-select"},
    )
