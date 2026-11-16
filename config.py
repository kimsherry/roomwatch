"""Central tuning constants for RoomWatch.

Everything that affects detection math lives here so the operator can tune the
MVP per room without touching the engine. Values follow the classroom-5-8m
spec unless noted otherwise.
"""

from __future__ import annotations

from typing import Final

APP_NAME: Final[str] = "RoomWatch"
APP_VERSION: Final[str] = "1.0.0"

# ── BLE: smoothing + log-distance model ──────────────────────────────────────
EMA_ALPHA: Final[float] = 0.3
DEFAULT_TX_POWER_DBM: Final[float] = -59.0
# P_tx in the log-distance model is the calibrated RSSI at 1 m, NOT the radio's
# transmit power setting. Many phones advertise values such as +12 dBm, which
# would produce absurd distances if fed into the formula. Only accept values
# that are physically plausible as a 1 m reference RSSI.
TX_POWER_REF_MIN_DBM: Final[float] = -100.0
TX_POWER_REF_MAX_DBM: Final[float] = -25.0
PATH_LOSS_EXPONENT: Final[float] = 2.5
CLASSROOM_RSSI_CUTOFF_DBM: Final[float] = -86.0
NEAR_FIELD_RSSI_DBM: Final[float] = -78.0
PERSISTENCE_SECONDS: Final[float] = 10.0

# Consecutive-observation bookkeeping. A gap longer than this breaks the
# "continuous presence" streak used for the persistence bonus.
CONTINUITY_GAP_SECONDS: Final[float] = 6.0
EMA_RESET_GAP_SECONDS: Final[float] = 15.0
DEVICE_TTL_SECONDS: Final[float] = 40.0
PINNED_TTL_SECONDS: Final[float] = 180.0

# ── Wi-Fi: 802.11 uplink burst detector ──────────────────────────────────────
BURST_WINDOW_SECONDS: Final[float] = 2.0
BURST_MIN_FRAME_BYTES: Final[int] = 1100
BURST_FRAME_THRESHOLD: Final[int] = 45  # ">= 45" per spec section 2
BURST_MIN_RSSI_DBM: Final[float] = -78.0
BURST_SCORE_HOLD_SECONDS: Final[float] = 15.0

# ── Threat score ─────────────────────────────────────────────────────────────
SCORE_VENDOR_MATCH: Final[int] = 45
SCORE_NEAR_FIELD: Final[int] = 20
SCORE_UPLINK_BURST: Final[int] = 40
SCORE_PERSISTENCE: Final[int] = 15
CRITICAL_SCORE: Final[int] = 75
SUSPICIOUS_SCORE: Final[int] = 45
WATCH_SCORE: Final[int] = 20
MAX_SCORE: Final[int] = 100

# ── Session / UI ─────────────────────────────────────────────────────────────
# Automatic "learn everything already present" is disabled: in an exam where
# all electronics are banned, it can whitelist contraband. Only explicit
# operator approvals are excluded.
LEARNING_SECONDS: Final[float] = 0.0
MAX_EVENTS: Final[int] = 800
MAX_DEVICES: Final[int] = 250
WIFI_FPS_WINDOW_SECONDS: Final[float] = 5.0

# Manufacturer Specific Data company identifiers used as the primary BLE
# identifier on macOS, where the real MAC address is hidden by CoreBluetooth.
#
# COMPANY_NAMES is display-only. TARGET_VENDORS is the scoring set. Keeping
# these separate avoids treating every Samsung appliance or Xiaomi light bulb
# as a wearable.
COMPANY_NAMES: Final[dict[int, str]] = {
    0x058E: "Meta Platforms",
    0x000A: "Qualcomm",
    0x02B0: "Bestechnic (BES)",
    0x03E0: "Actions Semiconductor",
    0x004C: "Apple",
    0x00E0: "Google",
    0x0075: "Samsung",
    0x02E5: "Espressif",
    0x038F: "Xiaomi",
}

# The five examples from the specification. Apple is intentionally broad and
# is the main reason the explicit allowlist and human review matter.
TARGET_VENDORS: Final[dict[int, str]] = {
    0x058E: "Meta Platforms",
    0x000A: "Qualcomm",
    0x02B0: "Bestechnic (BES)",
    0x03E0: "Actions Semiconductor",
    0x004C: "Apple",
}

# Vendors that deserve a WARN-level raw event the first time they are seen.
# The others still receive the +45 company-ID score, but logging is quieter.
PRIMARY_WATCH_VENDORS: Final[frozenset[int]] = frozenset(
    {0x058E, 0x000A, 0x02B0, 0x03E0}
)

# Optional: add Service UUIDs that should be treated as high attention. They
# are displayed and preserved, but the spec's score is driven by company ID.
SUSPECT_SERVICE_UUIDS: Final[frozenset[str]] = frozenset()

# Small, deliberately incomplete OUI table. Most modern phones randomize their
# Wi-Fi MAC, so "LOCAL / RANDOMIZED" is often the honest answer.
WIFI_OUI_VENDORS: Final[dict[str, str]] = {
    "F0:18:98": "Apple",
    "3C:22:FB": "Apple",
    "A8:5C:2C": "Apple",
    "8C:77:12": "Samsung",
    "E8:50:8B": "Samsung",
    "3C:58:C2": "Intel",
    "A4:BB:6D": "Intel",
    "24:0A:C4": "Espressif",
    "84:F3:EB": "Espressif",
    "50:C7:BF": "TP-Link",
    "00:E0:FC": "Huawei",
    "64:09:80": "Xiaomi",
    "F4:F5:E8": "Google",
}

# Hardware defaults. en0 is the built-in Wi-Fi interface on Apple Silicon
# MacBook Airs. Monitor mode is entered by tcpdump; the airport(8) utility is
# never invoked.
DEFAULT_WIFI_IFACE: Final[str] = "auto"
DEFAULT_HOST: Final[str] = "127.0.0.1"
DEFAULT_PORT: Final[int] = 8000

# tcpdump / libpcap constants
DLT_IEEE802_11_RADIO: Final[int] = 127
PCAP_MAGIC_LE: Final[bytes] = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_BE: Final[bytes] = b"\xa1\xb2\xc3\xd4"
PCAP_MAGIC_NS_LE: Final[bytes] = b"\x4d\x3c\xb2\xa1"
PCAP_MAGIC_NS_BE: Final[bytes] = b"\xa1\xb2\x3c\x4d"

