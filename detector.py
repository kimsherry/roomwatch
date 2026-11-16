"""Detection engine: BLE smoothing, log-distance ranging, 802.11 burst
tracking, explicit allowlisting and the composite threat score.

All state is owned by the asyncio event loop. The tcpdump parser thread never
touches the engine directly -- it enqueues parsed frames and an async drain
task calls :meth:`DetectionEngine.ingest_wifi`. This keeps the data structures
single-threaded.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import config

# ── small utilities ──────────────────────────────────────────────────────────


def _clean(value: Any, limit: int = 64) -> str:
    """Strip control characters from untrusted advertisement/SSID text."""
    if value is None:
        return ""
    text = str(value)
    cleaned = "".join(ch for ch in text if ch.isprintable())
    return cleaned[:limit]


def _company_hex(company_id: int | None) -> str | None:
    if company_id is None:
        return None
    return f"0x{company_id:04X}"


def _is_local_mac(mac: str) -> bool:
    try:
        return bool(int(mac.split(":", 1)[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def _wifi_vendor(mac: str) -> str:
    upper = mac.upper()
    if _is_local_mac(upper):
        return "LOCAL / RANDOMIZED"
    return config.WIFI_OUI_VENDORS.get(upper[:8], "UNKNOWN")


def _short_id(identifier: str) -> str:
    if len(identifier) <= 18:
        return identifier
    return f"{identifier[:8]}…{identifier[-4:]}"


def _clock(ts: float) -> str:
    # Millisecond wall-clock label for the event stream.
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]


def _status_for_score(score: int) -> str:
    if score >= config.CRITICAL_SCORE:
        return "CRITICAL"
    if score >= config.SUSPICIOUS_SCORE:
        return "SUSPICIOUS"
    if score >= config.WATCH_SCORE:
        return "WATCH"
    return "CLEAR"


# ── records ──────────────────────────────────────────────────────────────────


@dataclass
class DeviceRecord:
    key: str
    kind: str  # "BLE" | "WIFI"
    identifier: str
    name: str = ""
    venue: str = ""
    company_id: int | None = None
    company_label: str = ""
    service_uuids: list[str] = field(default_factory=list)
    manufacturer_bytes: int = 0
    adv_bytes: int | None = None

    tx_power: float | None = None
    tx_power_used: float | None = None
    rssi_raw: float | None = None
    rssi_filtered: float | None = None
    rssi_delta: float | None = None
    distance_m: float | None = None
    last_frame_len: int | None = None

    first_seen: float = 0.0
    last_seen: float = 0.0
    streak_start: float = 0.0
    hits: int = 0

    whitelisted: bool = False
    simulated: bool = False
    notes: str = ""

    score: int = 0
    status: str = "CLEAR"
    pinned: bool = False
    factors: list[dict[str, Any]] = field(default_factory=list)

    # Wi-Fi burst statistics. The window itself is kept by the engine.
    burst_frames: int = 0
    burst_bytes: int = 0
    burst_rate: float = 0.0
    burst_count: int = 0
    last_burst_at: float | None = None
    burst_until: float = 0.0

    def to_dict(self, now: float) -> dict[str, Any]:
        return {
            "key": self.key,
            "kind": self.kind,
            "identifier": self.identifier,
            "short_id": _short_id(self.identifier),
            "name": self.name or ("Unknown BLE peripheral" if self.kind == "BLE" else "802.11 station"),
            "company_id": _company_hex(self.company_id),
            "company_label": self.company_label or None,
            "vendor": self.venue or "UNKNOWN",
            "service_uuids": self.service_uuids,
            "manufacturer_bytes": self.manufacturer_bytes,
            "adv_bytes": self.adv_bytes,
            "tx_power_dbm": _round(self.tx_power, 1),
            "tx_power_used_dbm": _round(self.tx_power_used, 1),
            "rssi_raw": _round(self.rssi_raw, 1),
            "rssi_filtered": _round(self.rssi_filtered, 1),
            "rssi_delta": _round(self.rssi_delta, 1),
            "distance_m": _round(self.distance_m, 2),
            "last_frame_len": self.last_frame_len,
            "first_seen": round(self.first_seen, 3),
            "last_seen": round(self.last_seen, 3),
            "last_seen_ago": round(max(0.0, now - self.last_seen), 1),
            "streak_start": round(self.streak_start, 3),
            "continuous_s": round(max(0.0, now - self.streak_start), 1),
            "hits": self.hits,
            "whitelisted": self.whitelisted,
            "allowed": self.whitelisted,
            "simulated": self.simulated,
            "notes": self.notes,
            "score": self.score,
            "status": "ALLOWED" if self.whitelisted else self.status,
            "pinned": self.pinned and not self.whitelisted,
            "factors": self.factors,
            "burst": {
                "frames": self.burst_frames,
                "bytes": self.burst_bytes,
                "rate_fps": _round(self.burst_rate, 1),
                "count": self.burst_count,
                "last_at": _round(self.last_burst_at, 3),
                "active": bool(self.burst_until > now and self.burst_frames >= config.BURST_FRAME_THRESHOLD),
            },
        }


def _round(value: float | None, digits: int) -> float | None:
    if value is None:
        return None
    return round(float(value), digits)


class DetectionEngine:
    """Single-loop detection state machine."""

    def __init__(self, learning_seconds: float = config.LEARNING_SECONDS) -> None:
        self.started_at = time.time()
        self.learning_duration = max(0.0, float(learning_seconds))
        self.learning_started_at = self.started_at
        self.learning_until = self.started_at + self.learning_duration
        self.learning_active = self.learning_duration > 0
        self.learning_end_reason = "running" if self.learning_active else "disabled"

        self.devices: dict[str, DeviceRecord] = {}
        self.ble_whitelist: set[str] = set()
        self.wifi_whitelist: set[str] = set()
        self.ssid_whitelist: set[str] = set()
        self.ssids: dict[str, dict[str, Any]] = {}

        self.burst_windows: dict[str, deque[tuple[float, int]]] = {}
        self.burst_active: dict[str, bool] = {}

        self.events: deque[dict[str, Any]] = deque(maxlen=config.MAX_EVENTS)
        self._event_seq = 0

        self.stats = self._new_stats()
        self.stats["allowed_devices"] = 0
        self._ble_frame_ts: deque[float] = deque(maxlen=60_000)
        self._wifi_frame_ts: deque[float] = deque(maxlen=60_000)

        self.simulation_mode = "off"  # off | cli | fallback
        self.simulation_fallback = False
        self.simulation_last_at: float | None = None
        self.simulation_injections = 0

        self._last_log_at: dict[str, float] = {}
        self._last_status: dict[str, str] = {}

        if self.learning_active:
            # Present for backward compatibility only; production starts with
            # learning disabled so existing contraband is never auto-excluded.
            self.note(
                "INFO",
                "SYS",
                "LEARNING_START",
                f"Baseline learning started ({self.learning_duration:.0f}s). "
                "Existing BLE UUIDs, Wi-Fi MACs and SSIDs are being whitelisted.",
                duration_s=self.learning_duration,
            )
        else:
            self.note(
                "INFO",
                "SYS",
                "POLICY_MODE",
                "Automatic exclusion is disabled. Only explicitly allowed devices are excluded.",
            )

    # ── public API ──────────────────────────────────────────────────────────

    def tick(self, now: float | None = None) -> None:
        now = time.time() if now is None else now
        self._finalize_learning(now)
        self._sweep_wifi_windows(now)
        self._prune_rates(now)
        self._expire_devices(now)

        # Persistence and burst hold can change without a new packet. Recompute
        # scores on the tick so the UI and CRITICAL transitions stay honest.
        for dev in list(self.devices.values()):
            if dev.whitelisted:
                continue
            if dev.kind == "BLE":
                self._score_device(dev, now, "BLE")
            elif dev.kind == "WIFI":
                self._score_device(dev, now, "WIFI")

    def ingest_ble(
        self,
        *,
        key: str,
        rssi: float,
        ts: float | None = None,
        name: str | None = None,
        company_id: int | None = None,
        manufacturer_name: str | None = None,
        service_uuids: Iterable[str] = (),
        tx_power: float | None = None,
        adv_bytes: int | None = None,
        manufacturer_bytes: int = 0,
        simulated: bool = False,
    ) -> DeviceRecord | None:
        """Process one BLE advertisement / scan response.

        Returns the updated record, or None when the smoothed signal was
        discarded by the classroom cut-off.
        """
        now = time.time() if ts is None else float(ts)
        self._finalize_learning(now)
        self.stats["ble_frames"] += 1
        self._ble_frame_ts.append(now)

        identifier = _clean(key, 96)
        if not identifier:
            return None
        device_key = identifier if identifier.startswith("ble:") else f"ble:{identifier}"
        whitelisted = device_key in self.ble_whitelist and not simulated

        if self.learning_active and not simulated:
            self.ble_whitelist.add(device_key)
            whitelisted = True
            self.stats["baseline_ble"] = len(self.ble_whitelist)

        existing = self.devices.get(device_key)
        if existing is not None and not simulated:
            whitelisted = whitelisted or existing.whitelisted

        prev_filtered = existing.rssi_filtered if existing else None
        prev_seen = existing.last_seen if existing else None

        # α = 0.3 EMA. Reset after a long silence so a device returning after
        # minutes does not inherit a stale filter value.
        if prev_filtered is None or prev_seen is None or (now - prev_seen) > config.EMA_RESET_GAP_SECONDS:
            filtered = float(rssi)
        else:
            filtered = config.EMA_ALPHA * float(rssi) + (1.0 - config.EMA_ALPHA) * prev_filtered

        # Hard classroom cut-off: concrete wall / corridor signals are dropped.
        if filtered <= config.CLASSROOM_RSSI_CUTOFF_DBM:
            self.stats["ble_dropped_far"] += 1
            if existing is not None:
                existing.notes = "SIGNAL DROPPED (<= -86 dBm cut-off)"
            return None

        dev = existing
        if dev is None:
            dev = DeviceRecord(
                key=device_key,
                kind="BLE",
                identifier=identifier,
                first_seen=now,
                last_seen=now,
                streak_start=now,
                simulated=simulated,
                whitelisted=whitelisted,
            )
            self.devices[device_key] = dev
            self._maybe_prune_devices()

        gap = now - dev.last_seen
        if gap > config.CONTINUITY_GAP_SECONDS:
            dev.streak_start = now
        if dev.first_seen == 0:
            dev.first_seen = now

        dev.last_seen = now
        dev.hits += 1
        dev.whitelisted = whitelisted
        dev.simulated = dev.simulated or simulated
        dev.notes = ""

        cleaned_name = _clean(name, 48)
        if cleaned_name:
            dev.name = cleaned_name

        dev.rssi_raw = float(rssi)
        dev.rssi_filtered = filtered
        dev.rssi_delta = None if prev_filtered is None else filtered - prev_filtered
        dev.company_id = company_id
        if company_id is not None:
            dev.company_label = config.COMPANY_NAMES.get(
                company_id, _clean(manufacturer_name, 48)
            )
            dev.venue = dev.company_label or "UNKNOWN"
        elif manufacturer_name:
            dev.venue = _clean(manufacturer_name, 48)

        if service_uuids:
            merged = {u.lower() for u in dev.service_uuids if isinstance(u, str)}
            for uuid in service_uuids:
                if isinstance(uuid, str) and uuid:
                    merged.add(uuid.lower())
            dev.service_uuids = sorted(merged)
        dev.manufacturer_bytes = max(dev.manufacturer_bytes, int(manufacturer_bytes or 0))
        if adv_bytes is not None:
            dev.adv_bytes = max(0, min(255, int(adv_bytes)))

        # TX power is used only when it is plausible as a calibrated RSSI at
        # 1 m; otherwise fall back to -59 dBm. A phone advertising +12 dBm is
        # reporting radio output, not a 1 m reference, and must be rejected.
        plausible_tx = (
            tx_power
            if tx_power is not None
            and config.TX_POWER_REF_MIN_DBM <= float(tx_power) <= config.TX_POWER_REF_MAX_DBM
            else None
        )
        dev.tx_power = float(tx_power) if tx_power is not None else None
        dev.tx_power_used = float(plausible_tx) if plausible_tx is not None else config.DEFAULT_TX_POWER_DBM
        dev.distance_m = 10.0 ** (
            (dev.tx_power_used - filtered) / (10.0 * config.PATH_LOSS_EXPONENT)
        )

        if dev.whitelisted:
            dev.score = 0
            dev.status = "CLEAR"
            dev.pinned = False
            dev.factors = []
            return dev

        if company_id is not None and company_id in config.TARGET_VENDORS:
            self.stats["ble_vendor_hits"] += 1
            throttle_key = f"ble-vendor:{device_key}"
            self._log_throttled(
                throttle_key,
                now,
                60.0,
                "WARN" if company_id in config.PRIMARY_WATCH_VENDORS else "INFO",
                "BLE",
                "BLE_VENDOR_MATCH",
                (
                    f"Company ID {_company_hex(company_id)} "
                    f"({config.TARGET_VENDORS[company_id]}) · "
                    f"{filtered:.1f} dBm filtered · {dev.distance_m:.1f} m · "
                    f"{dev.name}"
                ),
                device=dev.key, name=dev.name, company_id=_company_hex(company_id), vendor=config.TARGET_VENDORS[company_id], rssi_raw=round(float(rssi), 1), rssi_filtered=round(filtered, 1), distance_m=round(dev.distance_m, 2), tx_power_dbm=dev.tx_power_used, service_uuids=dev.service_uuids, adv_bytes=dev.adv_bytes, rssi_delta=_round(dev.rssi_delta, 1), simulated=simulated,
            )
        elif dev.hits == 1:
            self.note(
                "INFO",
                "BLE",
                "BLE_DEVICE_NEW",
                f"New BLE peripheral · {filtered:.1f} dBm · {dev.distance_m:.1f} m · {dev.name}",
                device=dev.key,
                identifier=dev.identifier,
                name=dev.name,
                rssi=round(filtered, 1),
                distance_m=round(dev.distance_m, 2),
                simulated=simulated,
            )

        self._score_device(dev, now, "BLE")
        return dev

    def ingest_wifi(
        self,
        *,
        addr2: str,
        frame_len: int,
        rssi: float | None,
        ts: float | None = None,
        frame_type: int = 2,
        subtype: int = 0,
        to_ds: bool = False,
        from_ds: bool = False,
        ssid: str | None = None,
        simulated: bool = False,
    ) -> DeviceRecord | None:
        """Process one parsed 802.11 frame from monitor mode."""
        now = time.time() if ts is None else float(ts)
        self._finalize_learning(now)

        self.stats["wifi_frames"] += 1
        self._wifi_frame_ts.append(now)

        mac = _clean(addr2, 17).upper()
        if not mac or len(mac) != 17:
            return None
        device_key = f"wifi:{mac}"
        whitelisted = device_key in self.wifi_whitelist and not simulated

        if frame_type == 0:
            self.stats["wifi_mgmt"] += 1
        elif frame_type == 2:
            self.stats["wifi_data"] += 1

        # SSID discovery / baseline collection (beacons, probe responses).
        if ssid:
            clean_ssid = _clean(ssid, 32)
            if clean_ssid:
                if self.learning_active and not simulated:
                    self.ssid_whitelist.add(clean_ssid)
                if clean_ssid not in self.ssids:
                    self.ssids[clean_ssid] = {
                        "ssid": clean_ssid,
                        "first_seen": now,
                        "last_seen": now,
                        "bssid": mac,
                        "baseline": clean_ssid in self.ssid_whitelist,
                    }
                    if not self.learning_active and not simulated:
                        self.note(
                            "INFO",
                            "WIFI",
                            "NEW_SSID",
                            f"New SSID observed: {clean_ssid!r} ({mac})",
                            ssid=clean_ssid,
                            bssid=mac,
                        )
                else:
                    self.ssids[clean_ssid]["last_seen"] = now

        if self.learning_active and not simulated:
            if frame_type in (0, 2):
                self.wifi_whitelist.add(device_key)
                existing = self.devices.get(device_key)
                if existing is not None:
                    existing.whitelisted = True
                    existing.score = 0
                    existing.status = "CLEAR"
                    existing.factors = []
                    existing.pinned = False
            self.stats["baseline_wifi"] = len(self.wifi_whitelist)
            return None

        # Strict uplink filter. Anything not matching is counted for the
        # inspector footer, then discarded.
        if frame_type != 2:
            return None
        if not to_ds or from_ds:
            self.stats["wifi_dropped_direction"] += 1
            return None
        if frame_len < config.BURST_MIN_FRAME_BYTES:
            self.stats["wifi_dropped_small"] += 1
            return None
        if rssi is None or float(rssi) < config.BURST_MIN_RSSI_DBM:
            self.stats["wifi_dropped_weak"] += 1
            return None

        self.stats["wifi_uplink_frames"] += 1

        if whitelisted:
            self.stats["wifi_whitelisted_uplink"] += 1
            dev = self.devices.get(device_key)
            if dev is None:
                dev = DeviceRecord(
                    key=device_key,
                    kind="WIFI",
                    identifier=mac,
                    first_seen=now,
                    last_seen=now,
                    streak_start=now,
                    simulated=simulated,
                    whitelisted=True,
                    hits=1,
                    venue=_wifi_vendor(mac),
                    notes="Allowed by operator",
                    tx_power_used=None,
                )
                self.devices[device_key] = dev
                self._maybe_prune_devices()
            else:
                dev.last_seen = now
                dev.hits += 1
                dev.whitelisted = True
            dev.rssi_raw = float(rssi)
            if dev.rssi_filtered is None:
                dev.rssi_filtered = float(rssi)
            else:
                dev.rssi_filtered = (
                    config.EMA_ALPHA * float(rssi)
                    + (1.0 - config.EMA_ALPHA) * dev.rssi_filtered
                )
            dev.score = 0
            dev.status = "CLEAR"
            dev.factors = []
            dev.pinned = False
            return None

        dev = self.devices.get(device_key)
        if dev is None:
            dev = DeviceRecord(
                key=device_key,
                kind="WIFI",
                identifier=mac,
                first_seen=now,
                last_seen=now,
                streak_start=now,
                simulated=simulated,
                whitelisted=False,
                venue=_wifi_vendor(mac),
                notes="ToDS=1 / FromDS=0 data frame",
                tx_power_used=None,
            )
            dev.service_uuids = []
            self.devices[device_key] = dev
            self._maybe_prune_devices()
            self.note(
                "INFO",
                "WIFI",
                "WIFI_UPLINK_SENDER",
                f"New large-frame uplink sender · {mac} · {frame_len} B · {float(rssi):.1f} dBm",
                device=dev.key,
                addr2=mac,
                frame_len=frame_len,
                rssi=round(float(rssi), 1),
                simulated=simulated,
            )

        gap = now - dev.last_seen
        if gap > config.CONTINUITY_GAP_SECONDS:
            dev.streak_start = now
        dev.last_seen = now
        dev.hits += 1
        dev.simulated = dev.simulated or simulated

        # Keep an EMA for display only; the hard cut-off above uses raw RSSI.
        previous_filtered = dev.rssi_filtered
        if previous_filtered is None:
            dev.rssi_filtered = float(rssi)
            dev.rssi_delta = None
        else:
            dev.rssi_filtered = (
                config.EMA_ALPHA * float(rssi)
                + (1.0 - config.EMA_ALPHA) * previous_filtered
            )
            dev.rssi_delta = dev.rssi_filtered - previous_filtered
        dev.rssi_raw = float(rssi)
        dev.last_frame_len = int(frame_len)

        window = self.burst_windows.setdefault(device_key, deque())
        window.append((now, int(frame_len)))
        cutoff = now - config.BURST_WINDOW_SECONDS
        while window and window[0][0] < cutoff:
            window.popleft()

        frames = len(window)
        total_bytes = sum(item[1] for item in window)
        dev.burst_frames = frames
        dev.burst_bytes = total_bytes
        dev.burst_rate = frames / config.BURST_WINDOW_SECONDS
        dev.notes = "ToDS=1 / FromDS=0 · RSSI >= -78 dBm · frame >= 1100 B"

        if frames >= config.BURST_FRAME_THRESHOLD:
            if not self.burst_active.get(device_key, False):
                self.burst_active[device_key] = True
                dev.burst_count += 1
                dev.last_burst_at = now
                self.stats["wifi_bursts"] += 1
                self.note(
                    "WARN",
                    "WIFI",
                    "UPLINK_BURST",
                    (
                        f"Uplink burst · {mac} · {frames} frames / "
                        f"{config.BURST_WINDOW_SECONDS:.0f}s · {total_bytes} B · "
                        f"{dev.burst_rate:.0f} fps · {float(rssi):.1f} dBm"
                    ),
                    device=dev.key,
                    addr2=mac,
                    frame_len=frame_len,
                    subtype=subtype,
                    to_ds=to_ds,
                    from_ds=from_ds,
                    frames=frames,
                    bytes=total_bytes,
                    window_s=config.BURST_WINDOW_SECONDS,
                    rate_fps=round(dev.burst_rate, 1),
                    rssi=round(float(rssi), 1),
                    simulated=simulated,
                )
            dev.burst_until = now + config.BURST_SCORE_HOLD_SECONDS
        else:
            self.burst_active[device_key] = False

        self._score_device(dev, now, "WIFI")
        return dev

    def snapshot(self) -> dict[str, Any]:
        now = time.time()
        self.tick(now)

        devices = sorted(
            self.devices.values(),
            key=lambda d: (
                0 if (d.pinned and not d.whitelisted) else 1,
                0 if not d.whitelisted else 1,
                -d.score,
                -d.last_seen,
            ),
        )
        thresholds = {
            "ema_alpha": config.EMA_ALPHA,
            "default_tx_power_dbm": config.DEFAULT_TX_POWER_DBM,
            "path_loss_n": config.PATH_LOSS_EXPONENT,
            "rssi_cutoff_dbm": config.CLASSROOM_RSSI_CUTOFF_DBM,
            "near_field_dbm": config.NEAR_FIELD_RSSI_DBM,
            "persistence_s": config.PERSISTENCE_SECONDS,
            "burst_window_s": config.BURST_WINDOW_SECONDS,
            "burst_min_frame_bytes": config.BURST_MIN_FRAME_BYTES,
            "burst_frame_threshold": config.BURST_FRAME_THRESHOLD,
            "critical_score": config.CRITICAL_SCORE,
            "suspicious_score": config.SUSPICIOUS_SCORE,
            "watch_score": config.WATCH_SCORE,
            "weights": {
                "vendor": config.SCORE_VENDOR_MATCH,
                "near": config.SCORE_NEAR_FIELD,
                "burst": config.SCORE_UPLINK_BURST,
                "persistence": config.SCORE_PERSISTENCE,
            },
        }

        return {
            "app": config.APP_NAME,
            "version": config.APP_VERSION,
            "server_time": round(now, 3),
            "uptime_s": round(now - self.started_at, 1),
            "stats": {
                **self.stats,
                "devices_total": len(self.devices),
                "active_devices": sum(1 for d in self.devices.values() if not d.whitelisted),
                "allowed_devices": sum(1 for d in self.devices.values() if d.whitelisted),
                "critical": sum(
                    1 for d in self.devices.values() if d.status == "CRITICAL" and not d.whitelisted
                ),
                "suspicious": sum(
                    1 for d in self.devices.values() if d.status == "SUSPICIOUS" and not d.whitelisted
                ),
                "pinned": sum(1 for d in self.devices.values() if d.pinned and not d.whitelisted),
                "ble_fps": round(len(self._ble_frame_ts) / config.WIFI_FPS_WINDOW_SECONDS, 1),
                "wifi_fps": round(len(self._wifi_frame_ts) / config.WIFI_FPS_WINDOW_SECONDS, 1),
                "ssids_seen": len(self.ssids),
            },
            "devices": [d.to_dict(now) for d in devices],
            "config": thresholds,
            "allowlist": {
                "count": len(self.ble_whitelist) + len(self.wifi_whitelist),
                "ble": len(self.ble_whitelist),
                "wifi": len(self.wifi_whitelist),
            },
            "simulation": {
                "mode": self.simulation_mode,
                "enabled": self.simulation_mode != "off",
                "fallback": self.simulation_fallback,
                "last_injection": _round(self.simulation_last_at, 3),
                "injections": self.simulation_injections,
            },
        }

    def events_after(self, cursor: int) -> list[dict[str, Any]]:
        if not self.events:
            return []
        return [event for event in self.events if int(event["id"]) > cursor]

    def recent_events(self, limit: int = 120) -> list[dict[str, Any]]:
        if limit <= 0:
            return []
        return list(self.events)[-limit:]

    def set_allowed(self, key: str, allowed: bool) -> bool:
        """Explicitly allow or re-flag one device.

        This is the only way a device is excluded. Automatic baseline
        whitelisting is intentionally disabled because it can hide a device
        that is already present when the exam starts.
        """
        key = key.strip()
        kind, _, _ = key.partition(":")
        if kind == "ble":
            allowed_set = self.ble_whitelist
        elif kind == "wifi":
            allowed_set = self.wifi_whitelist
        else:
            return False
        if not key or key == f"{kind}:":
            return False

        dev = self.devices.get(key)
        if allowed:
            allowed_set.add(key)
            self.burst_windows.pop(key, None)
            self.burst_active.pop(key, None)
            self._last_status.pop(key, None)
            if dev is not None:
                dev.whitelisted = True
                dev.score = 0
                dev.status = "CLEAR"
                dev.factors = []
                dev.pinned = False
                dev.burst_until = 0.0
                dev.burst_frames = 0
                dev.burst_bytes = 0
                dev.burst_rate = 0.0
                dev.notes = "Allowed by operator"
        else:
            allowed_set.discard(key)
            if dev is not None:
                dev.whitelisted = False
                dev.notes = ""
                self._score_device(dev, time.time(), dev.kind)

        self.stats["baseline_ble"] = len(self.ble_whitelist)
        self.stats["baseline_wifi"] = len(self.wifi_whitelist)
        self.stats["allowed_devices"] = sum(
            1 for item in self.devices.values() if item.whitelisted
        )
        self.note(
            "INFO" if allowed else "WARN",
            "SYS",
            "DEVICE_ALLOWED" if allowed else "DEVICE_UNALLOWED",
            (
                f"Device allowed: {key}" if allowed
                else f"Device returned to review: {key}"
            ),
            device=key,
            name=dev.name if dev is not None else key,
            kind=kind.upper(),
            allowed=allowed,
        )
        return True

    def skip_learning(self, reason: str = "operator") -> None:
        """Legacy hook kept for callers that explicitly enabled a learning window."""
        if not self.learning_active:
            return
        now = time.time()
        self.learning_active = False
        self.learning_end_reason = reason
        self.note(
            "OK",
            "SYS",
            "BASELINE_LOCKED",
            (
                f"Baseline locked early ({reason}). "
                f"BLE {len(self.ble_whitelist)} · Wi-Fi {len(self.wifi_whitelist)} · "
                f"SSID {len(self.ssid_whitelist)}"
            ),
            ble=len(self.ble_whitelist),
            wifi=len(self.wifi_whitelist),
            ssid=len(self.ssid_whitelist),
            elapsed_s=round(max(0.0, now - self.learning_started_at), 1),
        )

    def forget_device(self, key: str) -> None:
        """Remove one entity and its burst window (used by the simulator)."""
        self.devices.pop(key, None)
        self.burst_windows.pop(key, None)
        self.burst_active.pop(key, None)
        self._last_status.pop(key, None)
        for log_key in list(self._last_log_at):
            if log_key.endswith(key):
                self._last_log_at.pop(log_key, None)

    def reset(self) -> None:
        """Clear detections, counters and the explicit allowlist."""
        self.devices.clear()
        self.burst_windows.clear()
        self.burst_active.clear()
        self.ble_whitelist.clear()
        self.wifi_whitelist.clear()
        self.ssid_whitelist.clear()
        self.ssids.clear()
        self.stats = self._new_stats()
        self.stats["allowed_devices"] = 0
        self._ble_frame_ts.clear()
        self._wifi_frame_ts.clear()
        self._last_log_at.clear()
        self._last_status.clear()
        self.simulation_last_at = None
        self.simulation_injections = 0
        self.events.clear()
        self.note(
            "INFO",
            "SYS",
            "STATE_RESET",
            "Detection state and allowed devices cleared.",
        )

    def note(
        self,
        level: str,
        source: str,
        code: str,
        message: str,
        **data: Any,
    ) -> dict[str, Any]:
        now = time.time()
        self._event_seq += 1
        event = {
            "id": self._event_seq,
            "ts": round(now, 3),
            "time": _clock(now),
            "level": level,
            "source": source,
            "code": code,
            "message": message,
            "data": data,
        }
        self.events.append(event)
        return event

    # ── internals ───────────────────────────────────────────────────────────

    def _new_stats(self) -> dict[str, int]:
        return {
            "ble_frames": 0,
            "ble_dropped_far": 0,
            "ble_vendor_hits": 0,
            "baseline_ble": 0,
            "baseline_wifi": 0,
            "wifi_frames": 0,
            "wifi_mgmt": 0,
            "wifi_data": 0,
            "wifi_uplink_frames": 0,
            "wifi_dropped_direction": 0,
            "wifi_dropped_small": 0,
            "wifi_dropped_weak": 0,
            "wifi_bursts": 0,
            "wifi_whitelisted_uplink": 0,
        }

    def _finalize_learning(self, now: float) -> None:
        if not self.learning_active:
            return
        if now < self.learning_until:
            return
        self.learning_active = False
        self.learning_end_reason = "elapsed"
        self.note(
            "OK",
            "SYS",
            "BASELINE_LOCKED",
            (
                "Baseline learning complete. "
                f"BLE {len(self.ble_whitelist)} · Wi-Fi {len(self.wifi_whitelist)} · "
                f"SSID {len(self.ssid_whitelist)} whitelisted."
            ),
            ble=len(self.ble_whitelist),
            wifi=len(self.wifi_whitelist),
            ssid=len(self.ssid_whitelist),
            elapsed_s=round(max(0.0, now - self.learning_started_at), 1),
        )

    def _score_device(self, dev: DeviceRecord, now: float, source: str) -> None:
        if dev.whitelisted:
            return

        factors: list[dict[str, Any]] = []
        points = 0

        if dev.kind == "BLE" and dev.company_id in config.TARGET_VENDORS:
            points += config.SCORE_VENDOR_MATCH
            factors.append(
                {
                    "code": "VENDOR_MATCH",
                    "label": f"Target company {_company_hex(dev.company_id)} "
                    f"({config.TARGET_VENDORS[dev.company_id]})",
                    "points": config.SCORE_VENDOR_MATCH,
                }
            )

        if (
            dev.kind == "BLE"
            and dev.rssi_filtered is not None
            and dev.rssi_filtered >= config.NEAR_FIELD_RSSI_DBM
        ):
            points += config.SCORE_NEAR_FIELD
            factors.append(
                {
                    "code": "NEAR_FIELD",
                    "label": f"Near field (filtered >= {config.NEAR_FIELD_RSSI_DBM:.0f} dBm)",
                    "points": config.SCORE_NEAR_FIELD,
                }
            )

        if dev.kind == "WIFI" and now <= dev.burst_until:
            points += config.SCORE_UPLINK_BURST
            factors.append(
                {
                    "code": "UPLINK_BURST",
                    "label": f"802.11 uplink burst (>= {config.BURST_FRAME_THRESHOLD} x "
                    f"{config.BURST_MIN_FRAME_BYTES}B / {config.BURST_WINDOW_SECONDS:.0f}s)",
                    "points": config.SCORE_UPLINK_BURST,
                }
            )

        # Persistence only amplifies an existing suspicious signal.
        continuous = (
            now - dev.streak_start >= config.PERSISTENCE_SECONDS
            and now - dev.last_seen <= config.CONTINUITY_GAP_SECONDS
            and dev.hits >= 2
        )
        if continuous and points > 0:
            points += config.SCORE_PERSISTENCE
            factors.append(
                {
                    "code": "PERSISTENCE",
                    "label": f"Continuous suspicious signal >= {config.PERSISTENCE_SECONDS:.0f}s",
                    "points": config.SCORE_PERSISTENCE,
                }
            )

        points = max(0, min(config.MAX_SCORE, int(points)))
        old_status = dev.status
        new_status = _status_for_score(points)

        dev.score = points
        dev.factors = factors
        dev.status = new_status
        dev.pinned = new_status == "CRITICAL"

        if old_status != new_status:
            dev_key = dev.key
            last = self._last_status.get(dev_key)
            if last != new_status:
                self._last_status[dev_key] = new_status
                # Scores can oscillate around a threshold as RSSI moves by a
                # few dB. Update the row immediately, but do not flood the
                # activity log with the same transition every few seconds.
                if not self._status_log_allowed(dev_key, new_status, now):
                    return
                points_note = " ".join(
                    f"{f['code']}+{f['points']}" for f in factors
                ) or "no factors"
                if new_status == "CRITICAL":
                    self.note(
                        "CRITICAL",
                        source,
                        "THREAT_CRITICAL",
                        (
                            f"CRITICAL {points}/100 · {dev.identifier} · "
                            f"{dev.name} · {points_note} · PINNED"
                        ),
                        device=dev.key,
                        identifier=dev.identifier,
                        name=dev.name,
                        kind=dev.kind,
                        score=points,
                        status=new_status,
                        factors=factors,
                        pinned=True,
                    )
                elif old_status == "CRITICAL" or new_status == "SUSPICIOUS":
                    self.note(
                        "WARN" if new_status == "SUSPICIOUS" else "INFO",
                        source,
                        "THREAT_ESCALATED" if new_status == "SUSPICIOUS" else "THREAT_DOWNGRADED",
                        f"{new_status} {points}/100 · {dev.identifier} · {dev.name}",
                        device=dev.key,
                        identifier=dev.identifier,
                        name=dev.name,
                        kind=dev.kind,
                        score=points,
                        status=new_status,
                        factors=factors,
                    )

    def _sweep_wifi_windows(self, now: float) -> None:
        cutoff = now - config.BURST_WINDOW_SECONDS
        for key in list(self.burst_windows.keys()):
            window = self.burst_windows[key]
            while window and window[0][0] < cutoff:
                window.popleft()

            dev = self.devices.get(key)
            active = len(window) >= config.BURST_FRAME_THRESHOLD
            if dev is not None:
                dev.burst_frames = len(window)
                dev.burst_bytes = sum(item[1] for item in window)
                dev.burst_rate = len(window) / config.BURST_WINDOW_SECONDS
            if not active and self.burst_active.get(key, False):
                self.burst_active[key] = False
            if not window:
                del self.burst_windows[key]

    def _expire_devices(self, now: float) -> None:
        for key, dev in list(self.devices.items()):
            ttl = (
                config.PINNED_TTL_SECONDS
                if (dev.pinned or dev.status == "CRITICAL")
                else config.DEVICE_TTL_SECONDS
            )
            if now - dev.last_seen > ttl:
                if dev.score >= config.SUSPICIOUS_SCORE:
                    self.note(
                        "INFO",
                        "SYS",
                        "DEVICE_EXPIRED",
                        f"Expired {dev.identifier} after {ttl:.0f}s without RF contact.",
                        device=key,
                        name=dev.name,
                        kind=dev.kind,
                        score=dev.score,
                    )
                self.devices.pop(key, None)
                self.burst_windows.pop(key, None)
                self.burst_active.pop(key, None)
                self._last_status.pop(key, None)

    def _maybe_prune_devices(self) -> None:
        if len(self.devices) <= config.MAX_DEVICES:
            return
        removable = [
            d for d in self.devices.values() if not d.pinned and not d.whitelisted
        ]
        removable.sort(key=lambda d: (d.score, d.last_seen))
        for dev in removable[: max(1, len(self.devices) - config.MAX_DEVICES)]:
            self.devices.pop(dev.key, None)
            self.burst_windows.pop(dev.key, None)
            self.burst_active.pop(dev.key, None)

    def _prune_rates(self, now: float) -> None:
        cutoff = now - config.WIFI_FPS_WINDOW_SECONDS
        while self._ble_frame_ts and self._ble_frame_ts[0] < cutoff:
            self._ble_frame_ts.popleft()
        while self._wifi_frame_ts and self._wifi_frame_ts[0] < cutoff:
            self._wifi_frame_ts.popleft()

    def _status_log_allowed(
        self, device_key: str, status: str, now: float, interval: float = 30.0
    ) -> bool:
        log_key = f"status:{device_key}:{status}"
        last = self._last_log_at.get(log_key, 0.0)
        if now - last < interval:
            return False
        self._last_log_at[log_key] = now
        return True

    def _log_throttled(
        self,
        key: str,
        now: float,
        interval: float,
        level: str,
        source: str,
        code: str,
        message: str,
        **data: Any,
    ) -> None:
        last = self._last_log_at.get(key, 0.0)
        if now - last < interval:
            return
        self._last_log_at[key] = now
        self.note(level, source, code, message, **data)
