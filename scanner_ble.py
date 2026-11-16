"""BLE scanner built on bleak / CoreBluetooth.

macOS deliberately hides hardware MAC addresses from third-party apps. The
stable identifier exposed by CoreBluetooth is a per-host UUID, so this worker
passes that UUID to the detector and relies on Manufacturer Specific Data,
service UUIDs, TX power and RSSI for classification.
"""

from __future__ import annotations

import asyncio
import sys
import time
from typing import Any

from detector import DetectionEngine

try:  # Import lazily so BLE-only / simulation modes survive a broken install.
    from bleak import BleakScanner
except Exception as exc:  # pragma: no cover - depends on host install
    BleakScanner = None  # type: ignore[assignment]
    _BLEAK_IMPORT_ERROR: str | None = str(exc)
else:
    _BLEAK_IMPORT_ERROR = None

import config


class BleScanner:
    def __init__(self, engine: DetectionEngine, enabled: bool = True) -> None:
        self.engine = engine
        self.enabled = enabled
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._status: dict[str, Any] = {
            "state": "disabled" if not enabled else "starting",
            "backend": "bleak / CoreBluetooth",
            "identifier": "UUID (privacy-randomized)" if sys.platform == "darwin" else "MAC",
            "error": None,
            "frames": 0,
            "last_frame_at": None,
            "callback_errors": 0,
        }

    # ── lifecycle ───────────────────────────────────────────────────────────

    async def start(self) -> None:
        if not self.enabled:
            self.engine.note("INFO", "SYS", "BLE_DISABLED", "BLE scanner disabled by CLI flag.")
            return
        if BleakScanner is None:
            message = f"bleak import failed: {_BLEAK_IMPORT_ERROR}"
            self._status.update(state="error", error=message)
            self.engine.note("WARN", "SYS", "BLE_ERROR", message)
            return
        self._task = asyncio.create_task(self._run(), name="ble-scanner")

    async def stop(self) -> None:
        self._stop.set()
        if self._task is None:
            return
        try:
            await asyncio.wait_for(self._task, timeout=3.0)
        except (TimeoutError, asyncio.CancelledError):
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        self._status["state"] = "stopped"

    def status(self) -> dict[str, Any]:
        return dict(self._status)

    # ── worker ──────────────────────────────────────────────────────────────

    async def _run(self) -> None:
        attempts = 0
        while not self._stop.is_set():
            scanner = None
            started = False
            try:
                self._status.update(state="starting", error=None)
                scanner = BleakScanner(
                    detection_callback=self._on_detection,
                    scanning_mode="active",
                )
                await scanner.start()
                started = True
                attempts = 0
                self._status.update(
                    state="scanning",
                    error=None,
                    started_at=time.time(),
                )
                self.engine.note(
                    "OK",
                    "SYS",
                    "BLE_READY",
                    "BLE scan active (bleak / CoreBluetooth, active scanning).",
                    identifier=self._status["identifier"],
                )
                await self._stop.wait()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                attempts += 1
                message = self._human_error(exc)
                self._status.update(state="error", error=message)
                self.engine.note(
                    "WARN",
                    "SYS",
                    "BLE_ERROR",
                    message,
                    attempt=attempts,
                    hint=self._hint(message),
                )
                if self._stop.is_set():
                    break
                await asyncio.sleep(min(15.0, 1.5 * (2 ** min(attempts, 4))))
            finally:
                if scanner is not None and started:
                    try:
                        await scanner.stop()
                    except Exception:
                        pass
            if self._stop.is_set():
                return

    @staticmethod
    def _human_error(exc: Exception) -> str:
        text = f"{type(exc).__name__}: {exc}"
        return text[:500]

    @staticmethod
    def _hint(message: str) -> str:
        lower = message.lower()
        if "permission" in lower or "not authorized" in lower or "denied" in lower:
            return (
                "Grant Bluetooth permission to your terminal app in "
                "System Settings > Privacy & Security > Bluetooth, then restart the app."
            )
        if "corebluetooth" in lower or "bluetooth" in lower:
            return (
                "Check that Bluetooth is on and the terminal app has Bluetooth "
                "privacy permission. Simulation mode remains available."
            )
        return "BLE failed; Wi-Fi and simulation modes remain available."

    def _on_detection(self, device: Any, advertisement: Any) -> None:
        """bleak callback. Never let a malformed advertisement kill the scan."""
        try:
            rssi = getattr(advertisement, "rssi", None)
            if rssi is None:
                rssi = getattr(device, "rssi", None)
            if rssi is None:
                return

            identifier = getattr(device, "address", None) or getattr(device, "name", None)
            if not identifier:
                return

            manufacturer_data = getattr(advertisement, "manufacturer_data", None) or {}
            company_ids = [int(cid) for cid in manufacturer_data]
            target_ids = [cid for cid in company_ids if cid in config.TARGET_VENDORS]
            company_id = target_ids[0] if target_ids else (company_ids[0] if company_ids else None)

            service_uuids = list(getattr(advertisement, "service_uuids", None) or [])
            local_name = getattr(advertisement, "local_name", None) or getattr(device, "name", None)
            tx_power = getattr(advertisement, "tx_power", None)

            payload_bytes = 0
            for payload in manufacturer_data.values():
                payload_bytes += 2 + len(payload)
            payload_bytes += sum(2 + len(str(uuid)) for uuid in service_uuids)
            if local_name:
                payload_bytes += 2 + len(str(local_name))

            self.engine.ingest_ble(
                key=str(identifier),
                rssi=float(rssi),
                name=str(local_name) if local_name else None,
                company_id=company_id,
                service_uuids=service_uuids,
                tx_power=float(tx_power) if tx_power is not None else None,
                adv_bytes=min(255, payload_bytes) if payload_bytes else None,
                manufacturer_bytes=sum(len(v) for v in manufacturer_data.values()),
            )
            self._status["frames"] = int(self._status.get("frames", 0)) + 1
            self._status["last_frame_at"] = time.time()
        except Exception as exc:  # pragma: no cover - defensive
            self._status["callback_errors"] = int(
                self._status.get("callback_errors", 0)
            ) + 1
            try:
                self.engine.note(
                    "WARN",
                    "SYS",
                    "BLE_CALLBACK_ERROR",
                    f"Malformed BLE advertisement ignored: {type(exc).__name__}: {exc}",
                )
            except Exception:
                pass
