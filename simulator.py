"""Synthetic Ray-Ban-Meta-style BLE advertisements + an 802.11 upload burst.

The simulator feeds the exact same detector methods as real hardware. Nothing
in the UI is faked: the score, burst window, EMA, persistence and CRITICAL pin
are all produced by the production engine.

The injection replays the last ~12 seconds of observations. That lets the
persistence bonus (+15 after 10 s) and the 2-second burst window be evaluated
immediately instead of making the operator wait.
"""

from __future__ import annotations

import asyncio
import math
import time

from detector import DetectionEngine

SIM_BLE_KEY = "A1B2C3D4-058E-4A1B-9C2D-000000000001"
SIM_BLE_NAME = "Ray-Ban Meta"
SIM_BLE_COMPANY_ID = 0x058E  # Meta Platforms
SIM_SERVICE_UUID = "a1b2c3d4-0000-4000-8000-058e00000001"
SIM_WIFI_MAC = "02:53:49:4D:00:01"  # locally administered: 02 + "SIM"


class Simulator:
    def __init__(self, engine: DetectionEngine) -> None:
        self.engine = engine
        self._lock = asyncio.Lock()
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._sustain_task: asyncio.Task[None] | None = None

    async def inject_once(self, *, announce: bool = True) -> dict[str, int]:
        async with self._lock:
            await self.cancel_sustain()
            # A repeat click must not append a second historical replay on top
            # of the first one. Start each synthetic scenario from a clean
            # entity/window state.
            self.engine.forget_device(f"ble:{SIM_BLE_KEY}")
            self.engine.forget_device(f"wifi:{SIM_WIFI_MAC}")

            now = time.time()
            wifi_frames = 58
            wifi_bytes = 0

            # 58 frames in 1.8 s => well past the >=45 frames / 2.0 s threshold.
            for i in range(wifi_frames):
                ts = now - 1.8 + (1.8 * i / (wifi_frames - 1))
                frame_len = 1180 + (i * 37) % 260
                rssi = -61.0 + (i % 3) * 0.7
                self.engine.ingest_wifi(
                    ts=ts,
                    addr2=SIM_WIFI_MAC,
                    frame_len=frame_len,
                    rssi=rssi,
                    frame_type=2,
                    subtype=8,
                    to_ds=True,
                    from_ds=False,
                    simulated=True,
                )
                wifi_bytes += frame_len

            # 12 s of advertisements at ~2 Hz. Filtered RSSI settles near -57
            # dBm, i.e. ~0.8 m under the configured log-distance model.
            ble_samples = 26
            for i in range(ble_samples):
                ts = now - 12.0 + (12.0 * i / (ble_samples - 1))
                rssi = -56.0 + 1.8 * math.sin(i * 0.8) + (i % 3 - 1) * 0.6
                self.engine.ingest_ble(
                    key=SIM_BLE_KEY,
                    rssi=rssi,
                    ts=ts,
                    name=SIM_BLE_NAME,
                    company_id=SIM_BLE_COMPANY_ID,
                    service_uuids=[SIM_SERVICE_UUID],
                    tx_power=-59.0,
                    adv_bytes=47,
                    manufacturer_bytes=12,
                    simulated=True,
                )

            self.engine.simulation_last_at = time.time()
            self.engine.simulation_injections += 1
            self.engine.tick()
            self._schedule_sustain()

            if announce:
                self.engine.note(
                    "INFO",
                    "SIM",
                    "SIM_INJECT",
                    (
                        f"Test scenario injected: {ble_samples} BLE advertisements "
                        f"and {wifi_frames} uplink frames ({wifi_bytes} B). "
                        "Test devices appear as review candidates."
                    ),
                    ble_samples=ble_samples,
                    wifi_frames=wifi_frames,
                    wifi_bytes=wifi_bytes,
                    simulated=True,
                )

            return {
                "ble_samples": ble_samples,
                "wifi_frames": wifi_frames,
                "wifi_bytes": wifi_bytes,
            }

    # ── live tail ───────────────────────────────────────────────────────────

    def _schedule_sustain(self, duration: float = 28.5) -> None:
        """Keep the synthetic device alive with live packets after the replay.

        Without this, the 12s replay's last packet ages out of the 6s
        continuity window and the demo CRITICAL would decay after ~6s. Live
        advertisements keep the exact same persistence rule satisfied.
        """
        if self._sustain_task is not None and not self._sustain_task.done():
            self._sustain_task.cancel()
        self._sustain_task = asyncio.create_task(
            self._sustain(duration), name="simulator-sustain"
        )

    async def _sustain(self, duration: float) -> None:
        started = time.time()
        tick = 0
        try:
            while time.time() - started < duration and not self._stop.is_set():
                await asyncio.sleep(1.0)
                now = time.time()
                tick += 1
                self.engine.ingest_ble(
                    key=SIM_BLE_KEY,
                    rssi=-56.0 + 1.6 * math.sin(tick * 0.7) + (tick % 3 - 1) * 0.5,
                    ts=now,
                    name=SIM_BLE_NAME,
                    company_id=SIM_BLE_COMPANY_ID,
                    service_uuids=[SIM_SERVICE_UUID],
                    tx_power=-59.0,
                    adv_bytes=47,
                    manufacturer_bytes=12,
                    simulated=True,
                )
                if tick % 5 == 0:
                    for i in range(52):
                        ts = now - 1.8 + (1.8 * i / 51)
                        self.engine.ingest_wifi(
                            ts=ts,
                            addr2=SIM_WIFI_MAC,
                            frame_len=1200 + (i * 41) % 220,
                            rssi=-61.0 + (i % 3) * 0.6,
                            frame_type=2,
                            subtype=8,
                            to_ds=True,
                            from_ds=False,
                            simulated=True,
                        )
                if tick % 10 == 0:
                    self.engine.tick()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pragma: no cover - defensive
            self.engine.note(
                "WARN",
                "SIM",
                "SIM_ERROR",
                f"Simulation sustain failed: {type(exc).__name__}: {exc}",
            )

    async def cancel_sustain(self) -> None:
        if self._sustain_task is None:
            return
        self._sustain_task.cancel()
        try:
            await self._sustain_task
        except (asyncio.CancelledError, Exception):
            pass
        self._sustain_task = None

    async def start_periodic(
        self,
        *,
        initial_delay: float = 1.0,
        interval: float = 30.0,
    ) -> None:
        if self._task is not None:
            return
        self._task = asyncio.create_task(
            self._run_periodic(initial_delay=initial_delay, interval=interval),
            name="simulator",
        )

    async def _run_periodic(self, *, initial_delay: float, interval: float) -> None:
        try:
            if initial_delay:
                await asyncio.wait_for(self._stop.wait(), timeout=initial_delay)
                return
        except TimeoutError:
            pass
        while not self._stop.is_set():
            try:
                await self.inject_once()
            except Exception as exc:  # pragma: no cover - defensive
                self.engine.note(
                    "WARN",
                    "SIM",
                    "SIM_ERROR",
                    f"Simulation injection failed: {type(exc).__name__}: {exc}",
                )
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval)
                return
            except TimeoutError:
                continue

    async def stop(self) -> None:
        self._stop.set()
        await self.cancel_sustain()
        if self._task is None:
            return
        try:
            await asyncio.wait_for(self._task, timeout=2.0)
        except (TimeoutError, asyncio.CancelledError):
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
