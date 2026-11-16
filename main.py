"""RoomWatch — local BLE + Wi-Fi classroom RF monitor.

Run:
    ./.venv/bin/python main.py                  # unprivileged: BLE-only
    sudo ./.venv/bin/python main.py             # macOS/Linux Wi-Fi monitor
    ./.venv\\Scripts\\python.exe main.py          # Windows
    ./.venv/bin/python main.py --simulate       # no hardware needed

The dashboard is a single static HTML file served by FastAPI and updated over
a WebSocket. All detection state is in-memory and local; nothing is uploaded.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import sys
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

import config
from detector import DetectionEngine
from scanner_ble import BleScanner
from scanner_wifi import WifiScanner, is_admin
from simulator import Simulator

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
INDEX_FILE = STATIC_DIR / "index.html"


# ── websocket fan-out ────────────────────────────────────────────────────────


class WSHub:
    """Per-client queues keep a slow browser from blocking the detector."""

    def __init__(self) -> None:
        self._queues: dict[int, asyncio.Queue[dict[str, Any]]] = {}
        self._next_id = 0

    def register(self) -> tuple[int, asyncio.Queue[dict[str, Any]]]:
        self._next_id += 1
        client_id = self._next_id
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=128)
        self._queues[client_id] = queue
        return client_id, queue

    def unregister(self, client_id: int) -> None:
        self._queues.pop(client_id, None)

    @property
    def clients(self) -> int:
        return len(self._queues)

    async def broadcast(self, payload: dict[str, Any]) -> None:
        for queue in list(self._queues.values()):
            try:
                queue.put_nowait(payload)
            except asyncio.QueueFull:
                # Drop the oldest snapshot and keep the newest state.
                try:
                    queue.get_nowait()
                    queue.put_nowait(payload)
                except (asyncio.QueueEmpty, asyncio.QueueFull):
                    pass


# ── runtime ──────────────────────────────────────────────────────────────────


@dataclass
class Runtime:
    args: argparse.Namespace
    engine: DetectionEngine
    ble: BleScanner
    wifi: WifiScanner
    simulator: Simulator
    hub: WSHub
    broadcaster: asyncio.Task[None] | None = None
    watchdog: asyncio.Task[None] | None = None
    started_at: float = 0.0

    def build_state(self) -> dict[str, Any]:
        state = self.engine.snapshot()
        ble_status = self.ble.status()
        wifi_status = self.wifi.status()
        wifi_ok = wifi_status.get("state") == "monitor"
        ble_ok = ble_status.get("state") == "scanning"
        simulation = self.engine.simulation_mode != "off"

        warnings: list[str] = []
        if not self.args.simulate:
            if not self.args.no_wifi and wifi_status.get("state") == "starting":
                warnings.append("와이파이 감지를 준비하고 있습니다.")
            elif not self.args.no_wifi and not wifi_ok:
                detail = str(wifi_status.get("error") or "").lower()
                warnings.append(
                    "와이파이 감지를 켜지 못했습니다. "
                    + ("관리자 권한이 필요할 수 있습니다. " if "permission" in detail else "")
                    + "블루투스만으로 계속합니다."
                )
            if (
                not self.args.no_ble
                and not ble_ok
                and ble_status.get("state") not in ("starting", "disabled")
            ):
                warnings.append(
                    "블루투스 감지를 켜지 못했습니다. "
                    "터미널 앱의 블루투스 권한을 확인해 주세요."
                )
        if self.engine.simulation_mode in ("cli", "fallback", "manual"):
            warnings.append(
                "테스트 신호가 켜져 있습니다. '테스트'라고 표시된 기기는 실제 기기가 아닙니다."
            )
        if self.engine.simulation_fallback:
            warnings.append(
                "실제 무선 신호를 잡지 못해 테스트 화면으로 전환했습니다."
            )
        if not self.args.simulate and state["uptime_s"] > 10:
            wall_now = time.time()
            wifi_last = wifi_status.get("last_frame_at")
            ble_last = ble_status.get("last_frame_at")
            if (
                wifi_ok
                and self.engine.stats["wifi_frames"] == 0
                and (wifi_last is None or wall_now - float(wifi_last) > 10)
            ):
                if not wifi_status.get("root"):
                    if sys.platform == "win32":
                        warnings.append(
                            "와이파이 감지는 켜졌지만 실제 802.11 신호가 없습니다. "
                            "Windows에서는 관리자 권한 터미널에서 "
                            ".venv\\Scripts\\python.exe main.py 를 실행하고, "
                            "Npcap의 802.11 모니터 모드 지원을 확인해 주세요."
                        )
                    else:
                        warnings.append(
                            "와이파이 감지는 켜졌지만 실제 802.11 신호가 없습니다. "
                            "관리자 권한 없이 실행되어 모니터 모드가 제한되었을 수 있습니다. "
                            "터미널에서 sudo .venv/bin/python main.py 로 다시 실행해 주세요."
                        )
                else:
                    warnings.append(
                        "와이파이 감지는 켜졌지만 아직 802.11 신호를 받지 못했습니다. "
                        "모니터 모드 지원 여부와 채널을 확인해 주세요."
                    )
            if (
                ble_ok
                and self.engine.stats["ble_frames"] == 0
                and (ble_last is None or wall_now - float(ble_last) > 10)
            ):
                warnings.append(
                    "블루투스 감지는 켜졌지만 아직 기기가 보이지 않습니다. "
                    "터미널 앱의 블루투스 권한을 확인해 주세요."
                )

        if simulation:
            mode = "SIMULATION" if self.engine.simulation_mode in ("cli", "fallback") else "LIVE + SIM"
        elif ble_ok and wifi_ok:
            mode = "DUAL ENGINE"
        elif ble_ok:
            mode = "BLE ONLY"
        elif wifi_ok:
            mode = "WIFI ONLY"
        else:
            mode = "DEGRADED"

        state["scanners"] = {"ble": ble_status, "wifi": wifi_status}
        state["system"] = {
            "mode": mode,
            "degraded": not (ble_ok and wifi_ok),
            "wifi_available": wifi_ok,
            "ble_available": ble_ok,
            "warnings": warnings,
            "host": self.args.host,
            "port": self.args.port,
            "clients": self.hub.clients,
            "started_at": self.started_at,
            "simulate_flag": bool(self.args.simulate),
        }
        state["engine"] = {
            "active_engine_tasks": int(ble_ok) + int(wifi_ok) + (1 if simulation else 0),
            "storage": "in-memory",
            "cloud": False,
        }
        return state


# ── background loops ─────────────────────────────────────────────────────────


async def broadcaster(runtime: Runtime) -> None:
    hub = runtime.hub
    engine = runtime.engine
    cursor = 0
    recent = engine.recent_events(1)
    if recent:
        cursor = int(recent[-1]["id"])
    last_state = 0.0
    while True:
        await asyncio.sleep(0.2)
        now = time.monotonic()
        if now - last_state >= 0.5:
            state = runtime.build_state()
            await hub.broadcast({"type": "state", "state": state})
            last_state = now

        events = engine.events_after(cursor)
        if events:
            cursor = int(events[-1]["id"])
            await hub.broadcast({"type": "events", "events": events})


async def fallback_watchdog(runtime: Runtime) -> None:
    """If neither RF engine can start, make the dashboard demonstrable.

    This is intentionally loud in the UI: the mode becomes SIMULATION and a
    warning banner explains that no real packets are being captured.
    """
    await asyncio.sleep(14.0)
    ble_state = runtime.ble.status().get("state")
    wifi_state = runtime.wifi.status().get("state")
    attempted = runtime.ble.enabled or runtime.wifi.enabled
    if attempted and ble_state in ("error", "disabled") and wifi_state in (
        "error",
        "unavailable",
        "disabled",
    ):
        runtime.engine.simulation_fallback = True
        runtime.engine.simulation_mode = "fallback"
        runtime.engine.note(
            "WARN",
            "SYS",
            "SIM_FALLBACK",
            "Both RF scanners are unavailable. Starting test feed fallback; "
            "synthetic devices are marked Test.",
        )
        await runtime.simulator.start_periodic(initial_delay=0.3, interval=30.0)


# ── app factory ─────────────────────────────────────────────────────────────


def create_app(args: argparse.Namespace) -> FastAPI:
    if not INDEX_FILE.exists():
        raise RuntimeError(f"Dashboard file missing: {INDEX_FILE}")

    # Automatic baseline learning is intentionally disabled. Every device is
    # a review candidate unless the operator explicitly allows it.
    engine = DetectionEngine(learning_seconds=0.0)
    if args.simulate:
        engine.simulation_mode = "cli"

    ble = BleScanner(engine, enabled=not args.simulate and not args.no_ble)
    wifi = WifiScanner(
        engine,
        iface=args.iface,
        enabled=not args.simulate and not args.no_wifi,
    )
    simulator = Simulator(engine)
    hub = WSHub()
    runtime = Runtime(
        args=args,
        engine=engine,
        ble=ble,
        wifi=wifi,
        simulator=simulator,
        hub=hub,
        started_at=time.time(),
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        runtime.started_at = time.time()

        if args.simulate:
            await simulator.start_periodic(initial_delay=0.6, interval=args.sim_interval)
            engine.note(
                "INFO",
                "SYS",
                "SIM_MODE",
                "CLI simulation mode: scanners disabled, synthetic RF scenario active.",
            )
        else:
            await ble.start()
            await wifi.start()
            runtime.watchdog = asyncio.create_task(
                fallback_watchdog(runtime), name="watchdog"
            )

        runtime.broadcaster = asyncio.create_task(
            broadcaster(runtime), name="ws-broadcaster"
        )

        try:
            yield
        finally:
            for task in (runtime.broadcaster, runtime.watchdog):
                if task is not None:
                    task.cancel()
            for task in (runtime.broadcaster, runtime.watchdog):
                if task is not None:
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        await task
            await simulator.stop()
            await wifi.stop()
            await ble.stop()

    app = FastAPI(
        title=config.APP_NAME,
        version=config.APP_VERSION,
        docs_url=None,
        redoc_url=None,
        lifespan=lifespan,
    )
    app.state.runtime = runtime

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(
            INDEX_FILE,
            media_type="text/html",
            headers={"Cache-Control": "no-store, max-age=0"},
        )

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon() -> Response:
        return Response(status_code=204)

    @app.get("/api/health")
    async def health() -> dict[str, Any]:
        return {
            "ok": True,
            "app": config.APP_NAME,
            "version": config.APP_VERSION,
            "uptime_s": round(time.time() - runtime.started_at, 1),
            "mode": runtime.build_state()["system"]["mode"],
            "ble": runtime.ble.status(),
            "wifi": runtime.wifi.status(),
            "simulation": runtime.engine.simulation_mode,
        }

    @app.get("/api/state")
    async def state() -> dict[str, Any]:
        return runtime.build_state()

    @app.post("/api/devices/allow")
    async def allow_device(payload: dict[str, Any]) -> dict[str, Any]:
        key = str(payload.get("key") or "").strip()
        allowed = bool(payload.get("allowed"))
        if not engine.set_allowed(key, allowed):
            raise HTTPException(status_code=400, detail="invalid device key")
        return {"ok": True, "state": runtime.build_state()}

    @app.post("/api/simulate")
    async def simulate() -> dict[str, Any]:
        if engine.simulation_mode == "off":
            engine.simulation_mode = "manual"
        result = await simulator.inject_once()
        return {"ok": True, "injected": result, "state": runtime.build_state()}

    @app.post("/api/reset")
    async def reset() -> dict[str, Any]:
        await simulator.cancel_sustain()
        engine.reset()
        if engine.simulation_mode == "manual":
            engine.simulation_mode = "off"
        return {"ok": True, "state": runtime.build_state()}

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket) -> None:
        await websocket.accept()
        client_id, queue = hub.register()
        try:
            await websocket.send_json(
                {
                    "type": "hello",
                    "state": runtime.build_state(),
                    "events": engine.recent_events(120),
                }
            )
            writer = asyncio.create_task(
                _ws_writer(websocket, queue), name=f"ws-writer-{client_id}"
            )
            try:
                while True:
                    # The browser only sends keepalive pings; state is pushed.
                    await websocket.receive_text()
            except WebSocketDisconnect:
                pass
            finally:
                writer.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await writer
        except WebSocketDisconnect:
            pass
        except Exception as exc:
            if not isinstance(exc, (WebSocketDisconnect, RuntimeError)):
                engine.note(
                    "WARN", "SYS", "WS_ERROR", f"WebSocket client error: {exc}"
                )
        finally:
            hub.unregister(client_id)
            with contextlib.suppress(Exception):
                await websocket.close()

    return app


async def _ws_writer(
    websocket: WebSocket, queue: asyncio.Queue[dict[str, Any]]
) -> None:
    try:
        while True:
            payload = await queue.get()
            await websocket.send_json(payload)
    except (WebSocketDisconnect, RuntimeError):
        return
    except Exception:
        return
    finally:
        with contextlib.suppress(Exception):
            await websocket.close()


# ── CLI ──────────────────────────────────────────────────────────────────────


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="roomwatch",
        description=(
            "Local real-time BLE + 802.11 classroom RF monitor for smart glasses "
            "and compact wearable transmitters."
        ),
    )
    parser.add_argument("--host", default=config.DEFAULT_HOST, help="bind address")
    parser.add_argument("--port", type=int, default=config.DEFAULT_PORT, help="HTTP port")
    parser.add_argument(
        "--iface",
        default=config.DEFAULT_WIFI_IFACE,
        help="Wi-Fi interface for monitor mode (auto, en0, wlan0, ...)",
    )
    parser.add_argument(
        "--simulate",
        action="store_true",
        help="disable real scanners and run synthetic BLE + Wi-Fi scenario",
    )
    parser.add_argument("--no-ble", action="store_true", help="disable BLE scanner")
    parser.add_argument(
        "--no-wifi", action="store_true", help="disable Wi-Fi monitor scanner"
    )
    parser.add_argument(
        "--sim-interval",
        type=float,
        default=30.0,
        help="seconds between synthetic scenarios with --simulate (default: 30)",
    )
    parser.add_argument(
        "--log-level",
        default="info",
        choices=["critical", "error", "warning", "info", "debug", "trace"],
    )
    parser.add_argument(
        "--version", action="version", version=f"{config.APP_NAME} {config.APP_VERSION}"
    )
    args = parser.parse_args(argv)
    if not (1 <= args.port <= 65535):
        parser.error("--port must be between 1 and 65535")
    if args.sim_interval < 5:
        parser.error("--sim-interval must be >= 5 seconds")
    return args


def print_banner(args: argparse.Namespace) -> None:
    url_host = "127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host
    admin = is_admin()
    if args.simulate:
        mode = "테스트 화면 (실제 무선 신호 사용 안 함)"
    elif admin:
        mode = f"실제 감시 (블루투스 + 와이파이, {args.iface})"
    elif sys.platform == "win32":
        mode = "실제 감시 (블루투스, 와이파이는 관리자 권한과 Npcap 필요)"
    elif sys.platform.startswith("linux"):
        mode = "실제 감시 (블루투스, 와이파이는 sudo 필요)"
    else:
        mode = "실제 감시 (블루투스, 와이파이는 sudo 필요)"
    line = "─" * 68
    print(line)
    print(f" RoomWatch {config.APP_VERSION}   이 컴퓨터 안에서만 동작")
    print(line)
    print(f" 대시보드   : http://{url_host}:{args.port}")
    print(f" 실행 모드  : {mode}")
    print(" 자동 제외  : 없음 (감독관이 허용한 기기만 제외)")
    print(line, flush=True)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    print_banner(args)
    app = create_app(args)
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_level=args.log_level,
        access_log=False,
    )


if __name__ == "__main__":
    main()
