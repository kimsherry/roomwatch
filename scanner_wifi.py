"""Cross-platform Wi-Fi monitor capture.

Capture strategy by platform:

* macOS   tcpdump -I (libpcap monitor mode), radiotap pcap on stdout.
* Linux   iw set type monitor + ip link up + tcpdump -y IEEE802_11_RADIO.
* Windows Wireshark TShark/Dumpcap with Npcap monitor mode (-I), pcap stdout.

All strategies feed the same pcap reader and Scapy RadioTap/Dot11 decoder.
Monitor mode normally requires root/administrator and temporarily disconnects
the interface from its network. Every failure path falls back to BLE-only mode
without crashing the dashboard.
"""

from __future__ import annotations

import asyncio
import ctypes
import glob
import os
import queue
import re
import shutil
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import config
from detector import DetectionEngine

try:
    from scapy.layers.dot11 import Dot11, RadioTap
except Exception as exc:  # pragma: no cover - depends on host install
    Dot11 = None  # type: ignore[assignment]
    RadioTap = None  # type: ignore[assignment]
    _SCAPY_IMPORT_ERROR: str | None = str(exc)
else:
    _SCAPY_IMPORT_ERROR = None


class PcapStreamError(RuntimeError):
    pass


def is_admin() -> bool:
    if sys.platform == "win32":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def _run_checked(command: list[str], timeout: float = 10.0) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise PcapStreamError(f"{command[0]} not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise PcapStreamError(f"{command[0]} timed out") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise PcapStreamError(
            f"{' '.join(command)} failed: {detail[:600] or result.returncode}"
        )
    return result.stdout


def detect_default_interface(requested: str) -> str:
    if requested and requested != "auto":
        return requested
    if sys.platform == "darwin":
        return "en0"
    if sys.platform.startswith("linux"):
        for path in glob.glob("/sys/class/net/*/wireless"):
            return Path(path).parent.name
        iw = shutil.which("iw") or "/sbin/iw"
        if os.path.exists(iw):
            try:
                output = _run_checked([iw, "dev"], timeout=5.0)
                match = re.search(r"Interface\s+(\S+)", output)
                if match:
                    return match.group(1)
            except PcapStreamError:
                pass
        return "wlan0"
    # Windows interface discovery happens inside the capture plan because it
    # needs TShark/Dumpcap's interface list.
    return "auto"


def _linux_monitor(iface: str, enable: bool) -> None:
    iw = shutil.which("iw") or "/sbin/iw"
    ip = shutil.which("ip") or "/sbin/ip"
    if not os.path.exists(iw):
        raise PcapStreamError("iw not found. Install it (for example: sudo apt install iw).")
    if not os.path.exists(ip):
        raise PcapStreamError("ip not found. Install iproute2.")

    if enable:
        try:
            info = _run_checked([iw, "dev", iface, "info"], timeout=5.0)
        except PcapStreamError:
            info = ""
        if "type monitor" not in info:
            try:
                _run_checked([ip, "link", "set", iface, "down"], timeout=5.0)
            except PcapStreamError:
                pass
            _run_checked([iw, "dev", iface, "set", "type", "monitor"])
        _run_checked([ip, "link", "set", iface, "up"])
    else:
        try:
            _run_checked([ip, "link", "set", iface, "down"], timeout=8.0)
            _run_checked([iw, "dev", iface, "set", "type", "managed"], timeout=8.0)
            _run_checked([ip, "link", "set", iface, "up"], timeout=8.0)
        except PcapStreamError:
            # Restoration is best-effort; the app must still shut down cleanly.
            pass


@dataclass
class CapturePlan:
    command: list[str]
    iface: str
    backend: str
    strategy: str
    pre: Callable[[], None] | None = None
    post: Callable[[], None] | None = None


def _darwin_plan(iface: str) -> CapturePlan:
    system_tcpdump = "/usr/sbin/tcpdump"
    tcpdump = (
        system_tcpdump
        if os.path.exists(system_tcpdump)
        else (shutil.which("tcpdump") or system_tcpdump)
    )
    if not os.path.exists(tcpdump):
        raise PcapStreamError(
            "tcpdump not found. Install the command line tools or use BLE-only mode."
        )
    return CapturePlan(
        command=[
            tcpdump,
            "-I",
            "-i",
            iface,
            "-y",
            "IEEE802_11_RADIO",
            "-s",
            "0",
            "--immediate-mode",
            "-U",
            "-w",
            "-",
        ],
        iface=iface,
        backend="tcpdump -I + scapy RadioTap",
        strategy="tcpdump -I -y IEEE802_11_RADIO",
    )


def _linux_plan(iface: str) -> CapturePlan:
    tcpdump = shutil.which("tcpdump") or "/usr/bin/tcpdump"
    if not os.path.exists(tcpdump):
        raise PcapStreamError(
            "tcpdump not found. Install it (for example: sudo apt install tcpdump)."
        )
    return CapturePlan(
        command=[
            tcpdump,
            "-i",
            iface,
            "-y",
            "IEEE802_11_RADIO",
            "-s",
            "0",
            "-U",
            "-w",
            "-",
        ],
        iface=iface,
        backend="iw monitor + tcpdump + scapy RadioTap",
        strategy="iw set type monitor; tcpdump -i <iface> -y IEEE802_11_RADIO",
        pre=lambda: _linux_monitor(iface, True),
        post=lambda: _linux_monitor(iface, False),
    )


def _windows_tool(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    candidates: list[Path] = []
    for env_name in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        base = os.environ.get(env_name)
        if base:
            candidates.append(Path(base) / "Wireshark" / f"{name}.exe")
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return None


def _windows_interface(tool: str, iface: str) -> str:
    if iface and iface != "auto":
        return iface
    output = _run_checked([tool, "-D"], timeout=20.0)
    for line in output.splitlines():
        if re.search(r"wi-?fi|wireless|wlan|802\.11", line, re.IGNORECASE):
            match = re.match(r"\s*(\d+)\.", line)
            if match:
                return match.group(1)
            return line.strip()
    raise PcapStreamError(
        "Wi-Fi interface not found. Run 'tshark -D' as administrator and pass "
        "the Wi-Fi interface with --iface."
    )


def _windows_plan(iface: str) -> CapturePlan:
    tshark = _windows_tool("tshark")
    if tshark:
        resolved = _windows_interface(tshark, iface)
        return CapturePlan(
            command=[
                tshark,
                "-i",
                resolved,
                "-I",
                "-F",
                "pcap",
                "-l",
                "-w",
                "-",
            ],
            iface=resolved,
            backend="tshark monitor + scapy RadioTap",
            strategy="tshark -I -F pcap (Npcap monitor mode)",
        )
    dumpcap = _windows_tool("dumpcap")
    if dumpcap:
        resolved = _windows_interface(dumpcap, iface)
        return CapturePlan(
            command=[dumpcap, "-i", resolved, "-I", "-w", "-"],
            iface=resolved,
            backend="dumpcap monitor + scapy RadioTap",
            strategy="dumpcap -I (Npcap monitor mode)",
        )
    raise PcapStreamError(
        "Wireshark TShark/Dumpcap not found. Install Wireshark with Npcap "
        "(802.11 monitor support), then retry."
    )


def build_capture_plan(platform: str, iface: str) -> CapturePlan:
    if platform == "darwin":
        return _darwin_plan(iface)
    if platform.startswith("linux"):
        return _linux_plan(iface)
    if platform == "win32":
        return _windows_plan(iface)
    raise PcapStreamError(f"Wi-Fi capture is not implemented for platform {platform!r}.")


# ── pcap / 802.11 decoding ──────────────────────────────────────────────────


def _read_exact(stream: Any, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = stream.read(remaining)
        if not chunk:
            raise EOFError("pcap stream closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _parse_pcap_header(header: bytes) -> tuple[str, bool, int]:
    magic = header[:4]
    if magic == config.PCAP_MAGIC_LE:
        endian, nano = "<", False
    elif magic == config.PCAP_MAGIC_BE:
        endian, nano = ">", False
    elif magic == config.PCAP_MAGIC_NS_LE:
        endian, nano = "<", True
    elif magic == config.PCAP_MAGIC_NS_BE:
        endian, nano = ">", True
    else:
        raise PcapStreamError(f"not a pcap stream (magic={magic.hex()})")
    network = struct.unpack_from(endian + "I", header, 20)[0]
    return endian, nano, network


def _decode_ssid(dot11: Any) -> str | None:
    """Extract SSID from beacon/probe-response tagged parameters."""
    try:
        if int(dot11.type) != 0 or int(dot11.subtype) not in (4, 5, 8):
            return None
        body = bytes(dot11.payload)
    except Exception:
        return None

    offset = 0 if int(dot11.subtype) == 4 else 12
    guard = 0
    while offset + 2 <= len(body) and guard < 64:
        element_id = body[offset]
        length = body[offset + 1]
        start = offset + 2
        end = start + length
        if end > len(body):
            break
        if element_id == 0:
            raw = body[start:end]
            if not raw:
                return None
            return raw.decode("utf-8", "replace")
        offset = end
        guard += 1
    return None


def _parse_dot11(data: bytes, ts: float) -> dict[str, Any] | None:
    """Decode one radiotap frame into the flat dict consumed by the engine."""
    if Dot11 is None or RadioTap is None:
        return None
    if len(data) < 8:
        return None
    try:
        radiotap_len = struct.unpack_from("<H", data, 2)[0]
    except struct.error:
        return None
    if radiotap_len < 8 or radiotap_len > len(data):
        return None

    rssi: float | None = None
    flags = 0
    try:
        radio = RadioTap(data[:radiotap_len])
        raw_rssi = getattr(radio, "dBm_AntSignal", None)
        if raw_rssi is not None:
            value = float(raw_rssi)
            if value != 0 and -120.0 <= value <= 10.0:
                rssi = value
        flags = int(getattr(radio, "Flags", 0) or 0)
    except Exception:
        return None

    raw = data[radiotap_len:]
    if flags & 0x10 and len(raw) >= 4:
        raw = raw[:-4]
    if len(raw) < 10:
        return None

    try:
        dot11 = Dot11(raw)
        frame_type = int(dot11.type)
        subtype = int(dot11.subtype)
        fcfield = int(dot11.FCField)
    except Exception:
        return None

    addr2 = getattr(dot11, "addr2", None)
    if not isinstance(addr2, str):
        return None

    return {
        "ts": ts,
        "addr2": addr2,
        "addr1": getattr(dot11, "addr1", None),
        "addr3": getattr(dot11, "addr3", None),
        "frame_len": len(raw),
        "rssi": rssi,
        "frame_type": frame_type,
        "subtype": subtype,
        "to_ds": bool(fcfield & 0x01),
        "from_ds": bool(fcfield & 0x02),
        "ssid": _decode_ssid(dot11),
    }


class WifiScanner:
    STREAM_HEADER = 24
    PACKET_HEADER = 16
    READY_TIMEOUT_S = 15.0

    def __init__(
        self,
        engine: DetectionEngine,
        iface: str = config.DEFAULT_WIFI_IFACE,
        enabled: bool = True,
    ) -> None:
        self.engine = engine
        self.iface = iface
        self.enabled = enabled
        self.platform = sys.platform
        self._stop = asyncio.Event()
        self._stop_thread = threading.Event()
        self._capture_task: asyncio.Task[None] | None = None
        self._drain_task: asyncio.Task[None] | None = None
        self._proc: subprocess.Popen[bytes] | None = None
        self._queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=20_000)
        self._stderr_lines: deque[str] = deque(maxlen=30)
        self._status: dict[str, Any] = {
            "state": "disabled" if not enabled else "starting",
            "platform": self.platform,
            "iface": iface,
            "backend": self._default_backend(),
            "strategy": self._default_strategy(),
            "admin": is_admin(),
            "root": is_admin(),
            "link_type": None,
            "error": None,
            "hint": None,
            "frames": 0,
            "bytes": 0,
            "parse_errors": 0,
            "queue_depth": 0,
            "dropped_queue": 0,
            "last_frame_at": None,
            "started_at": None,
            "stderr": None,
            "command": None,
        }

    def _default_backend(self) -> str:
        if self.platform == "darwin":
            return "tcpdump -I + scapy RadioTap"
        if self.platform.startswith("linux"):
            return "iw monitor + tcpdump + scapy RadioTap"
        if self.platform == "win32":
            return "tshark/dumpcap monitor + scapy RadioTap"
        return "unsupported"

    def _default_strategy(self) -> str:
        if self.platform == "darwin":
            return "tcpdump -I -y IEEE802_11_RADIO"
        if self.platform.startswith("linux"):
            return "iw monitor; tcpdump -y IEEE802_11_RADIO"
        if self.platform == "win32":
            return "Npcap monitor mode via tshark/dumpcap"
        return "not implemented"

    # ── lifecycle ───────────────────────────────────────────────────────────

    async def start(self) -> None:
        if not self.enabled:
            self.engine.note(
                "INFO", "SYS", "WIFI_DISABLED", "Wi-Fi monitor scanner disabled by CLI flag."
            )
            return
        if _SCAPY_IMPORT_ERROR is not None:
            message = f"scapy import failed: {_SCAPY_IMPORT_ERROR}"
            self._status.update(state="error", error=message)
            self.engine.note("WARN", "SYS", "WIFI_ERROR", message)
            return
        if self.platform not in ("darwin", "linux", "win32") and not self.platform.startswith("linux"):
            message = f"Wi-Fi monitor capture is not implemented for {self.platform!r}."
            self._status.update(state="unavailable", error=message)
            self.engine.note("WARN", "SYS", "WIFI_UNAVAILABLE", message)
            return

        self.iface = detect_default_interface(self.iface)
        self._status["iface"] = self.iface
        self._status["admin"] = is_admin()
        self._status["root"] = is_admin()
        self._drain_task = asyncio.create_task(self._drain_loop(), name="wifi-drain")
        self._capture_task = asyncio.create_task(self._run(), name="wifi-capture")
        self.engine.note(
            "INFO",
            "SYS",
            "WIFI_STARTING",
            (
                f"Starting 802.11 monitor capture on {self.iface} ({self.platform}). "
                "Monitor mode needs administrator privileges and temporarily "
                "detaches the interface from its network."
            ),
            iface=self.iface,
            root=is_admin(),
            platform=self.platform,
        )

    async def stop(self) -> None:
        self._stop.set()
        self._stop_thread.set()
        proc = self._proc
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass
            try:
                proc.wait(timeout=2.0)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        for task in (self._capture_task, self._drain_task):
            if task is None:
                continue
            try:
                await asyncio.wait_for(task, timeout=3.0)
            except (TimeoutError, asyncio.CancelledError):
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass
        self._status["state"] = "stopped"

    def status(self) -> dict[str, Any]:
        return dict(self._status)

    # ── orchestration ───────────────────────────────────────────────────────

    async def _run(self) -> None:
        try:
            plan = await asyncio.to_thread(
                build_capture_plan, self.platform, self.iface
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            message = str(exc)
            self._status.update(
                state="unavailable",
                error=message[:700],
                hint=self._hint(message),
            )
            self.engine.note(
                "WARN",
                "SYS",
                "WIFI_UNAVAILABLE",
                message[:700],
                iface=self.iface,
                platform=self.platform,
                hint=self._hint(message),
            )
            return

        self.iface = plan.iface
        self._status.update(
            iface=plan.iface,
            backend=plan.backend,
            strategy=plan.strategy,
            command=" ".join(plan.command),
        )

        attempts = 0
        last_error = "monitor mode could not be started"
        while not self._stop.is_set() and attempts < 3:
            attempts += 1
            try:
                await self._capture_once(plan)
                break
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                last_error = str(exc)
                self._status.update(
                    state="error",
                    error=last_error[:700],
                    hint=self._hint(last_error),
                )
                self.engine.note(
                    "WARN",
                    "SYS",
                    "WIFI_ERROR",
                    last_error[:700],
                    attempt=attempts,
                    iface=self.iface,
                    platform=self.platform,
                    hint=self._hint(last_error),
                )
                if self._stop.is_set():
                    break
                await asyncio.sleep(min(5.0, 1.5 * attempts))

        if self._stop.is_set():
            self._status["state"] = "stopped"
            return
        if self._status.get("state") != "monitor":
            self._status.update(
                state="unavailable",
                error=last_error[:700],
                hint=self._hint(last_error),
            )
            self.engine.note(
                "WARN",
                "SYS",
                "WIFI_UNAVAILABLE",
                (
                    "Wi-Fi monitor mode unavailable. Continuing in BLE-only mode; "
                    "the dashboard and test feed remain functional."
                ),
                error=last_error[:700],
                platform=self.platform,
                hint=self._hint(last_error),
            )

    async def _capture_once(self, plan: CapturePlan) -> None:
        self._stop_thread.clear()
        self._stderr_lines.clear()
        self._status.update(
            state="starting",
            error=None,
            hint=None,
            started_at=time.time(),
            link_type=None,
            frames=0,
            bytes=0,
            parse_errors=0,
            queue_depth=0,
            dropped_queue=0,
            command=" ".join(plan.command),
            backend=plan.backend,
            strategy=plan.strategy,
            iface=plan.iface,
        )

        prepared = False
        proc: subprocess.Popen[bytes] | None = None
        try:
            if plan.pre is not None:
                # Mark prepared before running so a partial monitor-mode change
                # is still restored by plan.post.
                prepared = True
                await asyncio.to_thread(plan.pre)

            try:
                proc = await asyncio.to_thread(
                    subprocess.Popen,
                    plan.command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    bufsize=0,
                )
            except Exception as exc:
                raise PcapStreamError(f"failed to launch capture tool: {exc}") from exc

            self._proc = proc
            threading.Thread(
                target=self._drain_stderr,
                args=(proc,),
                name="wifi-stderr",
                daemon=True,
            ).start()
            threading.Thread(
                target=self._read_pcap,
                args=(proc,),
                name="wifi-pcap",
                daemon=True,
            ).start()

            deadline = time.monotonic() + self.READY_TIMEOUT_S
            while time.monotonic() < deadline:
                if self._stop.is_set():
                    return
                if self._status.get("state") == "monitor":
                    break
                if proc.poll() is not None:
                    break
                await asyncio.sleep(0.1)

            if self._status.get("state") != "monitor":
                raise PcapStreamError(self._error_from_stderr(proc))

            self.engine.note(
                "OK",
                "SYS",
                "WIFI_MONITOR_READY",
                (
                    f"802.11 monitor capture active on {plan.iface} "
                    f"(radiotap, DLT {config.DLT_IEEE802_11_RADIO}, {plan.backend})."
                ),
                iface=plan.iface,
                link_type=self._status.get("link_type"),
                platform=self.platform,
                backend=plan.backend,
            )

            while not self._stop.is_set():
                if proc.poll() is not None:
                    raise PcapStreamError(self._error_from_stderr(proc))
                if self._status.get("state") == "error":
                    raise PcapStreamError(self._error_from_stderr(proc))
                await asyncio.sleep(0.4)
        finally:
            self._stop_thread.set()
            if proc is not None:
                if proc.poll() is None:
                    try:
                        proc.terminate()
                        proc.wait(timeout=2.0)
                    except Exception:
                        try:
                            proc.kill()
                        except Exception:
                            pass
                for stream in (proc.stdout, proc.stderr):
                    try:
                        if stream is not None:
                            stream.close()
                    except Exception:
                        pass
            self._proc = None
            if prepared and plan.post is not None:
                try:
                    await asyncio.to_thread(plan.post)
                except Exception:
                    pass
            if self._stop.is_set():
                self._status["state"] = "stopped"
            elif self._status.get("state") not in ("error", "monitor"):
                self._status["state"] = "unavailable"

    async def _drain_loop(self) -> None:
        while not self._stop.is_set() or not self._queue.empty():
            processed = 0
            while processed < 2_000:
                try:
                    item = self._queue.get_nowait()
                except queue.Empty:
                    break
                try:
                    self.engine.ingest_wifi(**item)
                except Exception:
                    self._status["parse_errors"] = int(self._status.get("parse_errors", 0)) + 1
                processed += 1
            self._status["queue_depth"] = self._queue.qsize()
            await asyncio.sleep(0.02 if processed else 0.1)

    # ── capture thread ──────────────────────────────────────────────────────

    def _read_pcap(self, proc: subprocess.Popen[bytes]) -> None:
        try:
            assert proc.stdout is not None
            header = _read_exact(proc.stdout, self.STREAM_HEADER)
            endian, nano, link_type = _parse_pcap_header(header)
            self._status["link_type"] = link_type
            if link_type != config.DLT_IEEE802_11_RADIO:
                raise PcapStreamError(
                    "capture did not provide radiotap "
                    f"(link type {link_type}; expected {config.DLT_IEEE802_11_RADIO})"
                )
            if self._stop_thread.is_set():
                return
            self._status["state"] = "monitor"

            while not self._stop_thread.is_set():
                packet_header = _read_exact(proc.stdout, self.PACKET_HEADER)
                ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(
                    endian + "IIII", packet_header
                )
                if incl_len <= 0 or incl_len > 262_144:
                    raise PcapStreamError(f"invalid pcap packet length: {incl_len}")
                data = _read_exact(proc.stdout, incl_len)
                ts = ts_sec + ts_frac / (1_000_000_000.0 if nano else 1_000_000.0)
                try:
                    parsed = _parse_dot11(data, ts)
                except Exception:
                    parsed = None
                if parsed is None:
                    self._status["parse_errors"] = int(self._status.get("parse_errors", 0)) + 1
                    continue
                self._status["frames"] = int(self._status.get("frames", 0)) + 1
                self._status["bytes"] = int(self._status.get("bytes", 0)) + len(data)
                self._status["last_frame_at"] = time.time()
                try:
                    self._queue.put_nowait(parsed)
                except queue.Full:
                    self._status["dropped_queue"] = int(
                        self._status.get("dropped_queue", 0)
                    ) + 1
        except (EOFError, OSError) as exc:
            if not self._stop_thread.is_set():
                self._status.update(
                    state="error",
                    error=f"capture stream ended: {self._error_from_stderr(proc) or exc}",
                )
        except PcapStreamError as exc:
            if not self._stop_thread.is_set():
                self._status.update(state="error", error=str(exc))
        except Exception as exc:
            if not self._stop_thread.is_set():
                self._status.update(
                    state="error",
                    error=f"pcap parser error: {type(exc).__name__}: {exc}",
                )

    def _drain_stderr(self, proc: subprocess.Popen[bytes]) -> None:
        stderr = proc.stderr
        if stderr is None:
            return
        try:
            while True:
                line = stderr.readline()
                if not line:
                    return
                text = line.decode("utf-8", "replace").strip()
                if text:
                    self._stderr_lines.append(text)
                    self._status["stderr"] = text
        except Exception:
            return

    # ── diagnostics ─────────────────────────────────────────────────────────

    def _error_from_stderr(self, proc: subprocess.Popen[bytes]) -> str:
        tail = " | ".join(list(self._stderr_lines)[-3:])
        if tail:
            return tail
        try:
            code = proc.poll()
        except Exception:
            code = None
        if code is not None:
            return f"capture process exited with status {code}"
        return str(self._status.get("error") or "monitor mode failed")

    def _hint(self, message: str) -> str:
        lower = message.lower()
        if self.platform == "win32":
            return (
                "Wi-Fi monitor mode on Windows needs Npcap installed with "
                "'Support raw 802.11 traffic (and monitor mode)' and Wireshark "
                "TShark/Dumpcap. Run the terminal as Administrator and use an "
                "adapter that supports monitor mode."
            )
        if self.platform.startswith("linux"):
            if "iw not found" in lower or "tcpdump not found" in lower:
                return "Install iw and tcpdump, for example: sudo apt install iw tcpdump."
            if "permission" in lower or "operation not permitted" in lower or "root" in lower:
                return (
                    "Run with sudo: sudo .venv/bin/python main.py. "
                    "NetworkManager may need the interface released before monitor mode."
                )
            if "monitor" in lower or "not supported" in lower:
                return (
                    "Some Linux Wi-Fi drivers refuse monitor mode. Try a USB "
                    "adapter with radiotap support, or continue in BLE-only mode."
                )
            return "Check the interface (iw dev), driver monitor support, and sudo."
        if "permission" in lower or "operation not permitted" in lower or "root" in lower:
            return (
                "Run with sudo: sudo .venv/bin/python main.py. "
                "BLE-only mode does not need root."
            )
        if "monitor mode" in lower or "biocsseesent" in lower or "not supported" in lower:
            return (
                "The built-in interface rejected monitor mode. Use BLE-only mode, "
                "or a USB Wi-Fi adapter that supports radiotap monitor capture."
            )
        if "datalink" in lower or "radiotap" in lower or "link type" in lower:
            return (
                "The capture tool did not emit radiotap headers. Verify the adapter "
                "with tcpdump -I (macOS) or tshark -I (Windows), then restart."
            )
        if "unrecognized option" in lower or "invalid option" in lower:
            return "The installed capture tool is too old for this mode."
        return "Check the interface name and monitor-mode permissions, or use BLE-only mode."
