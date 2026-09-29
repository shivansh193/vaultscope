"""Live capture sources: something that grows a capture file while it runs.

The seam is deliberately narrow. A source writes IPsec packets into one pcap
file, and says whether it is still running; it knows nothing about analysis.
Whoever drives it (``api.live``) re-reads that file with the Analysis module on
a tick. Because the file is the whole capture from the start of the run, the
frame numbers in every finding point into a file the analyst can download and
open in Wireshark -- live evidence is as checkable as uploaded evidence.

Two adapters:

``InterfaceSource``  ``dumpcap`` on a real NIC, filtered to IKE/ESP/AH. Needs
                     capture privilege (Wireshark's ChmodBPF on macOS,
                     ``CAP_NET_RAW`` on Linux).
``ReplaySource``     re-emits a stored capture packet by packet at a scaled
                     pace. Needs no privilege, so the demo and the tests run
                     anywhere, and it exercises exactly the code path a real
                     interface does.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import threading
import time
from abc import ABC, abstractmethod
from pathlib import Path

# IKE (500 / 4500 incl. ESP-in-UDP) and native ESP / AH, over IPv4 and IPv6.
CAPTURE_FILTER = (
    "udp port 500 or udp port 4500 or ip proto 50 or ip proto 51 or ip6 proto 50 or ip6 proto 51"
)

_MACOS_DUMPCAP = Path("/Applications/Wireshark.app/Contents/MacOS/dumpcap")


def dumpcap_path() -> str | None:
    found = shutil.which("dumpcap")
    if found:
        return found
    return str(_MACOS_DUMPCAP) if _MACOS_DUMPCAP.exists() else None


def list_interfaces() -> list[dict[str, str]]:
    """Capture interfaces ``dumpcap -D`` can see, ``[]`` when it cannot run."""
    tool = dumpcap_path()
    if tool is None:
        return []
    try:
        out = subprocess.run([tool, "-D"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    interfaces = []
    for line in out.splitlines():
        match = re.match(r"^\s*\d+\.\s+(\S+)(?:\s+\((.*)\))?", line)
        if match:
            interfaces.append({"name": match.group(1), "description": match.group(2) or ""})
    return interfaces


class LiveSource(ABC):
    """Grows a pcap at ``out`` between ``start`` and ``stop``."""

    kind: str = ""

    def __init__(self) -> None:
        self.error: str | None = None

    @property
    @abstractmethod
    def label(self) -> str: ...

    @abstractmethod
    def start(self, out: Path) -> None: ...

    @abstractmethod
    def stop(self) -> None: ...

    @property
    @abstractmethod
    def running(self) -> bool: ...


class ReplaySource(LiveSource):
    """Replays ``capture`` into ``out``, compressing time by ``speed``.

    Idle gaps are capped at ``max_gap_sec`` so a capture stitched from runs
    hours apart still plays in a demo-length window.
    """

    kind = "replay"

    def __init__(self, capture: Path, *, speed: float = 20.0, max_gap_sec: float = 0.5) -> None:
        super().__init__()
        self.capture = Path(capture)
        self.speed = speed
        self.max_gap_sec = max_gap_sec
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def label(self) -> str:
        return f"replay of {self.capture.name}"

    def start(self, out: Path) -> None:
        self._thread = threading.Thread(target=self._run, args=(out,), daemon=True)
        self._thread.start()

    def _run(self, out: Path) -> None:
        from scapy.utils import PcapReader, PcapWriter  # noqa: PLC0415

        try:
            with PcapReader(str(self.capture)) as reader, PcapWriter(str(out), sync=True) as w:
                previous: float | None = None
                for pkt in reader:
                    if self._stop.is_set():
                        return
                    now = float(pkt.time)
                    if previous is not None:
                        gap = max(0.0, now - previous) / self.speed
                        if self._stop.wait(min(gap, self.max_gap_sec)):
                            return
                    previous = now
                    w.write(pkt)
        except Exception as exc:  # a corrupt capture ends the run, visibly
            self.error = f"replay failed: {exc}"

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()


class InterfaceSource(LiveSource):
    """``dumpcap`` on ``interface``, writing classic pcap so it can be read mid-write."""

    kind = "interface"

    def __init__(self, interface: str) -> None:
        super().__init__()
        self.interface = interface
        self._proc: subprocess.Popen | None = None

    @property
    def label(self) -> str:
        return f"interface {self.interface}"

    def start(self, out: Path) -> None:
        tool = dumpcap_path()
        if tool is None:
            raise RuntimeError("dumpcap not found -- install Wireshark / tshark")
        self._proc = subprocess.Popen(
            [tool, "-i", self.interface, "-P", "-q", "-f", CAPTURE_FILTER, "-w", str(out)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        # Permission and bad-interface errors surface within a second or so.
        try:
            code = self._proc.wait(timeout=1.5)
        except subprocess.TimeoutExpired:
            return
        stderr = (self._proc.stderr.read() if self._proc.stderr else "").strip()
        raise RuntimeError(stderr.splitlines()[-1] if stderr else f"dumpcap exited with {code}")

    def stop(self) -> None:
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()

    @property
    def running(self) -> bool:
        if self._proc is None:
            return False
        if self._proc.poll() is None:
            return True
        if self._proc.returncode not in (0, -15) and self.error is None:
            stderr = self._proc.stderr.read() if self._proc.stderr else ""
            self.error = stderr.strip() or f"dumpcap exited with {self._proc.returncode}"
        return False


def wait_for_file(path: Path, timeout: float = 5.0) -> bool:
    """True once ``path`` exists with at least a pcap global header in it."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists() and path.stat().st_size >= 24:
            return True
        time.sleep(0.05)
    return False
