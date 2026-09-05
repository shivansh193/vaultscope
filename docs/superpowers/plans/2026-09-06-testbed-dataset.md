# Stage 0 Testbed and Labeled Dataset Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generate a labeled dataset of >=300 real IPsec pcaps by running strongSwan peer pairs in Docker across a cipher/group/PFS/IP-version matrix and pushing six classes of traffic through them.

**Architecture:** A pure config generator produces `swanctl.conf` pairs from the matrix. A harness brings one pair up in Docker, waits for the SA, and tears it down. Per-class generator containers push traffic across the SA while tcpdump captures on the initiator. A runner walks a stratified sample of the matrix, writing one pcap plus one ground-truth JSON per cell.

**Tech Stack:** Python 3.11, Docker + Docker Compose, strongSwan 5.9 (Debian bookworm), scapy (verification only), pytest.

**Spec:** `docs/superpowers/specs/2026-09-06-testbed-dataset-design.md`

## Global Constraints

- Python 3.11; `pyproject.toml` sets `pythonpath = ["."]`, so `import testbed.x` works with no install step.
- Ruff: line length 100, target py311, rules `E,F,I,UP,B`. Run `ruff check . && ruff format --check .` before every commit.
- Tests needing Docker or a generated dataset are marked `@pytest.mark.slow`; `pytest -m "not slow"` must stay green without Docker.
- Do **not** add `Co-Authored-By: Claude` trailers to commits.
- One commit per task ID; branch `feat/p1-testbed`; commit subjects match the spec's commit map, e.g. `feat(testbed): cartesian config generator for strongSwan peer pairs`.
- Label JSON reuses `core.models.IkeParams` vocabulary exactly: `encryption` values like `AES-256-GCM`, `integrity: "implicit"` for GCM suites, `dh_group` values like `MODP2048` / `ECP256`, `pfs` boolean, `mode` in `{tunnel, transport}`, `ip_version` in `{IPv4, IPv6}`.
- Capture duration default 30s (deliberate deviation from spec Section 8's 120s; recorded in the dataset README).
- The testbed image MUST install `libstrongswan-standard-plugins`, `libstrongswan-extra-plugins` and `libcharon-extra-plugins` — plain `strongswan` has no crypto backend and every connection fails to load.

---

### Task 1: Cipher/group vocabulary and config generator

**Files:**
- Create: `testbed/__init__.py`
- Create: `testbed/matrix.py`
- Create: `testbed/config_generator.py`
- Test: `tests/testbed/test_config_generator.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `testbed.matrix.CipherSuite` — frozen dataclass with fields `slug: str`, `encryption: str`, `integrity: str`, `ike_proposal: str`, `esp_proposal: str`.
  - `testbed.matrix.CIPHER_SUITES: list[CipherSuite]`, `DH_GROUPS: list[tuple[str, str]]` (slug, strongSwan keyword), `MODES`, `IP_VERSIONS`.
  - `testbed.config_generator.TunnelConfig` — frozen dataclass with fields `name: str`, `mode: str`, `suite: CipherSuite`, `dh_slug: str`, `dh_keyword: str`, `pfs: bool`, `ip_version: str`; method `label_config() -> dict`.
  - `testbed.config_generator.generate_configs() -> list[TunnelConfig]`
  - `testbed.config_generator.render_swanctl(config, local_ip, remote_ip, local_id, remote_id) -> str`

- [ ] **Step 1: Write the failing test**

```python
# tests/testbed/test_config_generator.py
"""Stage 0 config generator (P1-T1)."""

import re

from testbed.config_generator import generate_configs, render_swanctl


def test_all_cipher_configs_generated():
    configs = generate_configs()
    assert len(configs) >= 96  # 2 x 6 x 3 x 2 x 2 minimum without traffic-type dim


def test_config_naming_convention():
    configs = generate_configs()
    for c in configs:
        assert re.match(r"^(tunnel|transport)_.+_.+_(pfs|nopfs)_(ipv4|ipv6)$", c.name)


def test_every_matrix_dimension_is_covered():
    configs = generate_configs()
    assert {c.mode for c in configs} == {"tunnel", "transport"}
    assert {c.ip_version for c in configs} == {"IPv4", "IPv6"}
    assert {c.pfs for c in configs} == {True, False}
    assert len({c.suite.slug for c in configs}) == 6
    assert len({c.dh_slug for c in configs}) == 3


def test_weak_suites_are_present_because_they_are_the_point():
    slugs = {c.suite.slug for c in generate_configs()}
    assert "descbc_md5" in slugs
    assert "3descbc_sha1" in slugs
    assert "modp1024" in {c.dh_slug for c in generate_configs()}


def test_label_config_speaks_the_canonical_models_vocabulary():
    from core.models import IkeParams

    config = next(c for c in generate_configs() if c.suite.slug == "aes256gcm")
    label = config.label_config()
    assert label["encryption"] == "AES-256-GCM"
    assert label["integrity"] == "implicit"
    # Every value must be assignable to the canonical model without translation.
    IkeParams(**{k: v for k, v in label.items() if k in IkeParams.model_fields})


def test_render_swanctl_is_loadable_shaped():
    config = generate_configs()[0]
    text = render_swanctl(config, "10.90.0.2", "10.90.0.3", "alice", "bob")
    assert "connections {" in text
    assert "local-1 {" in text and "remote-1 {" in text
    assert "secrets {" in text
    assert ";" not in text.replace("\n", "")  # swanctl.conf is newline-structured
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/testbed/test_config_generator.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'testbed.config_generator'`

- [ ] **Step 3: Write the matrix vocabulary**

```python
# testbed/matrix.py
"""The Stage 0 configuration matrix (spec Section 3).

One place that knows both strongSwan's proposal keywords and the canonical
`core.models.IkeParams` vocabulary, so a generated tunnel and its ground-truth
label cannot drift apart.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class CipherSuite:
    slug: str
    encryption: str  # core.models vocabulary
    integrity: str  # "implicit" for AEAD, matching IkeParams' own default
    ike_proposal: str  # strongSwan keyword, minus the DH group
    esp_proposal: str


# AEAD suites carry no separate integrity transform; "implicit" is the value
# core.models.IkeParams already uses for exactly that.
CIPHER_SUITES: list[CipherSuite] = [
    CipherSuite("aes128cbc_sha256", "AES-128-CBC", "HMAC-SHA256", "aes128-sha256", "aes128-sha256"),
    CipherSuite("aes256cbc_sha256", "AES-256-CBC", "HMAC-SHA256", "aes256-sha256", "aes256-sha256"),
    CipherSuite("aes128gcm", "AES-128-GCM", "implicit", "aes128gcm16-prfsha256", "aes128gcm16"),
    CipherSuite("aes256gcm", "AES-256-GCM", "implicit", "aes256gcm16-prfsha384", "aes256gcm16"),
    CipherSuite("3descbc_sha1", "3DES-CBC", "HMAC-SHA1", "3des-sha1", "3des-sha1"),
    CipherSuite("descbc_md5", "DES-CBC", "HMAC-MD5", "des-md5", "des-md5"),
]

# (label slug, strongSwan keyword). MODP1024 is here on purpose: rule R03 fires
# on it, and a dataset of only healthy tunnels would prove nothing about Stage 4c.
DH_GROUPS: list[tuple[str, str]] = [
    ("modp1024", "modp1024"),
    ("modp2048", "modp2048"),
    ("ecp256", "ecp256"),
]

MODES: list[str] = ["tunnel", "transport"]
IP_VERSIONS: list[str] = ["IPv4", "IPv6"]
```

- [ ] **Step 4: Write the config generator**

```python
# testbed/config_generator.py
"""Cartesian config generator for strongSwan peer pairs (P1-T1).

Pure: no Docker, no network, no file I/O. `generate_configs()` enumerates the
matrix and `render_swanctl()` turns one cell into a peer's swanctl.conf.
"""

from dataclasses import dataclass
from itertools import product

from testbed.matrix import CIPHER_SUITES, DH_GROUPS, IP_VERSIONS, MODES, CipherSuite

PSK = "vaultscope-testbed-psk"


@dataclass(frozen=True)
class TunnelConfig:
    name: str
    mode: str
    suite: CipherSuite
    dh_slug: str
    dh_keyword: str
    pfs: bool
    ip_version: str

    def label_config(self) -> dict:
        """Ground truth for this cell, in core.models.IkeParams vocabulary."""
        return {
            "version": "IKEv2",
            "mode": self.mode,
            "encryption": self.suite.encryption,
            "integrity": self.suite.integrity,
            "dh_group": self.dh_slug.upper(),
            "pfs_status": "enabled" if self.pfs else "disabled",
            "auth_method": "PSK",
            "ip_version": self.ip_version,
        }


def generate_configs() -> list[TunnelConfig]:
    configs = []
    for mode, suite, (dh_slug, dh_keyword), pfs, ip_version in product(
        MODES, CIPHER_SUITES, DH_GROUPS, [True, False], IP_VERSIONS
    ):
        name = "_".join(
            [
                mode,
                suite.slug,
                dh_slug,
                "pfs" if pfs else "nopfs",
                "ipv4" if ip_version == "IPv4" else "ipv6",
            ]
        )
        configs.append(TunnelConfig(name, mode, suite, dh_slug, dh_keyword, pfs, ip_version))
    return configs


def render_swanctl(
    config: TunnelConfig,
    local_ip: str,
    remote_ip: str,
    local_id: str,
    remote_id: str,
) -> str:
    """One peer's swanctl.conf.

    swanctl.conf is newline-structured; semicolons do not parse. PFS off means
    no DH group in the ESP proposal, so the child SA reuses the IKE SA's keys.
    """
    prefix = "128" if config.ip_version == "IPv6" else "32"
    esp = config.suite.esp_proposal + (f"-{config.dh_keyword}" if config.pfs else "")
    return f"""connections {{
    vaultscope {{
        version = 2
        local_addrs = {local_ip}
        remote_addrs = {remote_ip}
        proposals = {config.suite.ike_proposal}-{config.dh_keyword}
        local-1 {{
            auth = psk
            id = {local_id}
        }}
        remote-1 {{
            auth = psk
            id = {remote_id}
        }}
        children {{
            net {{
                local_ts = {local_ip}/{prefix}
                remote_ts = {remote_ip}/{prefix}
                mode = {config.mode}
                esp_proposals = {esp}
                start_action = none
            }}
        }}
    }}
}}
secrets {{
    ike-vaultscope {{
        id-1 = {local_id}
        id-2 = {remote_id}
        secret = "{PSK}"
    }}
}}
"""
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/testbed/test_config_generator.py -v`
Expected: 6 passed

- [ ] **Step 6: Lint and commit**

```bash
ruff check . && ruff format .
git add testbed/ tests/testbed/test_config_generator.py
git commit -m "feat(testbed): cartesian config generator for strongSwan peer pairs (P1-T1)"
```

---

### Task 2: Testbed image and peer harness

**Files:**
- Create: `testbed/Dockerfile`
- Create: `testbed/harness.py`
- Test: `tests/testbed/test_harness.py`

**Interfaces:**
- Consumes: `testbed.config_generator.TunnelConfig`, `render_swanctl`.
- Produces:
  - `testbed.harness.IMAGE: str` (`"vaultscope-testbed"`)
  - `testbed.harness.PeerPair` — object with attributes `initiator: str` (container name), `responder: str`, `initiator_ip: str`, `responder_ip: str`, `network: str`; methods `exec(container, *argv, check=True) -> subprocess.CompletedProcess`, `start_capture(path_in_container)`, `stop_capture()`, `copy_out(container, src, dest)`.
  - `testbed.harness.build_image() -> None`
  - `testbed.harness.ipv6_supported() -> bool`
  - `testbed.harness.peer_pair(config, index) -> contextlib.AbstractContextManager[PeerPair]`
  - `testbed.harness.HarnessError` — raised when an SA will not establish.

- [ ] **Step 1: Write the failing test**

```python
# tests/testbed/test_harness.py
"""Peer harness (P1-T1). Needs Docker, so every test here is slow."""

import pytest

from testbed import harness
from testbed.config_generator import generate_configs

pytestmark = pytest.mark.slow


@pytest.fixture(scope="module")
def image():
    harness.build_image()


def test_strongswan_config_syntax_valid(image):
    """The spec's mandatory P1-T1 test: generated configs load into swanctl."""
    config = next(c for c in generate_configs() if c.name.startswith("tunnel_aes256gcm"))
    with harness.peer_pair(config, index=90) as pair:
        result = pair.exec(pair.initiator, "swanctl", "--load-all")
        assert result.returncode == 0
        assert "loaded connection 'vaultscope'" in result.stdout


def test_pair_establishes_a_real_sa(image):
    config = next(c for c in generate_configs() if c.name.startswith("tunnel_aes256gcm"))
    with harness.peer_pair(config, index=91) as pair:
        pair.establish()
        sas = pair.exec(pair.initiator, "swanctl", "--list-sas").stdout
        assert "ESTABLISHED" in sas
        assert "INSTALLED" in sas


def test_a_config_that_cannot_establish_raises_rather_than_hanging(image):
    """A cell that will not come up must fail fast, not stall a 300-cell run."""
    config = next(c for c in generate_configs() if c.name.startswith("tunnel_aes256gcm"))
    with harness.peer_pair(config, index=92) as pair:
        pair.exec(pair.responder, "pkill", "-f", "charon", check=False)
        with pytest.raises(harness.HarnessError):
            pair.establish(timeout=8)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/testbed/test_harness.py -v -m slow`
Expected: FAIL with `AttributeError: module 'testbed.harness' has no attribute 'build_image'`

- [ ] **Step 3: Write the Dockerfile**

```dockerfile
# testbed/Dockerfile
# strongSwan peer for the Stage 0 testbed, plus the traffic generators that
# ride the tunnel. One image for both peers; role is decided by the mounted
# swanctl.conf.
FROM debian:bookworm-slim

# The plugin packages are not optional: plain `strongswan` ships no crypto
# backend, and every connection fails to load with "invalid value for: auth".
RUN apt-get update && apt-get install -y --no-install-recommends \
        strongswan strongswan-swanctl charon-systemd \
        libstrongswan-standard-plugins libstrongswan-extra-plugins \
        libcharon-extra-plugins \
        iproute2 iputils-ping tcpdump procps \
        curl nginx ffmpeg sipp postfix swaks python3 \
    && rm -rf /var/lib/apt/lists/*

COPY generators /opt/generators
CMD ["sleep", "infinity"]
```

- [ ] **Step 4: Write the harness**

```python
# testbed/harness.py
"""Brings one strongSwan peer pair up in Docker and tears it down (P1-T1).

Each pair gets its own Docker network so pairs can run concurrently. Every
failure path tears the pair down: a cell that will not establish must not leak
containers into the next 300 cells.
"""

import contextlib
import shutil
import subprocess
import tempfile
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from testbed.config_generator import TunnelConfig, render_swanctl

IMAGE = "vaultscope-testbed"
TESTBED_DIR = Path(__file__).resolve().parent


class HarnessError(RuntimeError):
    """A peer pair could not be brought up or would not establish."""


def ipv6_supported() -> bool:
    """Docker only routes IPv6 when the daemon is configured for it.

    Probing once beats watching every IPv6 cell fail one at a time.
    """
    probe = "vs-ipv6-probe"
    _run(["docker", "network", "rm", probe], check=False)
    created = _run(
        ["docker", "network", "create", "--ipv6", "--subnet", "fd00:dead:beef::/64", probe],
        check=False,
    )
    _run(["docker", "network", "rm", probe], check=False)
    return created.returncode == 0


def build_image() -> None:
    subprocess.run(
        ["docker", "build", "-q", "-t", IMAGE, str(TESTBED_DIR)],
        check=True,
        capture_output=True,
        text=True,
    )


def _run(argv: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(argv, check=check, capture_output=True, text=True)


@dataclass
class PeerPair:
    network: str
    initiator: str
    responder: str
    initiator_ip: str
    responder_ip: str
    _capture: str | None = None

    def exec(self, container: str, *argv: str, check: bool = True):
        return _run(["docker", "exec", container, *argv], check=check)

    def establish(self, timeout: int = 30) -> None:
        """Load configs on both peers and initiate, waiting for INSTALLED."""
        for peer in (self.responder, self.initiator):
            self.exec(peer, "swanctl", "--load-all", check=False)
        self.exec(self.initiator, "swanctl", "--initiate", "--child", "net", check=False)

        deadline = time.time() + timeout
        while time.time() < deadline:
            sas = self.exec(self.initiator, "swanctl", "--list-sas", check=False).stdout
            if "INSTALLED" in sas:
                return
            time.sleep(1)

        log = self.exec(self.initiator, "cat", "/tmp/charon.log", check=False).stdout
        raise HarnessError(f"SA did not establish within {timeout}s. charon said:\n{log[-2000:]}")

    def start_capture(self, path: str = "/tmp/capture.pcap") -> None:
        self._capture = path
        _run(
            [
                "docker", "exec", "-d", self.initiator,
                "tcpdump", "-i", "any", "-w", path, "-U", "-s", "0",
                "udp port 500 or udp port 4500 or esp or ip proto 50",
            ]
        )
        time.sleep(1)  # let tcpdump open the file before traffic starts

    def stop_capture(self) -> None:
        self.exec(self.initiator, "pkill", "-INT", "tcpdump", check=False)
        time.sleep(1)

    def copy_out(self, container: str, src: str, dest: Path) -> None:
        dest.parent.mkdir(parents=True, exist_ok=True)
        _run(["docker", "cp", f"{container}:{src}", str(dest)])


@contextlib.contextmanager
def peer_pair(config: TunnelConfig, index: int) -> Iterator[PeerPair]:
    """One initiator/responder pair on its own network, torn down on exit."""
    if shutil.which("docker") is None:
        raise HarnessError("docker is not on PATH")

    network = f"vs-net-{index}"
    initiator, responder = f"vs-i-{index}", f"vs-r-{index}"
    ipv6 = config.ip_version == "IPv6"
    if ipv6:
        subnet, local_ip, remote_ip = f"fd00:90:{index}::/64", f"fd00:90:{index}::2", f"fd00:90:{index}::3"
    else:
        subnet, local_ip, remote_ip = f"10.90.{index}.0/24", f"10.90.{index}.2", f"10.90.{index}.3"

    workdir = Path(tempfile.mkdtemp(prefix="vs-testbed-"))
    (workdir / "i.conf").write_text(render_swanctl(config, local_ip, remote_ip, "alice", "bob"))
    (workdir / "r.conf").write_text(render_swanctl(config, remote_ip, local_ip, "bob", "alice"))

    net_argv = ["docker", "network", "create", "--subnet", subnet, network]
    if ipv6:
        net_argv.insert(3, "--ipv6")
    _run(net_argv, check=False)

    try:
        for name, ip, conf in ((initiator, local_ip, "i.conf"), (responder, remote_ip, "r.conf")):
            _run(
                [
                    "docker", "run", "-d", "--name", name, "--network", network,
                    "--ip6" if ipv6 else "--ip", ip, "--privileged",
                    "-v", f"{workdir / conf}:/etc/swanctl/conf.d/vaultscope.conf",
                    IMAGE, "sleep", "infinity",
                ]
            )
            _run(
                ["docker", "exec", "-d", name, "sh", "-c",
                 "/usr/sbin/charon-systemd > /tmp/charon.log 2>&1"]
            )
        time.sleep(4)  # charon needs a moment before its socket accepts swanctl
        yield PeerPair(network, initiator, responder, local_ip, remote_ip)
    finally:
        for name in (initiator, responder):
            _run(["docker", "rm", "-f", name], check=False)
        _run(["docker", "network", "rm", network], check=False)
        shutil.rmtree(workdir, ignore_errors=True)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/testbed/test_harness.py -v -m slow`
Expected: 3 passed (takes a few minutes; the first run builds the image)

- [ ] **Step 6: Verify the fast suite is unaffected**

Run: `pytest -m "not slow" -q`
Expected: all existing tests still pass, harness tests deselected

- [ ] **Step 7: Lint and commit**

```bash
ruff check . && ruff format .
git add testbed/ tests/testbed/test_harness.py
git commit -m "feat(testbed): strongSwan peer-pair harness in Docker (P1-T1)"
```

---

### Task 3: Traffic generators

**Files:**
- Create: `testbed/generators/__init__.py`
- Create: `testbed/generators/chat.py`
- Create: `testbed/generators/run.py`
- Test: `tests/testbed/test_generators.py`

**Interfaces:**
- Consumes: `testbed.harness.PeerPair`.
- Produces:
  - `testbed.generators.run.TRAFFIC_CLASSES: list[str]` — `["VoIP", "Video", "Web", "Email", "ICMP", "Chat"]`
  - `testbed.generators.run.GENERATORS: dict[str, Generator]` where `Generator` is a frozen dataclass with `name: str`, `substitution: bool`, `description: str`, `server: list[str] | None`, `client: list[str]` (argv templates taking `{peer}` and `{duration}`).
  - `testbed.generators.run.run_traffic(pair, traffic_class, duration) -> None`

- [ ] **Step 1: Write the failing test**

```python
# tests/testbed/test_generators.py
"""Traffic generators (P1-T2)."""

import re

import pytest

from testbed.generators.run import GENERATORS, TRAFFIC_CLASSES, run_traffic


def test_every_class_in_the_spec_has_a_generator():
    assert set(GENERATORS) == set(TRAFFIC_CLASSES)
    assert len(TRAFFIC_CLASSES) == 6


def test_chat_is_declared_a_substitution_and_nothing_else_is():
    substitutions = {name for name, g in GENERATORS.items() if g.substitution}
    assert substitutions == {"Chat"}
    assert "substitut" in GENERATORS["Chat"].description.lower()


def test_client_argv_templates_take_peer_and_duration():
    for name, generator in GENERATORS.items():
        joined = " ".join(generator.client)
        assert "{peer}" in joined, f"{name} never addresses the peer"
        assert "{duration}" in joined, f"{name} never bounds its runtime"


@pytest.mark.slow
def test_traffic_actually_crosses_the_tunnel():
    from testbed import harness
    from testbed.config_generator import generate_configs

    harness.build_image()
    config = next(c for c in generate_configs() if c.name.startswith("tunnel_aes256gcm"))
    with harness.peer_pair(config, index=93) as pair:
        pair.establish()
        def bytes_out() -> int:
            """Bytes the SA has actually protected, from swanctl's own counter."""
            text = pair.exec(pair.initiator, "swanctl", "--list-sas", "--raw").stdout
            match = re.search(r"bytes-out=(\d+)", text)
            return int(match.group(1)) if match else 0

        before = bytes_out()
        run_traffic(pair, "ICMP", duration=5)
        assert bytes_out() > before, "no traffic crossed the SA"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/testbed/test_generators.py -v -m "not slow"`
Expected: FAIL with `ModuleNotFoundError: No module named 'testbed.generators'`

- [ ] **Step 3: Write the chat generator**

```python
# testbed/generators/chat.py
"""Bursty chat-shaped traffic.

This is the spec's declared WhatsApp substitution: a real messaging client
cannot run in an isolated lab, so this reproduces the shape -- short messages
in bursts, long human idle gaps -- over a plain TCP socket. Every label it
produces is marked substitution: true. Do not present it as real chat traffic.
"""

import random
import socket
import sys
import time

PORT = 5222


def serve(duration: float) -> None:
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("", PORT))
        server.listen(1)
        server.settimeout(duration)
        try:
            conn, _ = server.accept()
        except socket.timeout:
            return
        with conn:
            conn.settimeout(duration)
            deadline = time.time() + duration
            while time.time() < deadline:
                try:
                    data = conn.recv(4096)
                except socket.timeout:
                    return
                if not data:
                    return
                conn.sendall(b"x" * random.randint(30, 200))  # a reply, same shape


def send(peer: str, duration: float, seed: int = 0) -> None:
    rng = random.Random(seed)
    deadline = time.time() + duration
    with socket.create_connection((peer, PORT), timeout=10) as sock:
        while time.time() < deadline:
            for _ in range(rng.randint(1, 5)):  # a burst of messages
                sock.sendall(b"m" * rng.randint(20, 300))
                sock.recv(4096)
                time.sleep(rng.uniform(0.2, 1.2))
            time.sleep(rng.uniform(2.0, 6.0))  # then the human stops typing


if __name__ == "__main__":
    role, peer, duration = sys.argv[1], sys.argv[2], float(sys.argv[3])
    serve(duration) if role == "serve" else send(peer, duration)
```

- [ ] **Step 4: Write the generator registry**

```python
# testbed/generators/run.py
"""One traffic generator per class, all riding the tunnel (P1-T2).

Five of the six classes use the protocol's real tool. Chat does not -- see
chat.py -- and is marked as a substitution everywhere it appears.
"""

import time
from dataclasses import dataclass, field

from testbed.harness import PeerPair

TRAFFIC_CLASSES = ["VoIP", "Video", "Web", "Email", "ICMP", "Chat"]


@dataclass(frozen=True)
class Generator:
    name: str
    description: str
    client: list[str]
    server: list[str] | None = None
    substitution: bool = False
    settle: float = 2.0
    env: dict = field(default_factory=dict)


GENERATORS: dict[str, Generator] = {
    "VoIP": Generator(
        name="sipp",
        description="sipp UAC against a UAS, G.711-rate RTP media",
        server=["sipp", "-sn", "uas", "-bg"],
        client=["sipp", "-sn", "uac", "-r", "2", "-d", "{duration}000", "-timeout", "{duration}s", "{peer}"],
    ),
    "Video": Generator(
        name="ffmpeg",
        description="ffmpeg streaming a generated test pattern over RTP",
        client=[
            "ffmpeg", "-re", "-f", "lavfi", "-i", "testsrc=size=640x480:rate=25",
            "-t", "{duration}", "-c:v", "libx264", "-preset", "ultrafast",
            "-f", "rtp", "rtp://{peer}:5004",
        ],
    ),
    "Web": Generator(
        name="curl + nginx",
        description="curl looping fetches of mixed-size objects from nginx",
        server=["nginx", "-g", "daemon off;"],
        client=["sh", "-c", "end=$(( $(date +%s) + {duration} )); while [ $(date +%s) -lt $end ]; do curl -s -o /dev/null http://{peer}/; sleep 0.3; done"],
    ),
    "Email": Generator(
        name="swaks + Postfix",
        description="swaks sending messages with attachments to Postfix",
        server=["sh", "-c", "postfix start-fg"],
        client=["sh", "-c", "end=$(( $(date +%s) + {duration} )); while [ $(date +%s) -lt $end ]; do swaks --to test@example.com --server {peer} --attach-type text/plain --attach - <<< \"$(head -c 20000 /dev/urandom | base64)\" >/dev/null 2>&1; sleep 2; done"],
    ),
    "ICMP": Generator(
        name="ping",
        description="ping at a fixed interval",
        client=["ping", "-i", "0.2", "-w", "{duration}", "{peer}"],
    ),
    "Chat": Generator(
        name="scripted bursty sender",
        description=(
            "Substitution for a real messaging client, which cannot run in an "
            "isolated lab: short messages in bursts with human idle gaps."
        ),
        server=["python3", "/opt/generators/chat.py", "serve", "-", "{duration}"],
        client=["python3", "/opt/generators/chat.py", "send", "{peer}", "{duration}"],
        substitution=True,
    ),
}


def _fill(argv: list[str], peer: str, duration: int) -> list[str]:
    return [a.replace("{peer}", peer).replace("{duration}", str(duration)) for a in argv]


def run_traffic(pair: PeerPair, traffic_class: str, duration: int) -> None:
    """Run one class of traffic across an established SA, blocking until done."""
    generator = GENERATORS[traffic_class]

    if generator.server:
        argv = _fill(generator.server, pair.initiator_ip, duration)
        pair.exec(pair.responder, "sh", "-c", " ".join(argv) + " &", check=False)
        time.sleep(generator.settle)

    argv = _fill(generator.client, pair.responder_ip, duration)
    pair.exec(pair.initiator, *argv, check=False)
```

- [ ] **Step 5: Run the fast tests**

Run: `pytest tests/testbed/test_generators.py -v -m "not slow"`
Expected: 3 passed

- [ ] **Step 6: Run the slow test**

Run: `pytest tests/testbed/test_generators.py -v -m slow`
Expected: 1 passed

- [ ] **Step 7: Lint and commit**

```bash
ruff check . && ruff format .
git add testbed/generators tests/testbed/test_generators.py
git commit -m "feat(testbed): traffic generators for all six classes (P1-T2)"
```

---

### Task 4: Capture, labels and the dataset runner

**Files:**
- Create: `testbed/labels.py`
- Create: `scripts/generate_dataset.py`
- Test: `tests/testbed/test_labels.py`

**Interfaces:**
- Consumes: everything from Tasks 1-3.
- Produces:
  - `testbed.labels.LABEL_KEYS: set[str]`
  - `testbed.labels.build_label(config, traffic_class, duration, pcap_name, testbed_commit) -> dict`
  - `testbed.labels.write_label(path, label) -> None`
  - `scripts/generate_dataset.py` CLI: `--target`, `--duration`, `--parallel`, `--seed`, `--out`

- [ ] **Step 1: Write the failing test**

```python
# tests/testbed/test_labels.py
"""Ground-truth label schema (P1-T3)."""

import json

from testbed.config_generator import generate_configs
from testbed.labels import LABEL_KEYS, build_label, write_label


def _label(traffic_class="VoIP"):
    config = next(c for c in generate_configs() if c.suite.slug == "aes256gcm")
    return build_label(config, traffic_class, duration=30, pcap_name="x.pcap", testbed_commit="abc123")


def test_label_carries_every_required_key():
    assert LABEL_KEYS <= set(_label())


def test_label_records_configuration_not_observation():
    label = _label()
    assert label["config"]["encryption"] == "AES-256-GCM"
    assert label["config"]["auth_method"] == "PSK"
    assert label["config"]["ike_version"] == "IKEv2"


def test_chat_is_flagged_as_a_substitution_and_voip_is_not():
    assert _label("Chat")["substitution"] is True
    assert _label("VoIP")["substitution"] is False


def test_nat_traversal_artifact_is_disclosed():
    notes = " ".join(_label()["harness_notes"]).lower()
    assert "4500" in notes and "artifact" in notes


def test_write_label_round_trips(tmp_path):
    path = tmp_path / "x.json"
    write_label(path, _label())
    assert json.loads(path.read_text())["traffic_class"] == "VoIP"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/testbed/test_labels.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'testbed.labels'`

- [ ] **Step 3: Write the label builder**

```python
# testbed/labels.py
"""Ground-truth labels for the dataset (P1-T3).

A label records what was *configured*, never what a parser recovered. Field
names and values reuse core.models.IkeParams vocabulary so a label can be
compared to a parsed session without a translation layer.
"""

import json
from datetime import UTC, datetime
from pathlib import Path

from testbed.config_generator import TunnelConfig
from testbed.generators.run import GENERATORS

LABEL_KEYS = {
    "pcap",
    "traffic_class",
    "substitution",
    "generator",
    "duration_sec",
    "config",
    "harness_notes",
    "captured_at",
    "testbed_commit",
}

# Disclosed up front rather than left for a consumer to misread as a finding.
HARNESS_NOTES = [
    "IKE observed on UDP 4500: Docker's NAT triggers NAT-T. An artifact of the "
    "harness, not of the configuration under test.",
    "Lab-clean capture: no cross-traffic, so real-world classifier accuracy will be lower.",
]


def build_label(
    config: TunnelConfig,
    traffic_class: str,
    duration: int,
    pcap_name: str,
    testbed_commit: str,
) -> dict:
    generator = GENERATORS[traffic_class]
    return {
        "pcap": pcap_name,
        "traffic_class": traffic_class,
        "substitution": generator.substitution,
        "generator": f"{generator.name} -- {generator.description}",
        "duration_sec": duration,
        "config": {**config.label_config(), "ike_version": "IKEv2"},
        "harness_notes": list(HARNESS_NOTES),
        "captured_at": datetime.now(UTC).isoformat(),
        "testbed_commit": testbed_commit,
    }


def write_label(path: Path, label: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(label, indent=2) + "\n")
```

- [ ] **Step 4: Write the dataset runner**

```python
# scripts/generate_dataset.py
"""Generate the labeled dataset (P1-T3, P1-T4).

    python scripts/generate_dataset.py --target 300 --duration 30 --parallel 4

Walks a stratified sample of the config matrix. For each cell: bring a peer
pair up, capture on the initiator, run the traffic generator, tear down, write
the pcap and its ground-truth label. Cells already on disk are skipped, so an
interrupted run resumes.
"""

import argparse
import random
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from testbed import harness  # noqa: E402
from testbed.config_generator import generate_configs  # noqa: E402
from testbed.generators.run import TRAFFIC_CLASSES, run_traffic  # noqa: E402
from testbed.labels import build_label, write_label  # noqa: E402

MIN_PACKETS = 20


def stratified_sample(target: int, seed: int) -> list[tuple]:
    """Every cipher, group and PFS state in every class, then fill at random.

    A plain head-of-list slice would give 300 captures that all share a cipher.
    """
    rng = random.Random(seed)
    configs = generate_configs()
    chosen: list[tuple] = []
    seen: set[tuple] = set()

    # The dimensions that must each be represented in every traffic class.
    dimensions = {
        "cipher": lambda c: c.suite.slug,
        "group": lambda c: c.dh_slug,
        "pfs": lambda c: c.pfs,
    }

    for traffic_class in TRAFFIC_CLASSES:
        for read in dimensions.values():
            for value in sorted({str(read(c)) for c in configs}):
                pool = [c for c in configs if str(read(c)) == value]
                pick = rng.choice(pool)
                if (pick.name, traffic_class) not in seen:
                    seen.add((pick.name, traffic_class))
                    chosen.append((pick, traffic_class))

    everything = [(c, t) for c in configs for t in TRAFFIC_CLASSES if (c.name, t) not in seen]
    rng.shuffle(everything)
    chosen.extend(everything[: max(0, target - len(chosen))])
    return chosen[:target]


def capture_cell(config, traffic_class: str, duration: int, index: int, out: Path, commit: str) -> str:
    stem = f"{config.name}__{traffic_class.lower()}"
    pcap_path = out / "pcaps" / f"{stem}.pcap"
    label_path = out / "labels" / f"{stem}.json"
    if pcap_path.exists() and label_path.exists():
        return f"skip {stem}"

    try:
        with harness.peer_pair(config, index=index) as pair:
            pair.establish()
            pair.start_capture()
            run_traffic(pair, traffic_class, duration)
            pair.stop_capture()
            pair.copy_out(pair.initiator, "/tmp/capture.pcap", pcap_path)
    except Exception as error:  # one bad cell must not sink the run
        return f"FAIL {stem}: {error}"

    if not pcap_path.exists() or pcap_path.stat().st_size < 200:
        pcap_path.unlink(missing_ok=True)
        return f"FAIL {stem}: capture empty"

    from scapy.utils import rdpcap

    packets = len(rdpcap(str(pcap_path)))
    if packets < MIN_PACKETS:
        pcap_path.unlink(missing_ok=True)
        return f"FAIL {stem}: only {packets} packets"

    write_label(label_path, build_label(config, traffic_class, duration, pcap_path.name, commit))
    return f"ok   {stem} ({packets} packets)"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=int, default=300)
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--parallel", type=int, default=4)
    parser.add_argument("--seed", type=int, default=20260906)
    parser.add_argument("--out", type=Path, default=ROOT / "data")
    args = parser.parse_args()

    if shutil.which("docker") is None:
        print("docker is not on PATH", file=sys.stderr)
        return 2
    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        print("the docker daemon is not running", file=sys.stderr)
        return 2

    commit = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True
    ).stdout.strip()

    print(f"building {harness.IMAGE}")
    harness.build_image()

    cells = stratified_sample(args.target, args.seed)
    if not harness.ipv6_supported():
        dropped = [c for c in cells if c[0].ip_version == "IPv6"]
        cells = [c for c in cells if c[0].ip_version == "IPv4"]
        print(f"docker has no usable IPv6; dropping {len(dropped)} IPv6 cells")
        # Refill from IPv4 so the target is still met.
        extra = [
            (config, klass)
            for config, klass in stratified_sample(args.target * 3, args.seed + 1)
            if config.ip_version == "IPv4" and (config.name, klass) not in {(c.name, k) for c, k in cells}
        ]
        cells.extend(extra[: max(0, args.target - len(cells))])
    print(f"{len(cells)} cells, {args.duration}s each, {args.parallel} at a time")

    failures = []
    with ThreadPoolExecutor(max_workers=args.parallel) as pool:
        futures = {
            pool.submit(capture_cell, config, klass, args.duration, i % args.parallel + 10, args.out, commit): (config, klass)
            for i, (config, klass) in enumerate(cells)
        }
        for done, future in enumerate(as_completed(futures), 1):
            line = future.result()
            if line.startswith("FAIL"):
                failures.append(line)
            print(f"[{done}/{len(cells)}] {line}", flush=True)

    written = len(list((args.out / "pcaps").glob("*.pcap")))
    print(f"\n{written} pcaps in {args.out / 'pcaps'}, {len(failures)} failures")
    for line in failures:
        print(f"  {line}")
    return 0 if written >= 1 else 1


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 5: Run the label tests**

Run: `pytest tests/testbed/test_labels.py -v`
Expected: 5 passed

- [ ] **Step 6: Smoke the runner on a tiny target**

Run: `python scripts/generate_dataset.py --target 4 --duration 5 --parallel 2 --out /tmp/vs-smoke`
Expected: 4 lines of `ok`, `4 pcaps in /tmp/vs-smoke/pcaps, 0 failures`

- [ ] **Step 7: Lint and commit**

```bash
ruff check . && ruff format .
git add testbed/labels.py scripts/generate_dataset.py tests/testbed/test_labels.py
git commit -m "feat(testbed): capture script, ground-truth labels and dataset runner (P1-T3)"
```

---

### Task 5: Generate the dataset and pin its balance

**Files:**
- Create: `tests/dataset/test_dataset_class_balance.py`
- Create: `data/README.md`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: `scripts/generate_dataset.py`.
- Produces: `data/pcaps/*.pcap`, `data/labels/*.json`, and the deliverable-1 test.

- [ ] **Step 1: Write the failing test**

```python
# tests/dataset/test_dataset_class_balance.py
"""Deliverable 1: the labeled dataset (spec Section 13)."""

import json
from pathlib import Path

import pytest

from testbed.generators.run import TRAFFIC_CLASSES

pytestmark = pytest.mark.slow

ROOT = Path(__file__).resolve().parent.parent.parent
PCAPS = ROOT / "data" / "pcaps"
LABELS = ROOT / "data" / "labels"


def _labels():
    return [json.loads(p.read_text()) for p in sorted(LABELS.glob("*.json"))]


def test_dataset_class_balance():
    labels = _labels()
    assert len(labels) >= 300, f"deliverable 1 wants >= 300 captures, found {len(labels)}"

    counts = {klass: 0 for klass in TRAFFIC_CLASSES}
    for label in labels:
        counts[label["traffic_class"]] += 1

    assert all(counts.values()), f"a class has no samples: {counts}"
    floor = 0.5 * (len(labels) / len(TRAFFIC_CLASSES))
    assert min(counts.values()) >= floor, f"class imbalance beyond 2:1: {counts}"


def test_every_pcap_has_a_label_and_vice_versa():
    pcaps = {p.stem for p in PCAPS.glob("*.pcap")}
    labels = {p.stem for p in LABELS.glob("*.json")}
    assert pcaps == labels


def test_label_schema_valid():
    from testbed.labels import LABEL_KEYS

    for label in _labels():
        assert LABEL_KEYS <= set(label)
        assert label["config"]["encryption"]
        assert isinstance(label["substitution"], bool)


def test_the_matrix_is_actually_varied():
    configs = [label["config"] for label in _labels()]
    assert len({c["encryption"] for c in configs}) >= 4
    assert len({c["dh_group"] for c in configs}) == 3
    assert {c["pfs_status"] for c in configs} == {"enabled", "disabled"}


def test_substitution_classes_are_declared():
    for label in _labels():
        if label["traffic_class"] == "Chat":
            assert label["substitution"] is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/dataset -v -m slow`
Expected: FAIL — `deliverable 1 wants >= 300 captures, found 0`

- [ ] **Step 3: Decide what gets committed**

Pcaps are binary and large. Commit the labels (small, reviewable, the ground
truth) and ignore the pcaps, with the README explaining how to regenerate them.

```bash
# .gitignore — append
data/pcaps/*.pcap
!data/pcaps/.gitkeep
```

- [ ] **Step 4: Generate the dataset**

Run: `python scripts/generate_dataset.py --target 300 --duration 30 --parallel 4`
Expected: roughly 40 minutes; a final line reporting >= 300 pcaps written

- [ ] **Step 5: Run the balance test**

Run: `pytest tests/dataset -v -m slow`
Expected: 5 passed

- [ ] **Step 6: Write the dataset README**

`data/README.md` covering: what the dataset is, the matrix, the naming
convention, the label schema, how to regenerate, and three disclosed
limitations — the Chat substitution, the lab-clean caveat, and the NAT-T
harness artifact.

- [ ] **Step 7: Commit**

```bash
git add data/labels data/README.md .gitignore tests/dataset
git commit -m "feat(dataset): 300-capture labeled IPsec dataset across the config matrix (P1-T4)"
```

---

### Task 6: Documentation and deliverable tracking

**Files:**
- Modify: `CLAUDE.md`
- Modify: `README.md`
- Create: `testbed/CLAUDE.md`

- [ ] **Step 1: Write the subtree guide**

`testbed/CLAUDE.md`: module map (`matrix`, `config_generator`, `harness`,
`generators`, `labels`), the two harness gotchas discovered by the probe
(missing crypto plugins, NAT-T artifact), how to run one cell by hand, and the
30s-vs-120s deviation.

- [ ] **Step 2: Update the root CLAUDE.md**

Project status: Stage 0 done. Commands: add `python scripts/generate_dataset.py`.
Subtree guides: add `testbed/CLAUDE.md`. Change log: a P1-T1..T4 entry.

- [ ] **Step 3: Add the deliverables table to README**

Spec Section 13 says status is tracked in the README. Add the twelve-row table
with current status, and a "Disclosed limitations" section covering the Chat
substitution, lab-clean accuracy, mid-session captures, and NAT-T — closing
deliverable 12, which is currently missing.

- [ ] **Step 4: Verify and commit**

```bash
pytest -m "not slow" -q && ruff check . && ruff format --check .
git add CLAUDE.md README.md testbed/CLAUDE.md
git commit -m "docs(testbed): dataset guide, deliverable tracking and disclosed limitations"
```
