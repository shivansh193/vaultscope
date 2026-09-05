"""Generate the labeled dataset (P1-T3, P1-T4).

    python scripts/generate_dataset.py --target 300 --duration 30 --parallel 4

Walks a stratified sample of the config matrix. For each cell: bring a peer
pair up, capture on the initiator, run the traffic generator, tear down, write
the pcap and its ground-truth label. Cells already on disk are skipped, so an
interrupted run resumes rather than restarting.
"""

import argparse
import random
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from queue import Queue

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from testbed import harness  # noqa: E402
from testbed.config_generator import TunnelConfig, generate_configs  # noqa: E402
from testbed.generators.run import TRAFFIC_CLASSES, run_traffic  # noqa: E402
from testbed.labels import build_label, write_label  # noqa: E402

# Below this a capture is not a sample of anything, whatever the generator did.
MIN_PACKETS = 20


def stratified_sample(target: int, seed: int, ipv4_only: bool = False) -> list[tuple]:
    """Every cipher, group and PFS state in every class, then fill at random.

    A plain head-of-list slice would hand back 300 captures that all share a
    cipher suite, which would teach a classifier the wrong thing and prove
    nothing about the rule engine.
    """
    rng = random.Random(seed)
    configs = generate_configs()
    if ipv4_only:
        configs = [c for c in configs if c.ip_version == "IPv4"]

    dimensions = {
        "cipher": lambda c: c.suite.slug,
        "group": lambda c: c.dh_slug,
        "pfs": lambda c: str(c.pfs),
    }

    chosen: list[tuple] = []
    seen: set[tuple] = set()
    for traffic_class in TRAFFIC_CLASSES:
        for read in dimensions.values():
            for value in sorted({read(c) for c in configs}):
                pool = [c for c in configs if read(c) == value]
                pick = rng.choice(pool)
                if (pick.name, traffic_class) not in seen:
                    seen.add((pick.name, traffic_class))
                    chosen.append((pick, traffic_class))

    everything = [(c, t) for c in configs for t in TRAFFIC_CLASSES if (c.name, t) not in seen]
    rng.shuffle(everything)
    chosen.extend(everything[: max(0, target - len(chosen))])
    return chosen[:target]


def capture_cell(
    config: TunnelConfig,
    traffic_class: str,
    duration: int,
    slots: "Queue[int]",
    out: Path,
    commit: str,
) -> str:
    """Run one cell. Borrows a slot number for the duration.

    The slot decides the Docker network and container names, so it has to be
    unique among *concurrently running* cells -- not merely among submitted
    ones, which is what indexing by position would give.
    """
    stem = f"{config.name}__{traffic_class.lower()}"
    pcap_path = out / "pcaps" / f"{stem}.pcap"
    label_path = out / "labels" / f"{stem}.json"
    if pcap_path.exists() and label_path.exists():
        return f"skip {stem}"

    index = slots.get()
    try:
        with harness.peer_pair(config, index=index) as pair:
            # Capture first: the IKE handshake happens during establish(), and
            # starting tcpdump afterwards records only the ESP data plane --
            # which parses as a crypto-less "esp-only" session.
            pair.start_capture()
            pair.establish()
            run_traffic(pair, traffic_class, duration)
            pair.stop_capture()
            pair.copy_out(pair.initiator, "/tmp/capture.pcap", pcap_path)
    except Exception as error:  # one bad cell must not sink a 300-cell run
        return f"FAIL {stem}: {str(error)[:160]}"
    finally:
        slots.put(index)

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

    ipv4_only = not harness.ipv6_supported()
    if ipv4_only:
        print("docker has no usable IPv6; restricting the sample to IPv4 cells")
    cells = stratified_sample(args.target, args.seed, ipv4_only=ipv4_only)
    print(f"{len(cells)} cells, {args.duration}s each, {args.parallel} at a time", flush=True)

    slots: Queue[int] = Queue()
    for slot in range(10, 10 + args.parallel):
        slots.put(slot)

    failures: list[str] = []
    with ThreadPoolExecutor(max_workers=args.parallel) as pool:
        futures = {
            pool.submit(capture_cell, config, klass, args.duration, slots, args.out, commit): (
                config,
                klass,
            )
            for config, klass in cells
        }
        for done, future in enumerate(as_completed(futures), 1):
            line = future.result()
            if line.startswith("FAIL"):
                failures.append(line)
            print(f"[{done}/{len(cells)}] {line}", flush=True)

    written = len(list((args.out / "pcaps").glob("*.pcap")))
    print(f"\n{written} pcaps in {args.out / 'pcaps'}, {len(failures)} failures")
    for line in failures[:20]:
        print(f"  {line}")
    return 0 if written >= 1 else 1


if __name__ == "__main__":
    raise SystemExit(main())
