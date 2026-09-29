"""Check the labeled dataset is what data/README.md says it is.

    python scripts/validate_dataset.py                  # labels + manifest (CI)
    python scripts/validate_dataset.py --require-pcaps  # also every pcap, hash-checked
    python scripts/validate_dataset.py --write-manifest # after regenerating captures

Every label must match the schema, name its own pcap, and have an entry in
data/MANIFEST.sha256 -- the published corpus. With --require-pcaps each capture
must also be on disk and hash to its manifest entry, which is how a reviewer who
downloaded the corpus confirms it is the one the labels and metrics describe.
"""

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
MANIFEST = DATA / "MANIFEST.sha256"

CLASSES = {"VoIP", "Video", "Web", "Email", "ICMP", "Chat"}
TOP_KEYS = {
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
CONFIG_KEYS = {
    "version",
    "mode",
    "encryption",
    "integrity",
    "dh_group",
    "pfs_status",
    "auth_method",
    "ip_version",
    "ike_version",
}
ALLOWED = {
    "mode": {"tunnel", "transport"},
    "pfs_status": {"enabled", "disabled"},
    "ip_version": {"IPv4", "IPv6"},
    "version": {"IKEv2"},
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def read_manifest(path: Path = MANIFEST) -> dict[str, str]:
    if not path.exists():
        return {}
    entries = {}
    for line in path.read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            digest, name = line.split(maxsplit=1)
            entries[name.strip().lstrip("*")] = digest
    return entries


def label_errors(path: Path) -> list[str]:
    try:
        label = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        return [f"{path.name}: not JSON ({exc})"]
    errors = []
    if missing := TOP_KEYS - label.keys():
        errors.append(f"{path.name}: missing {sorted(missing)}")
    if label.get("pcap") != f"{path.stem}.pcap":
        errors.append(f"{path.name}: pcap field {label.get('pcap')!r} does not match the file name")
    cls = label.get("traffic_class")
    if cls not in CLASSES:
        errors.append(f"{path.name}: traffic_class {cls!r} not in {sorted(CLASSES)}")
    if not path.stem.endswith(f"__{str(cls).lower()}"):
        errors.append(f"{path.name}: file name does not end in __{str(cls).lower()}")
    if label.get("substitution") is not (cls == "Chat"):
        errors.append(f"{path.name}: substitution must be true for Chat and only Chat")
    config = label.get("config", {})
    if missing := CONFIG_KEYS - config.keys():
        errors.append(f"{path.name}: config missing {sorted(missing)}")
    for key, allowed in ALLOWED.items():
        if key in config and config[key] not in allowed:
            errors.append(f"{path.name}: config.{key} {config[key]!r} not in {sorted(allowed)}")
    if config.get("mode") and not path.stem.startswith(config["mode"]):
        errors.append(f"{path.name}: file name does not start with its mode {config['mode']}")
    return errors


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--require-pcaps", action="store_true")
    ap.add_argument("--write-manifest", action="store_true")
    ap.add_argument("--data", type=Path, default=DATA)
    args = ap.parse_args(argv)

    labels = sorted((args.data / "labels").glob("*.json"))
    pcaps_dir = args.data / "pcaps"
    manifest_path = args.data / "MANIFEST.sha256"

    if args.write_manifest:
        missing = [p.stem for p in labels if not (pcaps_dir / f"{p.stem}.pcap").exists()]
        if missing:
            print(f"cannot write manifest: {len(missing)} labels have no pcap, e.g. {missing[0]}")
            return 1
        lines = [f"{sha256(pcaps_dir / f'{p.stem}.pcap')}  {p.stem}.pcap" for p in labels]
        manifest_path.write_text(
            "# SHA-256 of every capture in the published corpus (sha256sum -c format)\n"
            + "\n".join(lines)
            + "\n"
        )
        print(f"wrote {manifest_path} ({len(lines)} entries)")

    errors = [e for p in labels for e in label_errors(p)]
    manifest = read_manifest(manifest_path)
    if not manifest:
        errors.append(f"{manifest_path.name} missing or empty")
    else:
        names = {f"{p.stem}.pcap" for p in labels}
        errors += [f"{n}: label has no manifest entry" for n in sorted(names - manifest.keys())]
        errors += [f"{n}: manifest entry has no label" for n in sorted(manifest.keys() - names)]

    if args.require_pcaps:
        for p in labels:
            pcap = pcaps_dir / f"{p.stem}.pcap"
            if not pcap.exists():
                errors.append(f"{pcap.name}: label has no pcap on disk")
            elif manifest.get(pcap.name) and sha256(pcap) != manifest[pcap.name]:
                errors.append(f"{pcap.name}: SHA-256 does not match the manifest")

    for e in errors[:50]:
        print(e)
    if len(errors) > 50:
        print(f"... and {len(errors) - 50} more")
    print(f"{len(labels)} labels, {len(manifest)} manifest entries, {len(errors)} problems")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
