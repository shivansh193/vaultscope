"""Gateway-state import: fill what the wire hid, and flag where it disagrees.

IKEv2 negotiates mode, PFS and authentication inside the encrypted IKE_AUTH, so
a passive capture reads them as ``unknown``. The gateway itself knows. This
module reads what an operator can paste from the gateway and attaches it to the
captured sessions:

- ``swanctl --list-sas``   IKE SPIs, child mode, ESP proposal (a DH group there
                            means the child was keyed with PFS)
- ``swanctl --list-conns`` authentication method and mode per connection
- ``swanctl.conf``          declared auth, mode, and ``esp_proposals`` (PFS on
                            only when every ESP proposal names a DH group)
- ``ip xfrm state``         kernel SAs: mode and replay window (anti-replay)

A value fills a field only when the capture left it unknown or inferred; the
field is listed in ``ike.gateway_fields`` so reports show where it came from.
Where the wire *did* show a value and the gateway disagrees, the difference is
recorded in ``ike.gateway_mismatches`` and rule R21 fires: configuration drift
is exactly what a config-only review misses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from core.models import VPNSession

_DH_TOKEN = re.compile(r"(modp\d+|ecp\d+|curve\d+|x25519|x448|mlkem\d+|ml_kem|brainpool)", re.I)


@dataclass
class GatewayRecord:
    source: str
    local: str | None = None
    remote: str | None = None
    ike_spi_i: str | None = None
    values: dict = field(default_factory=dict)

    def peers(self) -> frozenset[str]:
        return frozenset(p for p in (self.local, self.remote) if p)


# --- parsers -------------------------------------------------------------------
def _parse_list_sas(text: str) -> list[GatewayRecord]:
    records: list[GatewayRecord] = []
    cur: GatewayRecord | None = None
    for line in text.splitlines():
        if m := re.match(
            r"^\S+: #\d+, \w+, (IKEv[12]), ([0-9a-f]{16})_i\*? ([0-9a-f]{16})_r", line
        ):
            cur = GatewayRecord("swanctl --list-sas", ike_spi_i=m[2].lower())
            cur.values["version"] = m[1]
            records.append(cur)
        elif cur is None:
            continue
        elif m := re.match(r"^\s+local\s+'[^']*' @ ([0-9a-fA-F:.]+)\[", line):
            cur.local = m[1]
        elif m := re.match(r"^\s+remote\s+'[^']*' @ ([0-9a-fA-F:.]+)\[", line):
            cur.remote = m[1]
        elif m := re.search(r"INSTALLED, (TUNNEL|TRANSPORT)[^,]*, (?:ESP|AH):(\S+)", line):
            cur.values["mode"] = m[1].lower()
            if _DH_TOKEN.search(m[2]):
                cur.values["pfs_status"] = "enabled"
    return records


_AUTH = {
    "pre-shared key": "PSK",
    "EAP": "EAP",
    "XAuth": "XAUTH",
}


def _parse_list_conns(text: str) -> list[GatewayRecord]:
    records: list[GatewayRecord] = []
    cur: GatewayRecord | None = None
    for line in text.splitlines():
        if m := re.match(r"^\S+: (IKEv[12])", line):
            cur = GatewayRecord("swanctl --list-conns")
            cur.values["version"] = m[1]
            records.append(cur)
        elif cur is None:
            continue
        elif m := re.match(r"^\s+local:\s+([0-9a-fA-F:.]+)\s*$", line):
            cur.local = m[1]
        elif m := re.match(r"^\s+remote:\s+([0-9a-fA-F:.]+)\s*$", line):
            cur.remote = m[1]
        elif m := re.match(r"^\s+remote (.+?) authentication:", line):
            for needle, method in _AUTH.items():
                if needle in m[1]:
                    cur.values["auth_method"] = method
        elif m := re.match(r"^\s+\S+: (TUNNEL|TRANSPORT)\b", line):
            cur.values["mode"] = m[1].lower()
    return records


def _conf_value(block: str, key: str) -> list[str]:
    return [v.strip() for v in re.findall(rf"^\s*{key}\s*=\s*(.+?)\s*$", block, re.M)]


def _parse_swanctl_conf(text: str) -> list[GatewayRecord]:
    body = re.sub(r"#.*", "", text)
    # One record per `remote_addrs`: each connection declares its own.
    starts = [m.start() for m in re.finditer(r"^\s*remote_addrs\s*=", body, re.M)]
    records = []
    for i, start in enumerate(starts):
        # the connection's local_addrs precedes remote_addrs in its block
        prev_end = starts[i - 1] if i else 0
        head = body[prev_end:start]
        block = body[start : starts[i + 1] if i + 1 < len(starts) else len(body)]
        rec = GatewayRecord("swanctl.conf")
        rec.remote = _conf_value(block, "remote_addrs")[0].split(",")[0].strip()
        if local := _conf_value(head, "local_addrs"):
            rec.local = local[-1].split(",")[0].strip()
        if version := _conf_value(head + block, "version"):
            rec.values["version"] = "IKEv1" if version[-1] == "1" else "IKEv2"
        auths = _conf_value(block, "auth")
        if auths and all(a == "psk" for a in auths):
            rec.values["auth_method"] = "PSK"
        elif auths and any(a.startswith("eap") for a in auths):
            rec.values["auth_method"] = "EAP"
        if modes := _conf_value(block, "mode"):
            rec.values["mode"] = "transport" if modes[0].startswith("transport") else "tunnel"
        elif re.search(r"children\s*{", block):
            rec.values["mode"] = "tunnel"  # strongSwan's default
        esp = _conf_value(block, "esp_proposals")
        if esp and "default" not in " ".join(esp):
            proposals = [p for line in esp for p in line.split(",")]
            has_dh = [bool(_DH_TOKEN.search(p)) for p in proposals]
            if all(has_dh):
                rec.values["pfs_status"] = "enabled"
            elif not any(has_dh):
                rec.values["pfs_status"] = "disabled"
        records.append(rec)
    return records


def _parse_xfrm(text: str) -> list[GatewayRecord]:
    by_pair: dict[frozenset, dict] = {}
    src = dst = None
    for line in text.splitlines():
        if m := re.match(r"^src (\S+) dst (\S+)", line):
            src, dst = m[1], m[2]
            by_pair.setdefault(
                frozenset((src, dst)), {"modes": set(), "windows": [], "a": src, "b": dst}
            )
        elif src and (m := re.search(r"proto (?:esp|ah) spi 0x[0-9a-f]+ .*mode (\w+)", line)):
            by_pair[frozenset((src, dst))]["modes"].add(m[1])
        elif src and (m := re.match(r"^\s+replay-window (\d+)", line)):
            by_pair[frozenset((src, dst))]["windows"].append(int(m[1]))
    records = []
    for info in by_pair.values():
        rec = GatewayRecord("ip xfrm state", local=info["a"], remote=info["b"])
        if len(info["modes"]) == 1 and next(iter(info["modes"])) in ("tunnel", "transport"):
            rec.values["mode"] = next(iter(info["modes"]))
        # Outbound SAs always show window 0; replay protection is on if any
        # (inbound) SA of the pair keeps a window, off only if none do.
        if len(info["windows"]) >= 2:
            rec.values["anti_replay"] = any(w > 0 for w in info["windows"])
        records.append(rec)
    return records


def parse_gateway_state(text: str) -> list[GatewayRecord]:
    """Detect the format(s) in ``text`` and parse each. Several may be pasted together."""
    records: list[GatewayRecord] = []
    if re.search(r"^\S+: #\d+, \w+, IKEv[12], [0-9a-f]{16}_i", text, re.M):
        records += _parse_list_sas(text)
    if re.search(r"^\S+: IKEv[12], ", text, re.M):
        records += _parse_list_conns(text)
    if re.search(r"^\s*connections\s*{", text, re.M):
        records += _parse_swanctl_conf(text)
    if re.search(r"^src \S+ dst \S+\s*$", text, re.M):
        records += _parse_xfrm(text)
    return records


# --- apply -----------------------------------------------------------------------
def _matches(session: VPNSession, rec: GatewayRecord) -> bool:
    if rec.ike_spi_i and session.session_id.lower().startswith(rec.ike_spi_i):
        return True
    return bool(rec.peers()) and rec.peers() == {session.initiator_ip, session.responder_ip}


def _unobserved(session: VPNSession, name: str, value) -> bool:
    return value is None or value == "unknown" or name in session.ike.inferred_fields


def apply_gateway_state(sessions: list[VPNSession], records: list[GatewayRecord]) -> dict:
    """Attach gateway values to matching sessions in place. Returns a summary."""
    filled: dict[str, int] = {}
    mismatches: list[str] = []
    matched: set[str] = set()
    used = [False] * len(records)
    for session in sessions:
        ike = session.ike
        for i, rec in enumerate(records):
            if not _matches(session, rec):
                continue
            used[i] = True
            matched.add(session.session_id)
            for name, value in rec.values.items():
                wire = getattr(ike, name)
                if _unobserved(session, name, wire):
                    setattr(ike, name, value)
                    ike.inferred_fields = [f for f in ike.inferred_fields if f != name]
                    if name == "mode":
                        ike.mode_confidence = None
                    if name not in ike.gateway_fields:
                        ike.gateway_fields.append(name)
                        filled[name] = filled.get(name, 0) + 1
                elif wire != value and name not in ike.gateway_fields:
                    note = f"{name}: wire {wire}, {rec.source} {value}"
                    if note not in ike.gateway_mismatches:
                        ike.gateway_mismatches.append(note)
                        mismatches.append(f"{session.session_id} {note}")
    return {
        "records": len(records),
        "matched_sessions": len(matched),
        "filled": filled,
        "mismatches": mismatches,
        "unmatched_records": [
            {"source": r.source, "local": r.local, "remote": r.remote}
            for r, u in zip(records, used, strict=True)
            if not u
        ],
    }
