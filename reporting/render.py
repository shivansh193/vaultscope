"""Report generation (Stage 5, P3-T4 + P3-T5).

Jinja2 templates render to HTML; WeasyPrint turns that into PDF.

``reporting`` must be imported before ``weasyprint`` on macOS (see
``reporting.ensure_native_libs``), so the import is deferred into the one
function that needs it -- that also keeps JSON/CEF export and HTML rendering
working on a box with no pango installed.
"""

import datetime as dt
import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined
from markupsafe import Markup

from core.models import VPNSession
from reporting import aggregate

TEMPLATE_DIR = Path(__file__).parent / "templates"
CONFUSION_MATRIX_PATH = Path(__file__).resolve().parent.parent / "models" / "confusion_matrix.json"

# Plain-English gloss per rule for the executive report. The technical report
# uses the rule descriptions verbatim; a DG-level reader needs the consequence.
PLAIN_ENGLISH: dict[str, str] = {
    "R01": "This tunnel uses an encryption algorithm that is considered broken. Traffic can be decrypted by an attacker who captures it.",
    "R02": "This tunnel uses 3DES, which has a known weakness (SWEET32) on long-lived connections. Replace it with AES.",
    "R03": "The key-exchange group is small enough to be broken outright with modest computing resources.",
    "R04": "The key-exchange group is one a well-resourced adversary can break after a one-time precomputation. This is the LOGJAM weakness.",
    "R05": "The key-exchange group is below current national guidance and should be replaced.",
    "R06": "The device sends a hash of the shared password in the clear during connection setup. Anyone capturing that exchange can attempt to crack the password offline.",
    "R07": "This tunnel uses IKEv1, a protocol version formally retired by the IETF. Migrate to IKEv2.",
    "R08": "The integrity algorithm is broken, so a capable attacker could forge traffic that the tunnel accepts as genuine.",
    "R09": "The integrity algorithm is deprecated and should be replaced with SHA-256 or stronger.",
    "R10": "Forward secrecy is off. If the tunnel's long-term key is ever compromised, every past session recorded by an adversary can be decrypted retrospectively.",
    "R11": "Encryption keys are kept in use for more than 24 hours, widening the window in which a stolen key stays useful.",
    "R12": "Encryption keys are rotated less often than good practice suggests.",
    "R13": "A shared password is combined with a weak key exchange, making offline password cracking practical.",
    "R14": "This device is exposed to a known remote code execution vulnerability in its IKE fragment handling (CVE-2016-1287). Patch it.",
    "R15": "Replay protection is off, so an attacker can re-send captured traffic and have it accepted.",
    "R16": "The peer's authentication certificate has expired. The tunnel is trusting a credential that is no longer valid; renew it immediately.",
    "R17": "Dead Peer Detection is not enabled, so failed tunnels are not cleaned up and half-open sessions build up over time.",
    "R18": "This tunnel runs IKEv1 over IPv6 -- an unusual combination that is frequently misconfigured. Move it to IKEv2.",
}

SEVERITY_PLAIN_ENGLISH: dict[str, str] = {
    "CRITICAL": "Exploitable now; fix immediately.",
    "HIGH": "Serious weakness; fix in this change window.",
    "MEDIUM": "Below best practice; schedule a fix.",
    "LOW": "Hygiene issue; fix opportunistically.",
    "SAFE": "Meets the configured baseline.",
}


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _load_confusion_matrix() -> dict | None:
    """Stage 4b metrics if P2 has trained a model; None is a valid state."""
    if not CONFUSION_MATRIX_PATH.exists():
        return None
    try:
        return json.loads(CONFUSION_MATRIX_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _verdict(summary: dict, overall: str) -> str:
    if summary["session_count"] == 0:
        return "No IPsec sessions were recovered from this capture."
    counts = summary["severity_counts"]
    if overall == "SAFE":
        return (
            f"All {summary['session_count']} assessed sessions met the configured "
            "cryptographic baseline. No action is required."
        )
    worst = counts["CRITICAL"] or counts["HIGH"]
    label = "critical" if counts["CRITICAL"] else "high-severity"
    return (
        f"{worst} of {summary['session_count']} assessed VPN sessions carry "
        f"{label} cryptographic weaknesses. The findings below are ordered by "
        "severity and each carries a ready-to-apply configuration change."
    )


def _actions(summary: dict) -> list[str]:
    actions = [
        f"{entry['finding'].description} — apply the vendor configuration "
        f"change in the technical report to {entry['session_count']} affected "
        f"session{'' if entry['session_count'] == 1 else 's'}."
        for entry in summary["top_findings"]
    ]
    actions.append(
        "Re-run this assessment after the changes land to confirm the posture "
        "score has recovered."
    )
    return actions


def _overall_severity(sessions: list[VPNSession]) -> str:
    from core.models import SEVERITY_ORDER

    if not sessions:
        return "SAFE"
    return min((s.security_assessment.overall_severity for s in sessions), key=SEVERITY_ORDER.index)


def _context(sessions: list[VPNSession], capture_name: str | None) -> dict:
    summary = aggregate.summarise(sessions)
    overall = _overall_severity(sessions)
    return {
        # Markup, not str: autoescape is on for session data (untrusted packet
        # fields), but escaping the stylesheet would mangle every quoted value
        # -- font stacks and @page footer content included.
        "css": Markup((TEMPLATE_DIR / "base.css").read_text()),
        "generated_at": dt.datetime.now(dt.UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "capture_name": capture_name,
        "sessions": sessions,
        "summary": summary,
        "overall_severity": overall,
        "verdict": _verdict(summary, overall),
        "actions": _actions(summary),
        "plain_english": PLAIN_ENGLISH,
        "severity_plain_english": SEVERITY_PLAIN_ENGLISH,
        "confusion_matrix": _load_confusion_matrix(),
        "cve_url": aggregate.cve_url,
        "standard_url": aggregate.standard_url,
    }


def render_executive_html(sessions: list[VPNSession], capture_name: str | None = None) -> str:
    return _env().get_template("executive.html.j2").render(**_context(sessions, capture_name))


def render_technical_html(sessions: list[VPNSession], capture_name: str | None = None) -> str:
    return _env().get_template("technical.html.j2").render(**_context(sessions, capture_name))


def html_to_pdf(html: str, path: str | Path) -> Path:
    """Render HTML to PDF. Imports WeasyPrint lazily -- see module docstring."""
    import weasyprint

    import reporting  # noqa: F401  ensures native libs are discoverable first

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    weasyprint.HTML(string=html).write_pdf(str(path))
    return path


def write_executive_pdf(
    sessions: list[VPNSession], path: str | Path, capture_name: str | None = None
) -> Path:
    return html_to_pdf(render_executive_html(sessions, capture_name), path)


def write_technical_html(
    sessions: list[VPNSession], path: str | Path, capture_name: str | None = None
) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_technical_html(sessions, capture_name))
    return path


def write_technical_pdf(
    sessions: list[VPNSession], path: str | Path, capture_name: str | None = None
) -> Path:
    return html_to_pdf(render_technical_html(sessions, capture_name), path)
