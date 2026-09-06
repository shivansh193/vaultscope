"""Generate the demo / slide diagrams into ~/Downloads.

    python scripts/make_diagrams.py

Every number in these diagrams is read from the repo at generation time --
models/eval_metrics.json, models/confusion_matrix.json, data/labels/ -- so a
slide can never quote a figure the code no longer produces.

Light background on purpose: decks and handouts are usually light, and these
have to stay legible projected and printed. The severity hues are the product's
own.
"""

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = Path.home() / "Downloads" / "vaultscope-diagrams"

INK = "#1c1c1e"
INK_2 = "#5b5b60"
INK_3 = "#8e8e93"
RULE = "#d8d8dc"
SURFACE = "#f6f6f7"
ACCENT = "#0a5fd8"

CRITICAL = "#d0342c"
HIGH = "#c8791a"
SAFE = "#1f8a4c"
ML = "#6b3fa0"

FONT = "-apple-system, BlinkMacSystemFont, 'SF Pro Text', 'Segoe UI', Inter, sans-serif"
MONO = "ui-monospace, 'SF Mono', Menlo, monospace"


def stats() -> dict:
    metrics = json.loads((ROOT / "models" / "eval_metrics.json").read_text())
    counts = Counter()
    for path in (ROOT / "data" / "labels").glob("*.json"):
        counts[json.loads(path.read_text())["traffic_class"]] += 1
    return {
        "f1": metrics["f1_macro"],
        "accuracy": metrics["accuracy"],
        "source": metrics["source"],
        "n_train": metrics["n_train"],
        "n_test": metrics["n_test"],
        "captures": sum(counts.values()),
        "classes": dict(sorted(counts.items(), key=lambda kv: -kv[1])),
    }


def svg_open(w: int, h: int, title: str) -> list[str]:
    return [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
        f'viewBox="0 0 {w} {h}" font-family="{FONT}">',
        f"<title>{title}</title>",
        f'<rect width="{w}" height="{h}" fill="#ffffff"/>',
    ]


def text(x, y, s, size=15, fill=INK, weight="400", anchor="start", font=None, spacing=None):
    extra = f' letter-spacing="{spacing}"' if spacing else ""
    return (
        f'<text x="{x}" y="{y}" font-size="{size}" fill="{fill}" font-weight="{weight}" '
        f'text-anchor="{anchor}" font-family="{font or FONT}"{extra}>{s}</text>'
    )


def box(x, y, w, h, fill="#ffffff", stroke=RULE, rx=10, width=1.5):
    return (
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" '
        f'stroke="{stroke}" stroke-width="{width}"/>'
    )


def arrow(x1, y1, x2, y2, color=INK_3, width=2, dash=None):
    d = f' stroke-dasharray="{dash}"' if dash else ""
    return (
        f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" '
        f'stroke-width="{width}" marker-end="url(#arrow)"{d}/>'
    )


MARKER = (
    '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" '
    'markerHeight="6" orient="auto-start-reverse">'
    f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{INK_3}"/></marker></defs>'
)


def wrap(s: str, width: int) -> list[str]:
    words, lines, line = s.split(), [], ""
    for word in words:
        if len(line) + len(word) + 1 > width:
            lines.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    if line:
        lines.append(line)
    return lines


# --------------------------------------------------------------------------- #
# 1. the pipeline                                                              #
# --------------------------------------------------------------------------- #
STAGES = [
    (
        "0",
        "Testbed",
        "Real strongSwan tunnels\nin Docker over the\nconfig matrix",
        "300 labeled captures",
    ),
    (
        "1",
        "Ingestion",
        "One pcap read, bucketed\nper SA by SPI pair.\nIKE + ESP streams",
        "NAT-T, mid-session flags",
    ),
    (
        "2",
        "IKE parser",
        "Hand-written RFC 7296\nbyte decoder. No\nWireshark dependency",
        "cipher, DH, PFS, vendor",
    ),
    (
        "3",
        "Flow features",
        "13 metadata features\nper ESP flow. Payload\nstays encrypted",
        "sizes, timing, bursts",
    ),
]
BRANCH = [
    (
        "4a",
        "Protocol classifier",
        "Recovers crypto from IKE\nmessage structure when\nthe parse is partial",
        ACCENT,
    ),
    (
        "4b",
        "Traffic classifier",
        "Predicts what rode the\ntunnel from metadata\nalone — the ML showpiece",
        ML,
    ),
    ("4c", "Rule engine", "18 rules, each tied to a\nCVE / RFC / NIST\nreference", CRITICAL),
]


def diagram_pipeline(s: dict) -> str:
    w, h = 2140, 900
    out = svg_open(w, h, "VaultScope pipeline")
    out.append(MARKER)
    out.append(text(64, 74, "VaultScope", 34, INK, "700"))
    out.append(
        text(64, 108, "One capture in, an assessed and scored session record out.", 17, INK_2)
    )

    # linear stages
    bw, bh, gap, y = 372, 190, 34, 168
    for i, (num, name, body, foot) in enumerate(STAGES):
        x = 64 + i * (bw + gap)
        out.append(box(x, y, bw, bh))
        out.append(text(x + 22, y + 40, f"Stage {num}", 13, INK_3, "600", spacing="0.06em"))
        out.append(text(x + 22, y + 70, name, 22, INK, "600"))
        for j, line in enumerate(body.split("\n")):
            out.append(text(x + 22, y + 100 + j * 21, line, 14.5, INK_2))
        out.append(text(x + 22, y + bh - 20, foot, 13, ACCENT, "600", font=MONO))
        if i < len(STAGES) - 1:
            out.append(arrow(x + bw + 6, y + bh / 2, x + bw + gap - 6, y + bh / 2))

    # fan out
    fan_y = y + bh + 66
    bw2 = 372
    out.append(
        text(64, fan_y + 6, "Three analyses run in parallel off the same session:", 15, INK_2)
    )
    by = fan_y + 34
    for i, (num, name, body, colour) in enumerate(BRANCH):
        x = 64 + i * (bw2 + gap)
        out.append(box(x, by, bw2, 172, fill=SURFACE, stroke=colour, width=2))
        out.append(text(x + 22, by + 38, f"Stage {num}", 13, colour, "700", spacing="0.06em"))
        out.append(text(x + 22, by + 68, name, 21, INK, "600"))
        for j, line in enumerate(body.split("\n")):
            out.append(text(x + 22, by + 98 + j * 21, line, 14.5, INK_2))
        out.append(arrow(x + bw2 / 2, by + 172 + 4, x + bw2 / 2, by + 208, colour))

    # converge
    cy = by + 214
    cw = 3 * bw2 + 2 * gap
    out.append(box(64, cy, cw, 96, fill="#ffffff", stroke=INK, width=2))
    out.append(text(88, cy + 40, "Stage 5 — scoring and reports", 21, INK, "600"))
    out.append(
        text(
            88,
            cy + 68,
            "risk score · threat matrix · executive PDF · technical HTML · JSON + CEF for a SIEM",
            15,
            INK_2,
        )
    )

    # stage 6 sits to the right of the linear stages, not on top of stage 3
    sx = 64 + len(STAGES) * (bw + gap)
    out.append(box(sx, y, 368, cy + 96 - y, fill=SURFACE, stroke=RULE))
    out.append(text(sx + 22, y + 40, "Stage 6", 13, INK_3, "600", spacing="0.06em"))
    out.append(text(sx + 22, y + 70, "Console", 22, INK, "600"))
    for j, line in enumerate(
        [
            "Next.js dashboard:",
            "session table, D3 peer",
            "graph, drilldown, live",
            "stream, export, diff",
        ]
    ):
        out.append(text(sx + 22, y + 100 + j * 21, line, 14.5, INK_2))
    out.append(text(sx + 22, y + 210, "docker compose up", 13.5, ACCENT, "600", font=MONO))

    out.append(
        text(
            64,
            h - 34,
            f"{s['captures']} labeled captures · 18 security rules · "
            f"traffic classifier macro-F1 {s['f1']:.2f} on held-out real captures",
            14,
            INK_3,
        )
    )
    out.append("</svg>")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# 2. the two AI problems                                                       #
# --------------------------------------------------------------------------- #
def diagram_two_problems(s: dict) -> str:
    w, h = 1600, 880
    out = svg_open(w, h, "Two AI problems of very different difficulty")
    out.append(MARKER)
    out.append(text(64, 74, "Two problems, deliberately not confused", 34, INK, "700"))
    out.append(
        text(
            64,
            108,
            "Most tools treat VPN analysis as one task. It is two, and only one of them is machine learning.",
            17,
            INK_2,
        )
    )

    cw, cx2 = 720, 816
    top = 168

    # left: deterministic
    out.append(box(64, top, cw, 560, stroke=ACCENT, width=2))
    out.append(
        text(96, top + 44, "THE HANDSHAKE IS IN CLEARTEXT", 13, ACCENT, "700", spacing="0.08em")
    )
    out.append(text(96, top + 84, "Crypto identification", 27, INK, "600"))
    out.append(text(96, top + 116, "Stage 2 — a parser, not a model", 16, INK_2))
    body = [
        "IKE negotiates in the clear before the tunnel exists.",
        "The cipher, DH group, PFS status and vendor are simply",
        "there to be read.",
        "",
        "So we wrote a byte-level RFC 7296 decoder rather than",
        "training a model to guess at facts already on the wire.",
        "",
        "ML enters only where the parse cannot: a truncated or",
        "malformed handshake falls back to Stage 4a, which",
        "recovers the DH group from message structure.",
    ]
    for i, line in enumerate(body):
        out.append(text(96, top + 158 + i * 26, line, 15.5, INK_2))
    out.append(box(96, top + 428, cw - 64, 104, fill=SURFACE, stroke=RULE))
    out.append(text(120, top + 462, "Result", 13, INK_3, "700", spacing="0.06em"))
    out.append(text(120, top + 494, "Exact parameters, with a confidence source", 16, INK, "600"))
    out.append(text(120, top + 518, "on every field — parser or classifier.", 16, INK, "600"))

    # right: side-channel ML
    out.append(box(cx2, top, cw, 560, stroke=ML, width=2))
    out.append(
        text(cx2 + 32, top + 44, "THE PAYLOAD NEVER DECRYPTS", 13, ML, "700", spacing="0.08em")
    )
    out.append(text(cx2 + 32, top + 84, "Traffic-type inference", 27, INK, "600"))
    out.append(text(cx2 + 32, top + 116, "Stage 4b — the genuine ML problem", 16, INK_2))
    body2 = [
        "ESP payloads are encrypted and stay that way. We never",
        "attempt decryption and hold no keys.",
        "",
        "What survives encryption is metadata: packet sizes,",
        "inter-arrival timing, direction ratio, burstiness.",
        "A video stream and a chat session leave different",
        "shapes even when both are opaque.",
        "",
        "13 features per flow, RandomForest against XGBoost,",
        "selected on validation macro-F1.",
    ]
    for i, line in enumerate(body2):
        out.append(text(cx2 + 32, top + 158 + i * 26, line, 15.5, INK_2))
    out.append(box(cx2 + 32, top + 428, cw - 64, 104, fill=SURFACE, stroke=RULE))
    out.append(text(cx2 + 56, top + 462, "Result", 13, INK_3, "700", spacing="0.06em"))
    out.append(
        text(
            cx2 + 56,
            top + 494,
            f"macro-F1 {s['f1']:.2f} on held-out real captures,",
            16,
            INK,
            "600",
        )
    )
    out.append(text(cx2 + 56, top + 518, "reported as a confusion matrix.", 16, INK, "600"))

    out.append(
        text(
            64,
            h - 40,
            "Keeping these apart is the design decision: over-modelling a solved parsing problem is how tools "
            "end up with confident, wrong answers.",
            15,
            INK_3,
        )
    )
    out.append("</svg>")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# 3. dataset + model evidence                                                  #
# --------------------------------------------------------------------------- #
def diagram_evidence(s: dict) -> str:
    cm = json.loads((ROOT / "models" / "confusion_matrix.json").read_text())
    labels, matrix = cm["labels"], cm["matrix"]
    w, h = 1600, 900
    out = svg_open(w, h, "Dataset and model evidence")
    out.append(text(64, 74, "The dataset is ours, and so is the evidence", 34, INK, "700"))
    out.append(
        text(
            64,
            108,
            "No public corpus fits IPsec ESP with per-tunnel crypto labels, so we generated one.",
            17,
            INK_2,
        )
    )

    # dataset column
    top = 168
    out.append(box(64, top, 700, 300, fill=SURFACE, stroke=RULE))
    out.append(text(96, top + 42, "THE DATASET", 13, INK_3, "700", spacing="0.08em"))
    out.append(text(96, top + 78, f"{s['captures']} labeled captures", 26, INK, "600"))
    out.append(text(96, top + 108, "Real strongSwan tunnels, real IKE, real ESP.", 15.5, INK_2))
    bar_x, bar_y, bar_w = 96, top + 140, 620
    total = sum(s["classes"].values())
    cursor = bar_x
    palette = [ACCENT, ML, SAFE, HIGH, "#0f7d8c", "#a83a6b"]
    for i, (_klass, n) in enumerate(s["classes"].items()):
        seg = bar_w * n / total
        out.append(
            f'<rect x="{cursor:.1f}" y="{bar_y}" width="{max(seg - 3, 2):.1f}" height="26" '
            f'rx="3" fill="{palette[i % len(palette)]}"/>'
        )
        cursor += seg
    for i, (klass, n) in enumerate(s["classes"].items()):
        col, row = i % 3, i // 3
        lx, ly = bar_x + col * 210, bar_y + 62 + row * 30
        out.append(
            f'<rect x="{lx}" y="{ly - 11}" width="11" height="11" rx="2" '
            f'fill="{palette[i % len(palette)]}"/>'
        )
        out.append(text(lx + 20, ly, f"{klass} {n}", 14.5, INK_2))
    out.append(
        text(
            96,
            top + 274,
            "144-cell matrix: mode x cipher x DH group x PFS x IP version",
            13.5,
            INK_3,
            font=MONO,
        )
    )

    # how it was made
    hy = top + 328
    out.append(box(64, hy, 700, 340))
    out.append(text(96, hy + 42, "HOW IT WAS MADE", 13, INK_3, "700", spacing="0.08em"))
    made = [
        ("Real tunnels", "Two strongSwan peers per cell in Docker,"),
        ("", "SA established before capture starts."),
        ("Six generators", "sipp RTP, ffmpeg H.264, curl + nginx,"),
        ("", "swaks SMTP, ping, scripted chat."),
        ("Ground truth", "Every label records what was configured,"),
        ("", "never what a parser recovered."),
        ("Reproducible", "One command, resumable, ~40 minutes."),
    ]
    for i, (lead, rest) in enumerate(made):
        yy = hy + 84 + i * 30
        if lead:
            out.append(text(96, yy, lead, 15, INK, "600"))
        out.append(text(232, yy, rest, 15, INK_2))
    out.append(
        text(
            96,
            hy + 312,
            "Chat is a declared substitution — a real messaging client cannot run in an isolated lab.",
            13.5,
            HIGH,
        )
    )

    # confusion matrix
    mx, my = 830, top + 34
    cell = 66
    out.append(
        text(830, top + 6, "CONFUSION MATRIX — HELD-OUT SPLIT", 13, INK_3, "700", spacing="0.08em")
    )
    peak = max(max(r) for r in matrix) or 1
    for j, label in enumerate(labels):
        out.append(text(mx + j * cell + cell / 2, my - 10, label[:5], 12.5, INK_3, anchor="middle"))
    for i, label in enumerate(labels):
        out.append(text(mx - 12, my + i * cell + cell / 2 + 5, label, 12.5, INK_3, anchor="end"))
        for j, value in enumerate(matrix[i]):
            if value == 0:
                fill, ink = "#ffffff", "#c9c9ce"
            elif i == j:
                alpha = 0.18 + 0.72 * value / peak
                fill, ink = f"rgba(31,138,76,{alpha:.2f})", "#ffffff" if alpha > 0.5 else INK
            else:
                fill, ink = CRITICAL, "#ffffff"
            out.append(
                f'<rect x="{mx + j * cell}" y="{my + i * cell}" width="{cell - 4}" '
                f'height="{cell - 4}" rx="6" fill="{fill}" stroke="{RULE}"/>'
            )
            out.append(
                text(
                    mx + j * cell + (cell - 4) / 2,
                    my + i * cell + (cell - 4) / 2 + 6,
                    str(value),
                    17,
                    ink,
                    "600",
                    anchor="middle",
                )
            )

    ny = my + len(labels) * cell + 40
    out.append(
        text(830, ny, f"macro-F1 {s['f1']:.3f}   ·   accuracy {s['accuracy']:.3f}", 21, INK, "600")
    )
    out.append(
        text(
            830,
            ny + 28,
            f"trained on {s['n_train']} real flows, tested on {s['n_test']} held out",
            15,
            INK_2,
        )
    )
    out.append(text(830, ny + 54, "One error: a Video flow called VoIP.", 15, INK_2))

    caveat = (
        "Read with its dataset in mind: each capture holds one traffic class from a deterministic "
        "generator, so the classes separate on coarse statistics. Real traffic interleaves classes on "
        "one tunnel and drops packets. This is an upper bound, not a deployment number."
    )
    out.append(box(64, h - 132, w - 128, 84, fill="#fff8f0", stroke="#e8c9a0"))
    for i, line in enumerate(wrap(caveat, 108)):
        out.append(text(92, h - 100 + i * 24, line, 14.5, "#7a4a12"))
    out.append("</svg>")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# 4. one capture's journey                                                     #
# --------------------------------------------------------------------------- #
JOURNEY = [
    ("Upload", "demo_capture.pcap\n6 tunnels, 2,884 packets", "POST /ingest", ACCENT),
    ("Bucket", "One RawSession per SA,\nkeyed on the SPI pair", "Stage 1", INK_2),
    ("Decode", "AES-128-CBC, MODP1024,\nPFS unknown, vendor", "Stage 2", INK_2),
    ("Measure", "13 features from the\nESP flow of those peers", "Stage 3", INK_2),
    ("Judge", "18 rules + traffic\nprediction + anomalies", "Stage 4a/4b/4c", CRITICAL),
    ("Report", "Score 60, CRITICAL,\nconfig diff to fix it", "Stage 5", SAFE),
]


def diagram_journey(s: dict) -> str:
    w, h = 1700, 620
    out = svg_open(w, h, "One capture's journey")
    out.append(MARKER)
    out.append(text(64, 74, "What happens to one capture", 34, INK, "700"))
    out.append(
        text(64, 108, "Six tunnels in one file, each assessed on its own evidence.", 17, INK_2)
    )

    bw, gap, y, bh = 236, 30, 176, 208
    for i, (name, body, stage, colour) in enumerate(JOURNEY):
        x = 64 + i * (bw + gap)
        out.append(
            box(
                x,
                y,
                bw,
                bh,
                stroke=colour if colour != INK_2 else RULE,
                width=2 if colour not in (INK_2,) else 1.5,
            )
        )
        out.append(text(x + 20, y + 36, stage, 12.5, INK_3, "700", spacing="0.06em"))
        out.append(text(x + 20, y + 68, name, 22, INK, "600"))
        for j, line in enumerate(body.split("\n")):
            out.append(text(x + 20, y + 100 + j * 21, line, 14, INK_2))
        if i < len(JOURNEY) - 1:
            out.append(arrow(x + bw + 4, y + bh / 2, x + bw + gap - 4, y + bh / 2))

    out.append(box(64, y + bh + 48, w - 128, 96, fill=SURFACE, stroke=RULE))
    out.append(text(92, y + bh + 84, "The contract that holds it together", 18, INK, "600"))
    out.append(
        text(
            92,
            y + bh + 114,
            "Every stage reads and writes one canonical VPNSession record — parser, classifiers, rule engine, "
            "database, API, reports and dashboard. There is no second shape for a session anywhere in the system.",
            15,
            INK_2,
        )
    )
    out.append("</svg>")
    return "\n".join(out)


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    s = stats()
    files = {
        "01-pipeline.svg": diagram_pipeline(s),
        "02-two-ai-problems.svg": diagram_two_problems(s),
        "03-dataset-and-model.svg": diagram_evidence(s),
        "04-capture-journey.svg": diagram_journey(s),
    }
    for name, body in files.items():
        (OUT / name).write_text(body)
        print(f"  {OUT / name}")
    print(f"\n{len(files)} diagrams written to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
