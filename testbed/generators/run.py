"""One traffic generator per class, all riding the tunnel (P1-T2).

Five of the six classes use the protocol's real tool. Chat does not -- see
:mod:`testbed.generators.chat` -- and is marked as a substitution everywhere it
appears, including in every label it produces.
"""

import time
from dataclasses import dataclass

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


def _loop(body: str) -> list[str]:
    """Run ``body`` repeatedly until the duration is up.

    The generators that have no duration flag of their own get one this way,
    rather than being killed mid-request and truncating the capture.
    """
    return [
        "sh",
        "-c",
        f"end=$(( $(date +%s) + {{duration}} )); while [ $(date +%s) -lt $end ]; do {body}; done",
    ]


GENERATORS: dict[str, Generator] = {
    "VoIP": Generator(
        name="sipp",
        description="sipp UAC against a UAS, G.711-rate RTP media",
        server=["sh", "-c", "sipp -sn uas >/dev/null 2>&1"],
        client=[
            "sh",
            "-c",
            "sipp -sn uac -r 2 -d 20000 -timeout {duration}s -m 200 {peer} >/dev/null 2>&1 || true",
        ],
    ),
    "Video": Generator(
        name="ffmpeg",
        description="ffmpeg streaming a generated test pattern over RTP",
        client=[
            "sh",
            "-c",
            "ffmpeg -re -f lavfi -i testsrc=size=640x480:rate=25 -t {duration} "
            "-c:v libx264 -preset ultrafast -f rtp rtp://{peer}:5004 >/dev/null 2>&1 || true",
        ],
    ),
    "Web": Generator(
        name="curl + nginx",
        description="curl looping fetches of mixed-size objects from nginx",
        server=["nginx", "-g", "daemon off;"],
        client=_loop("curl -s -o /dev/null http://{peer}/ ; sleep 0.3"),
    ),
    "Email": Generator(
        name="swaks",
        description="swaks sending messages with base64 attachments over SMTP",
        # Debian's Postfix rejects every recipient here with "451 Temporary
        # lookup failure" and `postconf -e` does not persist in the slim image,
        # so no message body ever transferred and the class was really just
        # SMTP handshakes. swaks -- the real client, and what actually shapes
        # this traffic -- now talks to a sink that accepts the message.
        server=["python3", "/opt/generators/smtp_sink.py", "{server_duration}"],
        client=_loop(
            "head -c 20000 /dev/urandom | base64 > /tmp/att.txt; "
            "swaks --to test@example.com --server {peer} --attach /tmp/att.txt "
            ">/dev/null 2>&1; sleep 1"
        ),
    ),
    "ICMP": Generator(
        name="ping",
        description="ping at a fixed interval",
        client=["sh", "-c", "ping -i 0.2 -w {duration} {peer} >/dev/null 2>&1 || true"],
    ),
    "Chat": Generator(
        name="scripted bursty sender",
        description=(
            "Substitution for a real messaging client, which cannot run in an "
            "isolated lab: short messages in bursts with human idle gaps."
        ),
        server=["python3", "/opt/generators/chat.py", "serve", "-", "{server_duration}"],
        client=[
            "sh",
            "-c",
            "python3 /opt/generators/chat.py send {peer} {duration} >/dev/null 2>&1 || true",
        ],
        substitution=True,
    ),
}


def _fill(argv: list[str], peer: str, duration: int) -> list[str]:
    # A server has to outlive its client: it starts first and the client runs
    # for the full duration after the settle.
    server_duration = duration + int(2 * max(g.settle for g in GENERATORS.values())) + 5
    return [
        a.replace("{peer}", peer)
        .replace("{server_duration}", str(server_duration))
        .replace("{duration}", str(duration))
        for a in argv
    ]


def run_traffic(pair: PeerPair, traffic_class: str, duration: int) -> None:
    """Run one class of traffic across an established SA, blocking until done."""
    generator = GENERATORS[traffic_class]

    if generator.server:
        pair.exec_detached(pair.responder, *_fill(generator.server, pair.initiator_ip, duration))
        time.sleep(generator.settle)

    argv = _fill(generator.client, pair.responder_ip, duration)
    pair.exec(pair.initiator, *argv, check=False)
