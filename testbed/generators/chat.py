"""Bursty chat-shaped traffic.

This is the spec's declared WhatsApp substitution: a real messaging client
cannot run in an isolated lab, so this reproduces the *shape* -- short messages
in bursts, long human idle gaps -- over a plain TCP socket. Every label it
produces is marked ``substitution: true``. Do not present it as real chat
traffic.
"""

import random
import socket
import sys
import time

PORT = 5222


def _listener(port: int) -> socket.socket:
    """A socket that accepts both IPv4 and IPv6.

    socket.socket() defaults to AF_INET, which silently refuses every IPv6
    peer -- the tunnel still carries IKE, so the capture passes a
    minimum-packet check while containing none of the traffic it is labeled
    with. Bind AF_INET6 with V6ONLY off so one listener serves both families.
    """
    try:
        server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    except OSError:  # host without IPv6 at all
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("", port))
    return server


def serve(duration: float) -> None:
    with _listener(PORT) as server:
        server.listen(1)
        server.settimeout(duration)
        try:
            conn, _ = server.accept()
        except (TimeoutError, OSError):
            return
        with conn:
            conn.settimeout(duration)
            deadline = time.time() + duration
            while time.time() < deadline:
                try:
                    data = conn.recv(4096)
                except (TimeoutError, OSError):
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
                if time.time() >= deadline:
                    return
            time.sleep(rng.uniform(2.0, 6.0))  # then the human stops typing


if __name__ == "__main__":
    role, peer, seconds = sys.argv[1], sys.argv[2], float(sys.argv[3])
    if role == "serve":
        serve(seconds)
    else:
        send(peer, seconds)
