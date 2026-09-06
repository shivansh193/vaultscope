"""An SMTP server that accepts everything, for the Email traffic class.

swaks -- the real client -- is what shapes this class's traffic: EHLO, MAIL,
RCPT, a DATA body with a base64 attachment, QUIT. The server only has to
terminate that conversation.

Debian's Postfix rejects every recipient here with "451 Temporary lookup
failure" and `postconf -e` does not persist in the slim image, so the SMTP
conversation would complete without a message body ever transferring -- which
would file an SMTP handshake under "Email". This sink accepts the body instead.
Python 3.12 removed the stdlib smtpd module, hence the hand-rolled one.
"""

import socket
import sys
import threading
import time

PORT = 25


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


def _serve_one(conn: socket.socket) -> None:
    with conn:
        conn.sendall(b"220 sink.example.com ESMTP\r\n")
        in_data = False
        buffer = b""
        while True:
            try:
                chunk = conn.recv(8192)
            except OSError:
                return
            if not chunk:
                return
            buffer += chunk

            if in_data:
                if b"\r\n.\r\n" in buffer:
                    conn.sendall(b"250 2.0.0 Ok: queued\r\n")
                    in_data = False
                    buffer = b""
                continue

            while b"\r\n" in buffer:
                line, buffer = buffer.split(b"\r\n", 1)
                verb = line[:4].upper()
                if verb == b"EHLO":
                    conn.sendall(b"250-sink.example.com\r\n250 SIZE 10485760\r\n")
                elif verb == b"HELO":
                    conn.sendall(b"250 sink.example.com\r\n")
                elif verb == b"DATA":
                    conn.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    in_data = True
                    break
                elif verb == b"QUIT":
                    conn.sendall(b"221 2.0.0 Bye\r\n")
                    return
                else:  # MAIL, RCPT, RSET, NOOP -- all accepted
                    conn.sendall(b"250 2.1.0 Ok\r\n")


def serve(duration: float) -> None:
    with _listener(PORT) as server:
        server.listen(8)
        server.settimeout(1.0)
        deadline = time.time() + duration
        while time.time() < deadline:
            try:
                conn, _ = server.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=_serve_one, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    serve(float(sys.argv[1]))
