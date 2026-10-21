"""A fake SMTP-over-SSL mail server on localhost:465. Every message is written to $SP/mail_migration.

The monitor only uses SSL on exactly port 465, so the fake has to listen there. On Linux that needs
root (or `sysctl net.ipv4.ip_unprivileged_port_start=465`). Without it the suites that need mail
report SKIPPED, loudly, and the run is not counted as green.
"""

import os
import socketserver
import ssl
import threading
import time

import _paths

MAIL_DIR = os.path.join(os.environ["SP"], "mail_migration")
CERT = os.path.join(os.environ["SP"], "certs", "cert.pem")
KEY = os.path.join(os.environ["SP"], "certs", "key.pem")
BAD_LOGIN_FLAG = os.path.join(os.environ["SP"], "BAD_LOGIN")   # create this file to make logins fail


class _Smtp(socketserver.StreamRequestHandler):
    def send(self, line):
        self.wfile.write((line + "\r\n").encode())
        self.wfile.flush()

    def handle(self):
        self.send("220 localhost fake smtp")
        data_mode, buf = False, []
        while True:
            raw = self.rfile.readline()
            if not raw:
                return
            line = raw.decode(errors="replace").rstrip("\r\n")
            if data_mode:
                if line == ".":
                    data_mode = False
                    name = os.path.join(MAIL_DIR, f"mail-{time.time_ns()}.eml")
                    with open(name, "w", encoding="utf-8") as handle:
                        handle.write("\n".join(buf))
                    self.send("250 queued")
                else:
                    buf.append(line[1:] if line.startswith("..") else line)
                continue
            cmd = line.upper()
            if cmd.startswith("EHLO") or cmd.startswith("HELO"):
                self.wfile.write(b"250-localhost\r\n250 AUTH PLAIN LOGIN\r\n")
                self.wfile.flush()
            elif cmd.startswith("AUTH"):
                self.send("535 5.7.8 Authentication credentials invalid" if os.path.exists(BAD_LOGIN_FLAG) else "235 2.7.0 Authentication successful")
            elif cmd.startswith("MAIL FROM") or cmd.startswith("RCPT TO"):
                self.send("250 ok")
            elif cmd == "DATA":
                data_mode, buf = True, []
                self.send("354 go ahead")
            elif cmd == "QUIT":
                self.send("221 bye")
                return
            else:
                self.send("250 ok")


class _TlsServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def get_request(self):
        sock, addr = super().get_request()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(CERT, KEY)
        return context.wrap_socket(sock, server_side=True), addr


def start():
    """Start the mail server in this process (a background thread). Safe to call twice."""
    if getattr(start, "server", None):
        return start.server
    try:
        server = _TlsServer(("127.0.0.1", 465), _Smtp)
    except PermissionError:
        _paths.skip("cannot listen on port 465 (needs root, or net.ipv4.ip_unprivileged_port_start=465 on Linux)")
    except OSError as exc:
        _paths.skip(f"port 465 is not available ({exc})")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    start.server = server
    return server
