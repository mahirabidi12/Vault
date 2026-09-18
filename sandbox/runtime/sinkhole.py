"""Fake internet inside the sandbox. Nothing here reaches a real network.

DNS answers every name with a unique 127.x.y.z address (so a later connect() to that address maps back
to the name that was asked for), and HTTP / HTTPS / a few raw TCP ports accept, log and answer with
harmless stubs. Everything is recorded in memory for the supervisor to collect."""

import os
import socket
import socketserver
import ssl
import struct
import subprocess
import tempfile
import threading
import time

MAX_BODY = 64 * 1024
MAX_EVENTS = 5000
TCP_PORTS = (3333, 4444, 5555, 7777, 8080, 8443, 9001, 14444, 1337, 6667, 8000, 9999)


class Sinkhole:
    def __init__(self, ca_cert: str, ca_key: str) -> None:
        self.ca_cert, self.ca_key = ca_cert, ca_key
        self._ctx_cache: dict[str, ssl.SSLContext] = {}
        self._workdir = tempfile.mkdtemp(prefix="sbx-certs-")
        self._leaf_key = os.path.join(self._workdir, "leaf.key")
        subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-out", self._leaf_key], check=True, capture_output=True)
        self.events: list[dict] = []
        self.ip_to_name: dict[str, str] = {}
        self._name_to_ip: dict[str, str] = {}
        self._lock = threading.Lock()
        self._next = 1
        self._servers: list = []
        self.t0 = time.time()

    def log(self, event: dict) -> None:
        with self._lock:
            if len(self.events) < MAX_EVENTS:
                event["t"] = int(time.time() * 1000)
                self.events.append(event)

    def _alloc(self, name: str) -> str:
        with self._lock:
            ip = self._name_to_ip.get(name)
            if ip is None:
                n = self._next
                self._next += 1
                ip = f"127.{1 + (n >> 16) % 250}.{(n >> 8) & 255}.{n & 255 or 1}"
                self._name_to_ip[name] = ip
                self.ip_to_name[ip] = name
            return ip

    # ---- DNS (UDP) ----
    def _dns_response(self, data: bytes) -> bytes | None:
        try:
            tid = data[:2]
            i, labels = 12, []
            while data[i]:
                labels.append(data[i + 1 : i + 1 + data[i]].decode("ascii", "replace"))
                i += 1 + data[i]
            qtype = struct.unpack(">H", data[i + 1 : i + 3])[0]
            question = data[12 : i + 5]
            name = ".".join(labels).lower()
        except Exception:
            return None
        ip = None
        if qtype == 1:
            ip = self._alloc(name)
        self.log({"type": "dns", "name": name, "qtype": qtype, "answer": ip})
        header = tid + b"\x81\x80" + b"\x00\x01" + (b"\x00\x01" if ip else b"\x00\x00") + b"\x00\x00\x00\x00"
        answer = b""
        if ip:
            answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton(ip)
        return header + question + answer

    def _serve_dns(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 53))
        self._servers.append(sock)
        while True:
            try:
                data, addr = sock.recvfrom(1024)
            except OSError:
                return
            reply = self._dns_response(data)
            if reply:
                sock.sendto(reply, addr)

    def _context_for(self, name: str | None) -> ssl.SSLContext:
        """A certificate for `name` signed by the sandbox CA (trusted inside the image), so HTTPS calls
        succeed and the sinkhole sees the whole request instead of a failed handshake."""
        key = (name or "sinkhole").lower()[:200]
        with self._lock:
            cached = self._ctx_cache.get(key)
        if cached:
            return cached
        safe = "".join(c if c.isalnum() else "_" for c in key)[:80]
        csr, crt, ext = (os.path.join(self._workdir, f"{safe}.{x}") for x in ("csr", "crt", "ext"))
        san = f"DNS:{key}" if all(c.isalnum() or c in "-." for c in key) else "DNS:sinkhole"
        with open(ext, "w") as fh:
            fh.write(f"subjectAltName={san}\n")
        subprocess.run(["openssl", "req", "-new", "-key", self._leaf_key, "-subj", "/CN=sinkhole", "-out", csr], check=True, capture_output=True)
        subprocess.run(
            ["openssl", "x509", "-req", "-in", csr, "-CA", self.ca_cert, "-CAkey", self.ca_key, "-CAcreateserial", "-days", "3650", "-extfile", ext, "-out", crt],
            check=True, capture_output=True,
        )  # fmt: skip
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, self._leaf_key)
        with self._lock:
            self._ctx_cache[key] = ctx
        return ctx

    # ---- HTTP / HTTPS / raw TCP ----
    def _http_handler(self, tls: bool):
        outer = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                conn = self.request
                conn.settimeout(3)
                sni = None
                if tls:
                    try:
                        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                        ctx.load_cert_chain(*outer._context_default())

                        def pick(sock, name, _c):
                            sock.sbx_sni = name
                            try:
                                sock.context = outer._context_for(name)
                            except Exception:
                                pass

                        ctx.sni_callback = pick
                        conn = ctx.wrap_socket(conn, server_side=True)
                        sni = getattr(conn, "sbx_sni", None)
                    except Exception as exc:
                        outer.log({"type": "tls_fail", "error": str(exc)[:120]})
                        return
                try:
                    raw = b""
                    while b"\r\n\r\n" not in raw and len(raw) < 65536:
                        chunk = conn.recv(8192)
                        if not chunk:
                            break
                        raw += chunk
                    head, _, body = raw.partition(b"\r\n\r\n")
                    lines = head.decode("latin-1").split("\r\n")
                    parts = lines[0].split(" ")
                    headers = {}
                    for line in lines[1:41]:
                        if ":" in line:
                            k, v = line.split(":", 1)
                            headers[k.strip().lower()] = v.strip()[:500]
                    length = int(headers.get("content-length", "0") or 0)
                    while len(body) < min(length, MAX_BODY):
                        chunk = conn.recv(8192)
                        if not chunk:
                            break
                        body += chunk
                    outer.log(
                        {
                            "type": "http",
                            "tls": tls,
                            "sni": sni,
                            "host": headers.get("host", sni),
                            "method": parts[0][:10],
                            "path": (parts[1] if len(parts) > 1 else "")[:2000],
                            "headers": headers,
                            "body": body[:MAX_BODY].decode("utf-8", "replace"),
                            "dest": self.request.getsockname()[0] if not tls else conn.getsockname()[0],
                        }
                    )
                    wants_json = "json" in headers.get("accept", "") or "json" in (parts[1] if len(parts) > 1 else "")
                    payload = b"{}\n" if wants_json else b"#!/bin/sh\nexit 0\n"
                    conn.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: "
                        + str(len(payload)).encode()
                        + b"\r\n\r\n"
                        + payload
                    )
                except Exception:
                    pass

        return Handler

    def _context_default(self) -> tuple[str, str]:
        self._context_for("sinkhole")
        return os.path.join(self._workdir, "sinkhole.crt"), self._leaf_key

    def _tcp_handler(self):
        outer = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                self.request.settimeout(1.5)
                try:
                    data = self.request.recv(4096)
                except Exception:
                    data = b""
                outer.log(
                    {
                        "type": "tcp",
                        "port": self.request.getsockname()[1],
                        "dest": self.request.getsockname()[0],
                        "data": data.decode("utf-8", "replace")[:2000],
                    }
                )

        return Handler

    def _serve_tcp(self, port: int, handler) -> None:
        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        try:
            server = Server(("0.0.0.0", port), handler)
        except OSError:
            return
        self._servers.append(server)
        server.serve_forever()

    def start(self) -> None:
        threading.Thread(target=self._serve_dns, daemon=True).start()
        for port, tls in ((80, False), (443, True)):
            threading.Thread(target=self._serve_tcp, args=(port, self._http_handler(tls)), daemon=True).start()
        for port in TCP_PORTS:
            threading.Thread(target=self._serve_tcp, args=(port, self._tcp_handler()), daemon=True).start()
        time.sleep(0.3)
