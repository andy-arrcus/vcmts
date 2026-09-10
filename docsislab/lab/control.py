"""Control socket: how `docsis cli` and `docsis dash` attach to a running lab.

A Unix domain socket carrying newline-delimited JSON.  Requests arrive on a
socket thread and are handed to the simulation's event loop through a queue,
so every command reads consistent state without any locking inside the
simulation itself.
"""

from __future__ import annotations

import json
import os
import queue
import socket
import threading
from dataclasses import dataclass

from ..cmts.cli import Cli

DEFAULT_SOCKET = ".docsislab.sock"


@dataclass
class _Request:
    payload: dict
    reply: queue.Queue


class ControlServer:
    """Serves the control socket that `docsis cli` and `docsis dash` attach to."""
    def __init__(self, lab, path: str = DEFAULT_SOCKET):
        self.lab = lab
        self.path = path
        self.cli = Cli(lab)
        self._queue: "queue.Queue[_Request]" = queue.Queue()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.clients = 0

    # ------------------------------------------------------------------
    def start(self) -> None:
        if os.path.exists(self.path):
            os.unlink(self.path)
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(self.path)
        self._sock.listen(8)
        self._sock.settimeout(0.25)
        self._thread = threading.Thread(target=self._accept_loop, daemon=True,
                                        name="control")
        self._thread.start()
        self.lab.sched.add_poller(self.pump)
        self.lab.log.logger("lab").info(
            "control", f"control socket listening on {self.path}")

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if os.path.exists(self.path):
            try:
                os.unlink(self.path)
            except OSError:
                pass

    # ------------------------------------------------------------------
    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                break
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()

    def _client(self, conn: socket.socket) -> None:
        self.clients += 1
        buf = b""
        try:
            conn.settimeout(None)
            while not self._stop.is_set():
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        payload = json.loads(line)
                    except ValueError:
                        conn.sendall(json.dumps(
                            {"ok": False, "error": "bad json"}).encode() + b"\n")
                        continue
                    reply: queue.Queue = queue.Queue(maxsize=1)
                    self._queue.put(_Request(payload, reply))
                    try:
                        response = reply.get(timeout=30)
                    except queue.Empty:
                        response = {"ok": False, "error": "simulation busy"}
                    conn.sendall(json.dumps(response).encode() + b"\n")
        except (OSError, ConnectionError):
            pass
        finally:
            self.clients -= 1
            try:
                conn.close()
            except OSError:
                pass

    # ------------------------------------------------------------------
    def pump(self) -> None:
        """Called from inside the simulation loop."""
        while True:
            try:
                req = self._queue.get_nowait()
            except queue.Empty:
                return
            try:
                response = self._handle(req.payload)
            except Exception as exc:
                response = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
            try:
                req.reply.put_nowait(response)
            except queue.Full:
                pass

    def _handle(self, payload: dict) -> dict:
        cmd = payload.get("cmd", "")
        if cmd == "ping":
            return {"ok": True, "now": self.lab.sched.now()}
        if cmd == "exec":
            text = self.cli.execute(payload.get("line", ""))
            return {"ok": True, "text": text}
        if cmd == "snapshot":
            return {"ok": True, "data": self.lab.snapshot()}
        if cmd == "log":
            since = int(payload.get("since", 0))
            limit = int(payload.get("limit", 200))
            events = self.lab.log.since(since, limit)
            return {"ok": True,
                    "seq": self.lab.log.last_seq,
                    "events": [
                        {"seq": e.seq, "time": e.time, "source": e.source,
                         "level": e.level, "category": e.category,
                         "message": e.message}
                        for e in events]}
        if cmd == "speed":
            self.lab.sched.speed = float(payload.get("value", 1.0))
            self.lab.opts.speed = self.lab.sched.speed
            return {"ok": True, "speed": self.lab.sched.speed}
        if cmd == "shutdown":
            self.lab.sched.stop()
            return {"ok": True}
        return {"ok": False, "error": f"unknown command {cmd!r}"}


class ControlClient:
    """The other end: used by `docsis cli` and `docsis dash`."""

    def __init__(self, path: str = DEFAULT_SOCKET, timeout: float = 35.0):
        self.path = path
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.settimeout(timeout)
        self._sock.connect(path)
        self._buf = b""

    def request(self, **payload) -> dict:
        self._sock.sendall(json.dumps(payload).encode() + b"\n")
        while b"\n" not in self._buf:
            chunk = self._sock.recv(1 << 20)
            if not chunk:
                raise ConnectionError("control socket closed")
            self._buf += chunk
        line, self._buf = self._buf.split(b"\n", 1)
        return json.loads(line)

    def exec(self, line: str) -> str:
        r = self.request(cmd="exec", line=line)
        return r.get("text", "") if r.get("ok") else f"% {r.get('error')}"

    def snapshot(self) -> dict:
        r = self.request(cmd="snapshot")
        return r.get("data", {})

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass
