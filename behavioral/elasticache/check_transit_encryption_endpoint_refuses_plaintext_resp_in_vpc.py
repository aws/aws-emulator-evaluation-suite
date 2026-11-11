"""transit-encryption-endpoint-refuses-plaintext-resp-in-vpc."""
from __future__ import annotations

import base64
import hashlib
import io
import ipaddress
import json
import random
import secrets
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transit-encryption-endpoint-refuses-plaintext-resp-in-vpc"
GROUP = 'replication-group'
SERVICES = ['elasticache']

# The in-VPC executor. ElastiCache endpoints resolve only inside their VPC, so a Lambda with
# VpcConfig on the cache's subnets and security group runs a stdlib RESP probe and returns the raw
# reply bytes in the synchronous Invoke response. The codec frames RESP2 aggregates and RESP3 types
# and returns one flat span of raw bytes; `_agg`/`_frame_end` split it on the check side.
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

# Tags for the billable resource, so a leftover can be found and attributed to this check.
_RESOURCE_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    {"Key": "sim2real", "Value": CHECK},
]

# Carries the EC2 ENI actions without which CreateFunction with VpcConfig is rejected synchronously;
# AWSLambdaBasicExecutionRole alone is not enough.
_VPC_ACCESS_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"

# Marks a data-plane FAIL, so a failure message quoting `Connection refused` or `Read timed out`
# is graded as a fidelity failure rather than an environment error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_REDIS_PORT = 6379
_NODE_TYPE = "cache.t3.micro"
# Bounded windows for the VPC to hold no interface before it is deleted: inside the check body,
# after the function and the node are gone, and on the registered-cleanup path.
_NET_DRAIN_S = 1800
_NET_CLEANUP_S = 600

_HANDLER_SRC = r'''"""In-VPC probe executed by AWS Lambda inside the ElastiCache resource's VPC.

The T3 executor. It is deliberately DUMB: it opens sockets, returns raw bytes, and makes **no
assertions**. Every assertion lives in the check, for three reasons:

1. Only the check's own result is graded. An assertion that fires inside the Lambda reports as
   `FunctionError: Unhandled`, and the interesting bytes are then only in the function's log
   group -- i.e. in a place the check never reads.
2. Raw reply bytes are the whole point (`$-1` vs `$0\\r\\n\\r\\n`). Anything that parses them into
   a Python value on this side has already destroyed the evidence.
3. Changing an assertion must not require redeploying a function. The handler's contract is
   "commands in, raw replies out" and it is stable.

Operations:

  {"op": "selftest", "nonce": <hex>, "resolver": "10.20.0.2", "probe_host": <host|null>,
   "probe_port": <int>, "dns_name": "amazonaws.com"}
      -> evidence that (a) THIS code executed and (b) it executed with a network vantage point
         inside the caller's VPC. See `_route_source_ip` and `_dns_query`.

  {"op": "resp", "host": <str>, "port": <int>, "tls": <bool>,
   "commands": [["PING"], ["SET", "k", "v"], ...]}
      -> {"ok": true, "replies": [<base64 raw reply bytes>, ...], "tls_mode": ..., ...}
         or {"ok": false, "stage": "resolve"|"connect"|"io"|"framing", ...}

  {"op": "sessions", "host", "port", "tls", "sessions": [[cmds...], [cmds...]]}
      -> N CONCURRENT connections in ONE invoke, each on its own thread, rendezvoused on a
         `threading.Barrier`. A pseudo-command `{"sync": 1}` waits at the barrier and
         `{"sleep_ms": N}` sleeps, so a session script can place one connection's command
         strictly between two of another's. Required by anything whose semantics are a
         CROSS-CONNECTION ordering property (script atomicity observed by a second client);
         N simultaneous Invokes cannot express it, because they cannot be ordered against
         each other from inside.

NEVER raises out of `handler`: an exception would surface as `FunctionError` and cost the check the
structured evidence it needs to attribute the failure. Every failure is a return value.

Pure stdlib on purpose, and the RESP codec is HAND-FRAMED rather than `redis-py` even though
`redis-py` is pure Python and would zip with no layer. `redis-py` normalises `$-1` and
`$0\\r\\n\\r\\n` to the same Python value and would destroy the exact evidence every check that
uses this executor exists to produce.
"""

from __future__ import annotations

import base64
import hashlib
import os
import random
import socket
import ssl
import struct
import sys
import threading
import time

_CONNECT_TIMEOUT_S = 10
_IO_TIMEOUT_S = 15
_DNS_TIMEOUT_S = 3
_SESSION_SYNC_TIMEOUT_S = 60


# ---------------------------------------------------------------- network vantage point


def _route_source_ip(host: str, port: int) -> str:
    """The source address the kernel WOULD use to reach ``host:port``.

    `connect()` on a UDP socket sends no packets -- it only performs a route lookup and binds the
    local end -- so this is free and cannot be satisfied by anything listening at the far end.
    **Pass an IP literal**: on a hostname the call blocks in `getaddrinfo` instead, which
    `settimeout` does not bound because no socket I/O is involved.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, int(port)))
        return s.getsockname()[0]
    finally:
        s.close()


def _dns_query(resolver: str, name: str, timeout: float = _DNS_TIMEOUT_S) -> tuple[int, int]:
    """One hand-framed DNS A query straight at ``resolver``. Returns ``(rcode, ancount)``.

    Hand-framed rather than `socket.gethostbyname` because the RESOLVER IS THE SUBJECT: this must
    go to the address the caller nominated (the VPC's CIDR base + 2, where the Route 53 Resolver
    lives) and not to whatever `/etc/resolv.conf` happens to say. That address is answerable ONLY
    from inside that VPC and needs no NAT gateway and no internet route, which makes a reply from
    it the cheapest available proof of VPC attachment.

    The datagram we accept is validated on three counts, not one: it came from the resolver we
    nominated (the socket is unconnected, so the kernel would otherwise hand back a datagram from
    ANY source), it is a response rather than a stray query, and it carries our transaction id.
    Non-matching datagrams are SKIPPED rather than fatal, until the deadline.
    """
    qid = random.randrange(1, 0xFFFF)
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p for p in (lbl.encode() for lbl in name.split("."))) + b"\x00"
    packet = header + qname + struct.pack(">HH", 1, 1)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    deadline = time.monotonic() + timeout
    try:
        s.sendto(packet, (resolver, 53))
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError(f"no DNS reply from {resolver} matching id {qid} within {timeout}s")
            s.settimeout(remaining)
            data, addr = s.recvfrom(4096)
            if addr[0] != resolver or len(data) < 12:
                continue
            rid, flags, _qd, ancount, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
            if rid != qid or not flags & 0x8000:  # transaction id, then the QR bit
                continue
            return flags & 0x000F, ancount
    finally:
        s.close()


# ---------------------------------------------------------------- RESP2 + RESP3, framed by hand

# The type bytes, grouped by how the frame is DELIMITED rather than by what the value means -- the
# only thing a framer needs to know.
#
#   _SIMPLE     one CRLF-terminated line and nothing else.
#               + simple string   - error         : integer
#               , double          # boolean       ( big number        (RESP3)
#   _BULKISH    `<t><n>\r\n` then exactly n bytes then CRLF; n<0 is the null form.
#               $ bulk string     = verbatim string   ! blob error     (RESP3)
#   _AGGREGATE  `<t><n>\r\n` then n (or 2n) COMPLETE nested replies.
#               * array   ~ set   > push          (1 element per count)
#               % map     | attribute             (2 elements per count: key then value)
#   b"_"        the RESP3 null, `_\r\n`, which has no length field at all.
#
# The shipped codec this replaces framed `+-:$` only and returned `framing_understood=False` for
# EVERYTHING else, including every `*` array -- which desynchronises the stream, so no check could
# issue a second command after any array reply. That is why nothing in the corpus has ever asserted
# on XRANGE, CLUSTER SLOTS, EXEC, SCAN or a RESP3 aggregate.
_SIMPLE = b"+-:,#("
_BULKISH = b"$=!"
_AGGREGATE = {b"*": 1, b"~": 1, b">": 1, b"%": 2, b"|": 2}

# Bounds the recursion so a hostile or broken `*`-storm cannot exhaust the Lambda's stack and turn a
# fidelity finding into a FunctionError.
_MAX_DEPTH = 32


class _Desync(Exception):
    """The stream carried something this framer cannot delimit, so the connection is unusable.

    Carries every byte read for the reply so far: those bytes ARE the finding, and the check prints
    them. Never a crash and never discarded.
    """

    def __init__(self, raw: bytes, why: str):
        super().__init__(why)
        self.raw = raw
        self.why = why


def _resp_encode(*args) -> bytes:
    """Encode one command as a RESP2 array of bulk strings.

    Correct for every command including `HELLO 3` and `EVAL <body> <n> <keys...>`: RESP2's
    length-prefixed inline command form is what a RESP3 server also accepts for requests, so the
    encoder needs no version switch. A Lua script body containing CRLF is carried intact because
    the length prefix, not a delimiter scan, decides where the argument ends.
    """
    out = [b"*%d\r\n" % len(args)]
    for a in args:
        raw = a if isinstance(a, bytes) else str(a).encode()
        out.append(b"$%d\r\n" % len(raw))
        out.append(raw)
        out.append(b"\r\n")
    return b"".join(out)


def _open(host: str, port: int, tls: bool, io_timeout_s: float = _IO_TIMEOUT_S):
    """``(sock, tls_mode, tls_error)``. ``tls_mode`` is None when ``tls`` is False.

    On a TLS endpoint the handshake is attempted VERIFIED first and only then unverified, and which
    one succeeded is REPORTED rather than hidden. Two reasons it is not simply verified-or-bust:
    PKI is not the subject of any check that uses this executor (the corpus grades certificate
    chains in wire mode), and an emulator legitimately serves a self-signed certificate for an
    endpoint whose invariant under test is "TLS is required and RESP works over it". Reporting the
    mode keeps that tolerance from becoming invisible -- the check can still assert on it, and the
    transit-encryption check does.

    A failed handshake consumes the socket, so each attempt gets a FRESH connection.
    """
    if not tls:
        s = socket.create_connection((host, int(port)), timeout=_CONNECT_TIMEOUT_S)
        s.settimeout(io_timeout_s)
        return s, None, None
    first_err = None
    for mode in ("verified", "unverified"):
        raw = socket.create_connection((host, int(port)), timeout=_CONNECT_TIMEOUT_S)
        raw.settimeout(_IO_TIMEOUT_S)
        sslctx = ssl.create_default_context()
        if mode == "unverified":
            sslctx.check_hostname = False
            sslctx.verify_mode = ssl.CERT_NONE
        try:
            wrapped = sslctx.wrap_socket(raw, server_hostname=host)
            wrapped.settimeout(_IO_TIMEOUT_S)
            return wrapped, mode, first_err
        except (ssl.SSLError, OSError) as exc:
            if first_err is None:
                first_err = f"{type(exc).__name__}: {exc}"
            try:
                raw.close()
            except OSError:
                pass
    raise ssl.SSLError(f"TLS handshake failed verified AND unverified: {first_err}")


class _Resp:
    """A RESP2/RESP3 connection: send one command, return the COMPLETE RAW reply bytes.

    Raw bytes on purpose -- the semantics live in the framing (`+OK\\r\\n` vs `$-1\\r\\n` vs
    `$0\\r\\n\\r\\n` vs `:-2\\r\\n` vs `*-1\\r\\n` vs `*0\\r\\n`), and any client library normalises
    all of those into `None` / `''` / `-2` / `[]` and hides both the single most consequential Redis
    emulation bug (conflating "key absent" with "key present and empty") and its consumer-group
    equivalent (conflating "no entries pending" with "the group does not exist").

    Aggregates are framed RECURSIVELY and still returned as one flat byte span, so the caller keeps
    byte-level evidence and gets structure only when it asks for it (`_agg`, check-side).
    """

    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def _fill(self):
        chunk = self.sock.recv(65536)
        if not chunk:
            raise ConnectionError("endpoint closed the connection mid-reply")
        self.buf += chunk

    def _line(self):
        """One CRLF-terminated line, INCLUDING the trailing CRLF."""
        while b"\r\n" not in self.buf:
            self._fill()
        idx = self.buf.index(b"\r\n") + 2
        line, self.buf = self.buf[:idx], self.buf[idx:]
        return line

    def _exact(self, n):
        while len(self.buf) < n:
            self._fill()
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _count(self, first: bytes, seen: bytes) -> int:
        try:
            return int(first[1:-2])
        except ValueError:
            raise _Desync(seen, f"the length/count field of {first!r} is not an integer") from None

    def _read_reply(self, depth: int, prefix: bytes = b"") -> bytes:
        """One complete reply, as RAW BYTES, aggregates included.

        ``prefix`` is everything already read for the reply this one is nested inside, so a
        `_Desync` raised at depth 5 still reports the whole partial frame rather than one line of it.
        """
        first = self._line()
        seen = prefix + first
        kind = first[:1]
        if kind == b"_":                       # RESP3 null: `_\r\n`, no length field
            return first
        if kind in _SIMPLE:
            return first
        if kind in _BULKISH:
            n = self._count(first, seen)
            return first if n < 0 else first + self._exact(n + 2)
        mult = _AGGREGATE.get(kind)
        if mult is None:
            raise _Desync(seen, f"{kind!r} is not a RESP type byte at all")
        n = self._count(first, seen)
        if n < 0:                              # RESP2 null array `*-1\r\n`
            return first
        if depth >= _MAX_DEPTH:
            raise _Desync(seen, f"aggregate nesting exceeded {_MAX_DEPTH} levels")
        out = [first]
        for _ in range(n * mult):
            out.append(self._read_reply(depth + 1, b"".join(out)))
        return b"".join(out)

    def call(self, *args) -> tuple[bytes, bool]:
        """Send one command; return ``(raw_reply_bytes, framing_understood)``.

        ``framing_understood`` is False only when the stream carried something no RESP version
        defines. The bytes read so far are still returned -- never discarded and never raised --
        because those bytes ARE the finding, and the check's assertion prints them. The caller must
        stop issuing commands after a False, since the stream is now desynchronised.
        """
        self.sock.sendall(_resp_encode(*args))
        try:
            return self._read_reply(0), True
        except _Desync as exc:
            return exc.raw, False

    def read_push(self, timeout_s: float) -> bytes | None:
        """One SERVER-INITIATED frame, or None if none arrived within ``timeout_s``.

        Separate from `call` because there is no request to pair it with, which is exactly what
        makes a push frame unfakeable by request/response replay.
        """
        old = self.sock.gettimeout()
        self.sock.settimeout(timeout_s)
        try:
            return self._read_reply(0)
        except (socket.timeout, TimeoutError, OSError, _Desync):
            return None
        finally:
            try:
                self.sock.settimeout(old)
            except OSError:
                pass


def _resolve(host):
    """``(ip, error_dict_or_None)``. Resolved ONCE so `_route_source_ip` gets a literal (on a name
    UDP `connect()` blocks in `getaddrinfo`, which `settimeout` does not bound) and so the name
    cannot be looked up a second time and reach a different address than the one we measured."""
    try:
        return socket.gethostbyname(host), None
    except OSError as exc:
        return None, {
            "ok": False,
            "stage": "resolve",
            "errno": getattr(exc, "errno", None),
            "error": f"{type(exc).__name__}: {exc}",
            "host": host,
            "src_ip": None,
            "src_ip_error": None,
            "replies": [],
        }


def _vantage(ip, port):
    """``(src_ip, src_ip_error)`` -- free route lookup, no packets, purely for evidence."""
    try:
        return _route_source_ip(ip, port), None
    except OSError as exc:
        return None, f"{type(exc).__name__}: errno={exc.errno} {exc}"


def _resp_batch(host, port, commands, tls=False, io_timeout_s=_IO_TIMEOUT_S) -> dict:
    """Run ``commands`` in order against ``host:port``; return raw replies, base64'd.

    Every command ARGUMENT arrives base64-encoded and every reply leaves base64-encoded, in both
    directions, because the event travels as JSON and a Redis value is arbitrary BYTES. A value
    holding a CRLF -- the sequence RESP uses as its own frame delimiter, and therefore the sharpest
    available test of length-prefixed framing -- cannot be carried by a JSON string without the
    encoder deciding what its bytes mean.

    Serial, never pipelined: each reply is read to completion before the next command is sent, so a
    reply can never be attributed to the wrong command.
    """
    ip, err = _resolve(host)
    if err is not None:
        return err
    src_ip, src_err = _vantage(ip, port)

    try:
        sock, tls_mode, tls_err = _open(ip if not tls else host, port, tls,
                                        io_timeout_s=float(io_timeout_s))
        conn = _Resp(sock)
    except (OSError, socket.timeout) as exc:
        return {
            "ok": False,
            "stage": "connect",
            "errno": getattr(exc, "errno", None),
            "error": f"{type(exc).__name__}: {exc}",
            "src_ip": src_ip,
            "src_ip_error": src_err,
            "replies": [],
        }

    replies, stopped_at, framing_ok = [], None, True
    try:
        for i, cmd in enumerate(commands):
            raw, understood = conn.call(*[base64.b64decode(a) for a in cmd])
            replies.append(base64.b64encode(raw).decode())
            if not understood:
                framing_ok, stopped_at = False, i
                break
    except (OSError, socket.timeout, ConnectionError) as exc:
        return {
            "ok": False,
            "stage": "io",
            "errno": getattr(exc, "errno", None),
            "error": f"{type(exc).__name__}: {exc}",
            "src_ip": src_ip,
            "src_ip_error": src_err,
            "tls_mode": tls_mode,
            "tls_error": tls_err,
            "replies": replies,
            "stopped_at": len(replies),
        }
    finally:
        conn.close()

    return {
        "ok": True,
        "stage": "framing" if not framing_ok else "complete",
        "framing_understood": framing_ok,
        "stopped_at": stopped_at,
        # The address the NAME the control plane advertised actually resolved to, from inside the
        # VPC. Reported because `CLUSTER SLOTS` answers in raw IPs while DescribeCacheClusters
        # answers in DNS names, and the only way to assert the two planes agree is to resolve the
        # name at the vantage point that can see it.
        "target_ip": ip,
        "src_ip": src_ip,
        "src_ip_error": src_err,
        "tls_mode": tls_mode,
        "tls_error": tls_err,
        "replies": replies,
    }


def _sessions(host, port, sessions, tls=False) -> dict:
    """N CONCURRENT connections in one invoke, rendezvoused on a barrier.

    Each session is a list of either a command (a list of base64 args) or a pseudo-command:

        {"sync": 1}      wait until EVERY session reaches its next sync point
        {"sleep_ms": N}  sleep, without sending anything

    Both pseudo-commands append `null` to that session's reply list, so reply indices line up with
    the script the check wrote and no off-by-one can silently shift an assertion onto the wrong
    reply.

    A session that dies ABORTS the barrier rather than leaving its siblings blocked until the Lambda
    timeout -- a deadlock there would surface as a FunctionError, i.e. as "the instrument is
    unusable", for what is really one connection's failure. Every failure is a return value.
    """
    ip, err = _resolve(host)
    if err is not None:
        return err
    n = len(sessions)
    barrier = threading.Barrier(n)
    results: list = [None] * n
    monotonic0 = time.monotonic()

    def worker(idx: int, script: list) -> None:
        rec: dict = {"ok": False, "stage": None, "error": None, "replies": [], "t": []}
        results[idx] = rec
        try:
            sock, tls_mode, tls_err = _open(ip if not tls else host, port, tls)
        except (OSError, socket.timeout, ssl.SSLError) as exc:
            rec["stage"] = "connect"
            rec["error"] = f"{type(exc).__name__}: {exc}"
            barrier.abort()
            return
        rec["tls_mode"], rec["tls_error"] = tls_mode, tls_err
        conn = _Resp(sock)
        try:
            for step in script:
                if isinstance(step, dict):
                    if "sync" in step:
                        barrier.wait(timeout=_SESSION_SYNC_TIMEOUT_S)
                    else:
                        time.sleep(float(step["sleep_ms"]) / 1000.0)
                    rec["replies"].append(None)
                    rec["t"].append(round(time.monotonic() - monotonic0, 4))
                    continue
                raw, understood = conn.call(*[base64.b64decode(a) for a in step])
                rec["replies"].append(base64.b64encode(raw).decode())
                rec["t"].append(round(time.monotonic() - monotonic0, 4))
                if not understood:
                    rec["stage"] = "framing"
                    return
            rec["ok"] = True
            rec["stage"] = "complete"
        except threading.BrokenBarrierError as exc:
            rec["stage"] = "sync"
            rec["error"] = f"{type(exc).__name__}: a sibling session failed or timed out: {exc}"
        except Exception as exc:  # noqa: BLE001 -- every failure is a return value
            rec["stage"] = rec["stage"] or "io"
            rec["error"] = f"{type(exc).__name__}: {exc}"
            barrier.abort()
        finally:
            conn.close()

    threads = [threading.Thread(target=worker, args=(i, s), daemon=True)
               for i, s in enumerate(sessions)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=_SESSION_SYNC_TIMEOUT_S * 2)
    alive = [i for i, t in enumerate(threads) if t.is_alive()]
    return {
        "ok": all((r or {}).get("ok") for r in results) and not alive,
        "stage": "complete" if not alive else "hung",
        "hung_sessions": alive,
        "sessions": results,
    }


# ---------------------------------------------------------------- entry point


def _selftest(event: dict) -> dict:
    """Prove (a) this code ran and (b) it ran inside the caller's VPC.

    (a) is the nonce digest. An emulator that accepts `CreateFunction` and `Invoke` but does not
    execute the zip cannot produce sha256 over a value it never saw. The digest covers the OTHER
    reported fields too, so a target that runs the code and then rewrites the response invalidates
    its own proof.

    (b) is two independent signals, because neither is conclusive alone:
        `src_ip`  the address a packet to an in-VPC target would leave from. The check tests it
                  against the CIDR of the VPC it passed in `VpcConfig`.
        `rcode`   a DNS answer from the VPC resolver at CIDR-base+2, an address that only exists
                  inside that VPC.
    """
    nonce = str(event.get("nonce", ""))
    resolver = event.get("resolver")
    probe_host = event.get("probe_host") or resolver
    probe_port = int(event.get("probe_port", 53))

    src_ip, src_err = None, None
    if probe_host:
        try:
            src_ip = _route_source_ip(probe_host, probe_port)
        except OSError as exc:
            src_err = f"{type(exc).__name__}: errno={exc.errno} {exc}"

    rcode, ancount, dns_err = None, None, None
    if resolver:
        try:
            rcode, ancount = _dns_query(resolver, event.get("dns_name") or "amazonaws.com")
        except Exception as exc:  # noqa: BLE001 -- every failure is a return value, never a raise
            dns_err = f"{type(exc).__name__}: {exc}"

    hostname_ip = None
    try:
        hostname_ip = socket.gethostbyname(socket.gethostname())
    except OSError:
        pass

    return {
        "ok": True,
        "nonce": nonce,
        # Same f-string on both sides. JSON `null` renders as "None" in Python, which is why the
        # check must recompute from the DECODED values rather than from what it sent.
        "proof": hashlib.sha256(f"{nonce}|{src_ip}|{rcode}".encode()).hexdigest(),
        "src_ip": src_ip,
        "src_ip_error": src_err,
        "resolver": resolver,
        "resolver_rcode": rcode,
        "resolver_ancount": ancount,
        "resolver_error": dns_err,
        "hostname_ip": hostname_ip,
        "runtime": {
            "python": sys.version.split()[0],
            "function": os.environ.get("AWS_LAMBDA_FUNCTION_NAME"),
            "exec_env": os.environ.get("AWS_EXECUTION_ENV"),
            "region": os.environ.get("AWS_REGION"),
        },
    }


def handler(event, context):  # noqa: ARG001 -- Lambda signature
    op = (event or {}).get("op")
    try:
        if op == "selftest":
            return _selftest(event)
        if op == "resp":
            return _resp_batch(event["host"], event["port"], event["commands"],
                               tls=bool(event.get("tls")),
                               io_timeout_s=event.get("io_timeout_s", _IO_TIMEOUT_S))
        if op == "sessions":
            return _sessions(event["host"], event["port"], event["sessions"],
                             tls=bool(event.get("tls")))
        return {"ok": False, "stage": "dispatch", "error": f"unknown op {op!r}"}
    except Exception as exc:  # noqa: BLE001 -- see the module docstring: never raise
        import traceback

        return {
            "ok": False,
            "stage": "handler",
            "error": f"{type(exc).__name__}: {exc}",
            "traceback": traceback.format_exc()[-1200:],
        }
'''

_LOCAL_NS: dict = {}


def _local_client() -> dict:
    """Compile _HANDLER_SRC in this process and return its namespace.

    Runner and Lambda then drive the same codec, so the two vantage points cannot differ by client.
    """
    if not _LOCAL_NS:
        exec(compile(_HANDLER_SRC, "<invpc-handler>", "exec"), _LOCAL_NS)  # noqa: S102
    return _LOCAL_NS


def _dp_fail(msg: str) -> AssertionError:
    """The data-plane FAIL, returned rather than raised so a call site keeps `from exc` chaining."""
    return AssertionError(f"{DATAPLANE_MARKER}: {msg}")


def _never_ready(msg: str):
    """A resource the target accepted and never brought to its ready state within the budget."""
    return AssertionError(msg)


def _no_executor(msg: str):
    """The in-VPC executor is unusable, so this run measured nothing and records no verdict."""
    return AssertionError(f"the in-VPC executor is unusable, so this run measured nothing: {msg}")


def _no_capacity(msg: str):
    """InsufficientCacheClusterCapacity: the account ran out of the node type; the endpoint was never
    advertised, so this is not a data-plane failure."""
    return AssertionError(msg)


def _fault_base(code: str) -> str:
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code


def _code_of(exc: ClientError) -> str:
    return _fault_base(exc.response.get("Error", {}).get("Code") or "")


def _msg_of(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Message") or str(exc)


def _error_of(fn) -> tuple[str, str]:
    """The exact ``(code, message)`` ``fn()`` raised; raises AssertionError when it succeeds."""
    try:
        out = fn()
    except ClientError as exc:
        return _code_of(exc), _msg_of(exc)
    raise AssertionError(
        f"the call was expected to be rejected but SUCCEEDED, returning {out!r}. That is the "
        f"over-permissiveness this check exists to catch, not a code mismatch"
    )


def _poll(probe, predicate, *, timeout_s: float, interval_s: float):
    """Poll `probe` until `predicate`; return the last observation, or None on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            return None
        time.sleep(interval_s)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _paginate(client, op: str, key: str, **kwargs):
    """Every page of `op`, flattened on `key`."""
    try:
        pager = client.get_paginator(op)
    except Exception:  # noqa: BLE001 -- no paginator modeled; fall back to one call
        return getattr(client, op)(**kwargs).get(key, [])
    out = []
    for page in pager.paginate(**kwargs):
        out.extend(page.get(key, []))
    return out


# A lost race to create a subnet: both racers derive the same CIDR, so the loser adopts.
_SUBNET_RACE_LOST = frozenset({"InvalidSubnet.Conflict", "InvalidSubnetRange.Conflict"})


def _has_self_ingress(ec2, sg_id: str, port: int) -> bool:
    """Does sg_id already admit ``port`` from itself?

    Matched on the group pair, not a CIDR, so a connect proves the traffic came from our ENI.
    """
    groups = _paginate(ec2, "describe_security_groups", "SecurityGroups", GroupIds=[sg_id])
    for perm in (groups[0].get("IpPermissions", []) if groups else []):
        if perm.get("IpProtocol") != "tcp":
            continue
        lo, hi = perm.get("FromPort"), perm.get("ToPort")
        if lo is None or hi is None or not (lo <= port <= hi):
            continue
        if any(p.get("GroupId") == sg_id for p in perm.get("UserIdGroupPairs", [])):
            return True
    return False


def _ensure_self_ingress(ec2, sg_id: str, port: int = _REDIS_PORT) -> None:
    """Authorize the self-referencing rule for ``port`` on sg_id unless it is already there.

    Takes a port because cluster-mode shard nodes are reached directly, not only on 6379.
    """
    if _has_self_ingress(ec2, sg_id, port):
        return
    try:
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": port,
                "ToPort": port,
                "UserIdGroupPairs": [{
                    "GroupId": sg_id,
                    "Description": "in-VPC executor to cache node, same security group only",
                }],
            }],
        )
    except ClientError as exc:
        # A concurrent run added the same rule.
        if _code_of(exc) != "InvalidPermission.Duplicate":
            raise
    assert _has_self_ingress(ec2, sg_id, port), (
        f"{sg_id} still does not admit tcp/{port} from itself after authorizing; the round trip "
        f"below could not distinguish this from a broken data plane"
    )


def _dns_attributes_ok(ec2, vpc_id: str) -> bool:
    """Are both VPC DNS attributes already on? Read first so a correct VPC is never modified."""
    # The request spells the attribute lower-camel and the response upper-camel.
    return all(
        ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute=req)[resp]["Value"]
        for req, resp in (("enableDnsSupport", "EnableDnsSupport"),
                          ("enableDnsHostnames", "EnableDnsHostnames"))
    )


def _ensure_dns_attributes(ec2, vpc_id: str) -> None:
    """Turn on both DNS attributes, only if one is off; the VPC resolver proof needs DNS support."""
    if _dns_attributes_ok(ec2, vpc_id):
        return
    for attr in ("EnableDnsSupport", "EnableDnsHostnames"):
        ec2.modify_vpc_attribute(VpcId=vpc_id, **{attr: {"Value": True}})


def _network_subnets(ec2, vpc_id: str, want: int = 2) -> list:
    """Up to ``want`` of the VPC's available subnets, one per distinct availability zone.

    Two zones let ElastiCache place the node where capacity exists; lowest SubnetId per zone.
    """
    subnets = _paginate(ec2, "describe_subnets", "Subnets",
                        Filters=[{"Name": "vpc-id", "Values": [vpc_id]},
                                 {"Name": "state", "Values": ["available"]}])
    by_az: dict = {}
    for s in sorted(subnets, key=lambda s: s["SubnetId"]):
        az = s.get("AvailabilityZone")
        if az and az not in by_az:
            by_az[az] = s["SubnetId"]
    return [by_az[az] for az in sorted(by_az)[:want]]


def _create_infra_vpc(ctx, ec2, want: int = 2) -> str:
    """Build this run's executor VPC, one subnet per zone, teardown registered; -> VpcId."""
    # A random second octet makes the "source address inside our VPC" signal sharp.
    cidr = f"10.{random.randrange(20, 250)}.0.0/16"
    vpc_id = ec2.create_vpc(
        CidrBlock=cidr,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _MANAGED_TAGS}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda v=vpc_id: _teardown_network(ec2, v, timeout_s=_NET_CLEANUP_S))
    _ensure_dns_attributes(ec2, vpc_id)
    zones = _paginate(ec2, "describe_availability_zones", "AvailabilityZones",
                      Filters=[{"Name": "state", "Values": ["available"]},
                               {"Name": "opt-in-status", "Values": ["opt-in-not-required"]}])
    names = sorted(z["ZoneName"] for z in zones)
    assert names, (
        f"no available, non-opt-in availability zone in {ec2.meta.region_name!r}: {zones!r}; this "
        f"region cannot host the in-VPC executor")
    for i, az in enumerate(names[:want], start=1):
        try:
            ec2.create_subnet(
                VpcId=vpc_id,
                CidrBlock=f"{cidr.split('.')[0]}.{cidr.split('.')[1]}.{i}.0/24",
                AvailabilityZone=az,
                TagSpecifications=[{"ResourceType": "subnet", "Tags": _MANAGED_TAGS}],
            )
        except ClientError as exc:
            # A conflict means the subnet for this zone already exists in this run's VPC.
            if _code_of(exc) not in _SUBNET_RACE_LOST:
                raise
    assert _network_subnets(ec2, vpc_id, want), f"created no usable subnet in {vpc_id}"
    return vpc_id


def _executor_network(ctx, ec2, port: int = _REDIS_PORT) -> dict:
    """The executor network: this run's own VPC, two subnets in two zones, and a self-referencing
    security group. Every piece is created here and removed by `_teardown_network`."""
    vpc_id = _create_infra_vpc(ctx, ec2)

    vpcs = _paginate(ec2, "describe_vpcs", "Vpcs", VpcIds=[vpc_id])
    assert vpcs and vpcs[0].get("CidrBlock"), (
        f"the executor VPC {vpc_id} reports no CidrBlock: {vpcs!r}; the subnet addresses and the "
        f"resolver address are both derived from it")
    cidr = vpcs[0]["CidrBlock"]

    _ensure_dns_attributes(ec2, vpc_id)
    subnet_ids = _network_subnets(ec2, vpc_id, want=2)
    assert subnet_ids, (
        f"the executor VPC {vpc_id} has no available subnet, so neither the Lambda ENI nor the cache "
        f"node can be placed in it")

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-invpc-sg-"),
        Description=("sim2real in-VPC executor: Lambda ENI + ElastiCache node, "
                     "self-referencing"),
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _MANAGED_TAGS}],
    )["GroupId"]
    _ensure_self_ingress(ec2, sg_id, port)

    return {
        "vpc_id": vpc_id,
        "cidr": cidr,
        "resolver": str(ipaddress.ip_network(cidr).network_address + 2),
        "subnet_ids": subnet_ids,
        "sg_id": sg_id,
    }


def _ensure_cache_subnet_group(ctx, ec, net: dict) -> str:
    """The cache subnet group over this run's executor subnets, deleted on teardown."""
    name = f"sim2real-invpc-{net['vpc_id']}"[:255]
    try:
        found = (ec.describe_cache_subnet_groups(
            CacheSubnetGroupName=name).get("CacheSubnetGroups") or [None])[0]
        if found:
            # Complete, don't merely find: a single-AZ group would defeat the two-AZ mitigation.
            have = {s["SubnetIdentifier"] for s in found.get("Subnets", [])}
            want = set(net["subnet_ids"])
            if want - have:
                ec.modify_cache_subnet_group(CacheSubnetGroupName=name,
                                             SubnetIds=sorted(have | want))
            return name
    except ClientError as exc:
        if _code_of(exc) != "CacheSubnetGroupNotFound":
            raise
    try:
        ec.create_cache_subnet_group(
            CacheSubnetGroupName=name,
            CacheSubnetGroupDescription="sim2real in-VPC executor network",
            SubnetIds=net["subnet_ids"],
            Tags=_MANAGED_TAGS,
        )
    except ClientError as exc:
        # The name derives from the VPC id, so concurrent runs can both create; the loser adopts.
        if _code_of(exc) != "CacheSubnetGroupAlreadyExists":
            raise
    ctx.on_cleanup(lambda n=name: _delete_cache_subnet_group(ec, n))
    return name


def _delete_cache_subnet_group(ec, name: str, timeout_s: float = 300, interval_s: float = 2):
    """Delete the subnet group once no node holds it. Raises when it is still held at the end."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec.delete_cache_subnet_group(CacheSubnetGroupName=name)
            return
        except ClientError as exc:
            code = _code_of(exc)
            if code == "CacheSubnetGroupNotFound":
                return
            if code != "CacheSubnetGroupInUse" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


_LAMBDA_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}

_ROLE_NOT_READY = ("cannot be assumed", "does not have permissions", "CreateNetworkInterface")


def _vpc_exec_role_arn(ctx) -> str:
    """An execution role that can create ENIs, created per run and deleted on teardown.

    AWSLambdaVPCAccessExecutionRole carries the EC2 actions without which CreateFunction with
    VpcConfig is rejected outright.
    """
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-invpc-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_LAMBDA_TRUST),
        Description="sim2real in-VPC data-plane executor",
        Tags=_MANAGED_TAGS,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda n=name: _delete_role(iam, n))
    iam.attach_role_policy(RoleName=name, PolicyArn=_VPC_ACCESS_POLICY)
    return arn


def _delete_role(iam, name: str):
    try:
        for p in _paginate(iam, "list_attached_role_policies", "AttachedPolicies", RoleName=name):
            iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if _code_of(exc) not in ("NoSuchEntity", "NoSuchEntityException"):
            raise


def _make_zip(src: str, filename: str = "index.py") -> bytes:
    """The whole deployment package: one stdlib file, no dependency, no layer."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, src)
    return buf.getvalue()


def _deploy_executor(ctx, lam, net: dict, role_arn: str):
    """CreateFunction with VpcConfig, retried through IAM propagation, then wait Active.

    A role created seconds ago is rejected with InvalidParameterValueException until it propagates.
    """
    name = ctx.unique_name("sim2real-behav-invpc-fn-")
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=role_arn,
        Code={"ZipFile": _make_zip(_HANDLER_SRC)},
        MemorySize=512,
        # 300s: a `sessions` invoke holds connections open across a barrier and a deliberate wait.
        Timeout=300,
        VpcConfig={"SubnetIds": net["subnet_ids"], "SecurityGroupIds": [net["sg_id"]]},
        Tags={t["Key"]: t["Value"] for t in _MANAGED_TAGS},
    )
    deadline = time.monotonic() + 120
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            msg = _msg_of(exc)
            transient = _code_of(exc) == "InvalidParameterValue" and any(
                s in msg for s in _ROLE_NOT_READY)
            if not transient or time.monotonic() >= deadline:
                raise _no_executor(
                    f"CreateFunction with VpcConfig={kwargs['VpcConfig']!r} was rejected: "
                    f"{_code_of(exc)}: {msg}",
                ) from exc
            time.sleep(2)
    ctx.on_cleanup(lambda n=name: _delete_function(ctx, lam, n))

    last = _poll(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get("State") in ("Active", "Failed"),
        timeout_s=_budget_s(ctx, 300),
        interval_s=2,
    )
    if last is None:
        if _budget_spent(ctx):
            raise TimeoutError(f"the in-VPC executor {name} reaching State=Active: the run budget "
                               f"ended first; not graded")
        raise _never_ready(
            f"the in-VPC executor {name} did not reach State=Active within the bounded wait (a "
            f"first Hyperplane ENI in a fresh subnet/security-group pair is the slow part)",
        )
    if last["State"] != "Active":
        raise _no_executor(f"{name} entered State={last['State']!r}: {last.get('StateReason')!r}")
    return name, (last.get("VpcConfig") or {})


def _delete_function(ctx, lam, name: str):
    """Delete the function and its log group; Lambda releases the Hyperplane ENI asynchronously."""
    for fn in (
        lambda: lam.delete_function(FunctionName=name),
        lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}"),
    ):
        try:
            fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise


def _invoke(ctx, lam, fn: str, payload: dict) -> dict:
    """One synchronous Invoke, returning the decoded handler result.

    The handler never raises, so a FunctionError or non-200 means the executor itself is unusable.
    """
    resp = lam.invoke(FunctionName=fn, InvocationType="RequestResponse",
                      Payload=json.dumps(payload).encode())
    raw = resp["Payload"].read()
    if resp.get("FunctionError") or resp.get("StatusCode") != 200:
        raise _no_executor(
            f"Invoke of {fn} returned StatusCode={resp.get('StatusCode')!r} "
            f"FunctionError={resp.get('FunctionError')!r}: {raw[:600]!r}",
        )
    try:
        out = json.loads(raw)
    except ValueError as exc:
        raise _no_executor(f"Invoke of {fn} returned a body that is not JSON: {raw[:600]!r}") from exc
    if not isinstance(out, dict):
        raise _no_executor(
            f"Invoke of {fn} returned {type(out).__name__}, not the handler's object: {out!r}")
    return out


def _prove_executor_in_vpc(ctx, lam, fn: str, net: dict):
    """Before anything billable exists, decide whether the executor runs inside the VPC.

    Returns (evidence, in_vpc, reason): a nonce digest proves our code ran, and a source IP in the
    VPC CIDR or any reply from the VPC resolver at CIDR-base+2 proves it ran inside the VPC.
    """
    nonce = secrets.token_hex(16)
    ev = _invoke(ctx, lam, fn, {
        "op": "selftest",
        "nonce": nonce,
        "resolver": net["resolver"],
        "probe_host": net["resolver"],
        "probe_port": 53,
        "dns_name": "amazonaws.com",
    })

    # Our code executed.
    expected = hashlib.sha256(
        f"{nonce}|{ev.get('src_ip')}|{ev.get('resolver_rcode')}".encode()).hexdigest()
    if ev.get("nonce") != nonce or ev.get("proof") != expected:
        raise _no_executor(
            f"the invoke returned {ev!r}, which does not carry sha256 over the nonce {nonce!r} "
            f"bound to the network fields it reported (expected proof {expected!r}); the target "
            f"accepted CreateFunction and Invoke but did not execute the package")

    # It executed inside the VPC we asked for.
    signals = []
    src_ip = ev.get("src_ip")
    if src_ip:
        try:
            if ipaddress.ip_address(src_ip) in ipaddress.ip_network(net["cidr"]):
                signals.append(f"ip:{src_ip} in {net['cidr']}")
        except ValueError:
            pass
    if ev.get("resolver_rcode") is not None:
        signals.append(
            f"dns:reply rcode={ev['resolver_rcode']} from the VPC resolver {net['resolver']}")

    if signals:
        return ev, True, "; ".join(signals)
    return ev, False, (
        f"neither in-VPC signal fired: the source address toward {net['resolver']} was {src_ip!r} "
        f"(error {ev.get('src_ip_error')!r}), which is not inside the executor VPC CIDR "
        f"{net['cidr']}; and the VPC resolver at {net['resolver']} did not reply at all (error "
        f"{ev.get('resolver_error')!r})")


def _bring_up_executor(ctx, port: int = _REDIS_PORT):
    """Everything up to and including the control step, before anything billable exists.

    Returns (lam, net, fn, in_vpc, why).
    """
    ec2 = ctx.client("ec2")
    lam = ctx.client("lambda")
    net = _executor_network(ctx, ec2, port)
    role_arn = _vpc_exec_role_arn(ctx)
    fn, cfg_vpc = _deploy_executor(ctx, lam, net, role_arn)
    # Echoing VpcConfig back proves little; the selftest is the real proof.
    assert sorted(cfg_vpc.get("SubnetIds") or []) == sorted(net["subnet_ids"]), (
        f"GetFunctionConfiguration reports VpcConfig.SubnetIds={cfg_vpc.get('SubnetIds')!r}, not "
        f"the {net['subnet_ids']!r} passed to CreateFunction")
    evidence, in_vpc, why = _prove_executor_in_vpc(ctx, lam, fn, net)
    if not in_vpc:
        # A function proven to execute outside the named VPC could never reach the cache.
        raise _no_executor(
            f"CreateFunction accepted VpcConfig={cfg_vpc!r} and the package ran, but {why}. "
            f"Selftest evidence: {evidence!r}")
    return lam, net, fn, in_vpc, why


def _as_bytes(arg) -> bytes:
    return arg if isinstance(arg, bytes) else str(arg).encode()


def _enc_cmd(cmd) -> list:
    return [base64.b64encode(_as_bytes(a)).decode() for a in cmd]


class _Prober:
    """One vantage point, exposing the handler's ops with an identical signature either way.

    Chosen once by a PING, so a positive control and its refusal never land on different networks.
    """

    def __init__(self, label, fn):
        self.label = label
        self._fn = fn

    def resp(self, host, port, commands, tls=False, io_timeout_s=None) -> dict:
        """Run ``commands`` (lists of ``str``/``bytes`` args) and return the handler's result.

        Arguments are base64'd because the event is JSON and a Redis value is arbitrary bytes."""
        event = {"op": "resp", "host": host, "port": int(port), "tls": bool(tls),
                 "commands": [_enc_cmd(c) for c in commands]}
        if io_timeout_s is not None:
            event["io_timeout_s"] = io_timeout_s
        return self._fn(event)

    def sessions(self, host, port, sessions, tls=False) -> dict:
        """Run N concurrent sessions; a ``dict`` step is a ``sync``/``sleep_ms`` pseudo-command."""
        return self._fn({"op": "sessions", "host": host, "port": int(port), "tls": bool(tls),
                         "sessions": [[s if isinstance(s, dict) else _enc_cmd(s) for s in script]
                                      for script in sessions]})


def _dispatch_local(event: dict) -> dict:
    ns = _local_client()
    if event["op"] == "sessions":
        return ns["_sessions"](event["host"], event["port"], event["sessions"],
                               tls=event.get("tls", False))
    return ns["_resp_batch"](event["host"], event["port"], event["commands"],
                             tls=event.get("tls", False),
                             io_timeout_s=event.get("io_timeout_s", ns["_IO_TIMEOUT_S"]))


def _pick_prober(ctx, lam, fn: str, host, port, *, in_vpc: bool, why: str, tls: bool,
                 subject: str) -> _Prober:
    """The vantage point that can reach ``host:port``, or the failure that none can.

    Polled, because a cache reports 'available' before its endpoint accepts connections.
    """
    runner = _Prober("runner-outside-vpc", _dispatch_local)
    lamprobe = (_Prober("lambda-in-vpc", lambda ev: _invoke(ctx, lam, fn, ev))
                if in_vpc else None)
    budget = round(_budget_s(ctx, 300))
    deadline = time.monotonic() + budget
    outside, invpc, attempts = None, None, 0
    while True:
        attempts += 1
        if attempts == 1 or lamprobe is None:
            outside = runner.resp(host, port, [["PING"]], tls=tls)
            if outside.get("ok"):
                return runner
        if lamprobe is not None:
            invpc = lamprobe.resp(host, port, [["PING"]], tls=tls)
            if invpc.get("ok"):
                return lamprobe
        if time.monotonic() >= deadline:
            break
        time.sleep(2)

    if _budget_spent(ctx):
        raise TimeoutError(f"a RESP connection to {subject} at {host}:{port}: the run budget ended "
                           f"first; not graded")
    detail = (f"{subject} advertises {host}:{port} (tls={tls}). {attempts} attempts over {budget}s. "
              f"in-VPC probe: {invpc!r}. runner-side probe: {outside!r}.")
    if in_vpc:
        raise _dp_fail(
            f"the ElastiCache control plane provisioned {subject} and advertised {host}:{port}, but "
            f"nothing there accepts a RESP connection from inside its own VPC (executor proven "
            f"in-VPC by {why}). An endpoint that cannot be connected to is not a data plane. "
            f"{detail}")
    raise _no_executor(f"{why}. {detail}")


def _replies(result: dict, commands, *, source: str) -> list:
    """The raw reply bytes for ``commands``, asserting one reply per command."""
    assert result.get("ok"), (
        f"[{source}] the probe did not complete: {result!r}. Commands sent: "
        f"{[list(c) for c in commands]!r}")
    raws = [base64.b64decode(r) for r in result.get("replies", [])]
    assert len(raws) == len(commands), (
        f"[{source}] the endpoint framed {len(raws)} of {len(commands)} replies. Commands sent: "
        f"{[list(c) for c in commands]!r}. Raw replies received: {raws!r}")
    return raws


def _session_replies(result: dict, scripts, *, source: str) -> list:
    """Per-session raw reply lists, asserting every session completed its whole script.

    A pseudo-command's slot is None, so reply indexes match the script's command indexes.
    """
    assert result.get("ok"), (
        f"[{source}] the concurrent-session probe did not complete: {result!r}. Scripts: "
        f"{scripts!r}")
    out = []
    for i, (rec, script) in enumerate(zip(result.get("sessions") or [], scripts)):
        assert rec and rec.get("ok"), f"[{source}] session {i} did not complete: {rec!r}"
        raws = [None if r is None else base64.b64decode(r) for r in rec.get("replies", [])]
        assert len(raws) == len(script), (
            f"[{source}] session {i} returned {len(raws)} of {len(script)} replies: {raws!r}")
        out.append(raws)
    assert len(out) == len(scripts), (
        f"[{source}] {len(out)} of {len(scripts)} sessions reported at all: {result!r}")
    return out


# The handler's framing groups, as bytes literals for indexing a buffer.
_SIMPLE_B = b"+-:,#("
_BULKISH_B = b"$=!"
_AGG_B = {b"*": 1, b"~": 1, b">": 1, b"%": 2, b"|": 2}


def _frame_end(raw: bytes, i: int, *, depth: int = 0) -> int:
    """The index just past the one complete reply that starts at ``raw[i]``.

    Lets aggregates with server-generated ids be split into element spans and compared per element.
    """
    assert i < len(raw), f"ran off the end of a reply while framing at offset {i}: {raw!r}"
    crlf = raw.find(b"\r\n", i)
    assert crlf >= 0, f"no CRLF after offset {i} in {raw!r}"
    j, kind, head = crlf + 2, raw[i:i + 1], raw[i + 1:crlf]
    if kind == b"_" or kind in _SIMPLE_B:
        return j
    if kind in _BULKISH_B:
        n = int(head)
        return j if n < 0 else j + n + 2
    mult = _AGG_B.get(kind)
    assert mult is not None, (
        f"{kind!r} at offset {i} is not a RESP type byte at all, in reply {raw!r}")
    n = int(head)
    if n < 0:
        return j
    assert depth < 32, f"aggregate nesting exceeded 32 levels in {raw!r}"
    for _ in range(n * mult):
        j = _frame_end(raw, j, depth=depth + 1)
    return j


def _agg(raw: bytes, *, source: str = "", cmd: str = "") -> list:
    """One aggregate reply split into its element spans, each still raw bytes.

    A map (`%`) or attribute (`|`) yields ``2n`` flat spans: key, value, key, value.
    """
    kind = raw[:1]
    mult = _AGG_B.get(kind)
    assert mult is not None, (
        f"[{source}] {cmd} must return a RESP aggregate (*, ~, >, % or |), got {raw!r}")
    crlf = raw.index(b"\r\n")
    n = int(raw[1:crlf])
    assert n >= 0, (
        f"[{source}] {cmd} returned the NULL aggregate {raw!r}; there are no elements to read")
    out, i = [], crlf + 2
    for _ in range(n * mult):
        end = _frame_end(raw, i)
        out.append(raw[i:end])
        i = end
    assert i == len(raw), (
        f"[{source}] {cmd} declared {n} elements but its frame has {len(raw) - i} trailing bytes: "
        f"{raw!r}")
    return out


def _resp_int(raw: bytes, *, source: str, cmd: str) -> int:
    """The integer in a RESP ``:<n>\\r\\n`` reply, asserted numeric rather than crashing."""
    assert raw.startswith(b":") and raw.endswith(b"\r\n"), (
        f"[{source}] {cmd} must return a RESP integer reply (:<n>\\r\\n), got {raw!r}")
    try:
        return int(raw[1:-2])
    except ValueError:
        raise AssertionError(
            f"[{source}] {cmd} framed an integer reply but its payload is not an integer: {raw!r}. "
            f"A client's int conversion would raise on this") from None


def _resp_bulk(raw: bytes, *, source: str, cmd: str) -> bytes:
    """The payload of a RESP bulk-string reply; ``$-1\\r\\n`` (absent) is rejected, not b""."""
    assert raw.startswith(b"$"), (
        f"[{source}] {cmd} must return a RESP bulk string ($<len>\\r\\n<bytes>\\r\\n), got {raw!r}")
    head, _, rest = raw[1:].partition(b"\r\n")
    length = int(head)
    assert length >= 0, (
        f"[{source}] {cmd} returned the NULL bulk string {raw!r}, i.e. the value is ABSENT; there "
        f"is no payload to read")
    assert len(rest) == length + 2, (
        f"[{source}] {cmd} declared a {length}-byte bulk string but framed {len(rest) - 2} bytes: "
        f"{raw!r}")
    return rest[:-2]


def _bulk_expected(value: bytes) -> bytes:
    """The exact RESP bulk-string reply a faithful GET of ``value`` must produce, byte for byte."""
    return b"$%d\r\n%s\r\n" % (len(value), value)


def _resp_error_name(raw: bytes, *, source: str, cmd: str) -> str:
    """The error NAME out of a RESP error frame ``-NAME free text\\r\\n``, compared exactly."""
    assert raw.startswith(b"-") and raw.endswith(b"\r\n"), (
        f"[{source}] {cmd} was expected to be refused with a RESP error frame "
        f"(-NAME message\\r\\n), got {raw!r}")
    return raw[1:-2].split(b" ", 1)[0].decode("ascii", "replace")


def _info_field(raw: bytes, field: str, *, source: str) -> int:
    """One integer field out of an INFO bulk string, parsed per line and asserted present."""
    body = _resp_bulk(raw, source=source, cmd="INFO")
    for line in body.split(b"\r\n"):
        if line.startswith(b"#") or b":" not in line:
            continue
        name, _, val = line.partition(b":")
        if name == field.encode():
            try:
                return int(val)
            except ValueError:
                raise AssertionError(
                    f"[{source}] INFO reported {field}={val!r}, which is not an integer") from None
    raise AssertionError(
        f"[{source}] INFO does not report a {field!r} line at all. A Redis engine that serves INFO "
        f"must publish it. Body was {body[:1500]!r}")


def _info_text(raw: bytes, field: str, *, source: str) -> str:
    """One text field out of an INFO bulk string, parsed like `_info_field`."""
    body = _resp_bulk(raw, source=source, cmd="INFO")
    for line in body.split(b"\r\n"):
        if line.startswith(b"#") or b":" not in line:
            continue
        name, _, val = line.partition(b":")
        if name == field.encode():
            return val.decode("ascii", "replace")
    raise AssertionError(
        f"[{source}] INFO does not report a {field!r} line at all. Body was {body[:1500]!r}")


def _engine_at_least(version_text: str, want: tuple) -> bool:
    """Is the engine's own reported version (`INFO server`) at least ``want``?"""
    parts = []
    for p in str(version_text).split("."):
        digits = "".join(ch for ch in p if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts + [0, 0, 0])[:len(want)] >= want


def _describe_cluster(ec, cluster_id: str, **extra):
    try:
        resp = ec.describe_cache_clusters(CacheClusterId=cluster_id, **extra)
    except ClientError as exc:
        if "NotFound" in _code_of(exc):
            return None
        raise
    items = resp.get("CacheClusters", [])
    return items[0] if items else None


# Returned by _cluster_endpoint when node info never populated, distinct from (None, None) so a
# wait that ran out is never graded as a data-plane gap.
_NODE_INFO_TIMEOUT = object()


def _cluster_endpoint(ec, cluster_id: str):
    """``(Address, Port)`` for the single cache node, or ``_NODE_INFO_TIMEOUT``.

    Unpopulated node info is provisioning latency; an available cluster with no endpoint is a gap.
    """
    node = _poll(lambda: _describe_cluster(ec, cluster_id, ShowCacheNodeInfo=True),
                 lambda c: bool((c or {}).get("CacheNodes")),
                 timeout_s=300, interval_s=2)
    if node is None:
        return _NODE_INFO_TIMEOUT
    nodes = node["CacheNodes"]
    assert len(nodes) == 1, f"asked for one cache node, DescribeCacheClusters reports {nodes!r}"
    endpoint = nodes[0].get("Endpoint") or {}
    return endpoint.get("Address"), endpoint.get("Port")


def _wait_cluster_available(ctx, ec, cluster_id: str) -> dict:
    got = _poll(lambda: _describe_cluster(ec, cluster_id),
                lambda c: c is not None and c.get("CacheClusterStatus") == "available",
                timeout_s=_budget_s(ctx, 1200),
                interval_s=2)
    if got is None:
        if _budget_spent(ctx):
            raise TimeoutError(f"cache cluster {cluster_id} reaching 'available': the run budget "
                               f"ended first; not graded")
        raise _never_ready(
            f"cache cluster {cluster_id} did not reach 'available' within the bounded wait")
    return got


def _delete_cluster(ec, cluster_id: str, timeout_s: float = 900):
    """Get the billable node deleting; idempotent, and retried through `creating`, which refuses it.

    A node already `deleting` returns immediately.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        current = _describe_cluster(ec, cluster_id)
        if current is None or current.get("CacheClusterStatus") == "deleting":
            return
        try:
            ec.delete_cache_cluster(CacheClusterId=cluster_id)
            return
        except ClientError as exc:
            code = _code_of(exc)
            if code == "CacheClusterNotFound":
                return
            if code != "InvalidCacheClusterState" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _teardown_cluster_now(ec, cluster_id: str) -> str:
    """Delete the node inside the check and return the status the API reported.

    Registered cleanup is bounded and cannot fail the check, so deletion is asserted here instead.
    """
    return (ec.delete_cache_cluster(CacheClusterId=cluster_id)["CacheCluster"]
            ["CacheClusterStatus"])


def _wait_cluster_gone(ec, cluster_id: str, timeout_s: float = 1200, interval_s: float = 2):
    """Poll until DescribeCacheClusters no longer finds the node. Raises on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        current = _describe_cluster(ec, cluster_id)
        if current is None:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"cache cluster {cluster_id} is still listed {timeout_s}s after DeleteCacheCluster, "
                f"status {current.get('CacheClusterStatus')!r}")
        time.sleep(interval_s)


def _wait_rg_gone(ec, rg_id: str, timeout_s: float = 1500, interval_s: float = 2):
    """Poll until DescribeReplicationGroups no longer finds the group. Raises on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        current = _describe_rg(ec, rg_id)
        if current is None:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"replication group {rg_id} is still listed {timeout_s}s after "
                f"DeleteReplicationGroup, status {current.get('Status')!r}")
        time.sleep(interval_s)


def _teardown_network(ec2, vpc_id: str, *, timeout_s: float, interval_s: float = 2):
    """Delete every non-default security group, every subnet and then the VPC itself.

    Waits, bounded, for the asynchronously released Lambda and cache ENIs; idempotent.
    """
    vpc_filter = [{"Name": "vpc-id", "Values": [vpc_id]}]
    deadline = time.monotonic() + timeout_s
    while True:
        enis = _paginate(ec2, "describe_network_interfaces", "NetworkInterfaces", Filters=vpc_filter)
        blocked = [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}"
                   for e in enis]
        if not enis:
            groups = [g for g in _paginate(ec2, "describe_security_groups", "SecurityGroups",
                                           Filters=vpc_filter) if g.get("GroupName") != "default"]
            subnets = _paginate(ec2, "describe_subnets", "Subnets", Filters=vpc_filter)
            # A group referenced by another group's rule answers DependencyViolation until the
            # referencing group is gone, so each delete is attempted on its own and retried.
            for kind, op, ident in ([("sg", "delete_security_group", {"GroupId": g["GroupId"]})
                                     for g in groups]
                                    + [("subnet", "delete_subnet", {"SubnetId": n["SubnetId"]})
                                       for n in subnets]
                                    + [("vpc", "delete_vpc", {"VpcId": vpc_id})]):
                try:
                    getattr(ec2, op)(**ident)
                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "")
                    if kind == "vpc" and code == "InvalidVpcID.NotFound":
                        return
                    if code.endswith(".NotFound"):
                        continue
                    if code != "DependencyViolation":
                        raise
                    blocked.append(f"{kind}:{next(iter(ident.values()))}")
                    continue
                if kind == "vpc":
                    return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"VPC {vpc_id} could not be deleted within {timeout_s}s; still held by "
                f"{blocked!r}")
        time.sleep(interval_s)


def _describe_rg(ec, rg_id: str):
    try:
        items = ec.describe_replication_groups(ReplicationGroupId=rg_id).get(
            "ReplicationGroups", [])
    except ClientError as exc:
        if "NotFound" in _code_of(exc):
            return None
        raise
    return items[0] if items else None


def _wait_rg_available(ctx, ec, rg_id: str, timeout_s: float = 1500) -> dict:
    got = _poll(lambda: _describe_rg(ec, rg_id),
                lambda g: g is not None and g.get("Status") == "available",
                timeout_s=_budget_s(ctx, timeout_s),
                interval_s=2)
    if got is None:
        if _budget_spent(ctx):
            raise TimeoutError(f"replication group {rg_id} reaching 'available': the run budget "
                               f"ended first; not graded")
        raise _never_ready(
            f"replication group {rg_id} did not reach 'available' within the bounded wait")
    return got


def _delete_rg(ec, rg_id: str, timeout_s: float = 900):
    """Like `_delete_cluster`: a group already `deleting` is not retried."""
    deadline = time.monotonic() + timeout_s
    while True:
        current = _describe_rg(ec, rg_id)
        if current is None or current.get("Status") == "deleting":
            return
        try:
            ec.delete_replication_group(ReplicationGroupId=rg_id, RetainPrimaryCluster=False)
            return
        except ClientError as exc:
            code = _code_of(exc)
            if code == "ReplicationGroupNotFound":
                return
            if code != "InvalidReplicationGroupState" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _teardown_rg_now(ec, rg_id: str) -> str:
    """Delete the replication group inside the check and return the reported status."""
    return ec.delete_replication_group(
        ReplicationGroupId=rg_id, RetainPrimaryCluster=False)["ReplicationGroup"]["Status"]


def _newest_redis_family(ec):
    """``(engine_version, parameter_group_family)`` for the newest Redis the account can create.

    Derived, because the family must match the engine version and old engines are deprecated.
    """
    versions = _paginate(ec, "describe_cache_engine_versions", "CacheEngineVersions",
                         Engine="redis")
    assert versions, "describe_cache_engine_versions reports no 'redis' engine version at all"

    def key(v):
        parts = []
        for p in str(v.get("EngineVersion", "")).split("."):
            parts.append(int(p) if p.isdigit() else 0)
        return tuple(parts + [0, 0, 0])[:3]

    newest = max(versions, key=key)
    family = newest.get("CacheParameterGroupFamily")
    version = newest.get("EngineVersion")
    assert family and version, (
        f"the newest redis engine version entry is missing EngineVersion or "
        f"CacheParameterGroupFamily: {newest!r}")
    return version, family


_CONTROL_KEY = "sim2real:tls:control"
_SMUGGLED_KEY = "sim2real:tls:smuggled"
# A value carrying RESP's own CRLF delimiter: it survives only if the endpoint frames by length.
_CONTROL_VALUE = b"tls-value-with\r\nembedded-crlf"

# A `required`-mode endpoint completes the TCP handshake and then never answers plaintext RESP;
# repeated because the claim is "refused every time", not "refused once".
_PLAINTEXT_ATTEMPTS = 3
# A required-mode endpoint answers plaintext with silence, so each attempt ends in this read timeout.
_PLAINTEXT_IO_TIMEOUT_S = 3


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "concern:representation", "dp:native", "plane:data")
# tls-subject: the check asserts transit encryption and reports whether the endpoint's TLS verifies.
def run(ctx) -> None:
    """A group with TransitEncryptionMode='required' serves RESP over verified TLS, while plaintext
    RESP to the same host and port gets no reply and a plaintext SET does not land; with cluster
    mode disabled it exposes a PrimaryEndpoint and no ConfigurationEndpoint.

    Reference: https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/in-transit-encryption.html
    """
    ec = ctx.client("elasticache")
    lam, net, fn, in_vpc, why = _bring_up_executor(ctx)
    subnet_group = _ensure_cache_subnet_group(ctx, ec, net)
    engine_version, _family = _newest_redis_family(ec)

    rg_id = ctx.unique_name("sim2real-behav-ectls-")
    try:
        created = ec.create_replication_group(
            ReplicationGroupId=rg_id,
            ReplicationGroupDescription="sim2real transit-encryption data-plane check (in-VPC)",
            Engine="redis",
            EngineVersion=engine_version,
            CacheNodeType=_NODE_TYPE,
            NumCacheClusters=1,
            Port=_REDIS_PORT,
            CacheSubnetGroupName=subnet_group,
            SecurityGroupIds=[net["sg_id"]],
            TransitEncryptionEnabled=True,
            TransitEncryptionMode="required",
            AtRestEncryptionEnabled=True,
            SnapshotRetentionLimit=0,
            Tags=_RESOURCE_TAGS,
        )["ReplicationGroup"]
    except ClientError as exc:
        if _code_of(exc) != "InsufficientCacheClusterCapacity":
            raise
        raise _no_capacity(
            f"no {_NODE_TYPE} capacity for subnet group {subnet_group}: {_msg_of(exc)}") from exc
    ctx.on_cleanup(lambda r=rg_id: _delete_rg(ec, r))
    assert created["ReplicationGroupId"] == rg_id, created
    assert created["Status"] == "creating", (
        f"create_replication_group reported Status={created['Status']!r}, not 'creating'")

    try:
        # The group typically reaches `available` in about eight minutes.
        group = _wait_rg_available(ctx, ec, rg_id, timeout_s=1500)

        # The control plane must report the posture it was asked for.
        assert group.get("TransitEncryptionEnabled") is True, (
            f"the group was created with TransitEncryptionEnabled=True but reports "
            f"{group.get('TransitEncryptionEnabled')!r}")
        assert group.get("TransitEncryptionMode") == "required", (
            f"the group was created with TransitEncryptionMode='required' but reports "
            f"{group.get('TransitEncryptionMode')!r}; 'preferred' would silently permit plaintext, "
            f"so the two values are the difference between 'TLS is available' and 'plaintext is "
            f"refused'")
        assert group.get("AtRestEncryptionEnabled") is True, (
            f"the group was created with AtRestEncryptionEnabled=True but reports "
            f"{group.get('AtRestEncryptionEnabled')!r}")

        # Cluster mode disabled: a primary endpoint and no configuration endpoint.
        assert group.get("ConfigurationEndpoint") in (None, {}), (
            f"a cluster-mode-DISABLED replication group must not expose a ConfigurationEndpoint, "
            f"got {group.get('ConfigurationEndpoint')!r}; that endpoint belongs to cluster mode "
            f"enabled only and pointing clients at it breaks discovery")
        node_groups = group.get("NodeGroups") or []
        assert len(node_groups) == 1, (
            f"a single-shard replication group must report exactly one NodeGroup, got "
            f"{len(node_groups)}: {node_groups!r}")
        primary = node_groups[0].get("PrimaryEndpoint") or {}
        host, port = primary.get("Address"), primary.get("Port")
        assert host, (
            f"NodeGroups[0].PrimaryEndpoint.Address is empty: {node_groups[0]!r}; without it there "
            f"is no data plane to reach")
        host, port = ctx.endpoint_host(host, port)

        probe = _pick_prober(ctx, lam, fn, host, port, in_vpc=in_vpc, why=why, tls=True,
                             subject=f"transit-encrypted replication group {rg_id}")
        src = probe.label

        tls_cmds = [["PING"], ["SET", _CONTROL_KEY, _CONTROL_VALUE], ["GET", _CONTROL_KEY],
                    ["GET", _SMUGGLED_KEY]]
        tls_result = probe.resp(host, port, tls_cmds, tls=True)
        tls = _replies(tls_result, tls_cmds, source=src)

        assert tls_result.get("tls_mode") == "verified", (
            f"[{src}] the TLS handshake against {host}:{port} succeeded only as "
            f"{tls_result.get('tls_mode')!r} (first error {tls_result.get('tls_error')!r}). A real "
            f"transit-encrypted ElastiCache endpoint presents a publicly-trusted certificate for "
            f"its own hostname, so a chain or hostname that does not verify means the endpoint is "
            f"encrypted to SOMETHING but not authenticated as itself -- which is what transport "
            f"security is for")
        assert tls[0] == b"+PONG\r\n", (
            f"[{src}] PING over TLS must return exactly `+PONG\\r\\n`, got {tls[0]!r}; the "
            f"transit-encrypted endpoint terminates TLS but is not speaking RESP behind it")
        assert tls[1] == b"+OK\r\n", (
            f"[{src}] SET over TLS must return `+OK\\r\\n`, got {tls[1]!r}")
        assert tls[2] == _bulk_expected(_CONTROL_VALUE), (
            f"[{src}] GET over TLS returned {tls[2]!r}, not the byte-exact "
            f"{_bulk_expected(_CONTROL_VALUE)!r}. The value contains the CRLF that RESP uses as its "
            f"own delimiter, so anything else means the endpoint is scanning for a terminator "
            f"instead of honouring the `$<n>` length prefix")
        assert tls[3] == b"$-1\r\n", (
            f"[{src}] {_SMUGGLED_KEY!r} already exists before any plaintext attempt was made "
            f"({tls[3]!r}); the effect-absent probe below would prove nothing")

        # Drop TLS only: same host, same port, same code.
        attempts = []
        for _ in range(_PLAINTEXT_ATTEMPTS):
            attempts.append(probe.resp(
                host, port,
                [["PING"], ["SET", _SMUGGLED_KEY, b"written-in-the-clear"]],
                tls=False, io_timeout_s=_PLAINTEXT_IO_TIMEOUT_S))

        for i, plain in enumerate(attempts):
            replies = [base64.b64decode(r) for r in plain.get("replies", [])]
            assert b"+PONG\r\n" not in replies, (
                f"[{src}] attempt {i}: a TransitEncryptionMode='required' endpoint answered a "
                f"PLAINTEXT RESP PING with `+PONG`. Transit encryption is NOT being enforced: every "
                f"client's traffic can travel unencrypted while the control plane reports it as "
                f"encrypted, which is a silent compliance failure. Probe result: {plain!r}")
            assert not plain.get("ok"), (
                f"[{src}] attempt {i}: the plaintext probe COMPLETED against a TLS-required "
                f"endpoint ({plain!r}). A plaintext RESP conversation must not succeed here at all")
            assert replies == [], (
                f"[{src}] attempt {i}: the plaintext connection received {len(replies)} reply "
                f"frame(s) {replies!r}. MEASURED behaviour of a real `required`-mode endpoint is to "
                f"complete the TCP handshake and then answer NOTHING (stage='io', a read timeout, "
                f"zero frames) -- it does not reset, it does not close, and it does not send a RESP "
                f"error. Any frame at all means something is parsing plaintext RESP on a port that "
                f"must not")
            assert plain.get("stage") == "io", (
                f"[{src}] attempt {i}: the plaintext probe failed at stage "
                f"{plain.get('stage')!r}, not at 'io'. 'connect' would mean the TCP handshake itself "
                f"was refused, which is a DIFFERENT posture (a closed port, e.g. a security-group "
                f"change) and would not show that the endpoint accepts connections and then declines "
                f"to speak plaintext on them. Probe result: {plain!r}")

        back_cmds = [["GET", _SMUGGLED_KEY], ["GET", _CONTROL_KEY], ["PING"], ["DBSIZE"]]
        back = _replies(probe.resp(host, port, back_cmds, tls=True), back_cmds, source=src)
        assert back[0] == b"$-1\r\n", (
            f"[{src}] the plaintext SET actually LANDED: reading {_SMUGGLED_KEY!r} back over TLS "
            f"returned {back[0]!r}, expected the null bulk string `$-1\\r\\n`. The endpoint accepted "
            f"a write over an unencrypted transport it reports as required-encrypted")

        assert back[1] == _bulk_expected(_CONTROL_VALUE), (
            f"[{src}] control: the value written over TLS is no longer readable: {back[1]!r}")
        assert back[2] == b"+PONG\r\n", (
            f"[{src}] control: a fresh TLS connection no longer answers PING after the "
            f"{_PLAINTEXT_ATTEMPTS} plaintext attempts: {back[2]!r}")
        assert _resp_int(back[3], source=src, cmd="DBSIZE") == 1, (
            f"[{src}] control: DBSIZE is {back[3]!r}; exactly ONE key ({_CONTROL_KEY!r}) was ever "
            f"written successfully, so any other number means a plaintext write landed under some "
            f"name this check did not read back")
    finally:
        # Function first so its ENI drains while the group deletes; RetainPrimaryCluster=False
        # stops the primary surviving as an orphan, and no final snapshot is taken.
        _delete_function(ctx, lam, fn)
        status = _teardown_rg_now(ec, rg_id)
        assert status == "deleting", (
            f"DeleteReplicationGroup on {rg_id} reported Status={status!r}, not 'deleting'; a group "
            f"that does not enter the deleting state keeps billing")
        _wait_rg_gone(ec, rg_id)
        code, message = _error_of(lambda: ec.describe_replication_groups(ReplicationGroupId=rg_id))
        assert code == "ReplicationGroupNotFound", (
            f"a deleted replication group must be reported as ReplicationGroupNotFound, got {code!r}")
        assert message == f"ReplicationGroup {rg_id} not found.", (
            f"DescribeReplicationGroups on the deleted group {rg_id} returned message {message!r}")
        _delete_cache_subnet_group(ec, subnet_group)
        _teardown_network(ctx.client("ec2"), net["vpc_id"], timeout_s=_NET_DRAIN_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
