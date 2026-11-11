"""elasticache-streams-xautoclaim-min-idle-threshold-selects-pending-entries."""
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

CHECK = "elasticache-streams-xautoclaim-min-idle-threshold-selects-pending-entries"
GROUP = 'cache-cluster'
SERVICES = ['elasticache']

# ElastiCache endpoints are VPC-only, so the data plane is reached from a Lambda with VpcConfig on
# the cache's subnets and security group, running a stdlib RESP probe that returns raw reply bytes.
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

# Tags for the billable resource this check creates; `sim2real` names the scenario.
_RESOURCE_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    {"Key": "sim2real", "Value": CHECK},
]

# Grants the EC2 network-interface actions and CloudWatch Logs; without the EC2 half, CreateFunction
# with VpcConfig is rejected synchronously.
_VPC_ACCESS_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"

# Marks a data-plane failure, so messages that quote connection errors are not read as an
# environment problem.
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

1. The verdict is the CHECK's. An assertion that fires inside the Lambda reports as
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


def _open(host: str, port: int, tls: bool):
    """``(sock, tls_mode, tls_error)``. ``tls_mode`` is None when ``tls`` is False.

    On a TLS endpoint the handshake encrypts without verifying the server's identity (SimParity
    CONTRACT.md, Artifact TLS), so ``tls_mode`` is "unverified" and ``tls_error`` is None.
    """
    if not tls:
        s = socket.create_connection((host, int(port)), timeout=_CONNECT_TIMEOUT_S)
        s.settimeout(_IO_TIMEOUT_S)
        return s, None, None
    raw = socket.create_connection((host, int(port)), timeout=_CONNECT_TIMEOUT_S)
    raw.settimeout(_IO_TIMEOUT_S)
    sslctx = ssl.create_default_context()
    sslctx.check_hostname = False
    sslctx.verify_mode = ssl.CERT_NONE
    try:
        wrapped = sslctx.wrap_socket(raw, server_hostname=host)
    except (ssl.SSLError, OSError):
        raw.close()
        raise
    wrapped.settimeout(_IO_TIMEOUT_S)
    return wrapped, "unverified", None


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


def _resp_batch(host, port, commands, tls=False) -> dict:
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
        sock, tls_mode, tls_err = _open(ip if not tls else host, port, tls)
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
                               tls=bool(event.get("tls")))
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
    """Compile _HANDLER_SRC in THIS process and return its namespace.

    The runner-side path then uses the exact codec the Lambda runs, so the two vantage points cannot
    disagree because of different client implementations.
    """
    if not _LOCAL_NS:
        exec(compile(_HANDLER_SRC, "<invpc-handler>", "exec"), _LOCAL_NS)  # noqa: S102
    return _LOCAL_NS


def _dp_fail(msg: str) -> AssertionError:
    """The native data-plane fidelity FAIL, distinct from an environment error.

    Returned rather than raised so a call site keeps its `from exc` chaining.
    """
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


def _poll(probe, predicate, *, timeout_s: float, interval_s: float):
    """Poll `probe` until `predicate`. Returns the last observation, or None on timeout."""
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
    """Every page of `op`, flattened on `key`, so our resource is not missed behind other pages."""
    try:
        pager = client.get_paginator(op)
    except Exception:  # noqa: BLE001 -- no paginator modeled; fall back to one call
        return getattr(client, op)(**kwargs).get(key, [])
    out = []
    for page in pager.paginate(**kwargs):
        out.extend(page.get(key, []))
    return out


# ---- the run's own executor network ---------------------------------------------------------

# A lost race to create the shared executor subnet, as opposed to a real failure. Both racers derive
# the same deterministic CIDR from the same VPC, so the loser's job is to adopt.
_SUBNET_RACE_LOST = frozenset({"InvalidSubnet.Conflict", "InvalidSubnetRange.Conflict"})


def _has_self_ingress(ec2, sg_id: str, port: int) -> bool:
    """Does sg_id already admit ``port`` FROM ITSELF?

    Matched on the group pair, not a CIDR: an open CIDR rule would not prove the traffic is ours.
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
    """Authorize the self-referencing cache-port rule on sg_id unless it is already there.

    Idempotent, and verified afterwards, so a missing rule is never mistaken for a dead data plane.
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
        # Two runs racing on the same reused group: the loser's rule is the rule we wanted.
        if _code_of(exc) != "InvalidPermission.Duplicate":
            raise
    assert _has_self_ingress(ec2, sg_id, port), (
        f"{sg_id} still does not admit tcp/{port} from itself after authorizing; the round trip "
        f"below could not distinguish this from a broken data plane"
    )


def _dns_attributes_ok(ec2, vpc_id: str) -> bool:
    """Are BOTH VPC DNS attributes already on?"""
    # The REQUEST spells the attribute lower-camel and the RESPONSE spells it upper-camel; they are
    # deliberately different keys in the model, so neither name works for both halves.
    return all(
        ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute=req)[resp]["Value"]
        for req, resp in (("enableDnsSupport", "EnableDnsSupport"),
                          ("enableDnsHostnames", "EnableDnsHostnames"))
    )


def _ensure_dns_attributes(ec2, vpc_id: str) -> None:
    """Turn on both DNS attributes, and ONLY if one of them is off.

    The VPC resolver at CIDR-base+2, one of the in-VPC proofs, answers only with DNS support on.
    """
    if _dns_attributes_ok(ec2, vpc_id):
        return
    for attr in ("EnableDnsSupport", "EnableDnsHostnames"):
        ec2.modify_vpc_attribute(VpcId=vpc_id, **{attr: {"Value": True}})


def _network_subnets(ec2, vpc_id: str, want: int = 2) -> list:
    """Up to ``want`` of the VPC's available subnets, one per DISTINCT availability zone.

    Two zones let ElastiCache pick one with cache.t3.micro capacity; the choice is deterministic.
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
    """Build this run's executor VPC, one subnet per zone, teardown registered at once. -> VpcId."""
    # A randomized second octet makes the "executor source address is inside our VPC" signal sharp.
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
            # Complete, don't merely find: a group built over one subnet would stay single-AZ.
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
        # The name is derived from the VPC id, so a concurrent create may win; adopt it.
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


# ---- the executor: role + function ---------------------------------------------------------


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
    """An execution role that can create ENIs, created per run and deleted on teardown."""
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
    """The whole deployment package: one stdlib-only file, no dependency, no layer."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, src)
    return buf.getvalue()


def _deploy_executor(ctx, lam, net: dict, role_arn: str):
    """CreateFunction with VpcConfig, retried through IAM propagation, then wait Active.

    A just-created role is rejected with InvalidParameterValueException until Lambda can see it.
    """
    name = ctx.unique_name("sim2real-behav-invpc-fn-")
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=role_arn,
        Code={"ZipFile": _make_zip(_HANDLER_SRC)},
        MemorySize=512,
        # A `sessions` invoke holds connections open across a barrier and deliberate waits.
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


def _delete_function(ctx, lam, name: str, *, reap_s: float = 90, interval_s: float = 5):
    """Delete the function, then reap its log group.

    Idempotent against a repeat call (this check's own `finally` and its registered cleanup both
    reach here): only the resource's own not-found code means it is already gone, everything else
    raises. The log group is REAPED rather than deleted once: Lambda's own log delivery is
    asynchronous and can recreate the group for seconds after the function is gone, so a single
    delete is not enough to prove it stays absent.
    """
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if _code_of(exc) != "ResourceNotFound":
            raise

    logs = ctx.client("logs")
    log_group = f"/aws/lambda/{name}"
    deadline = time.monotonic() + reap_s
    absent = 0
    while True:
        try:
            logs.delete_log_group(logGroupName=log_group)
            absent = 0
        except ClientError as exc:
            if _code_of(exc) != "ResourceNotFound":
                raise
            absent += 1
        if absent >= 3:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"log group {log_group} keeps reappearing after delete, {reap_s}s after the "
                f"function was deleted; Lambda's asynchronous log delivery never settled")
        time.sleep(interval_s)


def _invoke(ctx, lam, fn: str, payload: dict) -> dict:
    """One synchronous Invoke, returning the decoded handler result.

    The handler never raises, so a FunctionError or non-200 status means the executor is unusable.
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


# ---- THE CONTROL STEP ----------------------------------------------------------------------


def _prove_executor_in_vpc(ctx, lam, fn: str, net: dict):
    """Prove, before anything billable exists, that the probe code ran inside our VPC.

    Ran: the reply carries sha256 over our nonce and its network fields. In VPC: its source IP is in
    the VPC CIDR, or the VPC resolver at CIDR-base+2 answered. -> (evidence, in_vpc, reason).
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

    # --- claim 1: our code executed -----------------------------------------------------
    expected = hashlib.sha256(
        f"{nonce}|{ev.get('src_ip')}|{ev.get('resolver_rcode')}".encode()).hexdigest()
    if ev.get("nonce") != nonce or ev.get("proof") != expected:
        raise _no_executor(
            f"the invoke returned {ev!r}, which does not carry sha256 over the nonce {nonce!r} "
            f"bound to the network fields it reported (expected proof {expected!r}); the target "
            f"accepted CreateFunction and Invoke but did not execute the package")

    # --- claim 2: it executed inside the VPC we asked for -------------------------------
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
    """Network, role, function and in-VPC proof, before any billable cache exists.

    Returns (lam, net, fn, in_vpc, why).
    """
    ec2 = ctx.client("ec2")
    lam = ctx.client("lambda")
    net = _executor_network(ctx, ec2, port)
    role_arn = _vpc_exec_role_arn(ctx)
    fn, cfg_vpc = _deploy_executor(ctx, lam, net, role_arn)
    # Echoing VpcConfig back proves little; the selftest below is the real proof.
    assert sorted(cfg_vpc.get("SubnetIds") or []) == sorted(net["subnet_ids"]), (
        f"GetFunctionConfiguration reports VpcConfig.SubnetIds={cfg_vpc.get('SubnetIds')!r}, not "
        f"the {net['subnet_ids']!r} passed to CreateFunction")
    evidence, in_vpc, why = _prove_executor_in_vpc(ctx, lam, fn, net)
    if not in_vpc:
        # A proven-executing function that is NOT in the VPC we named is a broken
        # instrument, and there is no point paying for a cache we could never reach.
        raise _no_executor(
            f"CreateFunction accepted VpcConfig={cfg_vpc!r} and the package ran, but {why}. "
            f"Selftest evidence: {evidence!r}")
    return lam, net, fn, in_vpc, why


# ---- choosing the vantage point --------------------------------------------------------------


def _as_bytes(arg) -> bytes:
    return arg if isinstance(arg, bytes) else str(arg).encode()


def _enc_cmd(cmd) -> list:
    return [base64.b64encode(_as_bytes(a)).decode() for a in cmd]


class _Prober:
    """One vantage point (runner or in-VPC Lambda), exposing the handler's ops identically.

    Chosen once by a successful PING, so positive and negative legs share one network path.
    """

    def __init__(self, label, fn):
        self.label = label
        self._fn = fn

    def resp(self, host, port, commands, tls=False) -> dict:
        """Run ``commands`` (lists of str/bytes args) and return the handler's result dict.

        Arguments are base64'd because the event is JSON and a Redis value is arbitrary bytes.
        """
        return self._fn({"op": "resp", "host": host, "port": int(port), "tls": bool(tls),
                         "commands": [_enc_cmd(c) for c in commands]})

    def sessions(self, host, port, sessions, tls=False) -> dict:
        """Run N concurrent sessions; a ``dict`` step (``sync``/``sleep_ms``) travels unencoded."""
        return self._fn({"op": "sessions", "host": host, "port": int(port), "tls": bool(tls),
                         "sessions": [[s if isinstance(s, dict) else _enc_cmd(s) for s in script]
                                      for script in sessions]})


def _dispatch_local(event: dict) -> dict:
    ns = _local_client()
    if event["op"] == "sessions":
        return ns["_sessions"](event["host"], event["port"], event["sessions"],
                               tls=event.get("tls", False))
    return ns["_resp_batch"](event["host"], event["port"], event["commands"],
                             tls=event.get("tls", False))


def _pick_prober(ctx, lam, fn: str, host, port, *, in_vpc: bool, why: str, tls: bool,
                 subject: str) -> _Prober:
    """The vantage point that reaches ``host:port``, or a data-plane failure after a bounded poll.

    A node can report 'available' before its endpoint accepts connections, hence the poll. The
    runner side is tried once: on real AWS the endpoint is private and each attempt times out.
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


# ---- reading raw RESP replies ----------------------------------------------------------------


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


# ---- framing an aggregate on the CHECK side ---------------------------------------------------

# Same three groups as the handler's framer, as BYTES literals for indexing a buffer.
_SIMPLE_B = b"+-:,#("
_BULKISH_B = b"$=!"
_AGG_B = {b"*": 1, b"~": 1, b">": 1, b"%": 2, b"|": 2}


def _frame_end(raw: bytes, i: int, *, depth: int = 0) -> int:
    """The index just past the one complete reply that starts at ``raw[i]``."""
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
    """One aggregate reply split into its ELEMENT SPANS, each still raw bytes.

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
    """The integer in a RESP ``:<n>\\r\\n`` reply; a non-numeric payload fails as an assertion."""
    assert raw.startswith(b":") and raw.endswith(b"\r\n"), (
        f"[{source}] {cmd} must return a RESP integer reply (:<n>\\r\\n), got {raw!r}")
    try:
        return int(raw[1:-2])
    except ValueError:
        raise AssertionError(
            f"[{source}] {cmd} framed an integer reply but its payload is not an integer: {raw!r}. "
            f"A client's int conversion would raise on this") from None


def _resp_bulk(raw: bytes, *, source: str, cmd: str) -> bytes:
    """The payload of a RESP bulk string; a NULL (absent) bulk is rejected, not read as b""."""
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


def _resp_error_name(raw: bytes, *, source: str, cmd: str) -> str:
    """The error NAME out of a RESP error frame ``-NAME free text\\r\\n``, as an exact token."""
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
    """One TEXT field out of an INFO bulk string, parsed like `_info_field`."""
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
    """Is the engine's own reported version (from `INFO server`) at least ``want``?"""
    parts = []
    for p in str(version_text).split("."):
        digits = "".join(ch for ch in p if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts + [0, 0, 0])[:len(want)] >= want


# ---- ElastiCache control-plane helpers -------------------------------------------------------


def _describe_cluster(ec, cluster_id: str, **extra):
    try:
        resp = ec.describe_cache_clusters(CacheClusterId=cluster_id, **extra)
    except ClientError as exc:
        if "NotFound" in _code_of(exc):
            return None
        raise
    items = resp.get("CacheClusters", [])
    return items[0] if items else None


# Returned by _cluster_endpoint when node info never populated, distinct from (None, None).
_NODE_INFO_TIMEOUT = object()


def _cluster_endpoint(ec, cluster_id: str):
    """``(Address, Port)`` for the single cache node, or ``_NODE_INFO_TIMEOUT``.

    A wait that ran out is provisioning latency; an available node without endpoint is a gap.
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


def _resolved_endpoint(ctx, ec, cluster_id: str):
    endpoint = _cluster_endpoint(ec, cluster_id)
    if endpoint is _NODE_INFO_TIMEOUT:
        # Never a fidelity verdict: node info that has not populated yet says nothing about the data
        # plane, and on real AWS it is provisioning latency.
        raise _never_ready(
            f"cache cluster {cluster_id} reached 'available' but DescribeCacheClusters never "
            f"populated CacheNodes within the bounded wait")
    host, port = endpoint
    if not host or not port:
        raise _dp_fail(
            f"cluster {cluster_id} is 'available' but advertises no connectable endpoint "
            f"(Address={host!r} Port={port!r}); without an address there is no data plane")
    return ctx.endpoint_host(host, int(port))


def _delete_cluster(ec, cluster_id: str, timeout_s: float = 900):
    """Get the billable node deleting; idempotent, and retried through `creating`, which refuses
    deletion. A node already `deleting` returns immediately.
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
    """Delete the node INSIDE the check and return the status the API reported.

    Registered cleanups swallow errors, so the body deletes where the result can be asserted.
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


def _teardown_network(ec2, vpc_id: str, *, timeout_s: float, interval_s: float = 2):
    """Delete every non-default security group, every subnet and then the VPC itself.

    Waits, bounded, until the VPC holds no network interface: Lambda and cache ENIs are released
    asynchronously. Idempotent; raises naming what still holds the VPC when the window closes.
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


def _newest_redis_family(ec):
    """``(engine_version, parameter_group_family)`` for the newest Redis the account can create.

    Derived, not hardcoded: the family must match the engine version, and old engines are retired.
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


# ---- Streams reply navigation, all on RAW BYTES -----------------------------------------------
#
# The reply shapes below are those ElastiCache Redis 7.1 returns.


def _xreadgroup_ids(raw: bytes, *, source: str, stream: str) -> list:
    """The entry ids `XREADGROUP` / `XREAD` delivered, in delivery order.

    Shape: an array of (stream name, entries) pairs, entries (id, field-list); the name is checked.
    """
    per_stream = _agg(raw, source=source, cmd="XREADGROUP")
    assert len(per_stream) == 1, (
        f"[{source}] XREADGROUP on one stream must return exactly one per-stream element, got "
        f"{len(per_stream)}: {raw!r}")
    pair = _agg(per_stream[0], source=source, cmd="XREADGROUP per-stream")
    assert len(pair) == 2, (
        f"[{source}] a per-stream XREADGROUP element must be (name, entries), got {pair!r}")
    name = _resp_bulk(pair[0], source=source, cmd="XREADGROUP stream name")
    assert name == stream.encode(), (
        f"[{source}] XREADGROUP delivered entries under stream name {name!r}, not {stream!r}")
    out = []
    for entry in _agg(pair[1], source=source, cmd="XREADGROUP entries"):
        fields = _agg(entry, source=source, cmd="XREADGROUP entry")
        assert len(fields) == 2, (
            f"[{source}] a stream entry must be (id, field-list), got {fields!r}")
        out.append(_resp_bulk(fields[0], source=source, cmd="XREADGROUP entry id"))
    return out


def _entry_ids(raw: bytes, *, source: str, cmd: str) -> list:
    """The ids out of a bare entry array (`XRANGE`, and the second element of `XAUTOCLAIM`)."""
    out = []
    for entry in _agg(raw, source=source, cmd=cmd):
        fields = _agg(entry, source=source, cmd=f"{cmd} entry")
        assert len(fields) == 2, (
            f"[{source}] {cmd} entry must be (id, field-list), got {fields!r}")
        out.append(_resp_bulk(fields[0], source=source, cmd=f"{cmd} entry id"))
    return out


def _xpending_summary(raw: bytes, *, source: str):
    """``(total, lowest_id, highest_id, {consumer: count})`` from the SUMMARY form of `XPENDING`.

    The per-consumer count is a BULK STRING while the total is a RESP integer; parsed as each is.
    """
    parts = _agg(raw, source=source, cmd="XPENDING")
    assert len(parts) == 4, (
        f"[{source}] the XPENDING summary form must be a 4-element array "
        f"(total, lowest, highest, per-consumer), got {len(parts)}: {raw!r}")
    total = _resp_int(parts[0], source=source, cmd="XPENDING total")
    if total == 0:
        # An empty PEL reports the three remaining fields as nulls; there is no id to read.
        return 0, None, None, {}
    lowest = _resp_bulk(parts[1], source=source, cmd="XPENDING lowest id")
    highest = _resp_bulk(parts[2], source=source, cmd="XPENDING highest id")
    per: dict = {}
    for pair in _agg(parts[3], source=source, cmd="XPENDING per-consumer"):
        kv = _agg(pair, source=source, cmd="XPENDING consumer")
        assert len(kv) == 2, f"[{source}] XPENDING per-consumer entry must be (name, count): {kv!r}"
        name = _resp_bulk(kv[0], source=source, cmd="XPENDING consumer name").decode()
        count_raw = _resp_bulk(kv[1], source=source, cmd="XPENDING consumer count")
        try:
            per[name] = int(count_raw)
        except ValueError:
            raise AssertionError(
                f"[{source}] XPENDING reports consumer {name!r} count as {count_raw!r}, which is "
                f"not a number") from None
    return total, lowest, highest, per


def _xpending_extended(raw: bytes, *, source: str) -> list:
    """``[(id, consumer, idle_ms, delivery_count), ...]`` from the EXTENDED form of `XPENDING`."""
    out = []
    for entry in _agg(raw, source=source, cmd="XPENDING extended"):
        f = _agg(entry, source=source, cmd="XPENDING extended entry")
        assert len(f) == 4, (
            f"[{source}] an extended XPENDING entry must be (id, consumer, idle, delivery-count), "
            f"got {f!r}")
        out.append((
            _resp_bulk(f[0], source=source, cmd="XPENDING id"),
            _resp_bulk(f[1], source=source, cmd="XPENDING consumer"),
            _resp_int(f[2], source=source, cmd="XPENDING idle"),
            _resp_int(f[3], source=source, cmd="XPENDING delivery-count"),
        ))
    return out


def _xautoclaim(raw: bytes, *, source: str):
    """``(cursor, claimed_ids, deleted_ids)`` from `XAUTOCLAIM`.

    Three elements: the third lists PEL ids no longer in the stream (Redis >= 7.0).
    """
    parts = _agg(raw, source=source, cmd="XAUTOCLAIM")
    assert len(parts) == 3, (
        f"[{source}] XAUTOCLAIM must return (cursor, claimed-entries, deleted-ids), got "
        f"{len(parts)} elements: {raw!r}")
    cursor = _resp_bulk(parts[0], source=source, cmd="XAUTOCLAIM cursor")
    claimed = _entry_ids(parts[1], source=source, cmd="XAUTOCLAIM claimed")
    deleted = [_resp_bulk(x, source=source, cmd="XAUTOCLAIM deleted id")
               for x in _agg(parts[2], source=source, cmd="XAUTOCLAIM deleted")]
    return cursor, claimed, deleted


def _id_pair(raw_id: bytes) -> tuple:
    """``(ms, seq)`` out of a `<ms>-<seq>` entry id, compared as integers rather than strings."""
    text = raw_id.decode("ascii", "replace")
    ms, dash, seq = text.partition("-")
    assert dash and ms.isdigit() and seq.isdigit(), (
        f"a stream entry id must be <ms>-<seq> with both parts decimal, got {text!r}")
    return int(ms), int(seq)


_STREAM = "sim2real:stream:orders"
_GROUP_NAME = "sim2real-workers"
_N_AUTO = 50          # entries added with the server-assigned `*` id
_N_ACK = 10           # of C1's entries, how many are acknowledged
_UNREACHED_IDLE_MS = 86_400_000   # a min-idle-time no entry delivered during the check reaches


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:native", "plane:data")
def run(ctx) -> None:
    """ElastiCache Redis consumer groups: XREADGROUP delivers each entry to one consumer's PEL,
    XACK/XPENDING track it with idle times matching the wall time since delivery, XAUTOCLAIM claims
    none below its min-idle-time and all unacked at 0, and bad ids and groups are refused unchanged.

    Reference: https://redis.io/docs/latest/develop/data-types/streams/
    """
    ec = ctx.client("elasticache")
    lam, net, fn, in_vpc, why = _bring_up_executor(ctx)
    subnet_group = _ensure_cache_subnet_group(ctx, ec, net)
    engine_version, _family = _newest_redis_family(ec)

    cluster_id = ctx.unique_name("sim2real-behav-ecstream-")
    try:
        created = ec.create_cache_cluster(
            CacheClusterId=cluster_id,
            Engine="redis",
            EngineVersion=engine_version,
            CacheNodeType=_NODE_TYPE,
            NumCacheNodes=1,
            Port=_REDIS_PORT,
            CacheSubnetGroupName=subnet_group,
            SecurityGroupIds=[net["sg_id"]],
            TransitEncryptionEnabled=False,
            Tags=_RESOURCE_TAGS,
        )["CacheCluster"]
    except ClientError as exc:
        if _code_of(exc) != "InsufficientCacheClusterCapacity":
            raise
        raise _no_capacity(
            f"no {_NODE_TYPE} capacity for subnet group {subnet_group}: {_msg_of(exc)}") from exc
    ctx.on_cleanup(lambda c=cluster_id: _delete_cluster(ec, c))
    assert created["CacheClusterId"] == cluster_id, created
    assert created["CacheClusterStatus"] == "creating", (
        f"create_cache_cluster reported CacheClusterStatus={created['CacheClusterStatus']!r}, not "
        f"'creating'")

    try:
        _wait_cluster_available(ctx, ec, cluster_id)
        host, port = _resolved_endpoint(ctx, ec, cluster_id)
        probe = _pick_prober(ctx, lam, fn, host, port, in_vpc=in_vpc, why=why, tls=False,
                             subject=f"cache cluster {cluster_id}")
        src = probe.label

        def call(cmds):
            return _replies(probe.resp(host, port, cmds), cmds, source=src)

        # ---- the engine must actually be new enough for what follows -----------------------
        # Read off the WIRE, not off the control plane's EngineVersion: XAUTOCLAIM arrived in
        # Redis 6.2, and the control plane's version string is a record the engine never has to
        # honour. A target reporting 7.x on the control plane and 5.x on the wire is the disagreement
        # worth catching, and it would otherwise surface as a confusing `-ERR unknown command`.
        info = call([["INFO", "server"], ["DBSIZE"]])
        engine = _info_text(info[0], "redis_version", source=src)
        assert _engine_at_least(engine, (6, 2)), (
            f"[{src}] the engine reports redis_version={engine!r} on the wire while the control "
            f"plane provisioned EngineVersion={engine_version!r}; XAUTOCLAIM and the three-element "
            f"XAUTOCLAIM reply require 6.2 or newer, so the two planes disagree about what is "
            f"running")
        assert _resp_int(info[1], source=src, cmd="DBSIZE") == 0, (
            f"[{src}] a freshly provisioned node reports a non-empty DBSIZE ({info[1]!r}); the "
            f"stream accounting below assumes we are the only writer")

        # ---- 1. XADD mints monotonically increasing, server-sequenced ids ------------------
        add_cmds = [["XADD", _STREAM, "*", "seq", str(i)] for i in range(_N_AUTO)]
        auto_ids = [_resp_bulk(r, source=src, cmd="XADD") for r in call(add_cmds)]
        pairs = [_id_pair(i) for i in auto_ids]
        assert all(a < b for a, b in zip(pairs, pairs[1:])), (
            f"[{src}] the {len(pairs)} ids XADD minted are not strictly increasing as (ms, seq) "
            f"pairs: {pairs!r}. A stream is an ordered log and its ids are the order")

        # Same-millisecond sequencing, proved deterministically: separate round trips rarely share a
        # millisecond, so `<ms>-*` asks the server to assign the next sequence within a named one.
        top_ms = pairs[-1][0]
        seq_cmds = [["XADD", _STREAM, f"{top_ms}-*", "seq", "same-ms-1"],
                    ["XADD", _STREAM, f"{top_ms}-*", "seq", "same-ms-2"]]
        seq_ids = [_resp_bulk(r, source=src, cmd="XADD <ms>-*") for r in call(seq_cmds)]
        seq_pairs = [_id_pair(i) for i in seq_ids]
        assert [p[0] for p in seq_pairs] == [top_ms, top_ms], (
            f"[{src}] `XADD {top_ms}-*` must mint ids in millisecond {top_ms}, got {seq_pairs!r}; "
            f"the server ignored the millisecond the client specified")
        assert seq_pairs[1][1] == seq_pairs[0][1] + 1, (
            f"[{src}] two `XADD {top_ms}-*` calls returned sequences {seq_pairs[0][1]} then "
            f"{seq_pairs[1][1]}; within one millisecond the server must increment `seq` by exactly "
            f"1, which is the only thing that keeps ids unique and ordered at sub-millisecond "
            f"write rates")
        all_ids = auto_ids + seq_ids
        total = len(all_ids)

        # ---- 2. NEGATIVE ARM A: an id at or below the stream top is refused ----------------
        before_len = call([["XLEN", _STREAM]])[0]
        low = call([["XADD", _STREAM, "1-1", "rejected", "yes"],
                    ["XADD", _STREAM, all_ids[-1], "rejected", "yes"]])
        for raw, label in zip(low, ("1-1", "the current top id")):
            name = _resp_error_name(raw, source=src, cmd=f"XADD {label}")
            assert name == "ERR", (
                f"[{src}] XADD with {label} must be refused with a RESP `-ERR` frame, got "
                f"error name {name!r} in {raw!r}")
        after = call([["XLEN", _STREAM], ["XRANGE", _STREAM, "-", "+"]])
        assert after[0] == before_len, (
            f"[{src}] XLEN changed from {before_len!r} to {after[0]!r} across two REFUSED XADDs; "
            f"a rejected append must not append. This is the effect-absent probe")
        ranged = _entry_ids(after[1], source=src, cmd="XRANGE")
        assert ranged == all_ids, (
            f"[{src}] XRANGE - + returned {len(ranged)} ids and XADD minted {total}; the log the "
            f"engine reports is not the log it accepted. First divergence at index "
            f"{next((i for i, (a, b) in enumerate(zip(ranged, all_ids)) if a != b), len(ranged))}")
        assert _resp_int(after[0], source=src, cmd="XLEN") == total, (
            f"[{src}] XLEN reports {after[0]!r} for a stream {total} entries were appended to")

        # ---- 3. exactly-once delivery within the group -------------------------------------
        half = total // 2
        read_at = time.monotonic()
        grp = call([
            ["XGROUP", "CREATE", _STREAM, _GROUP_NAME, "0"],
            ["XREADGROUP", "GROUP", _GROUP_NAME, "C1", "COUNT", str(half), "STREAMS", _STREAM, ">"],
            ["XREADGROUP", "GROUP", _GROUP_NAME, "C2", "COUNT", str(total), "STREAMS", _STREAM, ">"],
        ])
        delivered_at = time.monotonic()
        assert grp[0] == b"+OK\r\n", (
            f"[{src}] XGROUP CREATE must return +OK, got {grp[0]!r}")
        c1_ids = _xreadgroup_ids(grp[1], source=src, stream=_STREAM)
        c2_ids = _xreadgroup_ids(grp[2], source=src, stream=_STREAM)
        assert len(c1_ids) == half, (
            f"[{src}] XREADGROUP COUNT {half} delivered {len(c1_ids)} entries to C1")
        assert not (set(c1_ids) & set(c2_ids)), (
            f"[{src}] {len(set(c1_ids) & set(c2_ids))} entries were delivered to BOTH C1 and C2: "
            f"{sorted(set(c1_ids) & set(c2_ids))[:5]!r}. A consumer group exists to deliver each "
            f"entry to exactly one consumer; an implementation that returns the tail of the log to "
            f"every reader has no group cursor at all and every worker in a fleet double-processes "
            f"every message")
        assert c1_ids + c2_ids == all_ids, (
            f"[{src}] C1 got {len(c1_ids)} entries and C2 got {len(c2_ids)}, together "
            f"{len(c1_ids) + len(c2_ids)} of the {total} appended, and in this order: the union must "
            f"be the WHOLE log in log order, or the group cursor skipped or reordered entries. "
            f"Missing: {sorted(set(all_ids) - set(c1_ids) - set(c2_ids))[:5]!r}")

        # ---- 4. the drained read is the NULL array, not the empty one ----------------------
        # Real Redis returns `*-1\r\n`; `*0` would mean "a batch arrived and it was empty". Client
        # libraries collapse the two, hence the raw-byte comparison.
        drained = call([
            ["XREADGROUP", "GROUP", _GROUP_NAME, "C1", "COUNT", "10", "STREAMS", _STREAM, ">"],
            ["XREADGROUP", "GROUP", _GROUP_NAME, "C-fresh", "COUNT", "10", "STREAMS", _STREAM, ">"],
        ])
        for raw, who in zip(drained, ("C1", "a consumer that has never read")):
            assert raw == b"*-1\r\n", (
                f"[{src}] with the stream fully delivered, `XREADGROUP ... >` from {who} must "
                f"return the NULL array `*-1\\r\\n`, got {raw!r}. `*0\\r\\n` is a different answer "
                f"-- an empty batch rather than no batch -- and clients branch on it")

        # ---- 5. XPENDING reports the per-consumer breakdown --------------------------------
        pend = call([["XPENDING", _STREAM, _GROUP_NAME]])[0]
        p_total, p_low, p_high, per = _xpending_summary(pend, source=src)
        assert p_total == total, (
            f"[{src}] XPENDING reports {p_total} pending entries after all {total} were delivered "
            f"and none acknowledged; every delivered entry must sit in some consumer's PEL")
        assert per == {"C1": len(c1_ids), "C2": len(c2_ids)}, (
            f"[{src}] XPENDING's per-consumer breakdown is {per!r}, not the "
            f"{{'C1': {len(c1_ids)}, 'C2': {len(c2_ids)}}} that was actually delivered. The PEL is "
            f"per CONSUMER, not per group")
        assert (p_low, p_high) == (all_ids[0], all_ids[-1]), (
            f"[{src}] XPENDING reports the pending id range as {p_low!r}..{p_high!r}, not the "
            f"{all_ids[0]!r}..{all_ids[-1]!r} that was delivered")

        # ---- 6. XACK removes exactly the entries named, and only once ----------------------
        acked = c1_ids[:_N_ACK]
        ack = call([["XACK", _STREAM, _GROUP_NAME] + [i.decode() for i in acked],
                    ["XACK", _STREAM, _GROUP_NAME] + [i.decode() for i in acked],
                    ["XACK", _STREAM, _GROUP_NAME, "999999999999-0"],
                    ["XPENDING", _STREAM, _GROUP_NAME]])
        assert ack[0] == b":%d\r\n" % _N_ACK, (
            f"[{src}] XACK of {_N_ACK} pending ids must return `:{_N_ACK}`, got {ack[0]!r}")
        assert ack[1] == b":0\r\n", (
            f"[{src}] a SECOND XACK of the same {_N_ACK} ids returned {ack[1]!r}, not `:0`. XACK "
            f"reports how many entries it actually removed from the PEL, so an already-acknowledged "
            f"entry must count for nothing -- otherwise an at-least-once worker's retry looks like "
            f"progress")
        assert ack[2] == b":0\r\n", (
            f"[{src}] XACK of an id nobody ever read returned {ack[2]!r}, not `:0`")
        a_total, _, _, a_per = _xpending_summary(ack[3], source=src)
        assert a_total == total - _N_ACK, (
            f"[{src}] XPENDING reports {a_total} pending after {_N_ACK} of {total} were "
            f"acknowledged; expected {total - _N_ACK}")
        assert a_per == {"C1": len(c1_ids) - _N_ACK, "C2": len(c2_ids)}, (
            f"[{src}] after C1 acknowledged {_N_ACK} entries the breakdown is {a_per!r}; the ack "
            f"must debit C1 and leave C2 untouched, expected "
            f"{{'C1': {len(c1_ids) - _N_ACK}, 'C2': {len(c2_ids)}}}")

        # ---- 7. NEGATIVE ARM B: XGROUP CREATE of an existing group ------------------------
        busy = call([["XGROUP", "CREATE", _STREAM, _GROUP_NAME, "0"],
                     ["XPENDING", _STREAM, _GROUP_NAME]])
        assert _resp_error_name(busy[0], source=src, cmd="XGROUP CREATE (duplicate)") == "BUSYGROUP", (
            f"[{src}] re-creating the existing group {_GROUP_NAME!r} must be refused with "
            f"`-BUSYGROUP`, got {busy[0]!r}. A target that silently returns +OK has RESET the group "
            f"cursor and every unacknowledged entry is lost")
        assert busy[1] == ack[3], (
            f"[{src}] XPENDING changed across a REFUSED XGROUP CREATE: {ack[3]!r} -> {busy[1]!r}. "
            f"The refusal must leave the group's pending state byte-identical. This is the "
            f"effect-absent probe")

        # ---- 8. NEGATIVE ARM C: XREADGROUP against a group that does not exist ------------
        nog = call([
            ["XREADGROUP", "GROUP", "sim2real-nosuchgroup", "C1", "STREAMS", _STREAM, ">"],
            ["XPENDING", _STREAM, _GROUP_NAME],
        ])
        assert _resp_error_name(nog[0], source=src, cmd="XREADGROUP (unknown group)") == "NOGROUP", (
            f"[{src}] XREADGROUP naming a group that was never created must be refused with "
            f"`-NOGROUP`, got {nog[0]!r}. Returning entries there would hand a typo'd consumer the "
            f"whole log with no group accounting at all")
        assert nog[1] == ack[3], (
            f"[{src}] XPENDING for {_GROUP_NAME!r} changed across a REFUSED XREADGROUP against a "
            f"different, non-existent group: {ack[3]!r} -> {nog[1]!r}")

        # ---- 9. XAUTOCLAIM selects by the engine's own idle accounting --------------------
        # XPENDING's extended form reports each entry's idle time in milliseconds since its last
        # delivery, which lies between the wall time from the XREADGROUP reply to this request and
        # the wall time from the XREADGROUP request to this reply. A min-idle-time of a day
        # therefore selects none of them, and 0 selects all of them.
        ext_cmd = [["XPENDING", _STREAM, _GROUP_NAME, "IDLE", "0", "-", "+", str(total)]]
        asked_at = time.monotonic()
        rows = _xpending_extended(call(ext_cmd)[0], source=src)
        wall_ms = (time.monotonic() - read_at) * 1000.0 + 1000.0
        floor_ms = (asked_at - delivered_at) * 1000.0 - 100.0
        assert len(rows) == total - _N_ACK, (
            f"[{src}] the extended XPENDING lists {len(rows)} entries, not the "
            f"{total - _N_ACK} still pending")
        assert min(r[2] for r in rows) >= floor_ms, (
            f"[{src}] the extended XPENDING reports an idle time of {min(r[2] for r in rows)}ms, "
            f"less than the {floor_ms:.0f}ms that have passed since the entries were delivered; "
            f"the engine is not ageing its pending entries")
        assert max(r[2] for r in rows) <= wall_ms, (
            f"[{src}] the extended XPENDING reports an idle time of {max(r[2] for r in rows)}ms, "
            f"more than the {wall_ms:.0f}ms since the entries were delivered; idle time is "
            f"measured from the last delivery")
        owners = sorted({r[1] for r in rows})
        assert owners == [b"C1", b"C2"], (
            f"[{src}] the extended XPENDING attributes pending entries to {owners!r}, not to C1 "
            f"and C2")
        assert all(r[3] == 1 for r in rows), (
            f"[{src}] every entry has been delivered exactly once so far, so XPENDING must report "
            f"delivery-count 1 for all of them; got "
            f"{sorted({r[3] for r in rows})!r}")

        unripe = call([["XAUTOCLAIM", _STREAM, _GROUP_NAME, "C2", str(_UNREACHED_IDLE_MS), "0",
                        "COUNT", str(total)],
                       ["XPENDING", _STREAM, _GROUP_NAME]])
        u_cursor, u_claimed, u_deleted = _xautoclaim(unripe[0], source=src)
        assert (u_cursor, u_claimed, u_deleted) == (b"0-0", [], []), (
            f"[{src}] XAUTOCLAIM with min-idle-time {_UNREACHED_IDLE_MS}ms must scan the whole PEL "
            f"and claim nothing, since no entry has been idle that long; got cursor {u_cursor!r}, "
            f"{len(u_claimed)} claimed, deleted {u_deleted!r}")
        assert unripe[1] == ack[3], (
            f"[{src}] XPENDING changed across an XAUTOCLAIM that claimed nothing: {ack[3]!r} -> "
            f"{unripe[1]!r}")

        claim = call([["XAUTOCLAIM", _STREAM, _GROUP_NAME, "C2", "0", "0",
                       "COUNT", str(total)],
                      ["XPENDING", _STREAM, _GROUP_NAME]])
        cursor, claimed, deleted = _xautoclaim(claim[0], source=src)
        assert cursor == b"0-0", (
            f"[{src}] XAUTOCLAIM scanned the whole PEL and must report cursor `0-0`, got "
            f"{cursor!r}")
        assert deleted == [], (
            f"[{src}] XAUTOCLAIM reports {deleted!r} as deleted-from-the-stream; nothing was "
            f"deleted, so a non-empty list means the PEL references entries the log has lost")
        still_pending_c1 = [i for i in c1_ids if i not in set(acked)]
        assert set(claimed) == set(still_pending_c1) | set(c2_ids), (
            f"[{src}] XAUTOCLAIM claimed {len(claimed)} entries; it must claim exactly the "
            f"{len(still_pending_c1) + len(c2_ids)} entries still pending and NONE of the "
            f"{_N_ACK} already acknowledged. Wrongly claimed: "
            f"{sorted(set(claimed) & set(acked))[:5]!r}; missed: "
            f"{sorted((set(still_pending_c1) | set(c2_ids)) - set(claimed))[:5]!r}")
        assert not (set(claimed) & set(acked)), (
            f"[{src}] XAUTOCLAIM returned {len(set(claimed) & set(acked))} of the {_N_ACK} "
            f"ACKNOWLEDGED entries: {sorted(set(claimed) & set(acked))[:5]!r}. An acknowledged "
            f"entry has left the PEL and can never be reclaimed; a target that reclaims it makes "
            f"every consumer-group worker reprocess completed work forever")
        c_total, _, _, c_per = _xpending_summary(claim[1], source=src)
        assert c_total == total - _N_ACK, (
            f"[{src}] XPENDING reports {c_total} pending after the claim; a claim TRANSFERS "
            f"ownership and must not change the total, expected {total - _N_ACK}")
        assert c_per == {"C2": total - _N_ACK}, (
            f"[{src}] after XAUTOCLAIM to C2 the breakdown is {c_per!r}; every still-pending entry "
            f"must now be owned by C2 and C1 must hold none, expected "
            f"{{'C2': {total - _N_ACK}}}")

        # ---- 10. delivery_count really incremented ----------------------------------------
        after_claim = _xpending_extended(call(ext_cmd)[0], source=src)
        assert {r[1] for r in after_claim} == {b"C2"}, (
            f"[{src}] the extended XPENDING still attributes entries to "
            f"{sorted({r[1] for r in after_claim})!r} after the claim")
        assert all(r[3] == 2 for r in after_claim), (
            f"[{src}] after one claim every reclaimed entry must report delivery-count exactly 2 "
            f"(delivered once, claimed once); got {sorted({r[3] for r in after_claim})!r}. This "
            f"counter is how a worker fleet detects a poison message, and a target that does not "
            f"increment it lets one bad entry be retried forever with no signal")

        # ---- 11. CONTROL: the group still works after every arm ----------------------------
        ctrl = call([["XADD", _STREAM, "*", "control", "1"]])
        ctrl_id = _resp_bulk(ctrl[0], source=src, cmd="XADD (control)")
        assert _id_pair(ctrl_id) > _id_pair(all_ids[-1]), (
            f"[{src}] the control XADD minted {ctrl_id!r}, which is not above the previous top "
            f"{all_ids[-1]!r}")
        fresh = call([
            ["XREADGROUP", "GROUP", _GROUP_NAME, "C3", "COUNT", str(total), "STREAMS", _STREAM, ">"],
            ["XLEN", _STREAM],
        ])
        got = _xreadgroup_ids(fresh[0], source=src, stream=_STREAM)
        assert got == [ctrl_id], (
            f"[{src}] control: a new consumer reading `>` after every arm must receive EXACTLY the "
            f"one entry appended since the group cursor last advanced, got {got!r} for "
            f"{ctrl_id!r}. Anything else means the earlier refusals moved the cursor")
        assert _resp_int(fresh[1], source=src, cmd="XLEN") == total + 1, (
            f"[{src}] control: XLEN is {fresh[1]!r} after {total + 1} successful appends and four "
            f"refused ones")
    finally:
        # Inline teardown in dependency order, under this check's own budget: the function first so
        # its Hyperplane ENI drains while the node is deleted, then the node waited out until it is
        # no longer listed, then the subnet group and this run's VPC once it holds no interface.
        _delete_function(ctx, lam, fn)
        status = _teardown_cluster_now(ec, cluster_id)
        assert status == "deleting", (
            f"DeleteCacheCluster on {cluster_id} reported CacheClusterStatus={status!r}, not "
            f"'deleting'; a node that does not enter the deleting state keeps billing")
        _wait_cluster_gone(ec, cluster_id)
        _delete_cache_subnet_group(ec, subnet_group)
        _teardown_network(ctx.client("ec2"), net["vpc_id"], timeout_s=_NET_DRAIN_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
