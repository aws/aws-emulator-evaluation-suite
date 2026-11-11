"""elasticache-lua-eval-atomicity-and-script-cache."""
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

CHECK = "elasticache-lua-eval-atomicity-and-script-cache"
GROUP = 'cache-cluster'
SERVICES = ['elasticache']

# The in-VPC executor. ElastiCache is VPC-only, so the only client that can reach the data plane is
# inside the cluster's VPC: a Lambda with VpcConfig on the cache's subnets and security group runs a
# stdlib RESP probe and returns the raw reply bytes. The codec frames RESP2 aggregates and RESP3
# types recursively, so commands after an array reply stay in sync.
#
# The executor network is free, so an existing VPC is adopted and the executor group is found by
# this tag and reused: a VPC Lambda's Hyperplane ENI holds the subnet for up to ~20 minutes after
# the function is deleted, and VPC quotas are small. See `_executor_network`.
_INFRA_TAG_KEY = "sim2real:infra"
_INFRA_TAG_VALUE = "invpc-executor"

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    {"Key": _INFRA_TAG_KEY, "Value": _INFRA_TAG_VALUE},
]

# Tags for the billable resource; `sim2real` names the scenario so a leftover can be attributed.
_RESOURCE_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    {"Key": "sim2real", "Value": CHECK},
]

# Adds the ec2:*NetworkInterface actions to AWSLambdaBasicExecutionRole's; without them
# CreateFunction with VpcConfig is rejected synchronously.
_VPC_ACCESS_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"

# Prefix for a native data-plane failure: the endpoint was advertised but does not speak Redis.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


_REDIS_PORT = 6379
_NODE_TYPE = "cache.t3.micro"

_HANDLER_SRC = r'''"""In-VPC probe executed by AWS Lambda inside the ElastiCache resource's VPC.

The T3 executor. It is deliberately DUMB: it opens sockets, returns raw bytes, and makes **no
assertions**. Every assertion lives in the check, for three reasons:

1. The verdict grades the CHECK. An assertion that fires inside the Lambda reports as
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
# Every type is framed, arrays included: a codec that frames only `+-:$` desynchronises the
# stream after the first array reply, so no second command (XRANGE, EXEC, SCAN) could follow it.
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

    The runner and the in-VPC Lambda then drive the same source, so a disagreement between them is
    about the network, never the client.
    """
    if not _LOCAL_NS:
        exec(compile(_HANDLER_SRC, "<invpc-handler>", "exec"), _LOCAL_NS)  # noqa: S102
    return _LOCAL_NS


def _dp_fail(msg: str) -> AssertionError:
    """The native data-plane fidelity FAIL.

    Returned rather than raised so a call site keeps its `from exc` chaining.
    """
    return AssertionError(f"{DATAPLANE_MARKER}: {msg}")


def _no_executor(msg: str):
    """The in-VPC executor is unusable, so this run measured nothing."""
    return AssertionError(f"the in-VPC executor is unusable, so this run measured nothing: {msg}")


def _no_capacity(msg: str):
    """InsufficientCacheClusterCapacity: no node of the requested type could be placed."""
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


def _error_code(fn) -> str:
    """The exact error code ``fn()`` raised. Raises AssertionError when it SUCCEEDS, so acceptance
    is never mistaken for a code mismatch."""
    try:
        out = fn()
    except ClientError as exc:
        return _code_of(exc)
    raise AssertionError(
        f"the call was expected to be rejected but SUCCEEDED, returning {out!r}. That is the "
        f"over-permissiveness this check exists to catch, not a code mismatch"
    )


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


def _paginate(client, op: str, key: str, **kwargs):
    """Every page of `op`, flattened on `key`, so other resources in the account cannot push ours
    past the first page."""
    try:
        pager = client.get_paginator(op)
    except Exception:  # noqa: BLE001 -- no paginator modeled; fall back to one call
        return getattr(client, op)(**kwargs).get(key, [])
    out = []
    for page in pager.paginate(**kwargs):
        out.extend(page.get(key, []))
    return out


# ---- the reusable executor network ----------------------------------------------------------

# A lost race to create the shared executor subnet: both racers derive the same CIDR, so the loser
# adopts.
_SUBNET_RACE_LOST = frozenset({"InvalidSubnet.Conflict", "InvalidSubnetRange.Conflict"})


def _tag_filter():
    return [{"Name": f"tag:{_INFRA_TAG_KEY}", "Values": [_INFRA_TAG_VALUE]}]


def _has_self_ingress(ec2, sg_id: str, port: int) -> bool:
    """Does sg_id already admit ``port`` FROM ITSELF?

    Matched on the group pair, not on a CIDR: a 0.0.0.0/0 rule on the cache port would let the round
    trip succeed without proving the packets came from an ENI we attached, which is the whole load
    the self-reference carries.
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

    ``port`` is a parameter because cluster-mode shard nodes are reached directly. Idempotent, so a
    reused group whose rule is missing is healed rather than reused broken.
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
    """Are BOTH VPC DNS attributes already on?

    Read before write, because the executor network is normally a VPC this run did not create -- see
    `_executor_network`, which adopts one when the account is at its VPC quota. A pre-existing VPC
    that is already correct must not be modified at all, and the default VPC always is.
    """
    # The REQUEST spells the attribute lower-camel and the RESPONSE spells it upper-camel; they are
    # deliberately different keys in the model, so neither name works for both halves.
    return all(
        ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute=req)[resp]["Value"]
        for req, resp in (("enableDnsSupport", "EnableDnsSupport"),
                          ("enableDnsHostnames", "EnableDnsHostnames"))
    )


def _ensure_dns_attributes(ec2, vpc_id: str) -> None:
    """Turn on both DNS attributes, and ONLY if one of them is off.

    The VPC resolver at CIDR-base+2 answers only when DNS support is on, and that answer is one of
    the two in-VPC proofs. `EnableDnsSupport` defaults on but `EnableDnsHostnames` does NOT for a
    hand-created VPC, so a VPC left half-configured by a predecessor would silently cost the control
    step -- while a VPC that is already correct is left completely alone.
    """
    if _dns_attributes_ok(ec2, vpc_id):
        return
    for attr in ("EnableDnsSupport", "EnableDnsHostnames"):
        ec2.modify_vpc_attribute(VpcId=vpc_id, **{attr: {"Value": True}})


def _network_subnets(ec2, vpc_id: str, want: int = 2) -> list:
    """Up to ``want`` of the VPC's OWN available subnets, one per DISTINCT availability zone.

    Two zones let ElastiCache choose, so one zone without node capacity costs nothing. Deterministic
    (lowest SubnetId per zone, zones in name order); never a hardcoded zone name.
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
    """Build a fresh executor VPC with one subnet per zone. -> the VpcId.

    Reached only when no usable VPC can be adopted. Not registered for cleanup: the network is free
    and a VPC Lambda's Hyperplane ENI blocks its deletion for up to ~20 minutes.
    """
    # A randomized second octet makes the "source address is inside our VPC" signal sharp.
    cidr = f"10.{random.randrange(20, 250)}.0.0/16"
    vpc_id = ec2.create_vpc(
        CidrBlock=cidr,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _MANAGED_TAGS}],
    )["Vpc"]["VpcId"]
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
            # Two runs racing on the same fresh VPC both derive the same deterministic CIDR, so the
            # loser gets a conflict and its job is to adopt the winner's subnet.
            if _code_of(exc) not in _SUBNET_RACE_LOST:
                raise
    assert _network_subnets(ec2, vpc_id, want), f"created no usable subnet in {vpc_id}"
    return vpc_id


def _candidate_vpc(ec2):
    """The VPC to host the executor when we are adopting rather than creating one.

    The default VPC first, then the one with the most usable subnets, then lowest VpcId, so
    concurrent runs adopt the same VPC.
    """
    vpcs = _paginate(ec2, "describe_vpcs", "Vpcs",
                     Filters=[{"Name": "state", "Values": ["available"]}])
    scored = []
    for v in vpcs:
        if not v.get("CidrBlock"):
            continue
        n = len(_network_subnets(ec2, v["VpcId"], want=64))
        if n:
            scored.append((0 if v.get("IsDefault") else 1, -n, v["VpcId"], v))
    if not scored:
        return None
    return sorted(scored, key=lambda t: t[:3])[0][3]


def _has_infra_group(ec2):
    """The security group this run (or a predecessor) tagged as the executor group, if any.

    Discovery keys on the group, not the VPC, because an adopted VPC is not ours to tag.
    """
    groups = _paginate(ec2, "describe_security_groups", "SecurityGroups", Filters=_tag_filter())
    if not groups:
        return None
    # Lowest GroupId wins if two exist, so a duplicate from a concurrent run is inert.
    return sorted(groups, key=lambda g: g["GroupId"])[0]


def _executor_network(ctx, ec2, port: int = _REDIS_PORT) -> dict:
    """The executor network: a VPC, two subnets in two zones, and a self-referencing security group.

    Adopt first, create last. Every piece is completed rather than merely found; subnets are only
    created in a VPC this code created.
    """
    group = _has_infra_group(ec2)
    if group is not None:
        vpc_id, sg_id = group["VpcId"], group["GroupId"]
    else:
        vpc = _candidate_vpc(ec2)
        vpc_id = vpc["VpcId"] if vpc is not None else _create_infra_vpc(ctx, ec2)
        sg_id = None

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

    if sg_id is None:
        try:
            sg_id = ec2.create_security_group(
                GroupName=ctx.unique_name("sim2real-behav-invpc-sg-"),
                Description=("sim2real in-VPC executor: Lambda ENI + ElastiCache node, "
                             "self-referencing"),
                VpcId=vpc_id,
                TagSpecifications=[{"ResourceType": "security-group", "Tags": _MANAGED_TAGS}],
            )["GroupId"]
        except ClientError as exc:
            # Two runs racing to create the shared group: the loser adopts the winner's.
            if _code_of(exc) != "InvalidGroup.Duplicate":
                raise
            won = _has_infra_group(ec2)
            assert won is not None, "lost the create race for the executor group but none exists"
            sg_id = won["GroupId"]
    _ensure_self_ingress(ec2, sg_id, port)

    return {
        "vpc_id": vpc_id,
        "cidr": cidr,
        "resolver": str(ipaddress.ip_network(cidr).network_address + 2),
        "subnet_ids": subnet_ids,
        "sg_id": sg_id,
        "adopted": group is not None,
    }


def _ensure_cache_subnet_group(ec, net: dict) -> str:
    """The cache subnet group for the executor network, reused when the network is.

    Retained so teardown never waits for the node to delete (CacheSubnetGroupInUse).
    """
    name = f"sim2real-invpc-{net['vpc_id']}"[:255]
    try:
        found = (ec.describe_cache_subnet_groups(
            CacheSubnetGroupName=name).get("CacheSubnetGroups") or [None])[0]
        if found:
            # Complete, don't merely find. A group built when only one of the VPC's subnets was
            # available stays single-AZ even after the second one appears, which would silently
            # defeat the two-AZ capacity mitigation `_network_subnets` exists for.
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
        # The name is derived from the VPC id, so two runs completing the same shared network both
        # miss on the describe and both create. The loser adopts; the winner owns the group.
        if _code_of(exc) != "CacheSubnetGroupAlreadyExists":
            raise
    return name


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
    """The whole deployment package: one stdlib-only file, no dependency, no layer."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, src)
    return buf.getvalue()


def _deploy_executor(ctx, lam, net: dict, role_arn: str):
    """CreateFunction with VpcConfig, retried through IAM propagation, then wait Active.

    A just-created role is briefly rejected by CreateFunction with InvalidParameterValue.
    """
    name = ctx.unique_name("sim2real-behav-invpc-fn-")
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=role_arn,
        Code={"ZipFile": _make_zip(_HANDLER_SRC)},
        MemorySize=512,
        # 300s: a `sessions` invoke holds N connections open across a barrier and a deliberate
        # in-script wait, and a runtime timeout there would surface as FunctionError -- i.e. as "the
        # instrument is unusable" -- for a measurement that was merely long.
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
            time.sleep(5)
    ctx.on_cleanup(lambda n=name: _delete_function(ctx, lam, n))

    last = _poll(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get("State") in ("Active", "Failed"),
        timeout_s=300,
        interval_s=5,
    )
    if last is None:
        raise AssertionError(
            f"the in-VPC executor {name} did not reach State=Active within the bounded wait (a "
            f"first Hyperplane ENI in a fresh subnet/security-group pair is the slow part)",
        )
    if last["State"] != "Active":
        raise _no_executor(f"{name} entered State={last['State']!r}: {last.get('StateReason')!r}")
    return name, (last.get("VpcConfig") or {})


def _delete_function(ctx, lam, name: str):
    """Delete the function and its log group, raising on anything but not-found. Returns
    immediately: Lambda releases the Hyperplane ENI asynchronously, and nothing here waits for it."""
    for fn in (
        lambda: lam.delete_function(FunctionName=name),
        lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}"),
    ):
        try:
            fn()
        except ClientError as exc:
            if _code_of(exc) != "ResourceNotFound":
                raise


def _invoke(ctx, lam, fn: str, payload: dict) -> dict:
    """One synchronous Invoke, returning the decoded handler result.

    A FunctionError or a non-200 StatusCode means the RUNTIME failed, not that the handler reported
    a failure -- the handler never raises, so anything arriving here is the executor being unusable
    rather than a verdict about Redis.
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
    """Run the selftest before anything billable exists. Returns (evidence, in_vpc, reason).

    A nonce digest proves the code ran; a source address in the VPC CIDR or any reply from the VPC
    resolver at CIDR-base+2 proves it ran inside the VPC.
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
    """Everything up to and including the control step. -> (lam, net, fn, in_vpc, why).

    Ordered so nothing billable exists yet: the network and the function are free, and the cache
    resource is created by the caller only after this returns. A target that cannot run the probe is
    therefore never billed for a cache.
    """
    ec2 = ctx.client("ec2")
    lam = ctx.client("lambda")
    net = _executor_network(ctx, ec2, port)
    role_arn = _vpc_exec_role_arn(ctx)
    fn, cfg_vpc = _deploy_executor(ctx, lam, net, role_arn)
    # Round-tripping VpcConfig is necessary but nowhere near sufficient -- echoing a field back is
    # the cheapest thing an emulator can do, which is why the real proof is the selftest.
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
    """One vantage point, exposing the handler's ops with an identical signature either way.

    Chosen once, so a positive control and its contrasting refusal run from the same network.
    """

    def __init__(self, label, fn):
        self.label = label
        self._fn = fn

    def resp(self, host, port, commands, tls=False) -> dict:
        """Run ``commands`` (a list of arg lists, each arg ``str`` or ``bytes``) and return the
        handler's result dict. Arguments are base64'd for the trip because the event is JSON and a
        Redis value is arbitrary bytes; the caller keeps the ORIGINAL commands for its messages."""
        return self._fn({"op": "resp", "host": host, "port": int(port), "tls": bool(tls),
                         "commands": [_enc_cmd(c) for c in commands]})

    def sessions(self, host, port, sessions, tls=False) -> dict:
        """Run N concurrent sessions. A step that is a ``dict`` is a pseudo-command (``sync`` /
        ``sleep_ms``) and travels unencoded; anything else is a command."""
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
    """The vantage point that can actually reach ``host:port``, or the verdict that none can.

    Polled to a bounded deadline: a cache can report 'available' before its endpoint connects. The
    runner-side arm is tried once, for a target with no VPC isolation.
    """
    runner = _Prober("runner-outside-vpc", _dispatch_local)
    lamprobe = (_Prober("lambda-in-vpc", lambda ev: _invoke(ctx, lam, fn, ev))
                if in_vpc else None)
    budget = 300
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
    """The raw reply bytes for ``commands``, asserting one reply per command.

    The probe stops at the first byte that is not a RESP type at all, so a short list means the
    endpoint answered with something no RESP version defines -- a finding, and the raw bytes are
    printed rather than swallowed.
    """
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

    A pseudo-command's slot is None on both sides, so the reply index of a real command is the same
    number the check wrote in its script -- which is what makes an assertion on
    ``sess[1][4]`` auditable rather than a guess.
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


# ---- framing an aggregate on the CHECK side ---------------------------------------------------

# Same three groups as the handler's framer, as bytes literals; the handler source is a string
# constant, so they cannot be shared.
_SIMPLE_B = b"+-:,#("
_BULKISH_B = b"$=!"
_AGG_B = {b"*": 1, b"~": 1, b">": 1, b"%": 2, b"|": 2}


def _frame_end(raw: bytes, i: int, *, depth: int = 0) -> int:
    """The index just past the one complete reply that starts at ``raw[i]``.

    Byte-equality is right for scalars and wrong for `XRANGE` / `CLUSTER SLOTS` / `EXEC`, whose
    payloads contain server-generated ids and addresses. So the check side re-runs the SAME framing
    rules over the raw bytes to split an aggregate into its element spans, and every assertion is
    then still byte-level and still framing-aware, with no client library anywhere.
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
    """One aggregate reply split into its ELEMENT SPANS, each still raw bytes.

    A map (`%`) or attribute (`|`) yields ``2n`` flat spans -- key, value, key, value -- because
    that is exactly how the frame is laid out and inventing a dict here would be the same mistake as
    using a client library.
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
    """The payload of a RESP bulk-string reply. ``$-1\\r\\n`` (absent) is a distinct answer and is
    rejected here rather than collapsed to b"" -- conflating absence with emptiness is the single
    most consequential Redis emulation bug."""
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
    """The error NAME out of a RESP error frame ``-NAME free text\\r\\n``, as an exact token.

    The message text is not part of the contract; the name is compared exactly, not by prefix.
    """
    assert raw.startswith(b"-") and raw.endswith(b"\r\n"), (
        f"[{source}] {cmd} was expected to be refused with a RESP error frame "
        f"(-NAME message\\r\\n), got {raw!r}")
    return raw[1:-2].split(b" ", 1)[0].decode("ascii", "replace")


def _info_field(raw: bytes, field: str, *, source: str) -> int:
    """One integer field out of an INFO bulk string, asserting it is actually present.

    INFO is CRLF-separated ``key:value`` lines inside one bulk string. Parsed structurally on the
    line rather than by a substring search, so a field cannot be satisfied by a longer name that
    contains it or by the word appearing in a comment line.
    """
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
    """One TEXT field out of an INFO bulk string. Same structural parse as `_info_field`; separate
    because a value like ``redis_version:7.1.0`` is not an integer and coercing it would hide the
    very value under test."""
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
    """Is the engine's own reported version (`INFO server`) at least ``want``?

    Gated on what the engine reports, not the control plane's `EngineVersion`.
    """
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


# Returned by _cluster_endpoint when node info never populated, distinct from (None, None) so a
# wait that ran out is never graded as a data-plane gap.
_NODE_INFO_TIMEOUT = object()


def _cluster_endpoint(ec, cluster_id: str):
    """``(Address, Port)`` for the single cache node, or ``_NODE_INFO_TIMEOUT``.

    A timeout is provisioning latency, distinct from an available cluster with an empty endpoint.
    """
    node = _poll(lambda: _describe_cluster(ec, cluster_id, ShowCacheNodeInfo=True),
                 lambda c: bool((c or {}).get("CacheNodes")),
                 timeout_s=300, interval_s=10)
    if node is None:
        return _NODE_INFO_TIMEOUT
    nodes = node["CacheNodes"]
    assert len(nodes) == 1, f"asked for one cache node, DescribeCacheClusters reports {nodes!r}"
    endpoint = nodes[0].get("Endpoint") or {}
    return endpoint.get("Address"), endpoint.get("Port")


def _wait_cluster_available(ctx, ec, cluster_id: str) -> dict:
    got = _poll(lambda: _describe_cluster(ec, cluster_id),
                lambda c: c is not None and c.get("CacheClusterStatus") == "available",
                timeout_s=1200,
                interval_s=15)
    if got is None:
        raise AssertionError(
            f"cache cluster {cluster_id} did not reach 'available' within the bounded wait")
    return got


def _resolved_endpoint(ctx, ec, cluster_id: str):
    endpoint = _cluster_endpoint(ec, cluster_id)
    if endpoint is _NODE_INFO_TIMEOUT:
        # Never a fidelity verdict: node info that has not populated yet says nothing about the data
        # plane, and on real AWS it is provisioning latency.
        raise AssertionError(
            f"cache cluster {cluster_id} reached 'available' but DescribeCacheClusters never "
            f"populated CacheNodes within the bounded wait")
    host, port = endpoint
    if not host or not port:
        raise _dp_fail(
            f"cluster {cluster_id} is 'available' but advertises no connectable endpoint "
            f"(Address={host!r} Port={port!r}); without an address there is no data plane")
    return ctx.endpoint_host(host, int(port))


def _delete_cluster(ec, cluster_id: str, timeout_s: float = 900):
    """Get the billable node deleting. Idempotent, and retried through the `creating` state.

    A node already `deleting` returns at once.
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
            time.sleep(20)


def _teardown_cluster_now(ec, cluster_id: str) -> str:
    """Delete the node INSIDE the check and return the status the API reported, so the delete is
    asserted rather than assumed."""
    return (ec.delete_cache_cluster(CacheClusterId=cluster_id)["CacheCluster"]
            ["CacheClusterStatus"])


def _newest_redis_family(ec):
    """``(engine_version, parameter_group_family)`` for the newest Redis the account can create.

    Derived, never hardcoded: the family must match the engine version and old engines retire.
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


# ---- the scripts under test -------------------------------------------------------------------

# Writes two keys from KEYS and returns a heterogeneous Lua table. A table with an `err` field
# becomes a RESP error frame nested inside the array:
#     *3\r\n:1\r\n$3\r\ntwo\r\n-boom\r\n
_SCRIPT_WRITE_TWO = (
    "redis.call('SET', KEYS[1], ARGV[1])\n"
    "redis.call('SET', KEYS[2], ARGV[2])\n"
    "return {1, 'two', {err='boom'}}"
)

# Writes KEYS[1], then INCRs KEYS[2] (a non-numeric string), then would write KEYS[3]. The reply is
# a `-ERR` frame naming the script sha and line; KEYS[1] keeps its value and KEYS[3] is never
# written: scripts are atomic with respect to other clients but do not roll back on error.
_SCRIPT_HALF_FAILS = (
    "redis.call('SET', KEYS[1], 'landed-before-the-error')\n"
    "redis.call('INCR', KEYS[2])\n"
    "redis.call('SET', KEYS[3], 'never-reached')"
)

# The atomicity subject: set one key, burn CPU inside the interpreter, set the second. A second
# CONNECTION polling both keys throughout must never observe the first set without the second,
# because Redis executes a script to completion before serving any other client.
_SCRIPT_SLOW_PAIR = (
    "redis.call('SET', KEYS[1], 'first')\n"
    "local t = 0\n"
    "for i = 1, tonumber(ARGV[1]) do t = t + i end\n"
    "redis.call('SET', KEYS[2], tostring(t))\n"
    "return 'done'"
)

_CALIBRATE_ITERS = 20_000_000   # one timed pass, used to size the real run
_TARGET_SCRIPT_MS = 1200        # how long the slow script should run (150M iters ~ 1.1s)
_POLL_PAIRS = 60                # observations the second connection makes across the window
_SEND_SLACK_S = 0.005           # writer stamp -> EVAL bytes on the wire, plus network jitter
_REPLY_SLACK_S = 0.05           # two replies leaving the server together, read by two threads

_K1 = "sim2real:lua:pair:1"
_K2 = "sim2real:lua:pair:2"


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:negative-classes",
      "dp:native", "plane:data")
def run(ctx) -> None:
    """Lua runs server-side: SCRIPT LOAD returns the body's SHA1, EVALSHA matches EVAL byte for
    byte, Lua->RESP conversions follow the documented rules, unloaded or flushed digests get
    -NOSCRIPT, a failing script keeps earlier writes, and no other client runs during a script.

    Reference: https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/SupportedCommands.html
    """
    ec = ctx.client("elasticache")
    lam, net, fn, in_vpc, why = _bring_up_executor(ctx)
    subnet_group = _ensure_cache_subnet_group(ec, net)
    engine_version, _family = _newest_redis_family(ec)

    cluster_id = ctx.unique_name("sim2real-behav-eclua-")
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
    assert created["CacheClusterStatus"] == "creating", (
        f"create_cache_cluster reported CacheClusterStatus="
        f"{created['CacheClusterStatus']!r}, not 'creating'")

    try:
        _wait_cluster_available(ctx, ec, cluster_id)
        host, port = _resolved_endpoint(ctx, ec, cluster_id)
        probe = _pick_prober(ctx, lam, fn, host, port, in_vpc=in_vpc, why=why, tls=False,
                             subject=f"cache cluster {cluster_id}")
        src = probe.label

        def call(cmds):
            return _replies(probe.resp(host, port, cmds), cmds, source=src)

        base = call([["INFO", "server"], ["DBSIZE"]])
        engine = _info_text(base[0], "redis_version", source=src)
        assert _engine_at_least(engine, (6, 0)), (
            f"[{src}] the engine reports redis_version={engine!r} on the wire while the control "
            f"plane provisioned EngineVersion={engine_version!r}; the two planes disagree")
        assert _resp_int(base[1], source=src, cmd="DBSIZE") == 0, (
            f"[{src}] a freshly provisioned node reports a non-empty DBSIZE ({base[1]!r}); the key "
            f"accounting below assumes we are the only writer")

        # ---- 1. SCRIPT LOAD returns the SHA1 of the bytes WE sent --------------------------
        # Computed independently on this side, so a target minting arbitrary handles fails. This is
        # the cheapest unfakeable assertion in the whole axis: the digest is a function of the body
        # the client chose, so it cannot come from a recording.
        want_sha = hashlib.sha1(_SCRIPT_WRITE_TWO.encode()).hexdigest()  # noqa: S324 -- Redis's own
        loaded = call([["SCRIPT", "LOAD", _SCRIPT_WRITE_TWO],
                       ["SCRIPT", "EXISTS", want_sha],
                       ["SCRIPT", "EXISTS", "0" * 40]])
        got_sha = _resp_bulk(loaded[0], source=src, cmd="SCRIPT LOAD")
        assert got_sha == want_sha.encode(), (
            f"[{src}] SCRIPT LOAD returned {got_sha!r} for a body whose SHA1 is {want_sha!r}. The "
            f"script cache is CONTENT-ADDRESSED: every client computes this digest locally and "
            f"sends EVALSHA without ever shipping the body, so a target that mints its own handle "
            f"breaks every EVALSHA in production")
        assert loaded[1] == b"*1\r\n:1\r\n", (
            f"[{src}] SCRIPT EXISTS for the digest just loaded must be the one-element array "
            f"`*1\\r\\n:1\\r\\n`, got {loaded[1]!r}")
        assert loaded[2] == b"*1\r\n:0\r\n", (
            f"[{src}] SCRIPT EXISTS for a digest never loaded must be `*1\\r\\n:0\\r\\n`, got "
            f"{loaded[2]!r}")

        # ---- 2. NEGATIVE ARM A: EVALSHA of an unloaded digest -----------------------------
        absent_sha = hashlib.sha1(b"sim2real-never-loaded").hexdigest()  # noqa: S324
        arm_a = call([
            ["EVALSHA", absent_sha, "2", "sim2real:lua:noscript:1", "sim2real:lua:noscript:2",
             "a", "b"],
            ["EXISTS", "sim2real:lua:noscript:1"],
            ["EXISTS", "sim2real:lua:noscript:2"],
        ])
        assert _resp_error_name(arm_a[0], source=src, cmd="EVALSHA (unloaded)") == "NOSCRIPT", (
            f"[{src}] EVALSHA of a digest that was never loaded must be refused with `-NOSCRIPT`, "
            f"got {arm_a[0]!r}. `-NOSCRIPT` is the signal every client library keys on to fall back "
            f"to EVAL; a target that answers anything else turns a routine cache miss into a hard "
            f"application error")
        assert arm_a[1] == b":0\r\n" and arm_a[2] == b":0\r\n", (
            f"[{src}] the refused EVALSHA still wrote something: EXISTS on its two KEYS returned "
            f"{arm_a[1]!r} and {arm_a[2]!r}, expected `:0` for both. This is the effect-absent probe")

        # ---- 3. EVALSHA and EVAL are byte-identical ----------------------------------------
        run_both = call([
            ["EVALSHA", want_sha, "2", "sim2real:lua:w1", "sim2real:lua:w2", "v1", "v2"],
            ["GET", "sim2real:lua:w1"],
            ["GET", "sim2real:lua:w2"],
            ["EVAL", _SCRIPT_WRITE_TWO, "2", "sim2real:lua:e1", "sim2real:lua:e2", "v1", "v2"],
            ["GET", "sim2real:lua:e1"],
            ["GET", "sim2real:lua:e2"],
        ])
        assert run_both[0] == run_both[3], (
            f"[{src}] EVALSHA returned {run_both[0]!r} and EVAL of the same body returned "
            f"{run_both[3]!r}. The digest is an alias for the body and the two forms must be "
            f"indistinguishable on the wire")

        # ---- 4. the Lua -> RESP type mapping, byte for byte -------------------------------
        # The nested `-boom` error inside a `*3` array is the case a shim most often gets wrong.
        assert run_both[0] == b"*3\r\n:1\r\n$3\r\ntwo\r\n-boom\r\n", (
            f"[{src}] a script returning the Lua table `{{1, 'two', {{err='boom'}}}}` must produce "
            f"`*3\\r\\n:1\\r\\n$3\\r\\ntwo\\r\\n-boom\\r\\n` -- a three-element array whose third "
            f"element is an ERROR FRAME nested inside the array -- got {run_both[0]!r}")
        spans = _agg(run_both[0], source=src, cmd="EVAL (table)")
        assert [s[:1] for s in spans] == [b":", b"$", b"-"], (
            f"[{src}] the reply's three element type bytes are {[s[:1] for s in spans]!r}, not "
            f"integer / bulk string / error")
        assert _resp_error_name(spans[2], source=src, cmd="EVAL nested err") == "boom", (
            f"[{src}] the nested error frame is {spans[2]!r}; its name must be exactly `boom`, the "
            f"string the script put in the table's `err` field")

        # ---- 5. KEYS/ARGV really bind, and an undeclared key is NOT enforced ---------------
        assert run_both[1] == _bulk_expected(b"v1") and run_both[2] == _bulk_expected(b"v2"), (
            f"[{src}] the script's writes did not land on the names passed as KEYS: "
            f"sim2real:lua:w1={run_both[1]!r} sim2real:lua:w2={run_both[2]!r}, expected the ARGV "
            f"values v1 and v2")
        assert run_both[4] == _bulk_expected(b"v1") and run_both[5] == _bulk_expected(b"v2"), (
            f"[{src}] the EVAL form's writes did not land on its KEYS: {run_both[4]!r} "
            f"{run_both[5]!r}")
        # Redis does NOT enforce that a script only touches keys it declared. Asserting the REAL
        # behaviour rather than the documented convention is the point: an emulator that enforces
        # the convention is over-constrained and rejects scripts real AWS runs.
        undeclared = call([
            ["EVAL", "redis.call('SET', 'sim2real:lua:undeclared', 'x')\n"
                     "return redis.call('GET', 'sim2real:lua:undeclared')", "0"],
            ["EXISTS", "sim2real:lua:undeclared"],
        ])
        assert undeclared[0] == _bulk_expected(b"x"), (
            f"[{src}] a script writing a key it did NOT declare in KEYS must still succeed on real "
            f"Redis -- the KEYS list is a routing hint, not an access control -- got "
            f"{undeclared[0]!r}. A target that enforces the convention rejects scripts production "
            f"runs today")
        assert undeclared[1] == b":1\r\n", (
            f"[{src}] the undeclared key was not actually written: EXISTS returned "
            f"{undeclared[1]!r}")

        # ---- 6. scalar conversions ---------------------------------------------------------
        scalars = call([
            ["EVAL", "return 3.7", "0"],
            ["EVAL", "return redis.status_reply('CUSTOM')", "0"],
            ["EVAL", "return false", "0"],
            ["EVAL", "return true", "0"],
            ["EVAL", "return redis.error_reply('MYERR bad')", "0"],
            ["EVAL", "return {KEYS[1], ARGV[1], #KEYS}", "1", "kk", "aa"],
        ])
        assert scalars[0] == b":3\r\n", (
            f"[{src}] `return 3.7` must convert to the RESP integer `:3` -- Lua numbers are "
            f"TRUNCATED, not rounded and not returned as a string -- got {scalars[0]!r}. A target "
            f"answering `$3\\r\\n3.7\\r\\n` silently changes the type every caller receives")
        assert scalars[1] == b"+CUSTOM\r\n", (
            f"[{src}] `redis.status_reply('CUSTOM')` must produce the simple string `+CUSTOM`, got "
            f"{scalars[1]!r}")
        assert scalars[2] == b"$-1\r\n", (
            f"[{src}] `return false` must produce the NULL bulk string `$-1`, got {scalars[2]!r}. "
            f"`$0\\r\\n\\r\\n` is a DIFFERENT answer -- present and empty rather than absent -- and "
            f"conflating the two is the single most consequential Redis emulation bug")
        assert scalars[3] == b":1\r\n", (
            f"[{src}] `return true` must produce `:1`, got {scalars[3]!r}")
        assert _resp_error_name(scalars[4], source=src, cmd="EVAL error_reply") == "MYERR", (
            f"[{src}] `redis.error_reply('MYERR bad')` must produce an error frame named MYERR, got "
            f"{scalars[4]!r}")
        assert scalars[5] == b"*3\r\n$2\r\nkk\r\n$2\r\naa\r\n:1\r\n", (
            f"[{src}] a script returning `{{KEYS[1], ARGV[1], #KEYS}}` with one key and one arg must "
            f"produce `*3\\r\\n$2\\r\\nkk\\r\\n$2\\r\\naa\\r\\n:1\\r\\n`, got {scalars[5]!r}; the "
            f"numeric key COUNT argument is what splits KEYS from ARGV")

        # ---- 7. a script that errors part-way does NOT roll back --------------------------
        # Redis scripts are atomic with respect to other clients but are not transactions: a write
        # issued before the error stays.
        half = call([
            ["SET", "sim2real:lua:notanumber", "not-a-number"],
            ["EVAL", _SCRIPT_HALF_FAILS, "3", "sim2real:lua:half:1", "sim2real:lua:notanumber",
             "sim2real:lua:half:3"],
            ["GET", "sim2real:lua:half:1"],
            ["EXISTS", "sim2real:lua:half:3"],
            ["GET", "sim2real:lua:notanumber"],
        ])
        assert _resp_error_name(half[1], source=src, cmd="EVAL (errors mid-script)") == "ERR", (
            f"[{src}] a script whose second redis.call INCRs a non-numeric string must return a "
            f"`-ERR` frame, got {half[1]!r}")
        assert half[2] == _bulk_expected(b"landed-before-the-error"), (
            f"[{src}] the write the script made BEFORE it errored is {half[2]!r}, expected it to "
            f"still hold `landed-before-the-error`. Real Redis does NOT roll a failed script back, "
            f"and this check pins that: a target that discards the earlier write is implementing "
            f"transactions Redis does not have, so code written against it corrupts state on real "
            f"AWS")
        assert half[3] == b":0\r\n", (
            f"[{src}] the write AFTER the error must never have happened: EXISTS returned "
            f"{half[3]!r}, expected `:0`. Execution stops at the failing call")
        assert half[4] == _bulk_expected(b"not-a-number"), (
            f"[{src}] the string the failed INCR targeted was modified: {half[4]!r}")

        # ---- 8. ATOMICITY: no other connection is served while a script runs --------------
        # The window is CALIBRATED rather than assumed, so it is sized to this node's real speed.
        cal = probe.sessions(host, port, [[
            {"sync": 1},
            ["EVAL", "local t = 0\nfor i = 1, " + str(_CALIBRATE_ITERS) + " do t = t + i end\n"
                     "return 1", "0"],
        ]])
        cal_reps = _session_replies(cal, [[None, None]], source=src)
        assert cal_reps[0][1] == b":1\r\n", (
            f"[{src}] the calibration script must return `:1`, got {cal_reps[0][1]!r}; the engine "
            f"is not executing Lua at all")
        cal_t = cal["sessions"][0]["t"]
        cal_ms = max(1.0, (cal_t[1] - cal_t[0]) * 1000.0)
        iters = int(_CALIBRATE_ITERS * (_TARGET_SCRIPT_MS / cal_ms))
        assert iters > 0, f"[{src}] calibration produced a non-positive iteration count {iters}"

        # Both keys are cleared BEFORE the concurrent invoke, never inside session A: with the DEL
        # inside A, session B can observe a state that predates the DEL, which is not a torn read.
        cleared = call([["DEL", _K1, _K2], ["EXISTS", _K1], ["EXISTS", _K2]])
        assert cleared[1] == b":0\r\n" and cleared[2] == b":0\r\n", (
            f"[{src}] the atomicity keys were not cleared before the concurrent window: "
            f"{cleared[1]!r} {cleared[2]!r}")

        writer = [{"sync": 1}, ["EVAL", _SCRIPT_SLOW_PAIR, "2", _K1, _K2, str(iters)]]
        reader = [{"sync": 1}] + [c for _ in range(_POLL_PAIRS)
                                  for c in (["EXISTS", _K1], ["EXISTS", _K2])]
        conc = probe.sessions(host, port, [writer, reader])
        sess = _session_replies(conc, [writer, reader], source=src)

        assert sess[0][1] == _bulk_expected(b"done"), (
            f"[{src}] the slow script must return the bulk string `done`, got {sess[0][1]!r}")
        wt = conc["sessions"][0]["t"]
        rt = conc["sessions"][1]["t"]
        script_s = wt[1] - wt[0]
        assert script_s > 0.05, (
            f"[{src}] the calibrated script ran for only {script_s:.4f}s ({iters} Lua iterations "
            f"calibrated from a {cal_ms:.1f}ms pass over {_CALIBRATE_ITERS}); there is no window in "
            f"which to observe a torn state, so the atomicity assertion below would be vacuous")

        # The torn observation: KEYS[1] present while KEYS[2] is absent. A pair straddling the whole
        # script (absent, present) is NOT torn -- KEYS[2] is written last, so that ordering can only
        # be produced by the two polls landing either side of the entire script.
        pairs = [(sess[1][i], sess[1][i + 1]) for i in range(1, len(sess[1]), 2)]
        torn = [(k, p) for k, p in enumerate(pairs) if p == (b":1\r\n", b":0\r\n")]
        assert len(pairs) == _POLL_PAIRS, (
            f"[{src}] the observing connection made {len(pairs)} of {_POLL_PAIRS} paired "
            f"observations")
        assert not torn, (
            f"[{src}] a SECOND CONNECTION observed {len(torn)} of {len(pairs)} times that "
            f"{_K1!r} was written while {_K2!r} was still absent -- e.g. observation {torn[0][0]}. "
            f"A Redis script runs to completion before any other client is served, so no client may "
            f"ever see a script's intermediate state. Every distributed lock and rate limiter in "
            f"production depends on exactly this")

        # ...and the observer really was held back, which is what makes the absence of a torn read
        # evidence rather than luck: every observation SENT once the EVAL was on the wire (writer's
        # send stamp + one observer round trip + slack) must be answered no earlier than the
        # script's own reply. Without this, a target that ignored the EVAL or served the second
        # connection mid-script would also show no torn pair.
        rtt = min((b - a for a, b in zip(rt[1:], rt[2:], strict=False)), default=0.0)
        sent_after = wt[0] + rtt + _SEND_SLACK_S
        late = [i for i in range(1, len(rt)) if rt[i - 1] >= sent_after]
        assert late, (
            f"[{src}] the observing connection sent none of its {len(rt) - 1} commands after "
            f"{sent_after:.4f}s (script sent at {wt[0]:.4f}s, observer round trip {rtt:.4f}s), so "
            f"no observation overlapped the running script. Observer timeline: {rt!r}")
        early = [i for i in late if rt[i] < wt[1] - _REPLY_SLACK_S]
        assert not early, (
            f"[{src}] {len(early)} observation(s) sent after the script was on the wire were "
            f"answered before the script's reply at {wt[1]:.4f}s -- e.g. command {early[0]} sent "
            f"at {rt[early[0] - 1]:.4f}s, answered at {rt[early[0]]:.4f}s. Another client's command "
            f"must QUEUE behind a running script; answering it mid-script means the engine "
            f"interleaved another client into a script's execution, and its scripts are not "
            f"atomic. Observer timeline: {rt!r}")
        final_pair = call([["GET", _K1], ["EXISTS", _K2]])
        assert final_pair[0] == _bulk_expected(b"first") and final_pair[1] == b":1\r\n", (
            f"[{src}] after the script completed both keys must be present: {final_pair!r}")

        # ---- 9. NEGATIVE ARM B: SCRIPT FLUSH makes a working digest stop working ----------
        flushed = call([
            ["SCRIPT", "FLUSH"],
            ["EVALSHA", want_sha, "2", "sim2real:lua:f1", "sim2real:lua:f2", "a", "b"],
            ["SCRIPT", "EXISTS", want_sha],
            ["EXISTS", "sim2real:lua:f1"],
        ])
        assert flushed[0] == b"+OK\r\n", (
            f"[{src}] SCRIPT FLUSH must return +OK, got {flushed[0]!r}")
        assert _resp_error_name(flushed[1], source=src, cmd="EVALSHA (after FLUSH)") == "NOSCRIPT", (
            f"[{src}] after SCRIPT FLUSH, EVALSHA of the digest that worked moments earlier must be "
            f"refused `-NOSCRIPT`, got {flushed[1]!r}. The script cache is real, mutable server "
            f"state; a target that keeps answering has hardcoded the script rather than cached it")
        assert flushed[2] == b"*1\r\n:0\r\n", (
            f"[{src}] SCRIPT EXISTS after FLUSH must be `*1\\r\\n:0\\r\\n`, got {flushed[2]!r}")
        assert flushed[3] == b":0\r\n", (
            f"[{src}] the refused EVALSHA still wrote its first key: EXISTS returned "
            f"{flushed[3]!r}. This is the effect-absent probe")

        # ---- 10. CONTROL: re-loading the identical body yields the identical digest -------
        control = call([
            ["SCRIPT", "LOAD", _SCRIPT_WRITE_TWO],
            ["EVALSHA", want_sha, "2", "sim2real:lua:c1", "sim2real:lua:c2", "c1v", "c2v"],
            ["GET", "sim2real:lua:c1"],
            ["PING"],
        ])
        assert _resp_bulk(control[0], source=src, cmd="SCRIPT LOAD (control)") == want_sha.encode(), (
            f"[{src}] control: re-loading the identical body must return the identical digest "
            f"{want_sha!r}, got {control[0]!r}; the cache key is the CONTENT")
        assert control[1] == b"*3\r\n:1\r\n$3\r\ntwo\r\n-boom\r\n", (
            f"[{src}] control: after the reload EVALSHA must work again and return the same reply, "
            f"got {control[1]!r}")
        assert control[2] == _bulk_expected(b"c1v"), (
            f"[{src}] control: the reloaded script's write did not land: {control[2]!r}")
        assert control[3] == b"+PONG\r\n", (
            f"[{src}] control: the connection no longer answers PING after every arm: "
            f"{control[3]!r}")
    finally:
        # Inline, verified teardown of the only billable resource: registered cleanups are bounded
        # and never affect the verdict, so a cut-short chain could leak a billing node.
        status = _teardown_cluster_now(ec, cluster_id)
        assert status == "deleting", (
            f"DeleteCacheCluster on {cluster_id} reported CacheClusterStatus={status!r}, not "
            f"'deleting'; a node that does not enter the deleting state keeps billing")
        gone = _poll(lambda: _describe_cluster(ec, cluster_id),
                     lambda c: c is None or c.get("CacheClusterStatus") == "deleting",
                     timeout_s=600, interval_s=15)
        assert gone is None or gone.get("CacheClusterStatus") == "deleting", (
            f"cache cluster {cluster_id} is still {gone.get('CacheClusterStatus')!r} after the "
            f"delete; it is still billing")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
