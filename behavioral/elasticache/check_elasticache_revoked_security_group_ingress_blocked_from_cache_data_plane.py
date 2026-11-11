"""elasticache-revoked-security-group-ingress-blocked-from-cache-data-plane."""
from __future__ import annotations

import base64
import errno
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

CHECK = "elasticache-revoked-security-group-ingress-blocked-from-cache-data-plane"
GROUP = 'overly-permissive'
SERVICES = ['elasticache']

# The in-VPC executor. ElastiCache is VPC-only, so the only client that can reach the data plane is
# inside the cluster's VPC: a Lambda with VpcConfig on the cache's subnets and security group runs a
# stdlib RESP2 probe and returns the raw reply bytes. The check creates and tears down its network.
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
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
# Bounded windows for the VPC to hold no interface before it is deleted: inside the check body,
# after the function and the node are gone, and on the registered-cleanup path.
_NET_DRAIN_S = 1800
_NET_CLEANUP_S = 600


_HANDLER_SRC = r'''"""In-VPC probe executed by AWS Lambda inside the ElastiCache resource's VPC.

The T3 executor. It is deliberately DUMB: it opens sockets, returns raw bytes, and makes **no
assertions**. Every assertion lives in the check, for three reasons:

1. The verdict is the CHECK's. An assertion that fires inside the Lambda reports as
   `FunctionError: Unhandled`, and the interesting bytes are then only in the function's log
   group — i.e. in a place the check never reads.
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

  {"op": "fill", "host", "port", "tls", "key_prefix", "start", "count", "size"}
      -> {"ok": true, "written": <int>, "distinct_replies": {<b64 reply>: <count>}, ...}
         The bulk-write op. It exists because forcing an engine past `maxmemory` needs thousands
         of large writes and returning one raw reply per write would blow the 6 MB Invoke response
         for no gain — so identical replies are TALLIED instead of listed. The raw bytes are still
         the dict KEYS, so `-OOM command not allowed ...` cannot be hidden by the summarisation.

NEVER raises out of `handler`: an exception would surface as `FunctionError` and cost the check the
structured evidence it needs to attribute the failure. Every failure is a return value.

Pure stdlib on purpose. `redis-py` is pure Python and would zip with no layer, but it is not needed
here and importing it would cost more than it buys.
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
import time

_CONNECT_TIMEOUT_S = 10
_IO_TIMEOUT_S = 15
_DNS_TIMEOUT_S = 3


# ---------------------------------------------------------------- network vantage point


def _route_source_ip(host: str, port: int) -> str:
    """The source address the kernel WOULD use to reach ``host:port``.

    `connect()` on a UDP socket sends no packets — it only performs a route lookup and binds the
    local end — so this is free and cannot be satisfied by anything listening at the far end.
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
    Non-matching datagrams are SKIPPED rather than fatal, until the deadline: on an unconnected
    socket a stray or duplicated datagram arriving first would otherwise discard the legitimate
    reply behind it and report "not in the VPC" for a network that is in fact attached.
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


# ---------------------------------------------------------------- RESP2, framed by hand


def _resp_encode(*args) -> bytes:
    """Encode one command as a RESP2 array of bulk strings."""
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
    """A minimal RESP2 connection: send one command, return the RAW reply bytes.

    Raw bytes on purpose — the semantics live in the framing (`+OK\\r\\n` vs `$-1\\r\\n` vs
    `$0\\r\\n\\r\\n` vs `:-2\\r\\n`), and any client library normalises all of those into
    `None` / `''` / `-2` and hides the single most consequential Redis emulation bug, which is
    conflating "key absent" with "key present and empty".
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

    def call(self, *args) -> tuple[bytes, bool]:
        """Send one command; return ``(raw_reply_bytes, framing_understood)``.

        ``framing_understood`` is False for a reply type this codec does not frame (an array, or a
        byte that is not a RESP type at all). The bytes read so far are still returned — never
        discarded and never raised — because those bytes ARE the finding, and the check's assertion
        prints them. The caller must stop issuing commands after a False, since the stream is now
        desynchronised.
        """
        self.sock.sendall(_resp_encode(*args))
        first = self._line()
        kind = first[:1]
        if kind in (b"+", b"-", b":"):
            return first, True
        if kind == b"$":
            try:
                length = int(first[1:-2])
            except ValueError:
                return first, False
            if length < 0:
                return first, True
            return first + self._exact(length + 2), True
        return first, False


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
    """``(src_ip, src_ip_error)`` — free route lookup, no packets, purely for evidence."""
    try:
        return _route_source_ip(ip, port), None
    except OSError as exc:
        return None, f"{type(exc).__name__}: errno={exc.errno} {exc}"


def _resp_batch(host, port, commands, tls=False) -> dict:
    """Run ``commands`` in order against ``host:port``; return raw replies, base64'd.

    Every command ARGUMENT arrives base64-encoded and every reply leaves base64-encoded, in both
    directions, because the event travels as JSON and a Redis value is arbitrary BYTES. A value
    holding a CRLF — the sequence RESP2 uses as its own frame delimiter, and therefore the sharpest
    available test of length-prefixed framing — cannot be carried by a JSON string without the
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
        "src_ip": src_ip,
        "src_ip_error": src_err,
        "tls_mode": tls_mode,
        "tls_error": tls_err,
        "replies": replies,
    }


def _fill(host, port, key_prefix, start, count, size, tls=False) -> dict:
    """SET ``count`` keys of ``size`` bytes each, tallying DISTINCT raw replies.

    The value is generated here rather than shipped in the event, so a 100 MB write costs a 200-byte
    request. Identical replies are tallied by their RAW BYTES, so an `-OOM` or `-MISCONF` error
    reply is still visible as its own key — the summarisation cannot turn a refusal into
    "written: N".
    """
    ip, err = _resolve(host)
    if err is not None:
        return err
    try:
        sock, tls_mode, tls_err = _open(ip if not tls else host, port, tls)
        conn = _Resp(sock)
    except (OSError, socket.timeout) as exc:
        return {
            "ok": False,
            "stage": "connect",
            "error": f"{type(exc).__name__}: {exc}",
            "written": 0,
            "distinct_replies": {},
        }
    payload = b"v" * int(size)
    tally: dict = {}
    written, io_error = 0, None
    try:
        for i in range(int(start), int(start) + int(count)):
            raw, understood = conn.call(b"SET", f"{key_prefix}{i}".encode(), payload)
            k = base64.b64encode(raw).decode()
            tally[k] = tally.get(k, 0) + 1
            written += 1
            if not understood:
                break
    except (OSError, socket.timeout, ConnectionError) as exc:
        io_error = f"{type(exc).__name__}: {exc}"
    finally:
        conn.close()
    return {
        "ok": io_error is None,
        "stage": "complete" if io_error is None else "io",
        "error": io_error,
        "tls_mode": tls_mode,
        "tls_error": tls_err,
        "first": int(start),
        "written": written,
        "distinct_replies": tally,
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
        except Exception as exc:  # noqa: BLE001 — every failure is a return value, never a raise
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


def handler(event, context):  # noqa: ARG001 — Lambda signature
    op = (event or {}).get("op")
    try:
        if op == "selftest":
            return _selftest(event)
        if op == "resp":
            return _resp_batch(event["host"], event["port"], event["commands"],
                               tls=bool(event.get("tls")))
        if op == "fill":
            return _fill(event["host"], event["port"], event["key_prefix"], event["start"],
                         event["count"], event["size"], tls=bool(event.get("tls")))
        return {"ok": False, "stage": "dispatch", "error": f"unknown op {op!r}"}
    except Exception as exc:  # noqa: BLE001 — see the module docstring: never raise
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

    The runner and the in-VPC Lambda then drive the same `_resp_batch` source, so a disagreement
    between them is about the network, never the client.
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


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
    except Exception:  # noqa: BLE001 — no paginator modeled; fall back to one call
        return getattr(client, op)(**kwargs).get(key, [])
    out = []
    for page in pager.paginate(**kwargs):
        out.extend(page.get(key, []))
    return out


# ---- the run's own executor network ---------------------------------------------------------

# A conflict on the deterministic subnet CIDR, as opposed to a real failure.
_SUBNET_RACE_LOST = frozenset({"InvalidSubnet.Conflict", "InvalidSubnetRange.Conflict"})


def _has_self_ingress(ec2, sg_id: str, port: int = _REDIS_PORT) -> bool:
    """Does sg_id already admit ``port`` FROM ITSELF?

    Matched on the group pair, not a CIDR: the self-reference proves packets came from our ENI.
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


def _ensure_self_ingress(ec2, sg_id: str) -> None:
    """Authorize the self-referencing Redis-port rule on sg_id unless it is already there.

    Read back after authorizing: the in-VPC control step proves attachment over the DNS resolver on
    port 53 and does not touch 6379, so a missing rule would otherwise surface as
    DATAPLANE_UNIMPLEMENTED for a defect of our own infrastructure.
    """
    if _has_self_ingress(ec2, sg_id):
        return
    try:
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": _REDIS_PORT,
                "ToPort": _REDIS_PORT,
                "UserIdGroupPairs": [{
                    "GroupId": sg_id,
                    "Description": "in-VPC executor to cache node, same security group only",
                }],
            }],
        )
    except ClientError as exc:
        # The rule is already there: that is the rule we wanted.
        if _code_of(exc) != "InvalidPermission.Duplicate":
            raise
    assert _has_self_ingress(ec2, sg_id), (
        f"{sg_id} still does not admit tcp/{_REDIS_PORT} from itself after authorizing; the round "
        f"trip below could not distinguish this from a broken data plane"
    )


def _dns_attributes_ok(ec2, vpc_id: str) -> bool:
    """Are BOTH VPC DNS attributes already on?

    Read before write, so a VPC that is already correct is not modified.
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
    hand-created VPC, so leaving it off would silently cost the control step.
    """
    if _dns_attributes_ok(ec2, vpc_id):
        return
    for attr in ("EnableDnsSupport", "EnableDnsHostnames"):
        ec2.modify_vpc_attribute(VpcId=vpc_id, **{attr: {"Value": True}})


def _network_subnets(ec2, vpc_id: str, want: int = 2) -> list[str]:
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
    """Build this run's executor VPC with one subnet per zone, teardown registered. -> VpcId.

    `_teardown_network` deletes the VPC, its subnets and groups once it holds no interface.
    """
    # A randomized second octet makes the "source address is inside our VPC" signal sharp.
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


def _executor_network(ctx, ec2) -> dict:
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
    _ensure_self_ingress(ec2, sg_id)

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
    ctx.on_cleanup(lambda n=name: _delete_cache_subnet_group(ec, n))
    return name


def _delete_cache_subnet_group(ec, name: str, timeout_s: float = 300, interval_s: float = 20,
                               ctx=None):
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
                if code == "CacheSubnetGroupInUse" and ctx is not None and _budget_spent(ctx):
                    raise TimeoutError(f"cache subnet group {name} being released: the run "
                                       f"budget ended first; not graded") from exc
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
    """The whole deployment package: one file, no dependency, no layer. The probe needs a RESP2
    framer, a DNS framer, a TLS wrap and a route lookup, all of which are stdlib."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, src)
    return buf.getvalue()


def _deploy_executor(ctx, lam, net: dict, role_arn: str) -> tuple[str, dict]:
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
        # The `fill` op drives thousands of 64 KiB writes in one invoke; a runtime timeout would
        # surface as FunctionError for a measurement that was merely long.
        Timeout=300,
        VpcConfig={"SubnetIds": net["subnet_ids"], "SecurityGroupIds": [net["sg_id"]]},
        Tags={t["Key"]: t["Value"] for t in _MANAGED_TAGS},
    )
    deadline = time.monotonic() + _budget_s(ctx, 120)
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            msg = _msg_of(exc)
            transient = _code_of(exc) == "InvalidParameterValue" and any(
                s in msg for s in _ROLE_NOT_READY)
            if not transient or time.monotonic() >= deadline:
                if transient and _budget_spent(ctx):
                    raise TimeoutError("CreateFunction waiting for the execution role to be "
                                       "assumable: the run budget ended first; not graded") from exc
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
    """Delete the function and its log group, raising on anything but the resource already being
    gone. Returns immediately — Lambda releases the Hyperplane ENI asynchronously, and
    `_teardown_network` waits for it."""
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
    a failure — the handler never raises, so anything arriving here is the executor being unusable
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


def _prove_executor_in_vpc(ctx, lam, fn: str, net: dict) -> tuple[dict, bool, str]:
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


def _bring_up_executor(ctx) -> tuple[object, dict, str, bool, str]:
    """Everything up to and including the control step. -> (lam, net, fn, in_vpc, why).

    Ordered so nothing billable exists yet: the network and the function are free, and the cache
    resource is created by the caller only after this returns. A target that cannot run the probe is
    therefore never billed for a cache.
    """
    ec2 = ctx.client("ec2")
    lam = ctx.client("lambda")
    net = _executor_network(ctx, ec2)
    role_arn = _vpc_exec_role_arn(ctx)
    fn, cfg_vpc = _deploy_executor(ctx, lam, net, role_arn)
    # Round-tripping VpcConfig is necessary but nowhere near sufficient — echoing a field back is
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
                         "commands": [[base64.b64encode(_as_bytes(a)).decode() for a in c]
                                      for c in commands]})

    def fill(self, host, port, key_prefix, start, count, size, tls=False) -> dict:
        return self._fn({"op": "fill", "host": host, "port": int(port), "key_prefix": key_prefix,
                         "start": int(start), "count": int(count), "size": int(size),
                         "tls": bool(tls)})


def _dispatch_local(event: dict) -> dict:
    ns = _local_client()
    if event["op"] == "fill":
        return ns["_fill"](event["host"], event["port"], event["key_prefix"], event["start"],
                           event["count"], event["size"], tls=event.get("tls", False))
    return ns["_resp_batch"](event["host"], event["port"], event["commands"],
                             tls=event.get("tls", False))


def _pick_prober(ctx, lam, fn: str, host, port, *, in_vpc: bool, why: str, tls: bool,
                 subject: str) -> _Prober:
    """The vantage point that can actually reach ``host:port``, or the verdict that none can.

    Polled to a bounded deadline: a cache can report 'available' before its endpoint connects. The
    runner-side arm, for a target with no VPC isolation, is retried only while its connect is
    refused.
    """
    runner = _Prober("runner-outside-vpc", _dispatch_local)
    lamprobe = (_Prober("lambda-in-vpc", lambda ev: _invoke(ctx, lam, fn, ev))
                if in_vpc else None)
    budget = _budget_s(ctx, 300)
    deadline = time.monotonic() + budget
    outside, invpc, attempts = None, None, 0
    runner_retry = True
    while True:
        attempts += 1
        if runner_retry or lamprobe is None:
            outside = runner.resp(host, port, [["PING"]], tls=tls)
            if outside.get("ok"):
                return runner
            runner_retry = outside.get("errno") == errno.ECONNREFUSED
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


def _replies(result: dict, commands, *, source: str) -> list[bytes]:
    """The raw reply bytes for ``commands``, asserting one reply per command.

    The probe stops at the first reply type RESP2 does not define, so a short list means the
    endpoint answered with something that is not a RESP reply — a finding, and the raw bytes are
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


def _resp_int(raw: bytes, *, source: str, cmd: str) -> int:
    """The integer in a RESP2 ``:<n>\\r\\n`` reply; a non-numeric payload fails as an assertion."""
    assert raw.startswith(b":") and raw.endswith(b"\r\n"), (
        f"[{source}] {cmd} must return a RESP integer reply (:<n>\\r\\n), got {raw!r}")
    try:
        return int(raw[1:-2])
    except ValueError:
        raise AssertionError(
            f"[{source}] {cmd} framed an integer reply but its payload is not an integer: {raw!r}. "
            f"A client's int conversion would raise on this") from None


def _resp_bulk(raw: bytes, *, source: str, cmd: str) -> bytes:
    """The payload of a RESP2 bulk-string reply. ``$-1\\r\\n`` (absent) is a distinct answer and is
    rejected here rather than collapsed to b"" — conflating absence with emptiness is the single
    most consequential Redis emulation bug."""
    assert raw.startswith(b"$"), (
        f"[{source}] {cmd} must return a RESP bulk string ($<len>\\r\\n<bytes>\\r\\n), got {raw!r}")
    head, _, rest = raw[1:].partition(b"\r\n")
    length = int(head)
    assert length >= 0, (
        f"[{source}] {cmd} returned the NULL bulk string {raw!r}, i.e. the key is ABSENT; there is "
        f"no payload to read")
    assert len(rest) == length + 2, (
        f"[{source}] {cmd} declared a {length}-byte bulk string but framed {len(rest) - 2} bytes: "
        f"{raw!r}")
    return rest[:-2]


def _bulk_expected(value: bytes) -> bytes:
    """The exact RESP2 bulk-string reply a faithful GET of ``value`` must produce, byte for byte."""
    return b"$%d\r\n%s\r\n" % (len(value), value)


def _resp_error_name(raw: bytes, *, source: str, cmd: str) -> str:
    """The error NAME out of a RESP2 error frame ``-NAME free text\\r\\n``, as an exact token.

    The message text is not part of the contract; the name is compared exactly, not by prefix.
    """
    assert raw.startswith(b"-") and raw.endswith(b"\r\n"), (
        f"[{source}] {cmd} was expected to be refused with a RESP error frame "
        f"(-NAME message\\r\\n), got {raw!r}")
    return raw[1:-2].split(b" ", 1)[0].decode("ascii", "replace")


def _info_field(raw: bytes, field: str, *, source: str) -> int:
    """One integer field out of an INFO bulk string, asserting it is actually present.

    INFO is CRLF-separated ``key:value`` lines inside one bulk string. Parsed structurally on the
    line rather than by a substring search, so `evicted_keys` cannot be satisfied by
    `keyspace_evicted_keys` or by the word appearing in a comment line.
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
    because a value like ``maxmemory_policy:allkeys-lru`` is not an integer and coercing it would
    hide the very value under test."""
    body = _resp_bulk(raw, source=source, cmd="INFO")
    for line in body.split(b"\r\n"):
        if line.startswith(b"#") or b":" not in line:
            continue
        name, _, val = line.partition(b":")
        if name == field.encode():
            return val.decode("ascii", "replace")
    raise AssertionError(
        f"[{source}] INFO does not report a {field!r} line at all. Body was {body[:1500]!r}")


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


def _cluster_endpoint(ctx, ec, cluster_id: str):
    """``(Address, Port)`` for the single cache node, or ``_NODE_INFO_TIMEOUT``.

    A timeout is provisioning latency, distinct from an available cluster with an empty endpoint.
    """
    node = _poll(lambda: _describe_cluster(ec, cluster_id, ShowCacheNodeInfo=True),
                 lambda c: bool((c or {}).get("CacheNodes")),
                 timeout_s=_budget_s(ctx, 300), interval_s=2)
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


def _resolved_endpoint(ctx, ec, cluster_id: str) -> tuple[str, int]:
    endpoint = _cluster_endpoint(ctx, ec, cluster_id)
    if endpoint is _NODE_INFO_TIMEOUT:
        if _budget_spent(ctx):
            raise TimeoutError(f"cache cluster {cluster_id} populating CacheNodes: the run budget "
                               f"ended first; not graded")
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
    """Get the billable node deleting. Idempotent, and retried through the `creating` state.

    A node already `deleting` returns at once: InvalidCacheClusterState covers both states.
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


def _wait_cluster_gone(ec, cluster_id: str, timeout_s: float = 1200, interval_s: float = 15,
                       ctx=None):
    """Poll until DescribeCacheClusters no longer finds the node. Raises on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        current = _describe_cluster(ec, cluster_id)
        if current is None:
            return
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"cache cluster {cluster_id} leaving DescribeCacheClusters: the "
                                   f"run budget ended first; not graded")
            raise AssertionError(
                f"cache cluster {cluster_id} is still listed {timeout_s}s after DeleteCacheCluster, "
                f"status {current.get('CacheClusterStatus')!r}")
        time.sleep(interval_s)


def _teardown_network(ec2, vpc_id: str, *, timeout_s: float, interval_s: float = 15, ctx=None):
    """Delete every non-default security group, every subnet and then the VPC itself.

    Waits, bounded, until the VPC holds no network interface: the Lambda's Hyperplane ENI and the
    cache node's ENI are released asynchronously after their owners are deleted, and until then
    every delete here answers DependencyViolation. Idempotent: a VPC already gone returns at once.
    Raises an AssertionError naming what still holds the VPC when the window closes.
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
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"VPC {vpc_id} being deleted: the run budget ended first; "
                                   f"not graded")
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


def _wait_rg_available(ctx, ec, rg_id: str) -> dict:
    got = _poll(lambda: _describe_rg(ec, rg_id),
                lambda g: g is not None and g.get("Status") == "available",
                timeout_s=_budget_s(ctx, 1500),
                interval_s=2)
    if got is None:
        if _budget_spent(ctx):
            raise TimeoutError(f"replication group {rg_id} reaching 'available': the run budget "
                               f"ended first; not graded")
        raise _never_ready(
            f"replication group {rg_id} did not reach 'available' within the bounded wait")
    return got


def _delete_rg(ec, rg_id: str, timeout_s: float = 900):
    """See `_delete_cluster`: the status is read first so a group the check body already put into
    `deleting` is not retried for the full timeout."""
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
    """Delete the replication group INSIDE the check and return the reported status — see
    _teardown_cluster_now for why the assertable form matters."""
    return ec.delete_replication_group(
        ReplicationGroupId=rg_id, RetainPrimaryCluster=False)["ReplicationGroup"]["Status"]


_VALUE = b"reachable\r\nvalue"
_DENIED_VALUE = b"written-through-a-revoked-rule"
# Both budgets are bounded polls on an OBSERVABLE condition (the connection failing, then working
# again), never a sleep sized to make something pass. A security-group change takes effect on new
# connections within seconds; these are generous ceilings, and nothing below asserts how long it took.
_BLOCK_BUDGET_S = 240
_RESTORE_BUDGET_S = 240
_READY_BUDGET_S = 180


def _cache_ingress_permission(from_sg: str) -> dict:
    """The ONE ingress rule this check turns on and off: a group pair, never a CIDR, so a
    successful connect proves the packets came from the ENI we attached."""
    return {
        "IpProtocol": "tcp",
        "FromPort": _REDIS_PORT,
        "ToPort": _REDIS_PORT,
        "UserIdGroupPairs": [{"GroupId": from_sg,
                              "Description": "sim2real in-VPC executor to cache node"}],
    }


def _admits_from(ec2, sg_id: str, from_sg: str, port: int) -> bool:
    """Does ``sg_id`` admit ``port`` from members of ``from_sg``? Read back structurally over every
    permission rather than trusting the Authorize/Revoke response, because the response is a
    statement about the request and this is a statement about the group."""
    groups = _paginate(ec2, "describe_security_groups", "SecurityGroups", GroupIds=[sg_id])
    for perm in (groups[0].get("IpPermissions", []) if groups else []):
        if perm.get("IpProtocol") != "tcp":
            continue
        lo, hi = perm.get("FromPort"), perm.get("ToPort")
        if lo is None or hi is None or not (lo <= port <= hi):
            continue
        if any(p.get("GroupId") == from_sg for p in perm.get("UserIdGroupPairs", [])):
            return True
    return False


def _delete_sg_when_free(ec2, sg_id: str, timeout_s: float = 420, interval_s: float = 20):
    """Bounded, idempotent teardown of the dedicated group. DependencyViolation persists while the
    cache node's interface references it, so it is registered FIRST (deleted LAST) and gives up
    rather than block past the deadline; the group is free and tagged. Any other failure raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            _delete_net(ec2, "delete_security_group", GroupId=sg_id)
            return
        except ClientError as exc:
            if _code_of(exc) in ("InvalidGroup.NotFound", "InvalidGroupId.NotFound"):
                return
            if _code_of(exc) != "DependencyViolation":
                raise
            if time.monotonic() >= deadline:
                return  # left to tag-based cleanup (a free resource); never mask a real verdict
        time.sleep(interval_s)


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:native", "plane:data")
def run(ctx) -> None:
    """Revoking the one security-group rule that admits the Redis port stops connections to a
    running cache node at the connect stage, a write attempted meanwhile leaves no key, and
    re-authorizing the same rule restores the connection and the earlier data.

    Reference: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html
    """
    ec = ctx.client("elasticache")
    ec2 = ctx.client("ec2")
    lam, net, fn, in_vpc, why = _bring_up_executor(ctx)
    subnet_group = _ensure_cache_subnet_group(ctx, ec, net)

    # ---- the dedicated group: this check's own gate, so nothing shared is ever revoked --------
    cache_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-ecsg-"),
        Description="sim2real cache node gate: one revocable rule from the in-VPC executor",
        VpcId=net["vpc_id"],
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _RESOURCE_TAGS}],
    )["GroupId"]
    ctx.on_cleanup(lambda g=cache_sg: _delete_sg_when_free(ec2, g))

    permission = _cache_ingress_permission(net["sg_id"])
    ec2.authorize_security_group_ingress(GroupId=cache_sg, IpPermissions=[permission])
    assert _admits_from(ec2, cache_sg, net["sg_id"], _REDIS_PORT), (
        f"{cache_sg} does not admit tcp/{_REDIS_PORT} from {net['sg_id']} after authorizing it; the "
        f"round trip below could not distinguish this from a broken data plane")

    cluster_id = ctx.unique_name("sim2real-behav-ecsgb-")
    try:
        created = ec.create_cache_cluster(
            CacheClusterId=cluster_id,
            Engine="redis",
            CacheNodeType=_NODE_TYPE,
            NumCacheNodes=1,
            Port=_REDIS_PORT,
            CacheSubnetGroupName=subnet_group,
            SecurityGroupIds=[cache_sg],
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

    cluster = _wait_cluster_available(ctx, ec, cluster_id)
    assert cache_sg in [g["SecurityGroupId"] for g in cluster.get("SecurityGroups") or []], (
        f"the available cluster reports security groups {cluster.get('SecurityGroups')!r}, not the "
        f"{cache_sg!r} it was created with; the rule this check revokes would not be its only gate")
    host, port = _resolved_endpoint(ctx, ec, cluster_id)
    probe = _pick_prober(ctx, lam, fn, host, port, in_vpc=in_vpc, why=why, tls=False,
                         subject=f"cache cluster {cluster_id}")
    src = probe.label

    key = f"sim2real:reach:{cluster_id}"
    denied_key = f"sim2real:blocked:{cluster_id}"

    # ---- 1. THE BARRIER: the positive path must WORK before anything is broken ----------------
    ready_cmds = [["PING"], ["SET", key, _VALUE], ["GET", key]]
    ready_budget = _budget_s(ctx, _READY_BUDGET_S)
    deadline = time.monotonic() + ready_budget
    ready, attempts = None, 0
    while True:
        attempts += 1
        ready = probe.resp(host, port, ready_cmds)
        if ready.get("ok"):
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(2)
    if not ready.get("ok") and _budget_spent(ctx):
        raise TimeoutError(f"[{src}] the authorized RESP path answering: the run budget ended "
                           f"first; not graded")
    ready_raws = _replies(ready, ready_cmds, source=src)
    assert ready_raws[0] == b"+PONG\r\n", (
        f"[{src}] PING through the authorized rule must return +PONG, got {ready_raws[0]!r} after "
        f"{attempts} attempts over {ready_budget:.0f}s")
    assert ready_raws[1] == b"+OK\r\n", (
        f"[{src}] SET through the authorized rule must return +OK, got {ready_raws[1]!r}")
    assert ready_raws[2] == _bulk_expected(_VALUE), (
        f"[{src}] GET through the authorized rule must return the value byte for byte, including the "
        f"embedded CRLF: expected {_bulk_expected(_VALUE)!r}, got {ready_raws[2]!r}")

    # ---- 2. break EXACTLY one thing: revoke that single rule ----------------------------------
    revoked = ec2.revoke_security_group_ingress(GroupId=cache_sg, IpPermissions=[permission])
    assert revoked.get("Return") is True, (
        f"RevokeSecurityGroupIngress on {cache_sg} returned Return={revoked.get('Return')!r}: "
        f"{revoked!r}")
    assert not revoked.get("UnknownIpPermissions"), (
        f"RevokeSecurityGroupIngress reports it did not recognise the rule it was asked to remove: "
        f"{revoked.get('UnknownIpPermissions')!r}. The rule this check authorized and the rule it "
        f"revoked must be the same one")
    assert not _admits_from(ec2, cache_sg, net["sg_id"], _REDIS_PORT), (
        f"{cache_sg} still admits tcp/{_REDIS_PORT} from {net['sg_id']} after the revoke was "
        f"accepted; DescribeSecurityGroups is the arbiter here, not the Revoke response")

    # ---- 3a. the refusal, established with a command that WRITES NOTHING ----------------------
    # PING first: a revoke is not instantaneous, so a write attempted right after it can still land
    # and would fail the effect-absent leg for propagation rather than enforcement.
    ping_cmds = [["PING"]]
    block_budget = _budget_s(ctx, _BLOCK_BUDGET_S)
    deadline = time.monotonic() + block_budget
    dropped, tries = None, 0
    while True:
        tries += 1
        dropped = probe.resp(host, port, ping_cmds)
        if not dropped.get("ok") or time.monotonic() >= deadline:
            break
        time.sleep(2)

    if dropped.get("ok") and _budget_spent(ctx):
        raise TimeoutError(f"[{src}] the revoked rule taking effect on {host}:{port}: the run "
                           f"budget ended first; not graded")
    assert dropped.get("ok") is False, (
        f"[{src}] {block_budget:.0f}s and {tries} attempts after the ONLY rule admitting "
        f"tcp/{_REDIS_PORT} to {cluster_id} was revoked, the endpoint {host}:{port} still accepts a "
        f"RESP connection and answered {dropped!r}. The security group is being stored and not "
        f"enforced, which means every cache node in this target is reachable by anything in its VPC")
    assert dropped.get("stage") == "connect", (
        f"[{src}] the blocked attempt failed at stage {dropped.get('stage')!r}, expected 'connect'. "
        f"A withdrawn security-group rule drops the packet, so the TCP connection must be what "
        f"fails: 'resolve' would mean the endpoint's DNS name stopped resolving and 'io' would mean "
        f"the connection was established and then broke — different findings, neither of them this "
        f"one. Full probe result: {dropped!r}")

    # ---- 3b. NOW attempt the write, with the drop already established ------------------------
    # A success here cannot be propagation latency, because the PING above already proved the packets
    # are being dropped. So it is unambiguously the block being cosmetic, and the key it would leave
    # behind is what the effect-absent leg reads for.
    blocked_cmds = [["SET", denied_key, _DENIED_VALUE]]
    blocked = probe.resp(host, port, blocked_cmds)
    assert blocked.get("ok") is False, (
        f"[{src}] a SET issued AFTER the drop was already proven (PING failed at the connect stage) "
        f"reached {host}:{port} and answered {blocked!r}. Writes are getting through a security group "
        f"that is dropping reads")
    assert blocked.get("stage") == "connect", (
        f"[{src}] the blocked SET failed at stage {blocked.get('stage')!r}, expected 'connect': "
        f"{blocked!r}")

    # ---- 4. restore the identical rule and wait for the connection to come back ---------------
    ec2.authorize_security_group_ingress(GroupId=cache_sg, IpPermissions=[permission])
    assert _admits_from(ec2, cache_sg, net["sg_id"], _REDIS_PORT), (
        f"{cache_sg} does not admit tcp/{_REDIS_PORT} from {net['sg_id']} after re-authorizing it")

    restore_cmds = [["GET", denied_key], ["EXISTS", denied_key], ["GET", key], ["DBSIZE"],
                    ["SET", f"{key}:again", _VALUE], ["GET", f"{key}:again"]]
    deadline = time.monotonic() + _budget_s(ctx, _RESTORE_BUDGET_S)
    restored, retries = None, 0
    while True:
        retries += 1
        restored = probe.resp(host, port, restore_cmds)
        if restored.get("ok") or time.monotonic() >= deadline:
            break
        time.sleep(2)
    if not restored.get("ok") and _budget_spent(ctx):
        raise TimeoutError(f"[{src}] the restored rule readmitting {host}:{port}: the run budget "
                           f"ended first; not graded")
    after = _replies(restored, restore_cmds, source=src)

    # ---- 5. the effect is ABSENT, and the control still works ---------------------------------
    assert after[0] == b"$-1\r\n", (
        f"[{src}] effect not absent: the key the SET attempted through the REVOKED rule reads back "
        f"as {after[0]!r}, expected the null bulk string $-1. The packet was dropped at the network "
        f"layer, so the command cannot have reached the engine — a value here means the block was "
        f"cosmetic")
    assert after[1] == b":0\r\n", (
        f"[{src}] effect not absent: EXISTS on {denied_key!r} returns {after[1]!r}, expected 0")
    assert after[2] == _bulk_expected(_VALUE), (
        f"[{src}] positive control: the key written BEFORE the revoke must still hold its exact "
        f"bytes, expected {_bulk_expected(_VALUE)!r}, got {after[2]!r} after {retries} attempts. "
        f"Withdrawing an ingress rule must not disturb the data plane's contents")
    assert _resp_int(after[3], source=src, cmd="DBSIZE") == 1, (
        f"[{src}] at the moment the rule was restored the keyspace must hold exactly the one key "
        f"written before the revoke; DBSIZE returned {after[3]!r}")
    assert after[4] == b"+OK\r\n", (
        f"[{src}] positive control: a fresh SET through the restored rule must return +OK, got "
        f"{after[4]!r}")
    assert after[5] == _bulk_expected(_VALUE), (
        f"[{src}] positive control: the fresh key must read back byte for byte, expected "
        f"{_bulk_expected(_VALUE)!r}, got {after[5]!r} — so the security-group rule is the only "
        f"thing that separated the refusal from the success")

    # ---- 6. teardown inside the check, in dependency order, so every wait is bounded here -----
    _delete_function(ctx, lam, fn)
    status = _teardown_cluster_now(ec, cluster_id)
    assert status == "deleting", (
        f"DeleteCacheCluster on {cluster_id} reported CacheClusterStatus={status!r}, not "
        f"'deleting'; a node that does not enter the deleting state keeps billing")
    _wait_cluster_gone(ec, cluster_id, timeout_s=_budget_s(ctx, 1200), interval_s=2, ctx=ctx)
    _delete_cache_subnet_group(ec, subnet_group, timeout_s=_budget_s(ctx, 300),
                               interval_s=2, ctx=ctx)
    _teardown_network(ec2, net["vpc_id"], timeout_s=_budget_s(ctx, _NET_DRAIN_S),
                      interval_s=2, ctx=ctx)


# Network deletes wait (bounded) for AWS-managed ENIs to leave and retry DependencyViolation:
# dependents delete asynchronously, and a swallowed DependencyViolation leaks the VPC.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
