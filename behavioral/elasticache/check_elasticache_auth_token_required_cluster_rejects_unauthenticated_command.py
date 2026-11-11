"""elasticache-auth-token-required-cluster-rejects-unauthenticated-command."""
from __future__ import annotations

import base64
import errno
import hashlib
import io
import ipaddress
import json
import secrets
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "elasticache-auth-token-required-cluster-rejects-unauthenticated-command"
GROUP = 'overly-permissive'
SERVICES = ['elasticache']

# ElastiCache endpoints are VPC-only, so the data plane is reached by a Lambda with VpcConfig on
# the cache's subnets and security group, running a stdlib RESP2 probe that returns raw reply bytes.
# Lambda leaves a Hyperplane ENI in the group after the function is deleted, so the function is
# deleted as soon as its last command has run and the group's teardown waits for the interfaces.

# Tags on the billable resource, so a leftover can be attributed to this check.
_RESOURCE_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    {"Key": "sim2real", "Value": CHECK},
]

# Adds the EC2 network-interface actions; without them CreateFunction with VpcConfig is
# rejected synchronously, so AWSLambdaBasicExecutionRole alone is not enough.
_VPC_ACCESS_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"

# Prefix for a native data-plane failure. The message carries errno text such as
# `Connection refused`, which would otherwise read as an environment error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_REDIS_PORT = 6379
_NODE_TYPE = "cache.t3.micro"


_HANDLER_SRC = r'''"""In-VPC probe executed by AWS Lambda inside the ElastiCache resource's VPC.

The T3 executor. It is deliberately DUMB: it opens sockets, returns raw bytes, and makes **no
assertions**. Every assertion lives in the check, for three reasons:

1. The check's own assertions decide the result. An assertion that fires inside the Lambda reports as
   `FunctionError: Unhandled`, and the interesting bytes are then only in the function's log
   group, which the check never reads.
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
    reply is still visible as its own key — the summarisation cannot launder a refusal into
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
    """Compile _HANDLER_SRC in this process and return its namespace, so the runner-side and
    in-VPC probes share one RESP2 codec."""
    if not _LOCAL_NS:
        exec(compile(_HANDLER_SRC, "<invpc-handler>", "exec"), _LOCAL_NS)  # noqa: S102
    return _LOCAL_NS


def _dp_fail(msg: str) -> AssertionError:
    """A native data-plane fidelity failure, returned so callers keep `from exc`."""
    return AssertionError(f"{DATAPLANE_MARKER}: {msg}")


def _no_executor(msg: str):
    """The in-VPC Lambda executor is unusable, so the cache data plane was not measured.
    Not marked as a data-plane failure: Lambda is only the instrument here."""
    return AssertionError(f"the in-VPC executor is unusable, so this run measured nothing: {msg}")


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
    """The exact error code ``fn()`` raised; raises AssertionError when the call succeeds."""
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
    """Poll `probe` until `predicate`; return the last observation, or None on timeout so the
    caller decides the verdict."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            return None
        time.sleep(interval_s)


def _paginate(client, op: str, key: str, **kwargs):
    """Every page of `op`, flattened on `key`, so our resource is not missed behind other resources
    in the account."""
    try:
        pager = client.get_paginator(op)
    except Exception:  # noqa: BLE001 — no paginator modeled; fall back to one call
        return getattr(client, op)(**kwargs).get(key, [])
    out = []
    for page in pager.paginate(**kwargs):
        out.extend(page.get(key, []))
    return out


#: How long the executor group's teardown waits for Lambda to release the function's interfaces.
_ENI_WAIT_S = 1620


def _executor_network(ctx, ec2) -> dict:
    """The run's shared network, two subnets in two zones, and a security group of this run's own
    admitting tcp/6379 from itself only. Two zones let ElastiCache pick one with capacity; the
    self-referencing rule proves the packets came from an ENI this run attached."""
    shared = ctx.network()
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-invpc-sg-"),
        Description="sim2real in-VPC executor: Lambda ENI + ElastiCache node, self-referencing",
        VpcId=shared.vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _RESOURCE_TAGS}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_executor_group(ec2, sg_id))
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
    return {
        "vpc_id": shared.vpc_id,
        "cidr": shared.cidr,
        "resolver": str(ipaddress.ip_network(shared.cidr).network_address + 2),
        "subnet_ids": shared.subnet_ids[:2],
        "sg_id": sg_id,
    }


def _delete_executor_group(ec2, sg_id: str) -> None:
    """Delete the executor group once no interface holds it; an available interface Lambda has not
    reaped yet is deleted here, and one that refuses the delete is waited for. A deadline miss
    raises, naming the interfaces still there and the refused deletes."""
    deadline = time.monotonic() + _ENI_WAIT_S
    refused: dict = {}
    while True:
        enis = _paginate(ec2, "describe_network_interfaces", "NetworkInterfaces",
                         Filters=[{"Name": "group-id", "Values": [sg_id]}])
        for eni in enis:
            if eni["Status"] == "available":
                try:
                    ec2.delete_network_interface(NetworkInterfaceId=eni["NetworkInterfaceId"])
                except ClientError as exc:
                    if _code_of(exc) == "InvalidNetworkInterfaceID.NotFound":
                        continue
                    if _code_of(exc) != "InvalidNetworkInterface.InUse":
                        raise
                    refused[eni["NetworkInterfaceId"]] = _code_of(exc)
        if not enis:
            try:
                ec2.delete_security_group(GroupId=sg_id)
                return
            except ClientError as exc:
                if _code_of(exc) == "InvalidGroup.NotFound":
                    return
                if _code_of(exc) != "DependencyViolation":
                    raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"security group {sg_id} still held after {_ENI_WAIT_S}s by "
                f"{[(e['NetworkInterfaceId'], e['Status']) for e in enis]}; refused deletes: "
                f"{refused}")
        time.sleep(15)


def _cache_subnet_group(ctx, ec, net: dict) -> str:
    """A cache subnet group of this run's own over the executor's subnets; its teardown waits
    while the deleting cache still holds it."""
    name = ctx.unique_name("sim2real-behav-invpc-sng-")
    ec.create_cache_subnet_group(
        CacheSubnetGroupName=name,
        CacheSubnetGroupDescription="sim2real in-VPC executor network",
        SubnetIds=net["subnet_ids"],
        Tags=_RESOURCE_TAGS,
    )

    def _delete():
        deadline = time.monotonic() + 1200
        while True:
            try:
                ec.delete_cache_subnet_group(CacheSubnetGroupName=name)
                return
            except ClientError as exc:
                if _code_of(exc) == "CacheSubnetGroupNotFound":
                    return
                if _code_of(exc) != "CacheSubnetGroupInUse" or time.monotonic() >= deadline:
                    raise
            time.sleep(20)

    ctx.on_cleanup(_delete)
    return name


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
    """A per-run execution role with AWSLambdaVPCAccessExecutionRole, whose EC2 actions
    CreateFunction with VpcConfig requires; deleted on teardown."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-invpc-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_LAMBDA_TRUST),
        Description="sim2real in-VPC data-plane executor",
        Tags=_RESOURCE_TAGS,
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
    """CreateFunction with VpcConfig, retried through IAM propagation, then wait Active. A role
    created seconds ago is not yet visible to Lambda, which rejects it with
    InvalidParameterValueException; that is transient, not a verdict."""
    name = ctx.unique_name("sim2real-behav-invpc-fn-")
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=role_arn,
        Code={"ZipFile": _make_zip(_HANDLER_SRC)},
        MemorySize=512,
        # 300 s: the `fill` op drives thousands of 64 KiB writes in one invoke, and a runtime
        # timeout would read as an unusable executor.
        Timeout=300,
        VpcConfig={"SubnetIds": net["subnet_ids"], "SecurityGroupIds": [net["sg_id"]]},
        Tags={t["Key"]: t["Value"] for t in _RESOURCE_TAGS},
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
                    raise TimeoutError(f"CreateFunction {name} past IAM role propagation: the run budget ended first; not graded") from exc
                raise _no_executor(
                    f"CreateFunction with VpcConfig={kwargs['VpcConfig']!r} was rejected: "
                    f"{_code_of(exc)}: {msg}"
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
            raise TimeoutError(f"the in-VPC executor {name} reaching State=Active: the run budget ended first; not graded")
        raise AssertionError(
            f"the in-VPC executor {name} did not reach State=Active within the bounded wait (a "
            f"first Hyperplane ENI in a fresh subnet/security-group pair is the slow part)"
        )
    if last["State"] != "Active":
        raise _no_executor(f"{name} entered State={last['State']!r}: {last.get('StateReason')!r}")
    return name, (last.get("VpcConfig") or {})


def _delete_function(ctx, lam, name: str):
    """Delete the function and its log group; a missing one is already gone. Lambda releases the
    Hyperplane ENI asynchronously, and the executor group's teardown waits for it."""
    for fn, gone in (
        (lambda: lam.delete_function(FunctionName=name), "ResourceNotFound"),
        (lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}"),
         "ResourceNotFound"),
    ):
        try:
            fn()
        except ClientError as exc:
            if _code_of(exc) != gone:
                raise


def _invoke(ctx, lam, fn: str, payload: dict) -> dict:
    """One synchronous Invoke, returning the decoded handler result. The handler never raises, so a
    FunctionError or non-200 StatusCode means the executor is unusable, not a Redis verdict."""
    resp = lam.invoke(FunctionName=fn, InvocationType="RequestResponse",
                      Payload=json.dumps(payload).encode())
    raw = resp["Payload"].read()
    if resp.get("FunctionError") or resp.get("StatusCode") != 200:
        raise _no_executor(
            f"Invoke of {fn} returned StatusCode={resp.get('StatusCode')!r} "
            f"FunctionError={resp.get('FunctionError')!r}: {raw[:600]!r}"
        )
    try:
        out = json.loads(raw)
    except ValueError as exc:
        raise _no_executor(
            f"Invoke of {fn} returned a body that is not JSON: {raw[:600]!r}") from exc
    if not isinstance(out, dict):
        raise _no_executor(
            f"Invoke of {fn} returned {type(out).__name__}, not the handler's object: {out!r}")
    return out


def _prove_executor_in_vpc(ctx, lam, fn: str, net: dict) -> tuple[dict, bool, str]:
    """Run the selftest before anything billable exists; return (evidence, in_vpc, reason).
    The code ran if the handler returns sha256 over our nonce and its network fields; it ran in our
    VPC if its source IP is in the VPC CIDR or the VPC resolver answered a DNS query."""
    nonce = secrets.token_hex(16)
    ev = _invoke(ctx, lam, fn, {
        "op": "selftest",
        "nonce": nonce,
        "resolver": net["resolver"],
        "probe_host": net["resolver"],
        "probe_port": 53,
        "dns_name": "amazonaws.com",
    })

    # Claim 1: the code ran. The digest covers the network fields too, so a rewrite fails.
    expected = hashlib.sha256(
        f"{nonce}|{ev.get('src_ip')}|{ev.get('resolver_rcode')}".encode()).hexdigest()
    if ev.get("nonce") != nonce or ev.get("proof") != expected:
        raise _no_executor(
            f"the invoke returned {ev!r}, which does not carry sha256 over the nonce {nonce!r} "
            f"bound to the network fields it reported (expected proof {expected!r}); the target "
            f"accepted CreateFunction and Invoke but did not execute the package")

    # Claim 2: it ran in our VPC. Either signal suffices; any resolver reply counts (even SERVFAIL),
    # because the VPC resolver at CIDR base+2 answers only from inside the VPC.
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
    """Create the executor and prove it is in the VPC; -> (lam, net, fn, in_vpc, why).
    Runs before the cache exists, so a target that cannot run the probe is never billed for one."""
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


def _as_bytes(arg) -> bytes:
    return arg if isinstance(arg, bytes) else str(arg).encode()


class _Prober:
    """One vantage point (runner-side or in-VPC Lambda), exposing the handler's ops identically.
    Chosen once, so a positive control and the refusal it is contrasted with share one path."""

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
    """The vantage point that can reach ``host:port``, or a data-plane failure if none can within a
    bounded poll (a cache can report 'available' before its endpoint connects). The runner-side
    arm is retried only while its connect is refused (reachable, not yet listening): a private
    endpoint costs a timeout per try."""
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
        raise TimeoutError(f"a RESP connection to {subject} at {host}:{port}: the run budget ended first; not graded")
    detail = (f"{subject} advertises {host}:{port} (tls={tls}). {attempts} attempts over {budget:.0f}s. "
              f"in-VPC probe: {invpc!r}. runner-side probe: {outside!r}.")
    if in_vpc:
        raise _dp_fail(
            f"the ElastiCache control plane provisioned {subject} and advertised {host}:{port}, but "
            f"nothing there accepts a RESP connection from inside its own VPC (executor proven "
            f"in-VPC by {why}). An endpoint that cannot be connected to is not a data plane. "
            f"{detail}")
    raise _no_executor(f"{why}. {detail}")


def _replies(result: dict, commands, *, source: str) -> list[bytes]:
    """The raw reply bytes for ``commands``, asserting one reply per command; a short list means the
    endpoint answered something that is not RESP2."""
    assert result.get("ok"), (
        f"[{source}] the probe did not complete: {result!r}. Commands sent: "
        f"{[list(c) for c in commands]!r}")
    raws = [base64.b64decode(r) for r in result.get("replies", [])]
    assert len(raws) == len(commands), (
        f"[{source}] the endpoint framed {len(raws)} of {len(commands)} replies. Commands sent: "
        f"{[list(c) for c in commands]!r}. Raw replies received: {raws!r}")
    return raws


def _resp_int(raw: bytes, *, source: str, cmd: str) -> int:
    """The integer in a RESP2 ``:<n>\\r\\n`` reply, as a fidelity assertion rather than a
    ValueError when a target answers a non-numeric payload."""
    assert raw.startswith(b":") and raw.endswith(b"\r\n"), (
        f"[{source}] {cmd} must return a RESP integer reply (:<n>\\r\\n), got {raw!r}")
    try:
        return int(raw[1:-2])
    except ValueError:
        raise AssertionError(
            f"[{source}] {cmd} framed an integer reply but its payload is not an integer: {raw!r}. "
            f"A client's int conversion would raise on this") from None


def _resp_bulk(raw: bytes, *, source: str, cmd: str) -> bytes:
    """The payload of a RESP2 bulk-string reply; ``$-1\\r\\n`` (absent) is rejected rather than
    collapsed to b"", since absence and emptiness are distinct answers."""
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
    """The error name out of a RESP2 error frame ``-NAME free text\\r\\n``, as an exact token so
    the caller asserts equality (a prefix match would accept ``-NOAUTHX``)."""
    assert raw.startswith(b"-") and raw.endswith(b"\r\n"), (
        f"[{source}] {cmd} was expected to be refused with a RESP error frame "
        f"(-NAME message\\r\\n), got {raw!r}")
    return raw[1:-2].split(b" ", 1)[0].decode("ascii", "replace")


def _info_field(raw: bytes, field: str, *, source: str) -> int:
    """One integer field out of an INFO bulk string, parsed per ``key:value`` line so
    `evicted_keys` cannot be satisfied by `keyspace_evicted_keys`."""
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
    """One text field out of an INFO bulk string, e.g. ``maxmemory_policy:allkeys-lru``; same
    parse as `_info_field` without integer coercion."""
    body = _resp_bulk(raw, source=source, cmd="INFO")
    for line in body.split(b"\r\n"):
        if line.startswith(b"#") or b":" not in line:
            continue
        name, _, val = line.partition(b":")
        if name == field.encode():
            return val.decode("ascii", "replace")
    raise AssertionError(
        f"[{source}] INFO does not report a {field!r} line at all. Body was {body[:1500]!r}")


def _describe_cluster(ec, cluster_id: str, **extra):
    try:
        resp = ec.describe_cache_clusters(CacheClusterId=cluster_id, **extra)
    except ClientError as exc:
        if "NotFound" in _code_of(exc):
            return None
        raise
    items = resp.get("CacheClusters", [])
    return items[0] if items else None


# Returned by _cluster_endpoint when node info never populated; a unique object, so `is` keeps
# a wait that ran out from being graded as a data-plane gap.
_NODE_INFO_TIMEOUT = object()


def _cluster_endpoint(ctx, ec, cluster_id: str):
    """``(Address, Port)`` for the single cache node, or ``_NODE_INFO_TIMEOUT`` when node info never
    populated (provisioning latency), unlike an advertised empty endpoint (a data-plane gap)."""
    node = _poll(lambda: _describe_cluster(ec, cluster_id, ShowCacheNodeInfo=True),
                 lambda c: bool((c or {}).get("CacheNodes")),
                 timeout_s=_budget_s(ctx, 300), interval_s=2)
    if node is None:
        if _budget_spent(ctx):
            raise TimeoutError(f"cache cluster {cluster_id} node info: the run budget ended first; not graded")
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
            raise TimeoutError(f"cache cluster {cluster_id} available: the run budget ended first; not graded")
        raise AssertionError(
            f"cache cluster {cluster_id} did not reach 'available' within the bounded wait")
    return got


def _delete_cluster(ec, cluster_id: str, timeout_s: float = 900):
    """Get the billable node deleting; idempotent and retried through `creating`, which refuses
    deletion. The status is read first so a node already `deleting` returns at once."""
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
    """Delete the node inside the check and return the reported status, so the delete can be
    asserted (`ctx.on_cleanup` swallows exceptions); the registered cleanup stays as a fallback."""
    return (ec.delete_cache_cluster(CacheClusterId=cluster_id)["CacheCluster"]
            ["CacheClusterStatus"])


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
            raise TimeoutError(f"replication group {rg_id} available: the run budget ended first; not graded")
        raise AssertionError(
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
            time.sleep(20)


def _teardown_rg_now(ec, rg_id: str) -> str:
    """Delete the replication group INSIDE the check and return the reported status — see
    _teardown_cluster_now for why the assertable form matters."""
    return ec.delete_replication_group(
        ReplicationGroupId=rg_id, RetainPrimaryCluster=False)["ReplicationGroup"]["Status"]


_VALUE = b"authenticated\r\nvalue"
_DENIED_VALUE = b"written-without-auth"
# Bounded wait for the authenticated path to work: until it does, a refusal is
# indistinguishable from an endpoint that is not serving yet.
_READY_BUDGET_S = 240


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:native", "plane:data")
def run(ctx) -> None:
    """A replication group with an AuthToken refuses SET, GET and DBSIZE without AUTH with RESP
    NOAUTH and the refused write leaves no key; a wrong token gets WRONGPASS and stays
    unauthenticated, while the same commands succeed after AUTH on the same endpoint."""
    ec = ctx.client("elasticache")
    lam, net, fn, in_vpc, why = _bring_up_executor(ctx)
    subnet_group = _cache_subnet_group(ctx, ec, net)

    # Generated per run and never persisted. token_urlsafe yields only [A-Za-z0-9_-], which avoids
    # every character AuthToken forbids ('@', '"', '/'), and 32 bytes is inside the 16-128 length
    # window.
    token = secrets.token_urlsafe(32)
    wrong_token = secrets.token_urlsafe(32)

    rg_id = ctx.unique_name("sim2real-behav-ecauth-")
    # AuthToken requires TransitEncryptionEnabled, which needs a replication group, not a cluster.
    try:
        created = ec.create_replication_group(
            ReplicationGroupId=rg_id,
            ReplicationGroupDescription="sim2real AuthToken enforcement on the RESP data plane",
            Engine="redis",
            CacheNodeType=_NODE_TYPE,
            NumCacheClusters=1,
            Port=_REDIS_PORT,
            CacheSubnetGroupName=subnet_group,
            SecurityGroupIds=[net["sg_id"]],
            TransitEncryptionEnabled=True,
            AuthToken=token,
            Tags=_RESOURCE_TAGS,
        )["ReplicationGroup"]
    except ClientError as exc:
        if _code_of(exc) != "InsufficientCacheClusterCapacity":
            raise
        raise AssertionError(
            f"no {_NODE_TYPE} capacity for subnet group {subnet_group}: {_msg_of(exc)}") from exc
    ctx.on_cleanup(lambda g=rg_id: _delete_rg(ec, g))
    assert created["Status"] == "creating", (
        f"create_replication_group reported Status={created['Status']!r}, not 'creating'")

    group = _wait_rg_available(ctx, ec, rg_id)
    assert group.get("TransitEncryptionEnabled") is True, (
        f"the group was created with TransitEncryptionEnabled=True but reports "
        f"{group.get('TransitEncryptionEnabled')!r}; without TLS the AuthToken is not even accepted")
    assert group.get("AuthTokenEnabled") is True, (
        f"the group was created with an AuthToken but reports "
        f"AuthTokenEnabled={group.get('AuthTokenEnabled')!r}")

    node_groups = group.get("NodeGroups") or []
    assert len(node_groups) == 1, (
        f"asked for one node group, DescribeReplicationGroups reports {node_groups!r}")
    endpoint = node_groups[0].get("PrimaryEndpoint") or {}
    host, port = endpoint.get("Address"), endpoint.get("Port")
    if not host or not port:
        raise _dp_fail(
            f"replication group {rg_id} is 'available' but advertises no primary endpoint "
            f"({endpoint!r}); without an address there is no data plane to authenticate against")
    host, port = ctx.endpoint_host(host, port)

    probe = _pick_prober(ctx, lam, fn, host, int(port), in_vpc=in_vpc, why=why, tls=True,
                         subject=f"replication group {rg_id}")
    src = probe.label

    key = f"sim2real:auth:{rg_id}"
    denied_key = f"sim2real:denied:{rg_id}"

    # 1. Barrier: the authenticated path must work before anything is broken.
    ready_cmds = [["AUTH", token], ["PING"]]
    ready_budget = _budget_s(ctx, _READY_BUDGET_S)
    deadline = time.monotonic() + ready_budget
    ready, attempts = None, 0
    while True:
        attempts += 1
        ready = probe.resp(host, int(port), ready_cmds, tls=True)
        if ready.get("ok"):
            raws = [base64.b64decode(r) for r in ready["replies"]]
            if raws == [b"+OK\r\n", b"+PONG\r\n"]:
                break
        if time.monotonic() >= deadline:
            break
        time.sleep(2)

    if (not (ready.get("ok") and [base64.b64decode(r) for r in ready["replies"]] == [b"+OK\r\n", b"+PONG\r\n"])
            and _budget_spent(ctx)):
        raise TimeoutError(f"AUTH + PING on replication group {rg_id}: the run budget ended first; not graded")
    ready_raws = _replies(ready, ready_cmds, source=src)
    assert ready_raws[0] == b"+OK\r\n", (
        f"[{src}] AUTH with the token the group was created with must return +OK, got "
        f"{ready_raws[0]!r} after {attempts} attempts over {ready_budget:.0f}s. Every leg below "
        f"contrasts an authenticated call with an unauthenticated one, so without this the refusal "
        f"could not be attributed to the missing AUTH")
    assert ready_raws[1] == b"+PONG\r\n", (
        f"[{src}] PING on an AUTHENTICATED connection must return +PONG, got {ready_raws[1]!r}")
    assert ready.get("tls_mode") is not None, (
        f"[{src}] the probe reached {host}:{port} without a TLS handshake, but the group reports "
        f"TransitEncryptionEnabled=True. An AuthToken is only meaningful over TLS, and a token sent "
        f"in the clear is worse than none: {ready!r}")

    # 2. Positive control on an authenticated connection.
    control_cmds = [["AUTH", token], ["SET", key, _VALUE], ["GET", key], ["DBSIZE"]]
    control = _replies(probe.resp(host, int(port), control_cmds, tls=True), control_cmds,
                       source=src)
    assert control[1] == b"+OK\r\n", (
        f"[{src}] positive control: SET on an authenticated connection must return +OK, got "
        f"{control[1]!r}")
    assert control[2] == _bulk_expected(_VALUE), (
        f"[{src}] positive control: GET must return the value byte for byte, including the embedded "
        f"CRLF: expected {_bulk_expected(_VALUE)!r}, got {control[2]!r}")
    assert _resp_int(control[3], source=src, cmd="DBSIZE") == 1, (
        f"[{src}] after exactly one authenticated SET the keyspace must hold exactly one key, "
        f"DBSIZE returned {control[3]!r}")

    # 3. Break one thing: same host, port, TLS and commands, but no AUTH.
    unauth_cmds = [["SET", denied_key, _DENIED_VALUE], ["GET", key], ["DBSIZE"]]
    unauth = _replies(probe.resp(host, int(port), unauth_cmds, tls=True), unauth_cmds, source=src)

    set_error = _resp_error_name(unauth[0], source=src, cmd=f"SET {denied_key!r} without AUTH")
    assert set_error == "NOAUTH", (
        f"[{src}] a SET issued WITHOUT AUTH on an AuthToken-protected endpoint must be refused with "
        f"the RESP error NOAUTH; the engine answered {unauth[0]!r} (error name {set_error!r}). "
        f"AuthTokenEnabled is reported as true by the control plane, so a reply that is not a "
        f"refusal means the token is recorded and not enforced")
    get_error = _resp_error_name(unauth[1], source=src, cmd="GET without AUTH")
    assert get_error == "NOAUTH", (
        f"[{src}] READING is refused too, with the same error: GET on an unauthenticated connection "
        f"answered {unauth[1]!r} (error name {get_error!r}), expected NOAUTH. An endpoint that "
        f"refuses writes and serves reads to anyone is the more dangerous half of this gap")
    dbsize_error = _resp_error_name(unauth[2], source=src, cmd="DBSIZE without AUTH")
    assert dbsize_error == "NOAUTH", (
        f"[{src}] even a metadata command must be refused before AUTH: DBSIZE answered "
        f"{unauth[2]!r} (error name {dbsize_error!r}), expected NOAUTH")

    # 4. The refused write left no trace, read back over an authenticated connection.
    absent_cmds = [["AUTH", token], ["GET", denied_key], ["EXISTS", denied_key], ["DBSIZE"]]
    absent = _replies(probe.resp(host, int(port), absent_cmds, tls=True), absent_cmds, source=src)
    assert absent[1] == b"$-1\r\n", (
        f"[{src}] effect not absent: the key the UNAUTHENTICATED SET tried to write reads back as "
        f"{absent[1]!r} on an authenticated connection, expected the null bulk string $-1. The "
        f"engine returned NOAUTH and then performed the write anyway")
    assert absent[2] == b":0\r\n", (
        f"[{src}] effect not absent: EXISTS on {denied_key!r} returns {absent[2]!r}, expected 0 — "
        f"the key is in the keyspace even though the command that created it was refused")
    assert _resp_int(absent[3], source=src, cmd="DBSIZE") == 1, (
        f"[{src}] the keyspace must still hold exactly the one key the AUTHENTICATED control wrote; "
        f"DBSIZE returned {absent[3]!r}")

    # 5. A wrong token is refused with WRONGPASS and leaves the connection unauthenticated.
    wrong_cmds = [["AUTH", wrong_token], ["GET", key]]
    wrong = _replies(probe.resp(host, int(port), wrong_cmds, tls=True), wrong_cmds, source=src)
    wrong_error = _resp_error_name(wrong[0], source=src, cmd="AUTH with the wrong token")
    assert wrong_error == "WRONGPASS", (
        f"[{src}] AUTH with a token the group was NOT created with must be refused with the RESP "
        f"error WRONGPASS; the engine answered {wrong[0]!r} (error name {wrong_error!r}). A "
        f"+OK there would mean the token is compared against nothing")
    still_denied = _resp_error_name(wrong[1], source=src, cmd="GET after a failed AUTH")
    assert still_denied == "NOAUTH", (
        f"[{src}] after a FAILED AUTH the connection must still be unauthenticated: GET answered "
        f"{wrong[1]!r} (error name {still_denied!r}), expected NOAUTH. A connection that a rejected "
        f"AUTH left authenticated is a bypass of the whole mechanism")

    # 6. The control still works unchanged.
    after_cmds = [["AUTH", token], ["GET", key], ["DBSIZE"]]
    after = _replies(probe.resp(host, int(port), after_cmds, tls=True), after_cmds, source=src)
    assert after[1] == _bulk_expected(_VALUE), (
        f"[{src}] positive control, re-run after the refusals: an authenticated GET must still "
        f"return the value byte for byte, expected {_bulk_expected(_VALUE)!r}, got {after[1]!r}. "
        f"Only the missing AUTH separated the refused calls from these, and the data written before "
        f"them is untouched")
    assert _resp_int(after[2], source=src, cmd="DBSIZE") == 1, (
        f"[{src}] the keyspace must be exactly as the authenticated control left it — one key — "
        f"DBSIZE returned {after[2]!r}")

    _delete_function(ctx, lam, fn)
    status = _teardown_rg_now(ec, rg_id)
    assert status == "deleting", (
        f"DeleteReplicationGroup on {rg_id} reported Status={status!r}, not 'deleting'; a node that "
        f"does not enter the deleting state keeps billing")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
