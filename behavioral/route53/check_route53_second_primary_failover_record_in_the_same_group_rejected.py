"""route53-second-primary-failover-record-in-the-same-group-rejected."""
from __future__ import annotations

import base64
import io
import json
import secrets
import socket
import struct
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "route53-second-primary-failover-record-in-the-same-group-rejected"
GROUP = 'resource-record-sets'
SERVICES = ['route53']

# ===== helpers (self-contained) =====
# WHY THERE IS A LAMBDA IN A route53 CHECK.
#
# Route 53's data plane is DNS on port 53, served by the four `awsdns-*` nameservers that
# GetHostedZone returns in DelegationSet.NameServers. The check host may have no egress to
# arbitrary internet addresses on port 53, so `socket.create_connection((ns_ip, 53))` from the
# check process cannot be relied on, and a check built on it would report a network restriction
# as a route53 fidelity failure.
#
# A Lambda function with NO VpcConfig has unrestricted outbound internet access and reaches
# awsdns:53 in ~2 ms. It is used purely as a NETWORK VANTAGE POINT.
#
# The handler is deliberately DUMB. It opens sockets, relays bytes and makes no assertions: the
# DNS message is encoded and decoded HERE, next to the assertions, so the assertions grade the
# DNS message itself and the raw wire bytes are the evidence (every parsed reply carries `raw_hex`).
#
# No IAM policy is attached to the execution role. A non-VPC Lambda needs only a trust
# relationship with lambda.amazonaws.com to be created and invoked, and the handler returns every
# diagnostic in its synchronous payload, so CloudWatch Logs would add nothing -- while WITHOUT the
# logs permission no `/aws/lambda/<fn>` log group is ever created, which removes the log group
# that otherwise races function teardown (references/cleanup-and-leaks.md, "The final sweep").

_HANDLER_SRC = r'''
# DNS transport, executed by AWS Lambda from a vantage point with network egress.
#
# Opens sockets, returns raw bytes, makes NO assertions and NEVER raises out of `handler` -- an
# exception would surface as `FunctionError` and cost the check the structured evidence it needs
# to attribute the failure, so every failure is a return value.
#
#   {"op": "resolve", "hosts": ["ns-361.awsdns-45.com", ...]}
#       -> the A records of each nameserver HOSTNAME, plus the errno when a name does not resolve.
#          Route 53 publishes its delegation set by hostname and the queries below must be
#          addressed to a literal.
#
#   {"op": "tcp53", "host": "<resolver or nameserver ip>", "payloads": [<base64 DNS query>, ...]}
#       -> one raw reply per payload, base64'd, in order.
#
# DNS over TCP (RFC 7766) rather than UDP: the 2-byte length prefix makes framing unambiguous and
# no answer can be silently truncated, which matters because several of these checks assert the
# SIZE of an answer set.
#
# A FRESH CONNECTION PER QUERY, deliberately. Route 53 evaluates weighted, multivalue and
# geolocation routing per query, so a distribution asserted over N queries must not be answered
# off one connection's state.
#
# This module is the string literal _HANDLER_SRC in the check that deploys it. It uses `#`
# comments rather than docstrings only so that it can be embedded in a triple-quoted literal
# without any quoting collision.

from __future__ import annotations

import base64
import os
import socket
import time

_CONNECT_TIMEOUT_S = 5
_IO_TIMEOUT_S = 5


def _resolve(hosts):
    out = {}
    for host in hosts:
        try:
            addrs = sorted(set(
                ai[4][0] for ai in socket.getaddrinfo(
                    host, 53, socket.AF_INET, socket.SOCK_STREAM)))
            out[host] = {"addresses": addrs, "error": None, "errno": None}
        except OSError as exc:
            out[host] = {"addresses": [], "errno": getattr(exc, "errno", None),
                         "error": "%s: %s" % (type(exc).__name__, exc)}
    return out


def _tcp53(host, payloads):
    replies = []
    for payload in payloads:
        msg = base64.b64decode(payload)
        started = time.time()
        try:
            sock = socket.create_connection((host, 53), timeout=_CONNECT_TIMEOUT_S)
        except OSError as exc:
            replies.append({"ok": False, "stage": "connect",
                            "errno": getattr(exc, "errno", None),
                            "error": "%s: %s" % (type(exc).__name__, exc)})
            continue
        try:
            sock.settimeout(_IO_TIMEOUT_S)
            sock.sendall(len(msg).to_bytes(2, "big") + msg)
            prefix = b""
            while len(prefix) < 2:
                chunk = sock.recv(2 - len(prefix))
                if not chunk:
                    raise ConnectionError("closed before the 2-byte DNS length prefix")
                prefix += chunk
            want = int.from_bytes(prefix, "big")
            buf = b""
            while len(buf) < want:
                chunk = sock.recv(want - len(buf))
                if not chunk:
                    raise ConnectionError("closed mid-message")
                buf += chunk
            replies.append({"ok": True, "raw": base64.b64encode(buf).decode(),
                            "elapsed_ms": int((time.time() - started) * 1000)})
        except (OSError, ConnectionError) as exc:
            replies.append({"ok": False, "stage": "io",
                            "errno": getattr(exc, "errno", None),
                            "error": "%s: %s" % (type(exc).__name__, exc)})
        finally:
            try:
                sock.close()
            except OSError:
                pass
    return replies


def handler(event, context):
    op = (event or {}).get("op")
    try:
        if op == "resolve":
            return {"ok": True, "addresses": _resolve(event["hosts"])}
        if op == "tcp53":
            return {"ok": True, "replies": _tcp53(event["host"], event["payloads"])}
        return {"ok": False, "stage": "dispatch", "error": "unknown op %r" % (op,)}
    except Exception as exc:
        import traceback
        return {"ok": False, "stage": "handler",
                "error": "%s: %s" % (type(exc).__name__, exc),
                "traceback": traceback.format_exc()[-1200:]}
'''

_MANAGED_TAGS = [{"Key": "sim2real", "Value": "route53-second-primary"},
                 {"Key": "sim2real:managed", "Value": "true"},
                 {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

_LAMBDA_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow",
                   "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}


# ---- generic helpers --------------------------------------------------------------------------


def _code_of(exc):
    return exc.response.get("Error", {}).get("Code") or ""


def _msg_of(exc):
    return exc.response.get("Error", {}).get("Message") or str(exc)


def _poll(probe, done, *, timeout_s, interval_s=2.0, what="condition"):
    """Poll an OBSERVABLE condition to a bounded deadline.

    Never a bare sleep standing in for a wait: every wait in this file watches either an AWS API
    field or a DNS answer, both of which report when the thing has actually happened.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; last={last!r}"
            )
        time.sleep(interval_s)


def _error(fn):
    """(error code, message) for a call that MUST fail. Raises if it succeeds instead.

    Deliberately does NOT return a falsy sentinel on unexpected success: a target that ACCEPTS
    input real AWS rejects is the strongest signal available here, and returning "" would flatten
    it into an error-code mismatch that reads like a naming difference.
    """
    try:
        result = fn()
    except ClientError as exc:
        return _code_of(exc), _msg_of(exc)
    raise AssertionError(
        f"the call was expected to be REFUSED and instead succeeded, returning {result!r}; "
        "whatever it created now exists and was never registered for cleanup"
    )


# ---- the DNS vantage point: an execution role and a Lambda ------------------------------------


def _zipped(src):
    """The whole deployment package: one stdlib-only file, no dependency and no layer."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", src)
    return buf.getvalue()


def _delete_role(iam, name):
    try:
        for pol in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=name, PolicyName=pol)
        for pol in iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=name, PolicyArn=pol["PolicyArn"])
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if _code_of(exc) not in ("NoSuchEntity", "NoSuchEntityException"):
            raise


_ROLE_NOT_READY = ("cannot be assumed", "does not have permissions", "CreateNetworkInterface",
                   "Lambda was unable to configure your environment")


def _delete_log_group(ctx, fn_name):
    """Delete the function's log group, if the first invocation created one.

    MUST run AFTER DeleteFunction, which is why it is registered BEFORE the function's own cleanup
    (ctx.on_cleanup is LIFO). Registered the other way round, it deletes the group while the
    function still exists and the next log flush recreates it, orphaning the group.

    ResourceNotFoundException is tolerated because it is the NORMAL outcome for the public-zone
    vantage point: its execution role carries no permissions policy at all, so no log group is ever
    created. Only the role that carries AWSLambdaVPCAccessExecutionRole can produce one.
    """
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{fn_name}")
    except ClientError as exc:
        if _code_of(exc) != "ResourceNotFoundException":
            raise


def _deploy_vantage(ctx, role_arn, **fn_kwargs):
    """A Lambda running _HANDLER_SRC, waited to Active. Returns (lambda client, function name).

    The CreateFunction retry is what makes this correct rather than flaky: a role created seconds
    ago is not yet visible to Lambda, and CreateFunction rejects it SYNCHRONOUSLY with
    InvalidParameterValueException naming the trust relationship. That is IAM propagation, not a
    verdict about anything -- and it is the one place a short sleep is legitimate, because no API
    reports that a trust policy has become effective. It sits INSIDE a bounded retry at the first
    use of the role rather than replacing one.
    """
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-behav-r53dns-fn-")
    kwargs = dict(
        FunctionName=fn_name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=role_arn,
        Code={"ZipFile": _zipped(_HANDLER_SRC)},
        MemorySize=256,
        Timeout=120,
        Description="sim2real-behav route53 DNS transport",
        Tags={t["Key"]: t["Value"] for t in _MANAGED_TAGS},
    )
    kwargs.update(fn_kwargs)
    deadline = time.monotonic() + 180
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            propagating = _code_of(exc) == "InvalidParameterValueException" and any(
                s in _msg_of(exc) for s in _ROLE_NOT_READY
            )
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(4)
    # The log group is a SEPARATE resource that outlives DeleteFunction, created LAZILY by the
    # first invocation rather than by CreateFunction. Both cleanups are registered here, at the
    # create that causes them, and the ORDER IS LOAD-BEARING: ctx.on_cleanup is LIFO, so
    # registering the log group FIRST makes it run LAST -- after the function is gone. Registered
    # the other way round it deletes the group while the function still exists, the next log flush
    # recreates it, and the group leaks. See _delete_log_group.
    ctx.on_cleanup(lambda: _delete_log_group(ctx, fn_name))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))

    cfg = _poll(
        lambda: lam.get_function_configuration(FunctionName=fn_name),
        lambda c: c.get("State") in ("Active", "Failed"),
        timeout_s=300, interval_s=3,
        what=f"the DNS vantage point {fn_name} to leave State=Pending",
    )
    assert cfg["State"] == "Active", (
        f"the DNS vantage point {fn_name} entered State={cfg['State']!r} "
        f"({cfg.get('StateReason')!r}); without it there is no way to send a DNS query at all "
        f"from this host -- see the plumbing note on blocked port-53 egress"
    )
    return lam, fn_name


def _plain_exec_role(ctx):
    """A bare Lambda execution role: a trust relationship and nothing else.

    No permissions policy on purpose -- see the plumbing note above. Registered for teardown
    immediately, before the function that uses it exists.
    """
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-r53dns-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_LAMBDA_TRUST),
        Description="sim2real-behav route53 DNS vantage point",
        Tags=_MANAGED_TAGS,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    return arn


def _deploy_dns_vantage(ctx):
    return _deploy_vantage(ctx, _plain_exec_role(ctx))


def _invoke(lam, fn_name, payload):
    """One synchronous Invoke, returning the decoded handler result.

    A FunctionError means the RUNTIME failed rather than the handler reporting a failure -- the
    handler never raises -- so it is the instrument being unusable, never a route53 verdict.
    """
    resp = lam.invoke(FunctionName=fn_name, InvocationType="RequestResponse",
                      Payload=json.dumps(payload).encode())
    raw = resp["Payload"].read()
    assert not resp.get("FunctionError") and resp.get("StatusCode") == 200, (
        f"the DNS vantage point {fn_name} failed to execute: "
        f"StatusCode={resp.get('StatusCode')!r} FunctionError={resp.get('FunctionError')!r}: "
        f"{raw[:800]!r}"
    )
    out = json.loads(raw)
    assert isinstance(out, dict) and out.get("ok"), (
        f"the DNS transport returned a failure rather than a result: {out!r}"
    )
    return out


# ---- the DNS codec: hand-framed queries, hand-parsed replies ----------------------------------
# dnspython is NOT importable in the check environment. Everything below is stdlib `struct` over
# the bytes the nameserver actually returned, which is the whole point: the graded value is a DNS
# message, not an AWS API response.

_TYPE_NUM = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28}
_TYPE_NAME = {v: k for k, v in _TYPE_NUM.items()}


def _encode_query(name, rtype, rd=False):
    """One DNS query message. Returns (transaction id, bytes).

    RD (recursion desired) defaults OFF because these queries are addressed to the AUTHORITATIVE
    server for the zone: asking it to recurse would be meaningless, and its answer must be
    authoritative, which is what the AA-bit assertions check. It is turned ON only for the
    Amazon-provided VPC resolver, which is a recursive resolver serving a private-zone view.
    """
    qid = secrets.randbits(15) + 1
    header = struct.pack(">HHHHHH", qid, 0x0100 if rd else 0x0000, 1, 0, 0, 0)
    labels = [lbl for lbl in name.rstrip(".").split(".") if lbl]
    qname = b"".join(bytes([len(l)]) + l.encode("ascii") for l in labels) + b"\x00"
    return qid, header + qname + struct.pack(">HH", _TYPE_NUM[rtype], 1)


def _read_name(buf, off):
    """A possibly compressed domain name. Returns (name with trailing dot, offset after it).

    Following compression pointers is mandatory, not optional: Route 53 compresses the owner name
    of every record after the first, so a parser that cannot follow one reads the answer section
    as garbage instead of failing loudly.
    """
    labels, next_off, hops = [], None, 0
    while True:
        if off >= len(buf):
            raise ValueError(f"a DNS name at {off} runs past the end of a {len(buf)}-byte message")
        length = buf[off]
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                raise ValueError("truncated DNS compression pointer")
            if next_off is None:
                next_off = off + 2
            off = ((length & 0x3F) << 8) | buf[off + 1]
            hops += 1
            if hops > 32:
                raise ValueError("DNS compression pointer loop")
            continue
        if length == 0:
            if next_off is None:
                next_off = off + 1
            break
        labels.append(buf[off + 1:off + 1 + length])
        off += 1 + length
    return (".".join(l.decode("latin-1") for l in labels) + "." if labels else "."), next_off


def _decode_rdata(buf, rtype, start, length):
    """RDATA in its canonical presentation form, per record type.

    Presentation form rather than raw bytes because the assertion has to be readable: an A
    record's value is '203.0.113.10' and a TXT record's is the quoted string a zone file would
    carry. An unknown type falls through to hex so it is VISIBLE in the failure message rather
    than silently decoding as something else.
    """
    end = start + length
    if rtype == "A":
        if length != 4:
            raise ValueError(f"an A record's RDATA must be 4 bytes, got {length}")
        return ".".join(str(b) for b in buf[start:end])
    if rtype == "AAAA":
        if length != 16:
            raise ValueError(f"an AAAA record's RDATA must be 16 bytes, got {length}")
        return socket.inet_ntop(socket.AF_INET6, buf[start:end])
    if rtype in ("NS", "CNAME"):
        return _read_name(buf, start)[0]
    if rtype == "TXT":
        parts, off = [], start
        while off < end:
            n = buf[off]
            parts.append(buf[off + 1:off + 1 + n].decode("latin-1"))
            off += 1 + n
        return "".join('"%s"' % p for p in parts)
    if rtype == "SOA":
        mname, off = _read_name(buf, start)
        rname, off = _read_name(buf, off)
        serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", buf[off:off + 20])
        return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
    return buf[start:end].hex()


def _parse_records(buf, off, count):
    out = []
    for _ in range(count):
        name, off = _read_name(buf, off)
        rtype_num, rclass, ttl, rdlength = struct.unpack(">HHIH", buf[off:off + 10])
        off += 10
        rtype = _TYPE_NAME.get(rtype_num, str(rtype_num))
        out.append({"name": name, "type": rtype, "class": rclass, "ttl": ttl,
                    "rdata": _decode_rdata(buf, rtype, off, rdlength)})
        off += rdlength
    return out, off


def _parse_dns(raw, qid, qtype):
    """The whole DNS reply, as the dict every assertion in this file reads.

    `rdata` and `ttl` are narrowed to the records of the QUERIED type in the answer section, so a
    reply carrying only a CNAME, or only an SOA, yields rdata == [] rather than a value of the
    wrong type quietly satisfying an equality.

    The transaction id is VERIFIED rather than trusted: across a batch of many queries a reply
    attributed to the wrong query would grade the wrong thing with no error raised.
    """
    if len(raw) < 12:
        raise ValueError(f"a DNS message is at least 12 bytes, got {len(raw)}: {raw.hex()}")
    rid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", raw[:12])
    if rid != qid:
        raise ValueError(f"the reply carries transaction id {rid}, not the {qid} that was sent")
    if not flags & 0x8000:
        raise ValueError(f"the reply does not have the QR bit set (flags 0x{flags:04x})")
    off = 12
    question = None
    for _ in range(qdcount):
        qname, off = _read_name(raw, off)
        qt, _qclass = struct.unpack(">HH", raw[off:off + 4])
        off += 4
        question = {"name": qname, "type": _TYPE_NAME.get(qt, str(qt))}
    answers, off = _parse_records(raw, off, ancount)
    authority, off = _parse_records(raw, off, nscount)
    additional, _off = _parse_records(raw, off, arcount)
    typed = [r for r in answers if r["type"] == qtype]
    return {
        "id": rid,
        "rcode": flags & 0x000F,
        "aa": bool(flags & 0x0400),
        "tc": bool(flags & 0x0200),
        "question": question,
        "answers": answers,
        "authority": authority,
        "additional": additional,
        "rdata": sorted(r["rdata"] for r in typed),
        "ttls": sorted({r["ttl"] for r in typed}),
        "ttl": (typed[0]["ttl"] if typed else None),
        "name": (answers[0]["name"] if answers else None),
        "raw_hex": raw.hex(),
    }


def _dns_queries(lam, fn_name, ns_ip, requests, rd=False):
    """`requests` is [(name, rtype), ...]. Returns one parsed reply per request, in order.

    A transport failure is an AssertionError rather than a shortened list: a socket error that
    silently dropped a query would shrink the sample of every across-N-queries assertion below
    and let it pass on less evidence than it claims.
    """
    encoded = [_encode_query(name, rtype, rd=rd) for name, rtype in requests]
    out = _invoke(lam, fn_name, {
        "op": "tcp53", "host": ns_ip,
        "payloads": [base64.b64encode(msg).decode() for _qid, msg in encoded],
    })
    replies = out["replies"]
    assert len(replies) == len(requests), (
        f"the DNS transport returned {len(replies)} replies for {len(requests)} queries: {out!r}"
    )
    parsed = []
    for (name, rtype), (qid, _msg), reply in zip(requests, encoded, replies):
        assert reply.get("ok"), (
            f"the query {name} {rtype} to the nameserver {ns_ip} did not complete: {reply!r}"
        )
        parsed.append(_parse_dns(base64.b64decode(reply["raw"]), qid, rtype))
    return parsed


def _dns_query(lam, fn_name, ns_ip, name, rtype, rd=False):
    return _dns_queries(lam, fn_name, ns_ip, [(name, rtype)], rd=rd)[0]


def _nameserver_ips(lam, fn_name, ns_list):
    """Every awsdns nameserver hostname resolved to a literal, as {hostname: ip}.

    Resolved INSIDE the vantage point rather than here: the delegation set is published as
    hostnames, and the queries must be addressed to an address the SENDER can route to.
    """
    out = _invoke(lam, fn_name, {"op": "resolve", "hosts": list(ns_list)})
    resolved = {}
    for host in ns_list:
        entry = out["addresses"][host]
        assert entry["addresses"], (
            f"the delegated nameserver {host} did not resolve from the vantage point: {entry!r}"
        )
        resolved[host] = entry["addresses"][0]
    return resolved


# ---- hosted zones -----------------------------------------------------------------------------


def _caller_reference():
    return f"cr-{secrets.token_hex(16)}"


def _zone_name(ctx, prefix="zone"):
    raw = ctx.unique_name("sim2real-behav-" + prefix).lower().replace("_", "-")
    return f"{raw}.example.test."


def _change(r53, zone_id, changes, tries=4):
    """Submit a ChangeBatch, retrying only the two documented transient conditions."""
    for attempt in range(tries):
        try:
            return r53.change_resource_record_sets(
                HostedZoneId=zone_id, ChangeBatch={"Changes": changes}
            )["ChangeInfo"]["Id"]
        except ClientError as exc:
            if _code_of(exc) not in ("PriorRequestNotComplete", "Throttling") \
                    or attempt == tries - 1:
                raise
            time.sleep(2.0 * (attempt + 1))


def _list_all(r53, zone_id, **extra):
    """Every record set in the zone, fully paginated.

    The account may be shared and these zones carry up to ten siblings at one name, so
    an un-paginated list could miss our own record behind them.
    """
    out = []
    kwargs = {"HostedZoneId": zone_id}
    kwargs.update(extra)
    while True:
        resp = r53.list_resource_record_sets(**kwargs)
        out.extend(resp["ResourceRecordSets"])
        if not resp.get("IsTruncated"):
            return out
        kwargs["StartRecordName"] = resp["NextRecordName"]
        kwargs["StartRecordType"] = resp["NextRecordType"]
        if resp.get("NextRecordIdentifier"):
            kwargs["StartRecordIdentifier"] = resp["NextRecordIdentifier"]


def _at(rrsets, name, rtype):
    want = name.rstrip(".").lower()
    return [r for r in rrsets if r["Name"].rstrip(".").lower() == want and r["Type"] == rtype]


def _zone_gone(r53, zone_id):
    try:
        r53.get_hosted_zone(Id=zone_id)
        return False
    except ClientError as exc:
        return _code_of(exc) == "NoSuchHostedZone"


def _empty_and_delete_zone(r53, zone_id):
    def _non_apex():
        return [r for r in _list_all(r53, zone_id) if r["Type"] not in ("NS", "SOA")]

    leftovers = _non_apex()
    # Alias records first: an alias whose target is a record in the SAME zone blocks that
    # target's deletion.
    leftovers.sort(key=lambda r: 0 if r.get("AliasTarget") else 1)
    if leftovers:
        try:
            _change(r53, zone_id,
                    [{"Action": "DELETE", "ResourceRecordSet": r} for r in leftovers])
        except ClientError:
            for rrs in leftovers:  # one unbatchable set must not strand the rest
                try:
                    _change(r53, zone_id, [{"Action": "DELETE", "ResourceRecordSet": rrs}])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in (
                        "HostedZoneNotFound",
                        "NoSuchHealthCheck",
                        "NoSuchHostedZone",
                    ):
                        raise
    try:
        _poll(_non_apex, lambda rem: rem == [], timeout_s=60.0, interval_s=2.0,
              what=f"the non-apex record sets in {zone_id} to clear before DeleteHostedZone")
    except AssertionError:
        print(f"[route53-cleanup] LEAK: hosted zone {zone_id} still holds record sets and "
              f"cannot be deleted; it bills $0.50/month until removed by hand")
        raise
    r53.delete_hosted_zone(Id=zone_id)
    _poll(lambda: _zone_gone(r53, zone_id), lambda gone: gone,
          timeout_s=60.0, interval_s=2.0,
          what=f"GetHostedZone({zone_id}) to report NoSuchHostedZone after DeleteHostedZone")


def _create_zone(ctx, r53, prefix="zone"):
    """One PUBLIC hosted zone, with its emptying teardown registered AT CREATION TIME.

    Returns (zone id, zone name, the four delegated nameserver hostnames). A public zone is what
    has a delegation set at all, and those four `awsdns-*` servers answer for the zone with NO
    registrar delegation whatsoever, because they ARE its authoritative servers -- nothing has to
    be bought, registered or delegated. AWS does not bill a hosted zone deleted within 12 hours of
    creation, which makes this teardown the single most load-bearing line in the file.
    """
    resp = r53.create_hosted_zone(
        Name=_zone_name(ctx, prefix),
        CallerReference=_caller_reference(),
        HostedZoneConfig={"Comment": "sim2real-behav ga-depth", "PrivateZone": False},
    )
    zone_id = resp["HostedZone"]["Id"]
    ctx.on_cleanup(lambda z=zone_id: _empty_and_delete_zone(r53, z))
    return zone_id, resp["HostedZone"]["Name"], resp["DelegationSet"]["NameServers"]


def _wait_insync(r53, change_id, timeout_s=180.0):
    """Poll GetChange to INSYNC and RETURN the status observed.

    Returned rather than discarded because INSYNC is the only propagation barrier Route 53
    publishes, and one of these checks exists to ask what it guarantees.
    """
    return _poll(
        lambda: r53.get_change(Id=change_id)["ChangeInfo"]["Status"],
        lambda st: st == "INSYNC",
        timeout_s=timeout_s, interval_s=2.0,
        what=f"change {change_id} to reach INSYNC",
    )


# ---- health checks ----------------------------------------------------------------------------
# THE UNRESOLVABLE-FQDN + Inverted IDIOM, which is what makes failover gradeable without
# provisioning an HTTP endpoint anywhere and without sending a packet at any address that is not
# ours. The health check targets a name under `.invalid` -- an RFC 2606 reserved TLD that can
# never be delegated -- so every Route 53 checker fails it identically and deterministically, and
# Inverted then reports it as healthy. Health state becomes a control-plane flag flip.
#
# A reserved address is not an option: Route 53 refuses IPAddress=192.0.2.1 (RFC 5737
# TEST-NET-1) with `InvalidInput: IPv4 address 192.0.2.1 is forbidden`. A `.invalid` FQDN sends
# no traffic to any address, and every checker reports `Failure: DNS resolution failed: Rcode
# NXDomain(3)` within seconds of creation.
#
# NOTE WHAT GetHealthCheckStatus REPORTS, because it is not what it looks like: the per-checker
# StatusReport carries the RAW observation ("Failure: ...") even when Inverted is true. The
# inversion applies to the health check's COMPUTED state, which is what DNS consumes and which no
# API field exposes directly. That is exactly why the evidence for the wiring is the DNS answer and
# never these strings.
#
# A health check bills $0.50/month for a non-AWS endpoint, prorated, and is NOT covered by the
# 12-hour grace period hosted zones get -- so its teardown is registered at creation, and because
# its only handle is a server-minted id, a Name tag carrying the sim2real prefix is applied
# immediately so a prefix- or tag-based cleanup can reach it at all.


def _unresolvable_fqdn(ctx):
    return ctx.unique_name("sim2real-behav-r53hc").lower().replace("_", "-") + ".invalid"


def _create_health_check(ctx, r53, *, inverted):
    """One HTTP health check against an unresolvable name. Returns (id, the HealthCheck object).

    `Inverted` is set in the CREATE call rather than in a follow-up UpdateHealthCheck so the
    record sets below never reference a health check in the wrong state.
    """
    resp = r53.create_health_check(
        CallerReference=_caller_reference(),
        HealthCheckConfig={
            "FullyQualifiedDomainName": _unresolvable_fqdn(ctx),
            "Port": 80,
            "Type": "HTTP",
            "ResourcePath": "/",
            "RequestInterval": 10,
            "FailureThreshold": 1,
            "Inverted": inverted,
        },
    )
    hc_id = resp["HealthCheck"]["Id"]
    ctx.on_cleanup(lambda h=hc_id: _delete_health_check(r53, h))
    r53.change_tags_for_resource(
        ResourceType="healthcheck", ResourceId=hc_id,
        AddTags=[{"Key": "Name", "Value": "sim2real-behav-r53-failover"}] + _MANAGED_TAGS,
    )
    return hc_id, resp["HealthCheck"]


def _delete_health_check(r53, hc_id):
    try:
        r53.delete_health_check(HealthCheckId=hc_id)
    except ClientError as exc:
        if _code_of(exc) != "NoSuchHealthCheck":
            raise


def _health_observations(r53, hc_id):
    """(observations, their StatusReport strings) for the health check.

    GetHealthCheckStatus reports one observation PER AWS health checker -- roughly fifteen of them
    worldwide -- rather than one aggregate boolean, so "is it healthy" only exists as a set of
    per-checker report strings.
    """
    obs = r53.get_health_check_status(HealthCheckId=hc_id)["HealthCheckObservations"]
    return obs, [(entry.get("StatusReport") or {}).get("Status") or "" for entry in obs]

# ===== end helpers =====

_PRIMARY, _SECONDARY, _REFUSED = "203.0.113.50", "203.0.113.51", "203.0.113.52"


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """A second PRIMARY in an established failover group is refused with an exact error code and
    leaves the live group untouched: the refused address is nowhere in the zone, the nameserver
    still answers the PRIMARY, and a legitimate change to the group still reaches INSYNC.
    """
    r53 = ctx.client("route53")
    lam, fn_name = _deploy_dns_vantage(ctx)
    zone_id, zone_name, ns_list = _create_zone(ctx, r53)
    ns_ip = _nameserver_ips(lam, fn_name, ns_list)[sorted(ns_list)[0]]
    hc_id, _hc = _create_health_check(ctx, r53, inverted=True)
    name = f"failover.{zone_name}"

    def _failover(set_id, role, value, health=None):
        rrs = {"Name": name, "Type": "A", "TTL": 1, "SetIdentifier": set_id,
               "Failover": role, "ResourceRecords": [{"Value": value}]}
        if health:
            rrs["HealthCheckId"] = health
        return rrs

    _wait_insync(r53, _change(r53, zone_id, [
        {"Action": "UPSERT", "ResourceRecordSet": _failover("p", "PRIMARY", _PRIMARY, hc_id)},
        {"Action": "UPSERT", "ResourceRecordSet": _failover("s", "SECONDARY", _SECONDARY)},
    ]))
    # THE BARRIER: wait until the group demonstrably resolves to its healthy PRIMARY.
    pre = _poll(
        lambda: _dns_query(lam, fn_name, ns_ip, name, "A"),
        lambda a: a["rdata"] == [_PRIMARY],
        timeout_s=240, interval_s=5,
        what=f"the failover group at {name} to resolve to its healthy PRIMARY {_PRIMARY}",
    )
    assert pre["rdata"] == [_PRIMARY], pre

    # --- break exactly one thing: a SECOND PRIMARY at the same name and type. It carries the
    # health check a non-alias PRIMARY requires, so the duplicate role is the only fault. ---
    code, msg = _error(lambda: r53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={"Changes": [
            {"Action": "CREATE", "ResourceRecordSet": _failover("p2", "PRIMARY", _REFUSED, hc_id)}]},
    ))
    assert code == "InvalidChangeBatch", (
        f"expected InvalidChangeBatch for a second PRIMARY in an established failover group, got "
        f"{code!r}: {msg!r}"
    )
    expected_message = (
        f"[RRSet with DNS name {name}, type A, SetIdentifier p2, and marked  as  PRIMARY cannot be "
        "created because a failover RRSet with the same name and type has already been marked as "
        "primary,]"
    )
    assert msg == expected_message, f"expected message {expected_message!r}, got {msg!r}"

    group = _at(_list_all(r53, zone_id), name, "A")
    assert {r["SetIdentifier"] for r in group} == {"p", "s"}, (
        f"effect absent: the group must be unchanged by the refusal, got {group!r}"
    )
    assert len(group) == 2 and all(r.get("Failover") in ("PRIMARY", "SECONDARY") for r in group), (
        f"the group must still hold exactly one PRIMARY and one SECONDARY: {group!r}"
    )
    assert all(_REFUSED not in [v["Value"] for v in r["ResourceRecords"]] for r in group), (
        f"the refused value {_REFUSED} must appear nowhere in the zone: {group!r}"
    )

    post = _dns_query(lam, fn_name, ns_ip, name, "A")
    assert post["rdata"] == [_PRIMARY], (
        f"positive control: the nameserver must still serve the PRIMARY after the refusal, got "
        f"{post!r}"
    )
    legit_status = _wait_insync(r53, _change(r53, zone_id, [
        {"Action": "UPSERT", "ResourceRecordSet": _failover("s", "SECONDARY", "203.0.113.53")}]))
    assert legit_status == "INSYNC", (
        f"positive control: a legitimate write to the same group must still be accepted and reach "
        f"INSYNC, got {legit_status!r} -- otherwise the refusal wedged the group"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
