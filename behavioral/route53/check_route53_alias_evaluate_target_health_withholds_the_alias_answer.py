"""route53-alias-evaluate-target-health-withholds-the-alias-answer."""

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

CHECK = "route53-alias-evaluate-target-health-withholds-the-alias-answer"
GROUP = "resource-record-sets"
SERVICES = ["route53"]

_SUBJECT = "route53-evaluate-target-health"

# ===== helpers (self-contained) =====
_MANAGED_TAGS = [{"Key": "sim2real", "Value": _SUBJECT},
                 {"Key": "sim2real:managed", "Value": "true"},
                 {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]


def _code_of(exc):
    return exc.response.get("Error", {}).get("Code") or ""


def _msg_of(exc):
    return exc.response.get("Error", {}).get("Message") or str(exc)


def _poll(probe, done, *, timeout_s, interval_s=2.0, what="condition"):
    """Poll an OBSERVABLE condition to a bounded deadline; RAISE on timeout.

    Never a bare sleep standing in for a wait: every wait in this file watches either an AWS API
    field or a DNS answer, both of which report when the thing has actually happened. It raises
    rather than returning its last value so a truncated wait can never be read as a result.
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


def _caller_reference():
    return f"cr-{secrets.token_hex(16)}"

# ---- hosted zones -----------------------------------------------------------------------------
# Zone names use the RFC 2606 reserved `.test` TLD so no third party can ever register them, and
# the emptying teardown RAISES rather than swallowing: a hosted zone that cannot be emptied bills
# $0.50/month forever. AWS does not bill a hosted zone deleted within 12 hours of creation, which
# makes that teardown the single most load-bearing line in this file.



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

    Paginated because these zones carry sibling groups at one name and an un-paginated list could
    miss our own record behind them.
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
    """One PUBLIC hosted zone, tagged, with its emptying teardown registered AT CREATION TIME.

    Returns (zone id, zone name, the four delegated nameserver hostnames). A public zone is what
    has a delegation set at all, and those four `awsdns-*` servers answer for the zone with NO
    registrar delegation whatsoever, because they ARE its authoritative servers -- nothing has to
    be bought, registered or delegated.
    """
    resp = r53.create_hosted_zone(
        Name=_zone_name(ctx, prefix),
        CallerReference=_caller_reference(),
        HostedZoneConfig={"Comment": "sim2real-behav", "PrivateZone": False},
    )
    zone_id = resp["HostedZone"]["Id"]
    ctx.on_cleanup(lambda z=zone_id: _empty_and_delete_zone(r53, z))
    r53.change_tags_for_resource(
        ResourceType="hostedzone", ResourceId=zone_id.split("/")[-1], AddTags=_MANAGED_TAGS,
    )
    return zone_id, resp["HostedZone"]["Name"], resp["DelegationSet"]["NameServers"]


def _wait_insync(r53, change_id, timeout_s=180.0):
    """Poll GetChange to INSYNC and RETURN the status observed.

    INSYNC is the only propagation barrier Route 53 publishes.
    """
    return _poll(
        lambda: r53.get_change(Id=change_id)["ChangeInfo"]["Status"],
        lambda st: st == "INSYNC",
        timeout_s=timeout_s, interval_s=2.0,
        what=f"change {change_id} to reach INSYNC",
    )

# WHY THERE IS A LAMBDA IN A route53 CHECK.
#
# Route 53's data plane is DNS on port 53, served by the four `awsdns-*` nameservers that
# GetHostedZone returns in DelegationSet.NameServers. The check host may have no egress to
# arbitrary internet addresses on port 53, so `socket.create_connection((ns_ip, 53))` from the
# check process cannot be relied on, and a check built on it would report a network restriction
# as a route53 fidelity failure.
#
# A Lambda function with NO VpcConfig has unrestricted outbound internet access and reaches
# awsdns:53 in ~2 ms. It is used purely as a NETWORK VANTAGE POINT: the Lambda is the instrument,
# not the subject, which is why SERVICES still leads with route53.
#
# The handler is deliberately DUMB. It opens sockets, relays bytes and makes no assertions: the
# DNS message is encoded and decoded HERE, next to the assertions, so the assertions grade the
# DNS message itself and the raw wire bytes are the evidence (every parsed reply carries `raw_hex`).
#
# No IAM policy is attached to the execution role. A non-VPC Lambda needs only a trust
# relationship with lambda.amazonaws.com to be created and invoked, and the handler returns every
# diagnostic in its synchronous payload -- while WITHOUT the logs permission no /aws/lambda/<fn>
# log group is ever created, which removes the group that otherwise races function teardown.

_LAMBDA_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow",
                   "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}

_ROLE_NOT_READY = ("cannot be assumed", "does not have permissions", "CreateNetworkInterface",
                   "Lambda was unable to configure your environment")


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


def _delete_log_group(ctx, fn_name):
    """Delete the function's log group, if the first invocation created one.

    MUST run AFTER DeleteFunction, which is why it is registered BEFORE the function's own
    cleanup (ctx.on_cleanup is LIFO). Registered the other way round it deletes the group while
    the function still exists, the next log flush recreates it, and the group leaks.
    ResourceNotFoundException is the NORMAL outcome here: the execution role carries no
    permissions policy at all, so no log group is ever created.
    """
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{fn_name}")
    except ClientError as exc:
        if _code_of(exc) != "ResourceNotFoundException":
            raise


def _plain_exec_role(ctx):
    """A bare Lambda execution role: a trust relationship and nothing else, tagged."""
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


def _deploy_vantage(ctx, role_arn, src, **fn_kwargs):
    """A Lambda running `src`, waited to Active. Returns (lambda client, function name).

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
        Code={"ZipFile": _zipped(src)},
        MemorySize=256,
        Timeout=120,
        Description="sim2real-behav route53 transport",
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
    # first invocation. The ORDER IS LOAD-BEARING: ctx.on_cleanup is LIFO, so registering the log
    # group FIRST makes it run LAST -- after the function is gone.
    ctx.on_cleanup(lambda: _delete_log_group(ctx, fn_name))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))

    cfg = _poll(
        lambda: lam.get_function_configuration(FunctionName=fn_name),
        lambda c: c.get("State") in ("Active", "Failed"),
        timeout_s=300, interval_s=3,
        what=f"the vantage point {fn_name} to leave State=Pending",
    )
    assert cfg["State"] == "Active", (
        f"the vantage point {fn_name} entered State={cfg['State']!r} "
        f"({cfg.get('StateReason')!r}); without it there is no way to send a DNS query at all "
        f"from this host -- see the plumbing note on blocked port-53 egress"
    )
    return lam, fn_name



def _invoke(lam, fn_name, payload):
    """One synchronous Invoke, returning the decoded handler result.

    A FunctionError means the RUNTIME failed rather than the handler reporting a failure -- the
    handler never raises -- so it is the instrument being unusable, never a route53 verdict.
    """
    resp = lam.invoke(FunctionName=fn_name, InvocationType="RequestResponse",
                      Payload=json.dumps(payload).encode())
    raw = resp["Payload"].read()
    assert not resp.get("FunctionError") and resp.get("StatusCode") == 200, (
        f"the vantage point {fn_name} failed to execute: StatusCode={resp.get('StatusCode')!r} "
        f"FunctionError={resp.get('FunctionError')!r}: {raw[:800]!r}"
    )
    out = json.loads(raw)
    assert isinstance(out, dict) and out.get("ok"), (
        f"the transport returned a failure rather than a result: {out!r}"
    )
    return out

_HANDLER_SRC = r"""
# DNS (and plain HTTP) transport, executed by AWS Lambda from a vantage point with egress.
#
# Opens sockets, returns raw bytes, makes NO assertions and NEVER raises out of `handler` -- an
# exception would surface as FunctionError and cost the check the structured evidence it needs to
# attribute the failure, so every failure is a return value.
#
#   {"op": "resolve", "hosts": [...]}                  -> the A records of each hostname
#   {"op": "tcp53", "host": ip, "payloads": [b64, ...]} -> one raw DNS reply per payload, in order
#   {"op": "http", "host": ip, "port": 80, "requests": [{"host_header": h, "path": p}, ...]}
#                                                       -> one raw HTTP response per request
#
# DNS over TCP (RFC 7766) rather than UDP: the 2-byte length prefix makes framing unambiguous and
# no answer can be silently truncated, which matters because these checks assert the SIZE of an
# answer set.
#
# A FRESH CONNECTION PER QUERY, deliberately. Route 53 evaluates weighted, multivalue, latency and
# geolocation routing per query, so a distribution asserted over N queries must not be answered
# off one connection's state.

from __future__ import annotations

import base64
import socket
import time

_CONNECT_TIMEOUT_S = 5
_IO_TIMEOUT_S = 10


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


def _http(host, port, requests):
    out = []
    for req in requests:
        try:
            sock = socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT_S)
        except OSError as exc:
            out.append({"ok": False, "stage": "connect",
                        "error": "%s: %s" % (type(exc).__name__, exc)})
            continue
        try:
            sock.settimeout(_IO_TIMEOUT_S)
            line = "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n" \
                   "User-Agent: sim2real-behav\r\n\r\n" % (req["path"], req["host_header"])
            sock.sendall(line.encode("ascii"))
            buf = b""
            while len(buf) < 262144:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
            out.append({"ok": True, "raw": base64.b64encode(buf).decode()})
        except (OSError, ConnectionError) as exc:
            out.append({"ok": False, "stage": "io",
                        "error": "%s: %s" % (type(exc).__name__, exc)})
        finally:
            try:
                sock.close()
            except OSError:
                pass
    return out


def handler(event, context):
    op = (event or {}).get("op")
    try:
        if op == "resolve":
            return {"ok": True, "addresses": _resolve(event["hosts"])}
        if op == "tcp53":
            return {"ok": True, "replies": _tcp53(event["host"], event["payloads"])}
        if op == "http":
            return {"ok": True, "responses": _http(
                event["host"], int(event.get("port", 80)), event["requests"])}
        return {"ok": False, "stage": "dispatch", "error": "unknown op %r" % (op,)}
    except Exception as exc:
        import traceback
        return {"ok": False, "stage": "handler",
                "error": "%s: %s" % (type(exc).__name__, exc),
                "traceback": traceback.format_exc()[-1200:]}
"""


def _deploy_dns_vantage(ctx):
    """The DNS vantage point: a bare execution role and a non-VPC Lambda running _HANDLER_SRC."""
    return _deploy_vantage(ctx, _plain_exec_role(ctx), _HANDLER_SRC)


# ---- the DNS codec: hand-framed queries, hand-parsed replies ----------------------------------
# dnspython is NOT importable in the check environment. Everything below is stdlib `struct` over
# the bytes the nameserver actually returned, which is the whole point: the graded value is a DNS
# message, not an AWS API response.

_TYPE_NUM = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28,
             "DNSKEY": 48, "RRSIG": 46, "DS": 43}
_TYPE_NAME = {v: k for k, v in _TYPE_NUM.items()}


def _encode_query(name, rtype, rd=False):
    """One DNS query message. Returns (transaction id, bytes).

    RD (recursion desired) defaults OFF because these queries are addressed to the AUTHORITATIVE
    server for the zone: asking it to recurse would be meaningless, and its answer must be
    authoritative, which is what the AA-bit assertions check.
    """
    qid = secrets.randbits(15) + 1
    header = struct.pack(">HHHHHH", qid, 0x0100 if rd else 0x0000, 1, 0, 0, 0)
    labels = [lbl for lbl in name.rstrip(".").split(".") if lbl]
    qname = b"".join(bytes([len(lbl)]) + lbl.encode("ascii") for lbl in labels) + b"\x00"
    return qid, header + qname + struct.pack(">HH", _TYPE_NUM[rtype], 1)


def _read_name(buf, off):
    """A possibly compressed domain name. Returns (name with trailing dot, offset after it).

    Following compression pointers is mandatory: Route 53 compresses the owner name of every
    record after the first, so a parser that cannot follow one reads the answer section as
    garbage instead of failing loudly.
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
    return (".".join(lbl.decode("latin-1") for lbl in labels) + "." if labels else "."), next_off


def _decode_rdata(buf, rtype, start, length):
    """RDATA in its canonical presentation form, per record type.

    Presentation form rather than raw bytes because the assertion has to be readable. An unknown
    type falls through to hex so it is VISIBLE in the failure message rather than silently
    decoding as something else.
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

# The health check targets a name under `.invalid` -- an RFC 2606 reserved TLD that can
# never be delegated -- so every Route 53 checker fails it identically and deterministically, and
# Inverted then reports it as healthy. Health state becomes a control-plane flag flip.
#
# RFC 5737 TEST-NET-1 does NOT work here: Route 53 answers `InvalidInput: IPv4 address 192.0.2.1
# is forbidden`, so the idiom has to be a NAME and not an address. The per-checker StatusReport
# carries the RAW observation ("Failure: DNS resolution failed: Rcode NXDomain(3)") even when
# Inverted is true -- the inversion applies to the COMPUTED state, which is what DNS consumes and
# which no API field exposes. That is why the evidence for any wiring assertion is the DNS answer
# and never these strings.
#
# A health check bills $0.50/month for a non-AWS endpoint and is NOT covered by the 12-hour grace
# period hosted zones get, so its teardown is registered at creation, and because its only handle
# is a server-minted id a Name tag carrying the sim2real prefix is applied immediately so a
# prefix- or tag-based cleanup can reach it at all.


def _unresolvable_fqdn(ctx):
    return ctx.unique_name("sim2real-behav-r53hc").lower().replace("_", "-") + ".invalid"


def _delete_health_check(r53, hc_id):
    try:
        r53.delete_health_check(HealthCheckId=hc_id)
    except ClientError as exc:
        if _code_of(exc) != "NoSuchHealthCheck":
            raise


def _tag_health_check(r53, hc_id):
    r53.change_tags_for_resource(
        ResourceType="healthcheck", ResourceId=hc_id,
        AddTags=[{"Key": "Name", "Value": "sim2real-behav-" + _SUBJECT}] + _MANAGED_TAGS,
    )


def _create_invalid_target_health_check(ctx, r53, *, inverted):
    """One HTTP health check against an unresolvable name, tagged, teardown registered.

    RequestInterval=10 with FailureThreshold=1 is the fastest observable cadence Route 53 offers,
    which is what keeps a multi-transition check inside a wall-clock budget at all.
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
    _tag_health_check(r53, hc_id)
    return hc_id, resp["HealthCheck"]


def _set_inverted(r53, hc_id, *, inverted):
    """UpdateHealthCheck with the CURRENT version, asserting the version actually advanced."""
    before = r53.get_health_check(HealthCheckId=hc_id)["HealthCheck"]
    after = r53.update_health_check(
        HealthCheckId=hc_id, HealthCheckVersion=before["HealthCheckVersion"], Inverted=inverted,
    )["HealthCheck"]
    assert after["HealthCheckConfig"]["Inverted"] is inverted, (
        f"UpdateHealthCheck must set Inverted={inverted}, got "
        f"{after['HealthCheckConfig'].get('Inverted')!r}"
    )
    assert after["HealthCheckVersion"] > before["HealthCheckVersion"], (
        f"UpdateHealthCheck must bump HealthCheckVersion, got {after['HealthCheckVersion']} "
        f"from {before['HealthCheckVersion']}"
    )
    return after

# ===== end helpers =====

_ORIGIN_IP, _FALLBACK_IP, _CONTROL_IP = "203.0.113.130", "203.0.113.131", "203.0.113.132"


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """EvaluateTargetHealth is a live predicate: when the shared target's health check turns
    unhealthy the True alias (a failover PRIMARY) withholds its answer so the SECONDARY is served,
    while the False alias keeps answering the target's address; re-inverting restores both.
    """
    r53 = ctx.client("route53")
    lam, fn_name = _deploy_dns_vantage(ctx)
    zone_id, zone_name, ns_list = _create_zone(ctx, r53, prefix="eth")
    ns_ip = _nameserver_ips(lam, fn_name, ns_list)[sorted(ns_list)[0]]
    bare_zone_id = zone_id.split("/")[-1]

    hc_id, _hc = _create_invalid_target_health_check(ctx, r53, inverted=True)
    origin = f"origin.{zone_name}"
    evaluated = f"evaluated.{zone_name}"
    ignored = f"ignored.{zone_name}"

    _wait_insync(r53, _change(r53, zone_id, [
        # The alias TARGET, carrying the health check whose state the aliases will disagree about.
        {"Action": "UPSERT", "ResourceRecordSet": {
            "Name": origin, "Type": "A", "TTL": 1, "SetIdentifier": "origin",
            "Weight": 1, "HealthCheckId": hc_id,
            "ResourceRecords": [{"Value": _ORIGIN_IP}]}},
        # The subject: a failover PRIMARY alias that EVALUATES the target's health.
        {"Action": "UPSERT", "ResourceRecordSet": {
            "Name": evaluated, "Type": "A", "SetIdentifier": "p", "Failover": "PRIMARY",
            "AliasTarget": {"HostedZoneId": bare_zone_id, "DNSName": origin,
                            "EvaluateTargetHealth": True}}},
        {"Action": "UPSERT", "ResourceRecordSet": {
            "Name": evaluated, "Type": "A", "TTL": 1, "SetIdentifier": "s",
            "Failover": "SECONDARY", "ResourceRecords": [{"Value": _FALLBACK_IP}]}},
        # The control: the same alias, the same target, EvaluateTargetHealth=False.
        {"Action": "UPSERT", "ResourceRecordSet": {
            "Name": ignored, "Type": "A",
            "AliasTarget": {"HostedZoneId": bare_zone_id, "DNSName": origin,
                            "EvaluateTargetHealth": False}}},
    ]))

    def _both():
        return _dns_queries(lam, fn_name, ns_ip, [(evaluated, "A"), (ignored, "A")])

    def _await_pair(want_evaluated, what):
        pair = _poll(_both, lambda p: p[0]["rdata"] == [want_evaluated],
                     timeout_s=300, interval_s=5, what=what)
        assert all(a["aa"] for a in pair), (
            f"both aliases are in this zone, so both answers must be authoritative: {pair!r}"
        )
        return pair

    healthy_eval, healthy_ignored = _await_pair(
        _ORIGIN_IP,
        f"the alias {evaluated} to answer its target's address {_ORIGIN_IP} while the target's "
        f"health check reports healthy")
    assert healthy_ignored["rdata"] == [_ORIGIN_IP], (
        f"the EvaluateTargetHealth=False alias must answer the target's address too: "
        f"{healthy_ignored!r}"
    )
    # Server-side alias resolution, not a redirect: neither answer may contain a CNAME.
    for reply in (healthy_eval, healthy_ignored):
        assert not [r for r in reply["answers"] if r["type"] == "CNAME"], (
            f"an alias is resolved server-side into the target's data; no CNAME may appear in the "
            f"answer section: {reply!r}"
        )

    # --- break exactly one thing: the TARGET's health. No record set is touched. ---
    _set_inverted(r53, hc_id, inverted=False)

    withheld, still_served = _await_pair(
        _FALLBACK_IP,
        f"the alias {evaluated} to withhold its answer and hand {evaluated} to the failover "
        f"SECONDARY {_FALLBACK_IP} once its target's health check stopped reporting healthy")
    assert withheld["rdata"] == [_FALLBACK_IP], (
        f"an EvaluateTargetHealth=True alias over an unhealthy target must not be answered: "
        f"{withheld!r}"
    )
    assert still_served["rdata"] == [_ORIGIN_IP], (
        f"CONTROL: in the same instant, the EvaluateTargetHealth=False alias must STILL answer the "
        f"same target's address {_ORIGIN_IP} -- if it also moved, the target is withholding aliases "
        f"regardless of the flag and the flag is not what this measured: {still_served!r}"
    )

    # --- effect-absent, at the control plane: the record sets are exactly as written. ---
    rrsets = _list_all(r53, zone_id)
    primary = _at(rrsets, evaluated, "A")
    assert {r["SetIdentifier"] for r in primary} == {"p", "s"}, (
        f"the failover group at {evaluated} must be untouched: {primary!r}"
    )
    alias_p = [r for r in primary if r["SetIdentifier"] == "p"][0]
    assert alias_p["AliasTarget"]["EvaluateTargetHealth"] is True, (
        f"the subject alias must still carry EvaluateTargetHealth=True: {alias_p!r}"
    )
    control = _at(rrsets, ignored, "A")
    assert len(control) == 1 and control[0]["AliasTarget"]["EvaluateTargetHealth"] is False, (
        f"the control alias must still carry EvaluateTargetHealth=False: {control!r}"
    )
    target_rrs = _at(rrsets, origin, "A")
    assert len(target_rrs) == 1 and target_rrs[0].get("HealthCheckId") == hc_id, (
        f"the alias target must still reference the health check it started with: {target_rrs!r}"
    )

    # --- restore: the same one flag, and the withheld answer must come back. ---
    _set_inverted(r53, hc_id, inverted=True)
    restored, _control_again = _await_pair(
        _ORIGIN_IP,
        f"the alias {evaluated} to answer {_ORIGIN_IP} again once its target is healthy again -- "
        f"withholding must be reversible, driven by the target's health alone")
    assert restored["rdata"] == [_ORIGIN_IP], (
        f"positive control: the alias must be answerable again: {restored!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
