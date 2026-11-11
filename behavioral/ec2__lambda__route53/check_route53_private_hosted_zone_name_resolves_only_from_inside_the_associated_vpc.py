"""route53-private-hosted-zone-name-resolves-only-from-inside-the-associated-vpc."""
from __future__ import annotations

import base64
import io
import ipaddress
import json
import os
import secrets
import socket
import struct
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "route53-private-hosted-zone-name-resolves-only-from-inside-the-associated-vpc"
GROUP = 'vpc-association'
SERVICES = ['ec2', 'lambda', 'route53']

# A private hosted zone resolves only from inside an associated VPC, so DNS queries are sent from
# a Lambda with VpcConfig. Its handler only relays bytes; DNS is encoded and decoded here.
# Inside Lambda the route to the VPC resolver leaves from a link-local source address, so that
# address is recorded but not asserted; reaching the resolver at all is the in-VPC proof.

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


def _route_source_ip(host, port):
    """The source address the kernel WOULD use to reach host:port.

    connect() on a UDP socket sends no packets -- it only performs a route lookup and binds the
    local end -- so this is free and cannot be satisfied by anything listening at the far end.
    Both outcomes carry information: an address means a route exists and this is the address
    packets toward host would carry, while an OSError (ENETUNREACH / EHOSTUNREACH) means there is
    no route at all, which is what an execution environment never attached to the VPC looks like.

    Pass an IP LITERAL. On a hostname the call blocks in getaddrinfo instead, which settimeout
    does not bound because no socket I/O is involved.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((host, int(port)))
        return sock.getsockname()[0]
    finally:
        sock.close()


def _vantage(event):
    src, err = None, None
    try:
        src = _route_source_ip(event["probe_host"], event.get("probe_port", 53))
    except OSError as exc:
        err = "%s: errno=%s %s" % (type(exc).__name__, getattr(exc, "errno", None), exc)
    return {"src_ip": src, "src_ip_error": err,
            "function": os.environ.get("AWS_LAMBDA_FUNCTION_NAME")}


def handler(event, context):
    op = (event or {}).get("op")
    try:
        if op == "resolve":
            return {"ok": True, "addresses": _resolve(event["hosts"])}
        if op == "tcp53":
            return {"ok": True, "replies": _tcp53(event["host"], event["payloads"])}
        if op == "vantage":
            return {"ok": True, "vantage": _vantage(event)}
        return {"ok": False, "stage": "dispatch", "error": "unknown op %r" % (op,)}
    except Exception as exc:
        import traceback
        return {"ok": False, "stage": "handler",
                "error": "%s: %s" % (type(exc).__name__, exc),
                "traceback": traceback.format_exc()[-1200:]}
'''

_MANAGED_TAGS = [{"Key": "sim2real", "Value": "route53-private-zone-view"},
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
    """Poll an observable condition to a bounded deadline."""
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

    Must run after DeleteFunction (cleanup is LIFO); a missing group is the normal outcome.
    """
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{fn_name}")
    except ClientError as exc:
        if _code_of(exc) != "ResourceNotFoundException":
            raise


def _deploy_vantage(ctx, role_arn, **fn_kwargs):
    """A Lambda running _HANDLER_SRC, waited to Active. Returns (lambda client, function name)."""
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
    # A fresh role is not yet visible to Lambda, and no API reports when its trust is effective.
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
    # ctx.on_cleanup is LIFO: the log group is registered first so it is deleted after the
    # function; the other way round a late log flush recreates it.
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
    """A bare Lambda execution role: a trust relationship and no permissions policy."""
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

    The handler never raises, so a FunctionError means the instrument itself is unusable.
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
# Stdlib `struct` over the raw bytes the nameserver returned; dnspython is not available.

_TYPE_NUM = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28}
_TYPE_NAME = {v: k for k, v in _TYPE_NUM.items()}


def _encode_query(name, rtype, rd=False):
    """One DNS query message. Returns (transaction id, bytes).

    RD defaults off for authoritative servers; it is set only for the recursive VPC resolver.
    """
    qid = secrets.randbits(15) + 1
    header = struct.pack(">HHHHHH", qid, 0x0100 if rd else 0x0000, 1, 0, 0, 0)
    labels = [lbl for lbl in name.rstrip(".").split(".") if lbl]
    qname = b"".join(bytes([len(l)]) + l.encode("ascii") for l in labels) + b"\x00"
    return qid, header + qname + struct.pack(">HH", _TYPE_NUM[rtype], 1)


def _read_name(buf, off):
    """A possibly compressed domain name. Returns (name with trailing dot, offset after it).

    Route 53 compresses owner names after the first record, so pointers must be followed.
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
    """RDATA in its presentation form per record type; unknown types fall through to hex."""
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
    """The whole DNS reply as a dict; `rdata`/`ttl` cover only answers of the queried type.

    The transaction id is verified so a reply cannot be attributed to the wrong query.
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

    A transport failure raises rather than silently shrinking the sample.
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
# The zone teardown raises rather than swallowing (an unemptied zone keeps billing), deletes alias
# records before their in-zone targets, and waits on API state rather than INSYNC. Zone names use
# the RFC 2606 reserved `.test` TLD.


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
    """Every record set in the zone, fully paginated."""
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
    """One PUBLIC hosted zone, with its emptying teardown registered at creation time.

    Returns (zone id, zone name, the four delegated nameserver hostnames).
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
    """Poll GetChange to INSYNC and return the status observed."""
    return _poll(
        lambda: r53.get_change(Id=change_id)["ChangeInfo"]["Status"],
        lambda st: st == "INSYNC",
        timeout_s=timeout_s, interval_s=2.0,
        what=f"change {change_id} to reach INSYNC",
    )


# ---- the in-VPC vantage point -----------------------------------------------------------------
# A private hosted zone exists ONLY from inside a VPC associated with it, so the only vantage
# point that can resolve it is an execution environment attached to that VPC.
# The run's shared VPC and subnets are used rather than a purpose-built VPC: a Lambda's Hyperplane
# ENI holds its subnet for up to ~20 minutes after the function is deleted and cannot be deleted.

# Only the three ENI actions, not AWSLambdaVPCAccessExecutionRole: its Logs actions create
# /aws/lambda/<fn>, which outlives DeleteFunction. The handler returns diagnostics in its payload.
_VPC_ENI_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["ec2:CreateNetworkInterface", "ec2:DescribeNetworkInterfaces",
                   "ec2:DeleteNetworkInterface"],
        "Resource": "*",
    }],
}


def _vpc_resolver(cidr):
    """The VPC's own Route 53 Resolver: the CIDR's base address plus two.

    Addressed directly so NXDOMAIN, SERVFAIL and REFUSED stay distinct; getaddrinfo merges them.
    """
    return str(ipaddress.ip_network(cidr).network_address + 2)


def _paginate(client, op, key, **kwargs):
    out = []
    for page in client.get_paginator(op).paginate(**kwargs):
        out.extend(page.get(key, []))
    return out


def _default_vpc(ec2, *, ctx):
    """(vpc id, cidr, two subnet ids in two AZs, default security group id).

    Both VPC DNS attributes are a private-zone prerequisite, so they are asserted rather than set.
    """
    vpcs = _paginate(ec2, "describe_vpcs", "Vpcs",
                     Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])
    assert len(vpcs) == 1, (
        f"this check needs exactly one shared network VPC in {ec2.meta.region_name}, found "
        f"{[v['VpcId'] for v in vpcs]!r}"
    )
    vpc = vpcs[0]
    for attr, key in (("enableDnsSupport", "EnableDnsSupport"),
                      ("enableDnsHostnames", "EnableDnsHostnames")):
        value = ec2.describe_vpc_attribute(VpcId=vpc["VpcId"], Attribute=attr)[key]["Value"]
        assert value is True, (
            f"the run's shared network {vpc['VpcId']} has {attr}={value!r}; Route 53 requires BOTH DNS "
            f"attributes on a VPC associated with a private hosted zone"
        )
    subnets = _paginate(ec2, "describe_subnets", "Subnets",
                        Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]},
                                 {"Name": "state", "Values": ["available"]},
                                 {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
    by_az = {}
    for sn in sorted(subnets, key=lambda s: s["SubnetId"]):
        by_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
    assert len(by_az) >= 2, (
        f"the run's shared network {vpc['VpcId']} must offer available subnets in at least two "
        f"availability zones, found {by_az!r}"
    )
    groups = _paginate(ec2, "describe_security_groups", "SecurityGroups",
                       Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]},
                                {"Name": "group-name", "Values": ["default"]}])
    assert groups, f"the shared network {vpc['VpcId']} has no default security group"
    return (vpc["VpcId"], vpc["CidrBlock"],
            [by_az[az] for az in sorted(by_az)][:2], groups[0]["GroupId"])


def _vpc_exec_role(ctx):
    """An execution role that can create ENIs, and can do nothing else.

    Without the ENI actions, CreateFunction with VpcConfig is rejected synchronously.
    """
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-r53vpc-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_LAMBDA_TRUST),
        Description="sim2real-behav route53 private-zone in-VPC resolver",
        Tags=_MANAGED_TAGS,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.put_role_policy(RoleName=name, PolicyName="eni-only",
                        PolicyDocument=json.dumps(_VPC_ENI_POLICY))
    return arn


def _private_zone(ctx, r53, vpc_id, region, prefix):
    """One PRIVATE hosted zone associated with vpc_id, teardown registered at creation.

    The association is not a second step: a private zone cannot be CREATED without one, and the
    VPC argument is what makes it private in the first place.
    """
    resp = r53.create_hosted_zone(
        Name=_zone_name(ctx, prefix),
        CallerReference=_caller_reference(),
        HostedZoneConfig={"Comment": "sim2real-behav ga-depth private", "PrivateZone": True},
        VPC={"VPCRegion": region, "VPCId": vpc_id},
    )
    zone_id = resp["HostedZone"]["Id"]
    ctx.on_cleanup(lambda z=zone_id: _empty_and_delete_zone(r53, z))
    return zone_id, resp["HostedZone"]["Name"]


def _zone_vpc_ids(r53, zone_id):
    return sorted(v["VPCId"] for v in r53.get_hosted_zone(Id=zone_id).get("VPCs", []))


def _in_vpc_answers(lam, fn_name, resolver, requests):
    """Parsed replies from the VPC's own Route 53 Resolver for each (name, rtype).

    RD is set: the VPC resolver is recursive, so its answers are non-authoritative.
    """
    return _dns_queries(lam, fn_name, resolver, requests, rd=True)


def _getaddrinfo_via(lam, fn_name, names):
    """{name: {"addresses": [...], "errno": int|None, "error": str|None}} from the vantage point.

    The system-resolver path, which is what an application actually calls.
    """
    return _invoke(lam, fn_name, {"op": "resolve", "hosts": list(names)})["addresses"]


def _resolver_reachable(lam, fn_name, resolver):
    """(reachable, evidence) for the VPC resolver, without asserting anything.

    Any well-formed reply counts whatever its rcode: reachability is the signal, not the answer.
    """
    qid, msg = _encode_query("amazonaws.com", "A", rd=True)
    transport = _invoke(lam, fn_name, {
        "op": "tcp53", "host": resolver,
        "payloads": [base64.b64encode(msg).decode()]})
    reply = transport["replies"][0]
    vantage = _invoke(
        lam, fn_name, {"op": "vantage", "probe_host": resolver, "probe_port": 53})["vantage"]
    evidence = {"resolver": resolver, "reply": {k: v for k, v in reply.items() if k != "raw"},
                "route": vantage}
    if not reply.get("ok"):
        return False, evidence
    # Parsed, not merely received: _parse_dns raises on a wrong transaction id or QR bit. The rcode
    # and the route source address are kept only for failure messages.
    evidence["rcode"] = _parse_dns(base64.b64decode(reply["raw"]), qid, "A")["rcode"]
    return True, evidence


def _prove_in_vpc(lam, fn_name, cidr, resolver, label):
    """Prove this function executes inside the VPC before any resolution result is believed.

    Raises otherwise, so a function never in the VPC cannot pass as "the private zone is private".
    """
    reachable, evidence = _resolver_reachable(lam, fn_name, resolver)
    assert reachable, (
        f"the {label} vantage point cannot reach the VPC resolver {resolver}, an RFC 1918 address "
        f"belonging to the VPC {cidr} that was passed in VpcConfig. So this execution environment "
        f"is not in that VPC and NOTHING about the private zone was measured: {evidence!r}"
    )
    return evidence

_PRIVATE_VALUE = "10.0.0.53"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """A Lambda in the zone's VPC resolves the private name via the VPC resolver and getaddrinfo.
    Identical code outside the VPC cannot resolve it, and cannot reach the VPC resolver at all,
    which proves the two vantage points really differ in network position.
    """
    r53 = ctx.client("route53")
    ec2 = ctx.client("ec2")
    vpc_id, cidr, subnet_ids, sg_id = _default_vpc(ec2, ctx=ctx)
    resolver = _vpc_resolver(cidr)

    zone_id, zone_name = _private_zone(ctx, r53, vpc_id, ctx.region, "pz")
    private_name = f"db.{zone_name}"
    _wait_insync(r53, _change(r53, zone_id, [{
        "Action": "UPSERT",
        "ResourceRecordSet": {"Name": private_name, "Type": "A", "TTL": 60,
                              "ResourceRecords": [{"Value": _PRIVATE_VALUE}]},
    }]))

    zone = r53.get_hosted_zone(Id=zone_id)
    assert zone["HostedZone"]["Config"]["PrivateZone"] is True, (
        f"the zone must be private: {zone['HostedZone']!r}"
    )
    assert _zone_vpc_ids(r53, zone_id) == [vpc_id], (
        f"the zone must be associated with exactly the VPC it was created against: "
        f"{_zone_vpc_ids(r53, zone_id)!r} != [{vpc_id!r}]"
    )

    # --- the two vantage points, from one package -----------------------------------------
    role_arn = _vpc_exec_role(ctx)
    inside_lam, inside_fn = _deploy_vantage(
        ctx, role_arn,
        VpcConfig={"SubnetIds": subnet_ids, "SecurityGroupIds": [sg_id]},
        Timeout=60,
    )
    outside_lam, outside_fn = _deploy_vantage(ctx, role_arn, Timeout=60)

    cfg = inside_lam.get_function_configuration(FunctionName=inside_fn)
    assert sorted((cfg.get("VpcConfig") or {}).get("SubnetIds") or []) == sorted(subnet_ids), (
        f"GetFunctionConfiguration reports VpcConfig.SubnetIds="
        f"{(cfg.get('VpcConfig') or {}).get('SubnetIds')!r}, not the {subnet_ids!r} passed to "
        f"CreateFunction"
    )
    inside_evidence = _prove_in_vpc(inside_lam, inside_fn, cidr, resolver, "in-VPC")
    # THE DIFFERENTIAL: the same address must be UNREACHABLE from the function without VpcConfig.
    # This is what proves the two vantage points genuinely differ in network position, rather than
    # both sitting somewhere that happens to resolve differently.
    outside_reachable, outside_evidence = _resolver_reachable(outside_lam, outside_fn, resolver)
    assert not outside_reachable, (
        f"the VPC resolver {resolver} answered the function that has NO VpcConfig, so the two "
        f"vantage points are not in different networks and the comparison below proves nothing: "
        f"{outside_evidence!r}"
    )

    # --- inside: the private name resolves, both ways -------------------------------------
    answer = _poll(
        lambda: _in_vpc_answers(inside_lam, inside_fn, resolver, [(private_name, "A")])[0],
        lambda a: a["rdata"] == [_PRIVATE_VALUE],
        timeout_s=180, interval_s=5,
        what=f"the VPC resolver {resolver} to answer {private_name} with {_PRIVATE_VALUE} "
             f"from inside {vpc_id}",
    )
    assert answer["rcode"] == 0, (
        f"the VPC resolver must answer NOERROR for a name in an associated private zone, got "
        f"rcode {answer['rcode']}: {answer!r}"
    )
    assert answer["rdata"] == [_PRIVATE_VALUE], (
        f"the in-VPC vantage point must resolve the private name to its configured address: "
        f"{answer!r} (in-VPC proof: {inside_evidence!r})"
    )
    assert answer["ttl"] == 60, (
        f"the configured TTL must be served through the VPC resolver, got {answer['ttl']!r}"
    )
    assert answer["name"].rstrip(".").lower() == private_name.rstrip(".").lower(), answer

    inside_gai = _getaddrinfo_via(inside_lam, inside_fn, [private_name])[private_name]
    assert inside_gai["addresses"] == [_PRIVATE_VALUE], (
        f"the private name must also resolve through getaddrinfo, which is what an application "
        f"actually calls: {inside_gai!r}"
    )

    # --- outside: the identical code cannot resolve it at all -----------------------------
    outside_gai = _getaddrinfo_via(outside_lam, outside_fn, [private_name])[private_name]
    assert outside_gai["addresses"] == [], (
        f"the same code OUTSIDE the VPC must not resolve the private name -- if it does, the zone "
        f"is not private: {outside_gai!r}"
    )
    assert outside_gai["error"], (
        f"the outside-VPC resolution must fail with an error rather than an empty success: "
        f"{outside_gai!r}"
    )
    assert outside_gai["errno"] in (-2, -3, -5), (
        f"the outside-VPC resolution must fail as a NAME resolution failure (EAI_NONAME -2, "
        f"EAI_AGAIN -3 or EAI_NODATA -5), got errno {outside_gai['errno']!r}: {outside_gai!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
