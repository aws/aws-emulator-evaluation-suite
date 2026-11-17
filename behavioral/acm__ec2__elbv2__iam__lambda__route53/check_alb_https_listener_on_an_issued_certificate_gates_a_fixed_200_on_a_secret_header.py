"""alb-https-listener-on-an-issued-certificate-gates-a-fixed-200-on-a-secret-header."""
from __future__ import annotations

import base64
import http.client
import io
import json
import secrets
import socket
import ssl
import struct
import time
import zipfile

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "alb-https-listener-on-an-issued-certificate-gates-a-fixed-200-on-a-secret-header"
GROUP = "data-plane"
SERVICES = ["acm", "ec2", "elbv2", "iam", "lambda", "route53"]

_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}
_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_THROTTLE_CODES = ("TooManyRequestsException", "ThrottlingException", "Throttling")
_SECRET_HEADER = "X-Sim2real-Origin-Token"
#: The listener's default answer: a fixed 403 for every request without the secret header.
_REFUSAL = "sim2real fixed refusal"


# ===== helpers (self-contained) =====


def _retry_throttle(fn, *, attempts=8, base_delay=3.0):
    """Call fn(), retrying only a throttle code with linear backoff."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(base_delay * (attempt + 1))
    raise last


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate(result); return it. RAISES on timeout, never returns stale."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; only not_found codes mean gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _dns_baseline(route53):
    """(apex, zone id, name servers) of the public zone carrying _BASELINE_TAG. Fails, never
    skips, when the account has none."""
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for zone in page["HostedZones"]:
            if zone["Config"].get("PrivateZone"):
                continue
            zone_id = zone["Id"].rsplit("/", 1)[-1]
            zone_tags = route53.list_tags_for_resource(
                ResourceType="hostedzone", ResourceId=zone_id
            )["ResourceTagSet"]["Tags"]
            if _BASELINE_TAG in zone_tags:
                servers = route53.get_hosted_zone(Id=zone_id)["DelegationSet"]["NameServers"]
                return zone["Name"].rstrip("."), zone_id, servers
    raise AssertionError(
        "no public hosted zone carries the DNS baseline tag, so the account has no domain to "
        "serve a load balancer on"
    )


def _change(route53, zone_id, action, rrset):
    """One ChangeResourceRecordSets of a single record set; returns the change id."""
    return route53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={"Changes": [{"Action": action, "ResourceRecordSet": rrset}]},
    )["ChangeInfo"]["Id"]


def _wait_insync(ctx, route53, change_id, what):
    _poll_until(
        ctx, lambda: route53.get_change(Id=change_id)["ChangeInfo"]["Status"],
        lambda status: status == "INSYNC", timeout_s=180, interval_s=5,
        description=f"Route 53 applying {what}",
    )


def _delete_certificate_when_free(ctx, acm, cert_arn):
    """Delete cert_arn once ACM lists no user of it: a deleted load balancer releases it a while
    later. RAISES if it is still in use when the cleanup budget ends."""
    try:
        _poll_until(
            ctx, lambda: acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]["InUseBy"],
            lambda users: users == [], timeout_s=900, interval_s=15,
            description=f"certificate {cert_arn} released by its users",
        )
        acm.delete_certificate(CertificateArn=cert_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _issue_certificate(ctx, acm, route53, zone_id, name):
    """A publicly issued, DNS-validated certificate for name. Registers the validation record's
    and the certificate's cleanup, the certificate's to run first."""
    cert_arn = _retry_throttle(lambda: acm.request_certificate(
        DomainName=name, ValidationMethod="DNS", Tags=_TAGS,
    ))["CertificateArn"]
    record = _poll_until(
        ctx,
        lambda: (acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]
                 .get("DomainValidationOptions", [{}])[0].get("ResourceRecord")),
        lambda r: r is not None, timeout_s=120, interval_s=5,
        description="ACM publishing the DNS validation record",
    )
    rrset = {"Name": record["Name"], "Type": record["Type"], "TTL": 60,
             "ResourceRecords": [{"Value": record["Value"]}]}
    ctx.on_cleanup(_teardown(lambda: _change(route53, zone_id, "DELETE", rrset),
                             "InvalidChangeBatch"))
    ctx.on_cleanup(lambda: _delete_certificate_when_free(ctx, acm, cert_arn))
    _change(route53, zone_id, "UPSERT", rrset)
    issued = _poll_until(
        ctx, lambda: acm.describe_certificate(CertificateArn=cert_arn)["Certificate"],
        lambda c: c["Status"] != "PENDING_VALIDATION", timeout_s=900, interval_s=15,
        description=f"the certificate for {name!r} leaving PENDING_VALIDATION",
    )
    assert issued["Status"] == "ISSUED", (
        f"a certificate whose validation record is published must be ISSUED; got "
        f"{issued['Status']!r} ({issued.get('FailureReason')!r})"
    )
    return cert_arn


def _https_context(verify) -> ssl.SSLContext:
    """The TLS context http.client builds by default, verifying with ``ctx.http_verify``."""
    if verify is False:
        context = ssl._create_unverified_context()
    else:
        context = ssl.create_default_context(cafile=verify if isinstance(verify, str) and verify else None)
    context.set_alpn_protocols(["http/1.1"])
    if context.post_handshake_auth is not None:
        context.post_handshake_auth = True
    return context


# tls-subject: the certificate served for the custom name is graded, so the connection
# verifies the chain and the hostname with ctx.http_verify, SNI and Host set to that name.
def _https_get(ctx, published_host, name, path, headers=None):
    """GET https://{name}{path} sent to the published host with SNI and Host set to name, the
    served certificate verified for name. Returns (status, body, peer certificate)."""
    extra = "".join(f"{k}: {v}\r\n" for k, v in (headers or {}).items())
    with socket.create_connection(ctx.endpoint_host(published_host, 443), timeout=15) as raw:
        with _https_context(ctx.http_verify).wrap_socket(raw, server_hostname=name) as tls:
            peer = tls.getpeercert()
            tls.sendall(
                f"GET {path} HTTP/1.1\r\nHost: {name}\r\nUser-Agent: sim2real-behav\r\n{extra}"
                f"Connection: close\r\n\r\n".encode()
            )
            response = http.client.HTTPResponse(tls)
            response.begin()
            return response.status, response.read(), peer


def _poll_https(ctx, published_host, name, path, accept, description):
    """Poll _https_get until accept(status, body): a just-active load balancer's nodes can take a
    while to answer. Transport and TLS errors are retried; RAISES on deadline."""
    last = None
    deadline = time.monotonic() + _budget_s(ctx, 300)
    while time.monotonic() < deadline:
        try:
            result = _https_get(ctx, published_host, name, path)
        except (OSError, http.client.HTTPException) as exc:
            last = f"{type(exc).__name__}: {exc}"
        else:
            if accept(*result[:2]):
                return result
            last = (result[0], result[1][:300])
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description}: never settled. Last: {last!r}")


# ----- an authoritative DNS query, sent from a Lambda function with outbound access -----
# The runner may have no egress on port 53, so the zone's own name servers are asked from a
# function without a VPC. The handler only relays bytes; the reply is decoded and graded here.

_VANTAGE_SRC = r'''
import base64
import socket


def _ask(server, query):
    try:
        address = socket.getaddrinfo(server, 53, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        with socket.create_connection((address, 53), timeout=5) as sock:
            sock.settimeout(5)
            message = base64.b64decode(query)
            sock.sendall(len(message).to_bytes(2, "big") + message)
            buf = b""
            while len(buf) < 2 or len(buf) < 2 + int.from_bytes(buf[:2], "big"):
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
        if len(buf) < 2 or len(buf) < 2 + int.from_bytes(buf[:2], "big"):
            return {"ok": False, "error": "a truncated reply of %d bytes" % len(buf)}
        return {"ok": True, "raw": base64.b64encode(buf[2:]).decode()}
    except OSError as exc:
        return {"ok": False, "error": "%s: %s" % (type(exc).__name__, exc)}


def _addresses(host):
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)})
    except OSError as exc:
        return "%s: %s" % (type(exc).__name__, exc)


def handler(event, context):
    return {
        "answers": {s: [_ask(s, q) for q in event["queries"]] for s in event["servers"]},
        "resolved": _addresses(event["resolve"]),
    }
'''

_LAMBDA_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}
_ROLE_NOT_READY = ("cannot be assumed", "does not have permissions")
_TYPE_A, _TYPE_CNAME, _TYPE_AAAA = 1, 5, 28


def _delete_when_detached(ctx, delete, **kwargs):
    """An EC2 delete retried while the load balancer's network interfaces still hold the object;
    RAISES when they still do at the end of the cleanup budget."""
    deadline = time.monotonic() + _budget_s(ctx, 600)
    while True:
        try:
            delete(**kwargs)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code.endswith(".NotFound"):
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _delete_load_balancer(ctx, elb, lb_arn):
    """Delete the load balancer and wait until DescribeLoadBalancers no longer finds it."""
    try:
        elb.delete_load_balancer(LoadBalancerArn=lb_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "LoadBalancerNotFound":
            return
        raise

    def gone():
        try:
            elb.describe_load_balancers(LoadBalancerArns=[lb_arn])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "LoadBalancerNotFound":
                return True
            raise
        return False

    _poll_until(ctx, gone, bool, timeout_s=300, interval_s=2,
                description=f"load balancer {lb_arn} gone")


def _zipped(src):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", src)
    return buf.getvalue()


def _delete_role(iam, name):
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_log_group(ctx, fn_name):
    """The function's log group, if an invocation created one; its role grants no logging, so
    normally there is none."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{fn_name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _deploy_vantage(ctx):
    """A VPC-less function running _VANTAGE_SRC under a role with no permissions, Active."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    role_name = ctx.unique_name("sim2real-behav-albdns-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_LAMBDA_TRUST), Tags=_TAGS,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    fn_name = ctx.unique_name("sim2real-behav-albdns-fn-")
    deadline = time.monotonic() + _budget_s(ctx, 120)
    while True:
        try:
            lam.create_function(
                FunctionName=fn_name, Runtime="python3.12", Handler="index.handler",
                Role=role_arn, Code={"ZipFile": _zipped(_VANTAGE_SRC)}, Timeout=60,
                Tags={t["Key"]: t["Value"] for t in _TAGS},
            )
            break
        except ClientError as exc:
            # A role created seconds ago is not yet assumable by Lambda; no API reports when it is.
            propagating = exc.response["Error"]["Code"] == "InvalidParameterValueException" and any(
                s in exc.response["Error"]["Message"] for s in _ROLE_NOT_READY
            )
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: _delete_log_group(ctx, fn_name))
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=fn_name),
                             "ResourceNotFoundException"))
    state = _poll_until(
        ctx, lambda: lam.get_function_configuration(FunctionName=fn_name)["State"],
        lambda s: s in ("Active", "Failed"), timeout_s=180, interval_s=3,
        description="the DNS query function becoming Active",
    )
    assert state == "Active", f"the DNS query function ended {state!r}"
    return lam, fn_name


def _dns_query(name, qtype):
    """(transaction id, message) of a non-recursive query for name and qtype."""
    qid = secrets.randbits(16)
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split(".")) + b"\x00"
    return qid, struct.pack(">HHHHHH", qid, 0, 1, 0, 0, 0) + qname + struct.pack(">HH", qtype, 1)


def _read_name(buf, off):
    """A possibly compressed name at off: (lower-case name, offset after it)."""
    labels, end, hops = [], None, 0
    while True:
        length = buf[off]
        if length & 0xC0 == 0xC0:
            end = off + 2 if end is None else end
            off = ((length & 0x3F) << 8) | buf[off + 1]
            hops += 1
            assert hops < 32, "a DNS compression pointer loop"
            continue
        if length == 0:
            return ".".join(labels).lower(), off + 1 if end is None else end
        labels.append(buf[off + 1:off + 1 + length].decode("ascii"))
        off += 1 + length


def _dns_reply(raw, qid):
    """(rcode, authoritative, answers) of the reply to qid; answers are (owner, type, value)."""
    rid, flags, qdcount, ancount, _ns, _ar = struct.unpack(">HHHHHH", raw[:12])
    assert rid == qid and flags & 0x8000, f"not the reply to query {qid}: {raw[:12].hex()}"
    off = 12
    for _ in range(qdcount):
        off = _read_name(raw, off)[1] + 4
    answers = []
    for _ in range(ancount):
        owner, off = _read_name(raw, off)
        rtype, _cls, _ttl, length = struct.unpack(">HHIH", raw[off:off + 10])
        off += 10
        if rtype == _TYPE_A:
            value = socket.inet_ntop(socket.AF_INET, raw[off:off + length])
        elif rtype == _TYPE_AAAA:
            value = socket.inet_ntop(socket.AF_INET6, raw[off:off + length])
        elif rtype == _TYPE_CNAME:
            value = _read_name(raw, off)[0]
        else:
            value = raw[off:off + length].hex()
        answers.append((owner, rtype, value))
        off += length
    return flags & 0x000F, bool(flags & 0x0400), answers


def _ask_authoritative(lam, fn_name, servers, name, qtypes, resolve):
    """({(server, qtype): (rcode, authoritative, answers)} from each of the zone's name servers,
    the IPv4 addresses the function's own resolver gives for resolve), or None when a server could
    not be reached this time, for the caller to ask again."""
    queries = [_dns_query(name, qtype) for qtype in qtypes]
    resp = lam.invoke(FunctionName=fn_name, Payload=json.dumps({
        "servers": servers, "resolve": resolve,
        "queries": [base64.b64encode(message).decode() for _qid, message in queries],
    }).encode())
    payload = resp["Payload"].read()
    if resp.get("FunctionError"):
        return None
    replies = json.loads(payload)
    out = {}
    for server in servers:
        for (qid, _message), qtype, reply in zip(
            queries, qtypes, replies["answers"][server], strict=True
        ):
            if not reply["ok"]:
                return None
            out[(server, qtype)] = _dns_reply(base64.b64decode(reply["raw"]), qid)
    return out, replies["resolved"]


@tags(
    "axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint",
    "plane:data", "requires:dns-baseline",
)
def run(ctx) -> None:
    """An internet-facing ALB's HTTPS listener serves the issued ACM certificate for its Route 53
    alias name, answers its fixed 403 without the secret header or with a wrong value, and the
    header rule's fixed 200 with it; the zone's name servers answer the alias with the ALB's addresses.

    Reference: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-update-rules.html
    Reference: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-to-elb-load-balancer.html
    """
    acm = ctx.client("acm")
    ec2 = ctx.client("ec2")
    elb = ctx.client("elbv2")
    route53 = ctx.client("route53")

    apex, zone_id, servers = _dns_baseline(route53)
    label = ctx.unique_name("sim2real")[:16]
    name = f"{label}.{apex}"
    assert len(name) <= 64, f"ACM caps a certificate's first name at 64 octets; {name!r}"
    secret = secrets.token_hex(16)
    content = f"sim2real synthetic response {label}"

    cert_arn = _issue_certificate(ctx, acm, route53, zone_id, name)

    net = ctx.network()
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-albdom-sg-"),
        Description="HTTPS from the runner only", VpcId=net.vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _TAGS}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_when_detached(ctx, ec2.delete_security_group, GroupId=sg_id))
    ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
        "IpRanges": [{"CidrIp": cidr} for cidr in ctx.ingress_cidrs()],
    }])

    lb = elb.create_load_balancer(
        Name=ctx.unique_name("sim2real-albdom-"), Subnets=list(net.subnet_ids)[:2],
        SecurityGroups=[sg_id], Scheme="internet-facing", Type="application",
        IpAddressType="ipv4", Tags=_TAGS,
    )["LoadBalancers"][0]
    lb_arn, lb_host, lb_zone = lb["LoadBalancerArn"], lb["DNSName"], lb["CanonicalHostedZoneId"]
    ctx.on_cleanup(lambda: _delete_load_balancer(ctx, elb, lb_arn))

    listener_arn = elb.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTPS", Port=443,
        Certificates=[{"CertificateArn": cert_arn}],
        DefaultActions=[{"Type": "fixed-response", "FixedResponseConfig": {
            "StatusCode": "403", "ContentType": "text/plain", "MessageBody": _REFUSAL}}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(_teardown(lambda: elb.delete_listener(ListenerArn=listener_arn),
                             "ListenerNotFound"))
    elb.create_rule(
        ListenerArn=listener_arn, Priority=10,
        Conditions=[{"Field": "http-header", "HttpHeaderConfig": {
            "HttpHeaderName": _SECRET_HEADER, "Values": [secret]}}],
        Actions=[{"Type": "fixed-response", "FixedResponseConfig": {
            "StatusCode": "200", "ContentType": "text/plain", "MessageBody": content}}],
    )

    alias = {"Name": name, "Type": "A", "AliasTarget": {
        "HostedZoneId": lb_zone, "DNSName": lb_host, "EvaluateTargetHealth": False,
    }}
    ctx.on_cleanup(_teardown(lambda: _change(route53, zone_id, "DELETE", alias),
                             "InvalidChangeBatch"))
    _wait_insync(ctx, route53, _change(route53, zone_id, "CREATE", alias),
                 "the A alias to the load balancer")

    state = _poll_until(
        ctx, lambda: elb.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
        ["State"]["Code"],
        lambda code: code in ("active", "failed"), timeout_s=600, interval_s=5,
        description="the load balancer leaving provisioning",
    )
    assert state == "active", f"the load balancer must become active; it is {state!r}"

    # (1) Each of the zone's own name servers answers the alias authoritatively, under the name
    #     itself, with addresses the load balancer's own name resolves to.
    lam, fn_name = _deploy_vantage(ctx)

    def ask():
        return _ask_authoritative(lam, fn_name, servers, name, (_TYPE_A,), lb_host)

    answers, resolved = _poll_until(
        ctx, ask,
        lambda result: result is not None and isinstance(result[1], list) and all(
            {r[2] for r in records} & set(result[1])
            for _rcode, _aa, records in result[0].values()
        ),
        timeout_s=180, interval_s=2,
        description="the alias answers sharing an address with the load balancer's own name",
    )
    for (server, _qtype), (rcode, authoritative, records) in answers.items():
        assert rcode == 0 and authoritative, (
            f"name server {server} must answer the alias authoritatively with NOERROR; got "
            f"rcode={rcode} aa={authoritative}"
        )
        assert records and all(r[0] == name.lower() and r[1] == _TYPE_A for r in records), (
            f"an alias to a load balancer is answered as A records under the aliased name, never "
            f"a CNAME; {server} answered {records!r}"
        )

    # (2) Without the header the listener's fixed 403, over a certificate issued for the name.
    status, body, peer = _poll_https(
        ctx, lb_host, name, "/", lambda s, b: s == 403 and b == _REFUSAL.encode(),
        "the listener answering its fixed refusal on the custom name",
    )
    subject_names = [v for kind, v in peer.get("subjectAltName", ()) if kind == "DNS"]
    assert subject_names == [name], (
        f"the served certificate must name exactly the custom name; SANs {subject_names!r}"
    )
    common = [v for rdn in peer.get("subject", ()) for k, v in rdn if k == "commonName"]
    assert common == [name], f"the served certificate's subject CN must be the name; got {common!r}"

    # (3) A wrong header value matches no rule and gets the same refusal.
    status, body, _peer = _https_get(ctx, lb_host, name, "/", {_SECRET_HEADER: secrets.token_hex(16)})
    assert (status, body) == (403, _REFUSAL.encode()), (
        f"a wrong {_SECRET_HEADER} value must get the default fixed 403; got {status} {body[:200]!r}"
    )

    # (4) The secret header selects the rule's fixed 200.
    status, body, _peer = _https_get(ctx, lb_host, name, "/", {_SECRET_HEADER: secret})
    assert (status, body) == (200, content.encode()), (
        f"the secret header must select the rule's fixed 200; got {status} {body[:200]!r}"
    )

    # (5) ACM reports the load balancer as the certificate's user.
    in_use = _poll_until(
        ctx, lambda: acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]["InUseBy"],
        lambda arns: bool(arns), timeout_s=120, interval_s=2,
        description="ACM listing the load balancer among the certificate's users",
    )
    assert in_use == [lb_arn], f"InUseBy must name exactly the load balancer; got {in_use!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
