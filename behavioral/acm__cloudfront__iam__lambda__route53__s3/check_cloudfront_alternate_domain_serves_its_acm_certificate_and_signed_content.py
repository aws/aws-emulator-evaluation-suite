"""cloudfront-alternate-domain-serves-its-acm-certificate-and-signed-content."""
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
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from behavioral_harness import tags

CHECK = "cloudfront-alternate-domain-serves-its-acm-certificate-and-signed-content"
GROUP = "data-plane"
SERVICES = ["acm", "cloudfront", "iam", "lambda", "route53", "s3"]

_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}
_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_THROTTLE_CODES = ("TooManyRequestsException", "ThrottlingException", "Throttling")
#: Route 53's fixed hosted zone id for every CloudFront alias target.
_CLOUDFRONT_ZONE_ID = "Z2FDTNDATAQYW2"
#: The AWS-managed "CachingDisabled" cache policy: signed content is never served from a shared entry.
_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
#: The edge error document for a request that carries no signature.
_MISSING_KEY = b"<Code>MissingKey</Code>"


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
        "serve a distribution on"
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
    """Delete cert_arn once ACM lists no user of it: a deleted distribution releases it a while
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


def _wait_deployed(ctx, cf, dist_id):
    """Poll GetDistribution to Deployed; return the ETag read then."""
    seen = {}

    def probe():
        resp = cf.get_distribution(Id=dist_id)
        seen["etag"] = resp["ETag"]
        return resp["Distribution"]["Status"]

    _poll_until(ctx, probe, lambda s: s == "Deployed", timeout_s=1500, interval_s=20,
                description=f"distribution {dist_id} reaching Deployed")
    return seen["etag"]


def _disable_then_delete(ctx, cf, dist_id):
    """Disable the distribution, wait for that to deploy, then delete it."""
    current = cf.get_distribution_config(Id=dist_id)
    config = current["DistributionConfig"]
    if config["Enabled"]:
        config["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=current["ETag"], DistributionConfig=config)
    cf.delete_distribution(Id=dist_id, IfMatch=_wait_deployed(ctx, cf, dist_id))


def _delete_by_etag(get_call, delete_call, resource_id):
    delete_call(Id=resource_id, IfMatch=get_call(Id=resource_id)["ETag"])


def _drain_and_delete_bucket(s3, bucket):
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objects:
            errors = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
            assert not errors, f"DeleteObjects left objects in {bucket!r}: {errors[:3]!r}"
    s3.delete_bucket(Bucket=bucket)


def _cf_safe_b64(data):
    """CloudFront's URL-safe base64: '+' to '-', '/' to '~', '=' to '_'."""
    return base64.b64encode(data).decode().translate(str.maketrans("+/=", "-~_"))


def _signed_query(url, expires, private_key, key_id):
    """The query string of a canned-policy signed URL for url."""
    policy = json.dumps({"Statement": [{
        "Resource": url, "Condition": {"DateLessThan": {"AWS:EpochTime": expires}},
    }]}, separators=(",", ":")).encode()
    signature = private_key.sign(policy, padding.PKCS1v15(), hashes.SHA1())
    return f"Expires={expires}&Signature={_cf_safe_b64(signature)}&Key-Pair-Id={key_id}"


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


# tls-subject: the certificate served for the alternate name is graded, so the connection
# verifies the chain and the hostname with ctx.http_verify, SNI and Host set to that name.
def _https_get(ctx, published_host, name, path):
    """GET https://{name}{path} sent to the published host with SNI and Host set to name, the
    served certificate verified for name. Returns (status, body, peer certificate)."""
    with socket.create_connection(ctx.endpoint_host(published_host, 443), timeout=15) as raw:
        with _https_context(ctx.http_verify).wrap_socket(raw, server_hostname=name) as tls:
            peer = tls.getpeercert()
            tls.sendall(
                f"GET {path} HTTP/1.1\r\nHost: {name}\r\nUser-Agent: sim2real-behav\r\n"
                f"Connection: close\r\n\r\n".encode()
            )
            response = http.client.HTTPResponse(tls)
            response.begin()
            return response.status, response.read(), peer


def _poll_https(ctx, published_host, name, path, accept, description):
    """Poll _https_get until accept(status, body): a just-deployed alternate name can take a while
    to reach every edge. Transport and TLS errors are retried; RAISES on deadline."""
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


def handler(event, context):
    return {server: [_ask(server, q) for q in event["queries"]] for server in event["servers"]}
'''

_LAMBDA_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}
_ROLE_NOT_READY = ("cannot be assumed", "does not have permissions")
_TYPE_A, _TYPE_CNAME, _TYPE_AAAA = 1, 5, 28


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
    role_name = ctx.unique_name("sim2real-behav-cfdns-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_LAMBDA_TRUST), Tags=_TAGS,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    fn_name = ctx.unique_name("sim2real-behav-cfdns-fn-")
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


def _ask_authoritative(lam, fn_name, servers, name, qtypes):
    """{(server, qtype): (rcode, authoritative, answers)} from each of the zone's name servers, or
    None when one of them could not be reached this time, for the caller to ask again."""
    queries = [_dns_query(name, qtype) for qtype in qtypes]
    resp = lam.invoke(FunctionName=fn_name, Payload=json.dumps({
        "servers": servers,
        "queries": [base64.b64encode(message).decode() for _qid, message in queries],
    }).encode())
    payload = resp["Payload"].read()
    if resp.get("FunctionError"):
        return None
    replies = json.loads(payload)
    out = {}
    for server in servers:
        for (qid, _message), qtype, reply in zip(queries, qtypes, replies[server], strict=True):
            if not reply["ok"]:
                return None
            out[(server, qtype)] = _dns_reply(base64.b64decode(reply["raw"]), qid)
    return out


@tags(
    "axis:rejection", "cap:c1", "concern:data-plane", "concern:e2e", "concern:negative-classes",
    "dp:endpoint", "plane:data", "requires:dns-baseline",
)
def run(ctx) -> None:
    """A distribution with an alternate domain name and an issued ACM certificate serves that
    certificate on the name, refuses an unsigned request with 403 MissingKey and returns the private
    S3 object to a signed URL; its Route 53 alias is answered authoritatively as A and AAAA.

    Reference: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/CNAMEs.html
    Reference: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-to-cloudfront-distribution.html
    """
    # CloudFront takes a viewer certificate only from ACM in us-east-1.
    acm = ctx.client("acm", region="us-east-1")
    cf = ctx.client("cloudfront")
    route53 = ctx.client("route53")
    s3 = ctx.client("s3")

    apex, zone_id, servers = _dns_baseline(route53)
    label = ctx.unique_name("sim2real")[:16]
    name = f"{label}.{apex}"
    assert len(name) <= 64, f"ACM caps a certificate's first name at 64 octets; {name!r}"

    cert_arn = _issue_certificate(ctx, acm, route53, zone_id, name)

    bucket = ctx.unique_name("sim2real-behav-cfdom-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(_teardown(lambda: _drain_and_delete_bucket(s3, bucket), "NoSuchBucket"))
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
    })
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAGS})
    content = f"sim2real synthetic object {label}\n".encode()
    s3.put_object(Bucket=bucket, Key="object.txt", Body=content, ContentType="text/plain")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key_id = cf.create_public_key(PublicKeyConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cfdom-pk-"),
        "Name": ctx.unique_name("sim2real-behav-cfdom-pk-"),
        "EncodedKey": private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode(),
    })["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: _delete_by_etag(cf.get_public_key, cf.delete_public_key, public_key_id))
    key_group_id = cf.create_key_group(KeyGroupConfig={
        "Name": ctx.unique_name("sim2real-behav-cfdom-kg-"), "Items": [public_key_id],
    })["KeyGroup"]["Id"]
    ctx.on_cleanup(lambda: _delete_by_etag(cf.get_key_group, cf.delete_key_group, key_group_id))
    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cfdom-oac-"),
        "OriginAccessControlOriginType": "s3", "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_by_etag(cf.get_origin_access_control,
                                           cf.delete_origin_access_control, oac_id))

    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cfdom-cr-"),
        "Comment": "every path requires a signed URL",
        "Enabled": True,
        "IsIPV6Enabled": True,
        "PriceClass": "PriceClass_100",
        "Aliases": {"Quantity": 1, "Items": [name]},
        "ViewerCertificate": {
            "ACMCertificateArn": cert_arn, "SSLSupportMethod": "sni-only",
            "MinimumProtocolVersion": "TLSv1.2_2021",
        },
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "s3origin",
            "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": ""},
            "OriginAccessControlId": oac_id,
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "s3origin",
            "ViewerProtocolPolicy": "https-only",
            "CachePolicyId": _CACHING_DISABLED,
            "TrustedKeyGroups": {"Enabled": True, "Quantity": 1, "Items": [key_group_id]},
        },
    })["Distribution"]
    dist_id, dist_arn, dist_host = dist["Id"], dist["ARN"], dist["DomainName"]
    ctx.on_cleanup(lambda: _disable_then_delete(ctx, cf, dist_id))
    cf.tag_resource(Resource=dist_arn, Tags={"Items": _TAGS})
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:{dist_arn.split(':')[1]}:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": dist_arn}},
        }],
    }))

    aliases = [
        {"Name": name, "Type": rtype, "AliasTarget": {
            "HostedZoneId": _CLOUDFRONT_ZONE_ID, "DNSName": dist_host,
            "EvaluateTargetHealth": False,
        }}
        for rtype in ("A", "AAAA")
    ]
    for rrset in aliases:
        ctx.on_cleanup(_teardown(lambda r=rrset: _change(route53, zone_id, "DELETE", r),
                                 "InvalidChangeBatch"))
        _wait_insync(ctx, route53, _change(route53, zone_id, "CREATE", rrset),
                     f"the {rrset['Type']} alias to the distribution")

    _wait_deployed(ctx, cf, dist_id)
    config = cf.get_distribution(Id=dist_id)["Distribution"]["DistributionConfig"]
    assert config["Aliases"].get("Items") == [name], (
        f"the distribution must hold exactly its alternate domain name; got {config['Aliases']!r}"
    )
    viewer = config["ViewerCertificate"]
    assert viewer.get("ACMCertificateArn") == cert_arn and viewer.get("CertificateSource") == "acm", (
        f"the viewer certificate must be the issued ACM certificate; got {viewer!r}"
    )

    # (1) Each of the zone's own name servers answers the aliases authoritatively under the name
    #     itself, with addresses and no CNAME.
    lam, fn_name = _deploy_vantage(ctx)
    answers = _poll_until(
        ctx, lambda: _ask_authoritative(lam, fn_name, servers, name, (_TYPE_A, _TYPE_AAAA)),
        lambda result: result is not None, timeout_s=120, interval_s=2,
        description="every name server of the zone answering over TCP",
    )
    for (server, qtype), (rcode, authoritative, records) in answers.items():
        assert rcode == 0 and authoritative, (
            f"name server {server} must answer type {qtype} for the alias authoritatively with "
            f"NOERROR; got rcode={rcode} aa={authoritative}"
        )
        assert records and all(r[0] == name.lower() and r[1] == qtype for r in records), (
            f"an alias to a distribution is answered as type {qtype} records under the aliased "
            f"name, never a CNAME; {server} answered {records!r}"
        )

    # (2) An unsigned request on the alternate name is refused with the edge's MissingKey 403,
    #     over a certificate issued for that name.
    status, body, peer = _poll_https(
        ctx, dist_host, name, "/object.txt", lambda s, b: s == 403 and _MISSING_KEY in b,
        "the alternate domain name answering an unsigned request",
    )
    assert _MISSING_KEY in body and content not in body, (
        f"an unsigned request must get the MissingKey error document, never the object; got "
        f"{body[:300]!r}"
    )
    subject_names = [v for kind, v in peer.get("subjectAltName", ()) if kind == "DNS"]
    assert subject_names == [name], (
        f"the served certificate must name exactly the alternate domain name; SANs {subject_names!r}"
    )
    common = [v for rdn in peer.get("subject", ()) for k, v in rdn if k == "commonName"]
    assert common == [name], f"the served certificate's subject CN must be the name; got {common!r}"

    status, body, _peer = _https_get(ctx, dist_host, name, "/")
    assert status == 403 and _MISSING_KEY in body, (
        f"the default path must also be refused with MissingKey; got {status} {body[:300]!r}"
    )

    # (3) A signed URL for the alternate name reaches the private origin through the OAC.
    expires = int(time.time()) + 600
    # tls: the signed policy names the URL the viewer requests on the alternate name
    query = _signed_query(f"https://{name}/object.txt", expires, private_key, public_key_id)
    status, body, _peer = _poll_https(
        ctx, dist_host, name, f"/object.txt?{query}", lambda s, _b: s == 200,
        "a signed URL on the alternate domain name being served",
    )
    assert body == content, f"the signed URL must return the stored bytes; got {body[:300]!r}"

    # (4) ACM reports the distribution as the certificate's user.
    in_use = _poll_until(
        ctx, lambda: acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]["InUseBy"],
        lambda arns: bool(arns), timeout_s=120, interval_s=10,
        description="ACM listing the distribution among the certificate's users",
    )
    assert in_use == [dist_arn], f"InUseBy must name exactly the distribution; got {in_use!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
