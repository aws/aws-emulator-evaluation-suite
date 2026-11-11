"""log-edge-producers-alb-https-access-log-records-negotiated-tls-and-sni."""
from __future__ import annotations

import datetime as _dt
import gzip
import json
import os
import re
import socket
import ssl
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "log-edge-producers-alb-https-access-log-records-negotiated-tls-and-sni"
GROUP = "access-logs"
SERVICES = ["elbv2", "s3"]

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

_LOG_DELIVERY_PRINCIPAL = "logdelivery.elasticloadbalancing.amazonaws.com"
_CIDR = "10.179.0.0/16"

#: The documented ALB access-log field order. AWS only ever APPENDS to it, so these positions are
#: the contract Athena tables are built on; anything past the last name is not asserted.
_FIELDS = (
    "type", "time", "elb", "client:port", "target:port", "request_processing_time",
    "target_processing_time", "response_processing_time", "elb_status_code",
    "target_status_code", "received_bytes", "sent_bytes", "request", "user_agent", "ssl_cipher",
    "ssl_protocol", "target_group_arn", "trace_id", "domain_name", "chosen_cert_arn",
    "matched_rule_priority", "request_creation_time", "actions_executed", "redirect_url",
    "error_reason", "target:port_list", "target_status_code_list", "classification",
    "classification_reason", "conn_trace_id",
)
_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|[^ ]+')
_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_SECONDS = re.compile(r"^\d+\.\d{3}$")


def _retry_throttled(fn, attempts=5):
    delays = [3, 6, 12, 24, 30]
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(delays[min(i, len(delays) - 1)])
    raise last


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=2.0, description="condition"):
    """Bounded retry. RAISES on timeout — never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _retrying_delete(what, fn, *, attempts=40, interval_s=8):
    """Teardown-only: retry through DependencyViolation (ALB ENIs release late). A delete that
    never converges raises, so it cannot vanish silently."""
    def _wrapped():
        last = None
        for _ in range(attempts):
            try:
                fn()
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code.endswith("NotFound") or code.endswith(".NotFound") or code in ("NoSuchBucket", "ResourceNotFoundException"):
                    return
                last = exc
            time.sleep(interval_s)
        raise RuntimeError(f"{what}: {last!r}")

    return _wrapped


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-lel-logs-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)

    def _empty():
        s3.delete_bucket_policy(Bucket=name)
        while True:
            listing = s3.list_objects_v2(Bucket=name, MaxKeys=1000)
            keys = [{"Key": o["Key"]} for o in listing.get("Contents") or []]
            if not keys:
                break
            s3.delete_objects(Bucket=name, Delete={"Objects": keys})
        s3.delete_bucket(Bucket=name)

    # Re-empties on every attempt: a final log flush can land after the load balancer is gone.
    ctx.on_cleanup(_retrying_delete(f"s3 bucket {name}", _empty, attempts=15, interval_s=10))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": list(_TAGS)})
    return name


def _own_vpc(ctx, azs):
    """A VPC this check creates, with an IGW and one public subnet per AZ given."""
    ec2 = ctx.client("ec2")

    def _spec(kind):
        return [{"ResourceType": kind, "Tags": list(_TAGS)}]

    vpc_id = ec2.create_vpc(CidrBlock=_CIDR, TagSpecifications=_spec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(_retrying_delete(f"vpc {vpc_id}", lambda: ec2.delete_vpc(VpcId=vpc_id)))
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=_spec("internet-gateway"))["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(_retrying_delete(
        f"igw {igw_id}", lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id)))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(_retrying_delete(
        f"igw attachment {igw_id}",
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)))
    rtb_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=_spec("route-table"))["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(_retrying_delete(
        f"route table {rtb_id}", lambda: ec2.delete_route_table(RouteTableId=rtb_id)))
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    base = _CIDR.split(".")
    subnets = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"{base[0]}.{base[1]}.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=_spec("subnet"))["Subnet"]["SubnetId"]
        ctx.on_cleanup(_retrying_delete(
            f"subnet {sid}", lambda s=sid: ec2.delete_subnet(SubnetId=s)))
        assoc = ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=sid)["AssociationId"]
        ctx.on_cleanup(_retrying_delete(
            f"rtb association {assoc}",
            lambda a=assoc: ec2.disassociate_route_table(AssociationId=a), attempts=3))
        subnets.append(sid)
    return vpc_id, subnets


def _security_group(ctx, vpc_id, name_prefix, ingress):
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name(name_prefix), Description="sim2real alb access-log check",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": list(_TAGS)}],
    )["GroupId"]
    ctx.on_cleanup(_retrying_delete(
        f"security group {sg_id}", lambda: ec2.delete_security_group(GroupId=sg_id)))
    ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=ingress)
    return sg_id


def _create_load_balancer(ctx, subnets, sg_id):
    elb = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-lel-")
    lb = _retry_throttled(lambda: elb.create_load_balancer(
        Name=name, Subnets=subnets, SecurityGroups=[sg_id], Scheme="internet-facing",
        Type="application", IpAddressType="ipv4", Tags=list(_TAGS)))["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]

    def _drop_lb():
        _retrying_delete(f"load balancer {arn}",
                         lambda: elb.delete_load_balancer(LoadBalancerArn=arn), attempts=5)()
        for _ in range(90):
            try:
                elb.describe_load_balancers(LoadBalancerArns=[arn])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                    raise
                return
            time.sleep(4)
        raise RuntimeError(f"load balancer {arn} still described after 360s")

    ctx.on_cleanup(_drop_lb)
    lb = _poll_until(
        lambda: elb.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0],
        lambda x: x["State"]["Code"] != "provisioning", timeout_s=600, interval_s=10,
        description=f"load balancer {name} leaving provisioning")
    assert lb["State"]["Code"] == "active", f"load balancer state {lb['State']!r}, expected active"
    return lb


def _parse_record(line):
    """Split one entry on single spaces, honouring double-quoted fields, and REFUSE any line whose
    tokens do not re-join to the exact line — so an empty field (two adjacent spaces) cannot be
    silently dropped and shift every later position."""
    raw = _TOKEN.findall(line)
    assert " ".join(raw) == line, (
        f"access-log line is not strictly single-space separated tokens (an empty field?): "
        f"{line!r}")
    values = [t[1:-1] if len(t) >= 2 and t[0] == '"' and t[-1] == '"' else t for t in raw]
    assert len(values) >= len(_FIELDS), (
        f"access-log line has {len(values)} fields, expected at least {len(_FIELDS)}: {line!r}")
    return dict(zip(_FIELDS, values)), values


def _log_objects(ctx, bucket, account):
    s3 = ctx.client("s3")
    out = []
    kwargs = {"Bucket": bucket, "Prefix": f"AWSLogs/{account}/elasticloadbalancing/"}
    while True:
        listing = s3.list_objects_v2(**kwargs)
        for obj in listing.get("Contents") or []:
            raw = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
            assert raw[:2] == b"\x1f\x8b", (
                f"access-log object {obj['Key']!r} is not gzip; first bytes {raw[:8]!r}")
            for line in gzip.decompress(raw).decode("utf-8").splitlines():
                if line.strip():
                    out.append((obj["Key"], line))
        if not listing.get("NextContinuationToken"):
            return out
        kwargs["ContinuationToken"] = listing["NextContinuationToken"]


def _iso(value):
    return _dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=_dt.timezone.utc)

def _self_signed(ctx, cn):
    """An RSA-2048 self-signed certificate made locally with openssl (no AWS call)."""
    with tempfile.TemporaryDirectory() as tmp:
        key, crt = os.path.join(tmp, "k.pem"), os.path.join(tmp, "c.pem")
        r = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
             "-out", crt, "-days", "2", "-subj", f"/CN={cn}"],
            env=ctx.subprocess_env(), capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, f"openssl req failed: {r.stderr[-400:]!r}"
        with open(key, "rb") as fk, open(crt, "rb") as fc:
            return fk.read(), fc.read()


def _import_cert(ctx, key_pem, cert_pem):
    acm = ctx.client("acm")
    arn = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem,
                                 Tags=[{"Key": t["Key"], "Value": t["Value"]} for t in _TAGS]
                                 )["CertificateArn"]
    # Registered BEFORE the load balancer, so LIFO deletes it after the listener is gone; the
    # retry absorbs the ResourceInUseException window while ELB lets go of it.
    ctx.on_cleanup(_retrying_delete(f"acm certificate {arn}",
                                    lambda: acm.delete_certificate(CertificateArn=arn),
                                    attempts=30, interval_s=10))
    return arn


def _tls_get(ctx, ip, sni, host, path, user_agent, *, tls12_cipher=None):
    """One HTTPS request over a raw TLS socket to a load balancer node address, with the SNI and
    Host chosen independently. Returns what the CLIENT negotiated and the exact plaintext bytes
    each way, so the log's TLS and byte fields are derived rather than guessed."""
    tctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tctx.check_hostname = False
    tctx.verify_mode = ssl.CERT_NONE        # self-signed: the chain is compared by DER below
    if tls12_cipher:
        tctx.maximum_version = ssl.TLSVersion.TLSv1_2
        tctx.minimum_version = ssl.TLSVersion.TLSv1_2
        tctx.set_ciphers(tls12_cipher)
    else:
        tctx.minimum_version = ssl.TLSVersion.TLSv1_3
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\n"
           f"Accept: */*\r\nConnection: close\r\n\r\n").encode("ascii")
    with socket.create_connection(ctx.endpoint_host(ip, 443), timeout=20) as raw:
        with tctx.wrap_socket(raw, server_hostname=sni) as sock:
            proto, cipher = sock.version(), sock.cipher()[0]
            peer = sock.getpeercert(binary_form=True)
            sock.sendall(req)
            chunks = []
            while True:
                try:
                    chunk = sock.recv(65536)
                except ssl.SSLZeroReturnError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
    resp = b"".join(chunks)
    head, _, body = resp.partition(b"\r\n\r\n")
    status = int(head.split(b" ", 2)[1]) if head.startswith(b"HTTP/") else None
    return {"sent": len(req), "received": len(resp), "status": status, "proto": proto,
            "cipher": cipher, "peer_der": peer, "body": body.decode("utf-8", "replace")}


_STATUS = "418"
_TLS12_CIPHER = "ECDHE-RSA-AES128-GCM-SHA256"
_POLICY = "ELBSecurityPolicy-TLS13-1-2-2021-06"


# timing:real-time — buffer: 186 s https://docs.aws.amazon.com/elasticloadbalancing/latest/application/enable-access-logging.html
@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:metrics",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "cap:c5",
    "timing:real-time",
)
def run(ctx) -> None:
    """ALB access-log records for HTTPS requests carry, by position, each connection's negotiated
    TLS protocol and cipher, the SNI sent (independent of Host) and the chosen certificate; a
    request answered by a fixed-response action logs '-' for every target field.
    """
    require_tools("openssl")
    elb = ctx.client("elbv2")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]
    marker = ctx.unique_name("m")
    ec2 = ctx.client("ec2")
    azs = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert len(azs) >= 2, f"{ctx.region} exposes {azs!r}; an ALB needs two available AZs"

    key_pem, cert_pem = _self_signed(ctx, f"{marker}.sim2real.invalid")
    cert_der = ssl.PEM_cert_to_DER_cert(cert_pem.decode("ascii"))
    cert_arn = _import_cert(ctx, key_pem, cert_pem)
    bucket = _create_bucket(ctx)
    vpc_id, subnets = _own_vpc(ctx, azs[:2])
    lb_sg = _security_group(ctx, vpc_id, "sim2real-lel-lbsg-", [
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
         "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]}])
    lb = _create_load_balancer(ctx, subnets, lb_sg)
    lb_arn, dns = lb["LoadBalancerArn"], lb["DNSName"]
    partition = lb_arn.split(":")[1]
    lb_id = lb_arn.split(":loadbalancer/", 1)[1]

    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": _LOG_DELIVERY_PRINCIPAL},
                       "Action": "s3:PutObject",
                       "Resource": f"arn:{partition}:s3:::{bucket}/AWSLogs/{account}/*"}],
    }))

    def _enable():
        try:
            return elb.modify_load_balancer_attributes(LoadBalancerArn=lb_arn, Attributes=[
                {"Key": "access_logs.s3.enabled", "Value": "true"},
                {"Key": "access_logs.s3.bucket", "Value": bucket}])["Attributes"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidConfigurationRequest":
                return None
            raise

    _poll_until(_enable, lambda a: a is not None, timeout_s=180, interval_s=10,
                description="access logging accepted once the bucket policy grants log delivery")
    ctx.on_cleanup(_retrying_delete(
        "disable access logs", lambda: elb.modify_load_balancer_attributes(
            LoadBalancerArn=lb_arn,
            Attributes=[{"Key": "access_logs.s3.enabled", "Value": "false"}]), attempts=3))

    fixed_body = f"log-edge-fixed-{marker}"
    listener_arn = elb.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTPS", Port=443, SslPolicy=_POLICY,
        Certificates=[{"CertificateArn": cert_arn}],
        DefaultActions=[{"Type": "fixed-response", "FixedResponseConfig": {
            "StatusCode": _STATUS, "ContentType": "text/plain", "MessageBody": fixed_body}}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(_retrying_delete(
        "listener", lambda: elb.delete_listener(ListenerArn=listener_arn), attempts=3))

    ua = f"sim2real-lel-tls/{marker}"
    other_sni = f"{marker}.sni.sim2real.invalid"

    def _get(path, sni, cipher=None):
        try:
            ip = socket.gethostbyname(ctx.endpoint_host(dns, 443)[0])
            return _tls_get(ctx, ip, sni, dns, path, ua, tls12_cipher=cipher)
        except (OSError, ssl.SSLError) as exc:     # DNS not yet published / listener warming
            return {"status": None, "error": repr(exc)}

    _poll_until(lambda: _get(f"/{marker}/warm", dns), lambda r: r.get("status") == int(_STATUS),
                timeout_s=420, interval_s=10, description="the HTTPS listener serving")

    p13, p12 = f"/{marker}/tls13", f"/{marker}/tls12?q=1"
    r13 = _get(p13, dns)
    r12 = _get(p12, other_sni, _TLS12_CIPHER)
    for label, r in (("tls13", r13), ("tls12", r12)):
        assert r.get("status") == int(_STATUS) and r.get("body") == fixed_body, (
            f"{label} request returned {r!r}, expected the fixed response {_STATUS} {fixed_body!r}")
        assert r["peer_der"] == cert_der, (
            f"{label}: the listener presented a certificate other than the one imported")
    assert (r13["proto"], r12["proto"], r12["cipher"]) == ("TLSv1.3", "TLSv1.2", _TLS12_CIPHER), (
        f"client negotiated {(r13['proto'], r13['cipher'])!r} and {(r12['proto'], r12['cipher'])!r}"
        f"; the check needs two DIFFERENT handshakes to be meaningful")

    wanted = {p13: "tls13", p12: "tls12"}

    def _mine():
        found = {}
        for key, line in _log_objects(ctx, bucket, account):
            rec, _values = _parse_record(line)
            parts = rec["request"].split(" ")
            path = parts[1].split(f"{dns}:443", 1)[-1] if len(parts) == 3 else None
            if path in wanted:
                found.setdefault(wanted[path], []).append((key, line, rec))
        return found

    found = _poll_until(_mine, lambda f: len(f) == 2, timeout_s=1200, interval_s=30,
                        description=f"access-log records for both HTTPS requests in s3://{bucket}")
    for label, recs in found.items():
        print(f"[record:{label}] {recs[0][1]}")
        assert len(recs) == 1, f"{label!r} request produced {len(recs)} records: {recs!r}"

    for label, r, path, sni in (("tls13", r13, p13, dns), ("tls12", r12, p12, other_sni)):
        rec = found[label][0][2]
        # The handshake, as the client negotiated it.
        assert rec["type"] == "https", f"{label} record type is {rec['type']!r}, expected 'https'"
        assert rec["ssl_protocol"] == r["proto"], (
            f"{label} record ssl_protocol is {rec['ssl_protocol']!r}; the client negotiated "
            f"{r['proto']!r}")
        assert rec["ssl_cipher"] == r["cipher"], (
            f"{label} record ssl_cipher is {rec['ssl_cipher']!r}; the client negotiated "
            f"{r['cipher']!r}")
        assert rec["domain_name"] == sni, (
            f"{label} record domain_name is {rec['domain_name']!r}; the ClientHello SNI was {sni!r} "
            f"(Host header was {dns!r})")
        assert rec["chosen_cert_arn"] == cert_arn, (
            f"{label} record chosen_cert_arn is {rec['chosen_cert_arn']!r}, expected {cert_arn!r}")
        # The request as sent.
        assert rec["elb"] == lb_id, f"{label} record elb is {rec['elb']!r}, expected {lb_id!r}"
        want_line = f"GET https://{dns}:443{path} HTTP/1.1"
        assert rec["request"] == want_line, (
            f"{label} record request is {rec['request']!r}, expected {want_line!r}")
        assert rec["user_agent"] == ua, f"{label} record user_agent is {rec['user_agent']!r}"
        assert rec["received_bytes"] == str(r["sent"]), (
            f"{label} record received_bytes is {rec['received_bytes']!r}; this check sent exactly "
            f"{r['sent']} plaintext bytes")
        assert rec["sent_bytes"] == str(r["received"]), (
            f"{label} record sent_bytes is {rec['sent_bytes']!r}; this check received exactly "
            f"{r['received']} plaintext bytes")
        # A fixed-response answer: the load balancer's status, and '-' for every target field.
        assert rec["elb_status_code"] == _STATUS, (
            f"{label} record elb_status_code is {rec['elb_status_code']!r}, expected {_STATUS!r}")
        for name in ("target:port", "target_status_code", "target_group_arn", "target:port_list",
                     "target_status_code_list", "redirect_url", "error_reason", "classification",
                     "classification_reason"):
            assert rec[name] == "-", (
                f"{label} record {name} is {rec[name]!r}, expected '-' — no target was involved")
        assert rec["actions_executed"] == "fixed-response", (
            f"{label} record actions_executed is {rec['actions_executed']!r}")
        assert rec["matched_rule_priority"] == "0", (
            f"{label} record matched_rule_priority is {rec['matched_rule_priority']!r}, expected "
            f"'0' (default action)")
        client_ip, client_port = rec["client:port"].rsplit(":", 1)
        assert client_port.isdigit() and client_ip.count(".") == 3, (
            f"{label} record client:port is {rec['client:port']!r}")
        assert _ISO.match(rec["time"]) and _ISO.match(rec["request_creation_time"]), (
            f"{label} record time fields {rec['time']!r}/{rec['request_creation_time']!r}")
        assert _iso(rec["request_creation_time"]) <= _iso(rec["time"]), (
            f"{label} record request_creation_time is after its response time")
        assert re.match(r"^Root=1-[0-9a-f]{8}-[0-9a-f]{24}$", rec["trace_id"]), (
            f"{label} record trace_id is {rec['trace_id']!r}")
        # Documented: -1 when the request is never dispatched to a target — a fixed response.
        for name in ("request_processing_time", "target_processing_time",
                     "response_processing_time"):
            assert rec[name] == "-1", (
                f"{label} record {name} is {rec[name]!r}, expected '-1' for a fixed-response "
                f"request that was never dispatched to a target")

    rec13, rec12 = found["tls13"][0][2], found["tls12"][0][2]
    assert rec13["conn_trace_id"] != rec12["conn_trace_id"], (
        "two separate TLS connections were logged with one conn_trace_id")
    key_re = re.compile(
        rf"^AWSLogs/{account}/elasticloadbalancing/{re.escape(ctx.region)}/\d{{4}}/\d{{2}}/\d{{2}}/"
        rf"{account}_elasticloadbalancing_{re.escape(ctx.region)}_"
        rf"{re.escape(lb_id.replace('/', '.'))}_\d{{8}}T\d{{4}}Z_[0-9.]+_[0-9a-z]+\.log\.gz$")
    for label, recs in found.items():
        assert key_re.match(recs[0][0]), f"{label} record delivered to {recs[0][0]!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
