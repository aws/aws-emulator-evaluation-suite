"""elbv2attr-deep-elbv2-1-server-header-removed-and-hsts-injected."""
from __future__ import annotations

import http.client
import urllib.parse
import io
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "elbv2attr-deep-elbv2-1-server-header-removed-and-hsts-injected"
GROUP = "data-plane"
SERVICES = ["elbv2"]

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

_LAMBDA_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})

_CIDR = "10.182.0.0/16"

_TRANSPORT_ERRORS = (OSError, ssl.SSLError, http.client.HTTPException, socket.timeout)


def _clamp_name(name, maxlen=32):
    return name[:maxlen].rstrip("-")


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


def _delete_until_gone(fn, gone_codes, *, timeout_s=600, interval_s=10):
    """Teardown that converges: retry a delete through DependencyViolation / ResourceInUse (a
    deleted load balancer releases its ENIs, and its listener releases its certificate, minutes
    after the delete returns) until it succeeds or the resource is reported gone. Raises on
    timeout so a leak is loud rather than swallowed."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in gone_codes:
                return
            if time.monotonic() > deadline:
                raise
            time.sleep(interval_s)


def _own_public_vpc(ctx, cidr=_CIDR, n_subnets=2):
    """A VPC this check creates, with an IGW and public subnets in n distinct AZs."""
    ec2 = ctx.client("ec2")

    def _tagspec(kind):
        return {"ResourceType": kind, "Tags": list(_TAGS)}

    vpc_id = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[_tagspec("vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_until_gone(
        lambda: ec2.delete_vpc(VpcId=vpc_id), {"InvalidVpcID.NotFound"}))

    azs = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]},
                     {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"]
    )
    assert len(azs) >= n_subnets, (
        f"{ctx.region} exposes {len(azs)} available AZs, need {n_subnets} for a load balancer"
    )

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[_tagspec("internet-gateway")])["InternetGateway"]["InternetGatewayId"]

    def _drop_igw():
        _delete_until_gone(
            lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id),
            {"Gateway.NotAttached", "InvalidInternetGatewayID.NotFound"})
        _delete_until_gone(
            lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id),
            {"InvalidInternetGatewayID.NotFound"})

    ctx.on_cleanup(_drop_igw)
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    rtb_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[_tagspec("route-table")])["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_until_gone(
        lambda: ec2.delete_route_table(RouteTableId=rtb_id), {"InvalidRouteTableID.NotFound"}))
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    octets = cidr.split(".")
    subnet_ids = []
    for i, az in enumerate(azs[:n_subnets]):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"{octets[0]}.{octets[1]}.{i}.0/24",
            AvailabilityZone=az, TagSpecifications=[_tagspec("subnet")],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda s=sid: _delete_until_gone(
            lambda: ec2.delete_subnet(SubnetId=s), {"InvalidSubnetID.NotFound"}))
        subnet_ids.append(sid)
        assoc = ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=sid)["AssociationId"]
        ctx.on_cleanup(lambda a=assoc: _delete_until_gone(
            lambda: ec2.disassociate_route_table(AssociationId=a),
            {"InvalidAssociationID.NotFound"}))
    return vpc_id, subnet_ids


def _open_sg(ctx, vpc_id, ports):
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real elbv2 data-plane ingress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": list(_TAGS)}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_until_gone(
        lambda: ec2.delete_security_group(GroupId=sg_id), {"InvalidGroup.NotFound"}))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": p, "ToPort": p,
             "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]}
            for p in ports
        ],
    )
    return sg_id


def _create_load_balancer(ctx, subnet_ids, sg_id):
    """Billable resource: waited teardown registered AT CREATION (cleanups run LIFO)."""
    elb = ctx.client("elbv2")
    name = _clamp_name(ctx.unique_name("sim2real-behav-lb-"))
    lb = _retry_throttled(lambda: elb.create_load_balancer(
        Name=name, Subnets=subnet_ids, SecurityGroups=[sg_id], Type="application",
        Scheme="internet-facing", Tags=list(_TAGS),
    ))["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]

    def _drop_lb():
        _delete_until_gone(lambda: elb.delete_load_balancer(LoadBalancerArn=arn),
                           {"LoadBalancerNotFound"})
        for _ in range(90):
            try:
                elb.describe_load_balancers(LoadBalancerArns=[arn])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                    raise
                return
            time.sleep(2)

    ctx.on_cleanup(_drop_lb)
    return lb


def _wait_for_lb_active(ctx, lb_arn, timeout_s=600):
    elb = ctx.client("elbv2")
    lb = _poll_until(
        lambda: elb.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0],
        lambda x: x["State"]["Code"] != "provisioning",
        timeout_s=timeout_s, interval_s=10,
        description="load balancer leaving the provisioning state",
    )
    assert lb["State"]["Code"] == "active", (
        f"load balancer state {lb['State']!r}, expected State.Code == 'active'"
    )
    return lb


def _openssl(ctx, *args, cwd):
    r = subprocess.run(["openssl", *args], cwd=cwd, env=ctx.subprocess_env(),
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, f"openssl {' '.join(args[:2])} failed rc={r.returncode}: {r.stderr[-400:]}"
    return r.stdout


def _make_server_cert(ctx, workdir, cn):
    cert = os.path.join(workdir, "server.pem")
    key = os.path.join(workdir, "server.key")
    _openssl(ctx, "req", "-x509", "-newkey", "rsa:2048", "-noenc", "-sha256", "-days", "2",
             "-keyout", key, "-out", cert, "-subj", f"/CN={cn}",
             "-addext", f"subjectAltName=DNS:{cn}",
             "-addext", "extendedKeyUsage=serverAuth", cwd=workdir)
    with open(cert, "rb") as fh:
        cert_pem = fh.read()
    with open(key, "rb") as fh:
        key_pem = fh.read()
    return cert_pem, key_pem


def _import_cert(ctx, cert_pem, key_pem):
    acm = ctx.client("acm")
    arn = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem,
        Tags=[{"Key": t["Key"], "Value": t["Value"]} for t in _TAGS],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_until_gone(
        lambda: acm.delete_certificate(CertificateArn=arn), {"ResourceNotFoundException"},
        timeout_s=300))
    return arn


def _create_lambda_target(ctx, source):
    """A Lambda target behind a lambda target group. The role carries NO policy at all, so the
    function cannot create a CloudWatch log group — nothing outlives the check."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    elb = ctx.client("elbv2")
    role_name = ctx.unique_name("sim2real-behav-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_LAMBDA_TRUST,
        Tags=[{"Key": t["Key"], "Value": t["Value"]} for t in _TAGS],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_until_gone(
        lambda: iam.delete_role(RoleName=role_name), {"NoSuchEntity"}, timeout_s=120))

    fn_name = ctx.unique_name("sim2real-behav-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", source)

    def _try_create():
        try:
            return lam.create_function(
                FunctionName=fn_name, Runtime="python3.12", Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": buf.getvalue()}, Timeout=10, MemorySize=128,
                Tags={t["Key"]: t["Value"] for t in _TAGS},
            )["FunctionArn"]
        except ClientError as exc:
            # IAM propagation: a just-created role is not yet assumable by Lambda.
            if exc.response.get("Error", {}).get("Code") == "InvalidParameterValueException":
                return None
            raise

    fn_arn = _poll_until(_try_create, lambda a: a is not None, timeout_s=180, interval_s=5,
                         description=f"lambda {fn_name} accepting its freshly created role")
    ctx.on_cleanup(lambda: _delete_until_gone(
        lambda: lam.delete_function(FunctionName=fn_name), {"ResourceNotFoundException"},
        timeout_s=120))
    _poll_until(lambda: lam.get_function_configuration(FunctionName=fn_name).get("State"),
                lambda s: s == "Active", timeout_s=180, interval_s=3,
                description=f"lambda {fn_name} reaching State=Active")

    tg_arn = _retry_throttled(lambda: elb.create_target_group(
        Name=_clamp_name(ctx.unique_name("sim2real-behav-tg-")), TargetType="lambda",
        Tags=list(_TAGS)))["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_until_gone(
        lambda: elb.delete_target_group(TargetGroupArn=tg_arn), {"TargetGroupNotFound"},
        timeout_s=180))
    lam.add_permission(FunctionName=fn_name, StatementId="elbv2-invoke",
                       Action="lambda:InvokeFunction",
                       Principal="elasticloadbalancing.amazonaws.com", SourceArn=tg_arn)

    def _register():
        try:
            elb.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": fn_arn}])
            return True
        except ClientError as exc:
            # The invoke grant above propagates asynchronously; RegisterTargets validates it.
            if exc.response.get("Error", {}).get("Code") == "AccessDenied":
                return False
            raise

    _poll_until(_register, bool, timeout_s=90, interval_s=5,
                description="RegisterTargets accepting the lambda once the invoke grant applies")
    return tg_arn


def _https(ctx, host, path, sslctx, headers=None, timeout=15):
    """One HTTPS GET. Returns (status, [(header, value), ...], body_bytes)."""
    # tls: HSTS is injected only on the HTTPS listener under test
    _url, _route = ctx.endpoint_route(f"https://{host}")
    _t = urllib.parse.urlsplit(_url)
    conn = http.client.HTTPSConnection(_t.hostname, _t.port or 443, context=sslctx, timeout=timeout)
    try:
        conn.request("GET", path, headers={**({"Host": host, **(headers or {})}), **_route})
        resp = conn.getresponse()
        return resp.status, resp.getheaders(), resp.read()
    finally:
        conn.close()


def _client_ctx(chain=None, key=None):
    """A TLS client context. Server verification is off ON PURPOSE: the listener presents a
    self-signed certificate this check minted; what is graded is the CLIENT certificate's journey
    to the target, not the server's trust path."""
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    if chain:
        c.load_cert_chain(certfile=chain, keyfile=key)
    return c


#: /bare answers with no Server and no Strict-Transport-Security of its own; /own answers with
#: BOTH, set to values this check owns. Everything else about the two responses is identical.
_FN_SRC = '''
import json


def lambda_handler(event, context):
    headers = {"Content-Type": "text/plain"}
    if event.get("path") == "/own":
        headers["Server"] = "sim2real-origin/7.3"
        headers["Strict-Transport-Security"] = "max-age=60"
    return {"statusCode": 200, "statusDescription": "200 OK", "isBase64Encoded": False,
            "headers": headers, "body": "TARGET:" + str(event.get("path"))}
'''

_HSTS = "max-age=31536000; includeSubDomains; preload"


#: Exactly what each path must carry, per leg: (Server values, sorted HSTS values, body).
_BACKEND_SERVER = "sim2real-origin/7.3"
_BACKEND_HSTS = "max-age=60"
_DEFAULTS = {
    "/bare": (["awselb/2.0"], [], "TARGET:/bare"),
    "/own": ([_BACKEND_SERVER], [_BACKEND_HSTS], "TARGET:/own"),
    "/fixed": (["awselb/2.0"], [], "ALB-FIXED"),
}
_CONFIGURED = {
    "/bare": ([], [_HSTS], "TARGET:/bare"),
    "/own": ([_BACKEND_SERVER], sorted([_BACKEND_HSTS, _HSTS]), "TARGET:/own"),
    "/fixed": ([], [_HSTS], "ALB-FIXED"),
}


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1", "cap:c5")
def run(ctx) -> None:
    """routing.http.response.server.enabled=false stops the ALB adding Server: awselb/2.0 while a target's own Server
    header passes through, and the configured HSTS value is added to every response beside a target's own HSTS
    header; restoring the attributes restores the defaults."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    elb = ctx.client("elbv2")
    workdir = tempfile.mkdtemp(prefix="sim2real-hdr-")
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))
    uniq = ctx.unique_name("u")[-10:]
    cert_pem, key_pem = _make_server_cert(ctx, workdir, f"sim2real-hdr-{uniq}.example.com")
    cert_arn = _import_cert(ctx, cert_pem, key_pem)

    tg_arn = _create_lambda_target(ctx, _FN_SRC)
    vpc_id, subnet_ids = _own_public_vpc(ctx)
    sg_id = _open_sg(ctx, vpc_id, (443,))
    lb = _create_load_balancer(ctx, subnet_ids, sg_id)
    _wait_for_lb_active(ctx, lb["LoadBalancerArn"])
    listener_arn = _retry_throttled(lambda: elb.create_listener(
        LoadBalancerArn=lb["LoadBalancerArn"], Protocol="HTTPS", Port=443,
        SslPolicy="ELBSecurityPolicy-TLS13-1-2-2021-06",
        Certificates=[{"CertificateArn": cert_arn}],
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    ))["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _delete_until_gone(
        lambda: elb.delete_listener(ListenerArn=listener_arn), {"ListenerNotFound"}))
    rule_arn = _retry_throttled(lambda: elb.create_rule(
        ListenerArn=listener_arn, Priority=10,
        Conditions=[{"Field": "path-pattern", "PathPatternConfig": {"Values": ["/fixed"]}}],
        Actions=[{"Type": "fixed-response", "FixedResponseConfig": {
            "StatusCode": "200", "ContentType": "text/plain", "MessageBody": "ALB-FIXED"}}],
    ))["Rules"][0]["RuleArn"]
    ctx.on_cleanup(lambda: _delete_until_gone(
        lambda: elb.delete_rule(RuleArn=rule_arn), {"RuleNotFound"}))

    host = lb["DNSName"]
    tls = _client_ctx()

    def _view(path):
        try:
            status, hdrs, body = _https(ctx, host, path, tls)
        except _TRANSPORT_ERRORS as exc:
            return ("transport", f"{type(exc).__name__}: {exc}")
        return (status,
                [v for k, v in hdrs if k.lower() == "server"],
                sorted(v for k, v in hdrs if k.lower() == "strict-transport-security"),
                body.decode("utf-8", "replace").strip())

    def _snapshot(rounds=3):
        """Every path, several fresh connections each — every load-balancer node must agree."""
        return {p: [_view(p) for _ in range(rounds)] for p in _DEFAULTS}

    def _matches(snap, want):
        return all(v == (200, *want[p]) for p, views in snap.items() for v in views)

    def _attrs():
        return {a["Key"]: a["Value"] for a in elb.describe_listener_attributes(
            ListenerArn=listener_arn)["Attributes"]}

    def _assert_leg(snap, want, leg):
        for p, views in snap.items():
            server, hsts, body = want[p]
            for v in views:
                assert v[0] == 200 and v[3] == body, f"{leg} {p}: status/body {v!r}, expected 200/{body!r}"
                assert v[1] == server, f"{leg} {p}: Server header(s) {v[1]!r}, expected {server!r}"
                assert v[2] == hsts, (
                    f"{leg} {p}: Strict-Transport-Security value(s) {v[2]!r}, expected {hsts!r}")

    # Leg 0 — defaults, the positive control for every arm.
    before = _attrs()
    assert (before.get("routing.http.response.server.enabled"),
            before.get("routing.http.response.strict_transport_security.header_value")) == ("true", ""), (
        f"new HTTPS listener defaults: {before!r}")
    leg0 = _poll_until(_snapshot, lambda s: _matches(s, _DEFAULTS), timeout_s=420, interval_s=10,
                       description="the listener serving all three paths with default headers")
    _assert_leg(leg0, _DEFAULTS, "defaults")

    # Leg 1 — change exactly the two attributes.
    _retry_throttled(lambda: elb.modify_listener_attributes(ListenerArn=listener_arn, Attributes=[
        {"Key": "routing.http.response.server.enabled", "Value": "false"},
        {"Key": "routing.http.response.strict_transport_security.header_value", "Value": _HSTS},
    ]))
    after = _attrs()
    assert (after.get("routing.http.response.server.enabled"),
            after.get("routing.http.response.strict_transport_security.header_value")) == ("false", _HSTS), (
        f"DescribeListenerAttributes after the modify: {after!r}")
    leg1 = _poll_until(_snapshot, lambda s: _matches(s, _CONFIGURED), timeout_s=300, interval_s=5,
                       description="every path reflecting server.enabled=false + the HSTS value")
    _assert_leg(leg1, _CONFIGURED, "configured")
    # The arms, stated individually so a failure names the one that broke.
    assert "server" not in [k.lower() for k, _ in _https(ctx, host, "/bare", tls)[1]], (
        "arm (a): a target that sends no Server header still got one from the load balancer")
    own = _view("/own")
    assert own[1] == [_BACKEND_SERVER], (
        f"arm (b): the target's own Server header became {own[1]!r}; real AWS passes it through")
    assert own[2].count(_HSTS) == 1, (
        f"the configured HSTS value appears {own[2].count(_HSTS)} time(s) on /own: {own[2]!r}")

    # Leg 2 — restore both attributes; the defaults return, so leg 1 was the attributes' doing.
    _retry_throttled(lambda: elb.modify_listener_attributes(ListenerArn=listener_arn, Attributes=[
        {"Key": "routing.http.response.server.enabled", "Value": "true"},
        {"Key": "routing.http.response.strict_transport_security.header_value", "Value": ""},
    ]))
    leg2 = _poll_until(_snapshot, lambda s: _matches(s, _DEFAULTS), timeout_s=300, interval_s=5,
                       description="every path returning to default headers after the restore")
    _assert_leg(leg2, _DEFAULTS, "restored")

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
