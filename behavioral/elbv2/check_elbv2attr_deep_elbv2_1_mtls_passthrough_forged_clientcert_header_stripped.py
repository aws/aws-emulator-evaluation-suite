"""elbv2attr-deep-elbv2-1-mtls-passthrough-forged-clientcert-header-stripped."""
from __future__ import annotations

import http.client
import io
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.parse
import zipfile

from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from behavioral_harness import tags

CHECK = "elbv2attr-deep-elbv2-1-mtls-passthrough-forged-clientcert-header-stripped"
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

_CIDR = "10.184.0.0/16"

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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=2.0, description="condition",
                ctx=None):
    """Bounded retry. RAISES on timeout — never returns its last value."""
    if ctx is not None:
        timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s:.0f}s. Last result: {last!r}")


def _delete_until_gone(fn, gone_codes, *, timeout_s=600, interval_s=10):
    """Retry a delete through DependencyViolation / ResourceInUse until it succeeds or the resource
    is gone; a deleted load balancer releases ENIs and certificates minutes later.

    Raises on timeout."""
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
    """Create an ALB and register its waited teardown immediately (cleanups run LIFO)."""
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
        timeout_s=timeout_s, interval_s=2.0, ctx=ctx,
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


def _write(path, text):
    with open(path, "w", encoding="ascii") as fh:
        fh.write(text)


def _make_ca_chain(ctx, workdir, uniq):
    """root CA -> intermediate CA -> client leaf, all minted locally with the openssl CLI.

    Returns the file paths of the three PEMs plus the leaf key and the chain file the client
    presents (leaf, intermediate, root — in that order)."""
    p = {k: os.path.join(workdir, f"{k}.pem") for k in ("root", "inter", "leaf")}
    k = {n: os.path.join(workdir, f"{n}.key") for n in ("root", "inter", "leaf")}
    _write(os.path.join(workdir, "ca.ext"),
           "basicConstraints=critical,CA:TRUE,pathlen:1\nkeyUsage=critical,keyCertSign,cRLSign\n"
           "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
    _write(os.path.join(workdir, "leaf.ext"),
           "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
           "extendedKeyUsage=clientAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
    _openssl(ctx, "req", "-x509", "-newkey", "rsa:2048", "-noenc", "-sha256", "-days", "2",
             "-keyout", k["root"], "-out", p["root"], "-subj", f"/O=sim2real/CN=sim2real-root-{uniq}",
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign", cwd=workdir)
    for name, issuer, ext in (("inter", "root", "ca.ext"), ("leaf", "inter", "leaf.ext")):
        csr = os.path.join(workdir, f"{name}.csr")
        _openssl(ctx, "req", "-new", "-newkey", "rsa:2048", "-noenc", "-keyout", k[name],
                 "-out", csr, "-subj", f"/O=sim2real/CN=sim2real-{name}-{uniq}", cwd=workdir)
        _openssl(ctx, "x509", "-req", "-in", csr, "-CA", p[issuer], "-CAkey", k[issuer],
                 "-set_serial", str(int.from_bytes(os.urandom(8), "big")), "-days", "2",
                 "-sha256", "-extfile", ext, "-out", p[name], cwd=workdir)
    chain = os.path.join(workdir, "client-chain.pem")
    with open(chain, "w", encoding="ascii") as out:
        for name in ("leaf", "inter", "root"):
            with open(p[name], encoding="ascii") as fh:
                out.write(fh.read())
    return p, k, chain


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

    fn_arn = _poll_until(_try_create, lambda a: a is not None, timeout_s=180, interval_s=2.0, ctx=ctx,
                         description=f"lambda {fn_name} accepting its freshly created role")
    ctx.on_cleanup(lambda: _delete_until_gone(
        lambda: lam.delete_function(FunctionName=fn_name), {"ResourceNotFoundException"},
        timeout_s=120))
    _poll_until(lambda: lam.get_function_configuration(FunctionName=fn_name).get("State"),
                lambda s: s == "Active", timeout_s=180, interval_s=1.0, ctx=ctx,
                description=f"lambda {fn_name} reaching State=Active")

    tg_arn = _retry_throttled(lambda: elb.create_target_group(
        Name=_clamp_name(ctx.unique_name("sim2real-behav-tg-")), TargetType="lambda",
        Tags=list(_TAGS)))["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_until_gone(
        lambda: elb.delete_target_group(TargetGroupArn=tg_arn), {"TargetGroupNotFound"},
        timeout_s=180))
    # Multi-value headers ON: the event then carries EVERY value of a repeated header, so a load
    # balancer that appends its own value beside a client-supplied one cannot hide behind
    # last-value-wins collapsing.
    _retry_throttled(lambda: elb.modify_target_group_attributes(
        TargetGroupArn=tg_arn,
        Attributes=[{"Key": "lambda.multi_value_headers.enabled", "Value": "true"}]))
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

    _poll_until(_register, bool, timeout_s=90, interval_s=2.0, ctx=ctx,
                description="RegisterTargets accepting the lambda once the invoke grant applies")
    return tg_arn


def _https(ctx, host, path, sslctx, headers=None, timeout=15):
    """One HTTPS GET. Returns (status, [(header, value), ...], body_bytes)."""
    # tls: the listener under test is mutual TLS passthrough
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
    """A TLS client context with server verification off: the listener presents a self-signed
    certificate this check minted, and only the client certificate's path is asserted."""
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    if chain:
        c.load_cert_chain(certfile=chain, keyfile=key)
    return c


def _ders_from_pem_text(text):
    """Every certificate in a PEM text, as DER bytes, in order."""
    blocks = []
    marker = "-----END CERTIFICATE-----"
    for part in text.split(marker):
        if "-----BEGIN CERTIFICATE-----" not in part:
            continue
        pem = (part[part.index("-----BEGIN CERTIFICATE-----"):] + marker + "\n").encode("ascii")
        blocks.append(x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER))
    return blocks


#: The target echoes EVERY value of every request header (multi-value mode), lower-cased.
_FN_SRC = '''
import json


def lambda_handler(event, context):
    mv = event.get("multiValueHeaders") or {}
    return {
        "statusCode": 200, "statusDescription": "200 OK", "isBase64Encoded": False,
        "multiValueHeaders": {"Content-Type": ["application/json"]},
        "body": json.dumps({"path": event.get("path"),
                            "headers": {k.lower(): v for k, v in mv.items()}}),
    }
'''

_HDR = "x-amzn-mtls-clientcert"
_FORGED = "-----BEGIN%20CERTIFICATE-----%0Asim2real-forged%0A-----END%20CERTIFICATE-----%0A"


@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """A client cannot forge `X-Amzn-Mtls-Clientcert` through a passthrough mTLS listener: without
    a certificate the header never reaches the target (the request is still served), and beside a
    real certificate it is replaced by the real chain, so the target sees exactly one value.

    Reference: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/mutual-authentication.html
    """
    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    elb = ctx.client("elbv2")

    workdir = tempfile.mkdtemp(prefix="sim2real-mtls-")
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))
    uniq = ctx.unique_name("u")[-10:]
    pems, keys, chain = _make_ca_chain(ctx, workdir, uniq)
    generated = []
    for name in ("leaf", "inter", "root"):
        with open(pems[name], encoding="ascii") as fh:
            generated.extend(_ders_from_pem_text(fh.read()))
    assert len(generated) == 3 and len(set(generated)) == 3, (
        f"openssl produced {len(generated)} certificates ({len(set(generated))} distinct), expected 3"
    )

    server_cn = f"sim2real-mtls-{uniq}.example.com"
    cert_pem, key_pem = _make_server_cert(ctx, workdir, server_cn)
    cert_arn = _import_cert(ctx, cert_pem, key_pem)

    tg_arn = _create_lambda_target(ctx, _FN_SRC)
    vpc_id, subnet_ids = _own_public_vpc(ctx)
    sg_id = _open_sg(ctx, vpc_id, (443,))
    lb = _create_load_balancer(ctx, subnet_ids, sg_id)
    _wait_for_lb_active(ctx, lb["LoadBalancerArn"])

    listener = _retry_throttled(lambda: elb.create_listener(
        LoadBalancerArn=lb["LoadBalancerArn"], Protocol="HTTPS", Port=443,
        SslPolicy="ELBSecurityPolicy-TLS13-1-2-2021-06",
        Certificates=[{"CertificateArn": cert_arn}],
        MutualAuthentication={"Mode": "passthrough"},
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    ))["Listeners"][0]
    listener_arn = listener["ListenerArn"]
    ctx.on_cleanup(lambda: _delete_until_gone(
        lambda: elb.delete_listener(ListenerArn=listener_arn), {"ListenerNotFound"}))

    host = lb["DNSName"]
    with_cert = _client_ctx(chain, keys["leaf"])
    without_cert = _client_ctx()

    def _echo(sslctx, path, headers=None):
        try:
            status, _hdrs, body = _https(ctx, host, path, sslctx, headers)
        except _TRANSPORT_ERRORS as exc:
            return {"transport": f"{type(exc).__name__}: {exc}"}
        try:
            return {"status": status, **json.loads(body)}
        except ValueError:
            return {"status": status, "raw": body[:200].decode("utf-8", "replace")}

    def _served(sslctx, path, headers=None):
        """One request, re-sent while the answer is a transport error or a gateway 5xx."""
        return _poll_until(
            lambda: _echo(sslctx, path, headers),
            lambda r: "transport" not in r and r.get("status") not in (502, 503, 504),
            timeout_s=30, interval_s=1.0, ctx=ctx,
            description=f"the load balancer answering {path} without a transport or gateway error",
        )

    def _chain_of(values):
        return [_ders_from_pem_text(urllib.parse.unquote(v)) for v in values]

    # Positive control: a real certificate arrives as the real chain, as ONE header value.
    ready = _poll_until(
        lambda: _echo(with_cert, "/control"),
        lambda r: r.get("status") == 200 and "headers" in r,
        timeout_s=420, interval_s=2.0, ctx=ctx,
        description="the passthrough HTTPS listener serving the multi-value lambda echo",
    )
    control = ready["headers"].get(_HDR)
    assert control is not None and len(control) == 1, (
        f"control: a real client certificate produced {_HDR} values {control!r}; expected one"
    )
    assert _chain_of(control) == [generated], (
        "control: the forwarded chain is not the generated leaf+intermediate+root"
    )

    # Break exactly one thing: no certificate, and a forged header in its place.
    for attempt in range(3):
        r = _served(without_cert, f"/forged-{attempt}", {"X-Amzn-Mtls-Clientcert": _FORGED})
        assert r.get("status") == 200 and r.get("path") == f"/forged-{attempt}", (
            f"the forged-header request was not served by the target at all: {r!r}"
        )
        assert _HDR not in r["headers"], (
            f"a certificate-less client's forged {_HDR} reached the target as "
            f"{r['headers'].get(_HDR)!r}; the load balancer must strip it"
        )
        assert "x-amzn-trace-id" in r["headers"], (
            f"the echo lacks the ALB's x-amzn-trace-id, so it does not prove the request crossed "
            f"the load balancer: {sorted(r['headers'])!r}"
        )

    # A forged header BESIDE a real certificate: replaced, not appended.
    for attempt in range(3):
        r = _served(with_cert, f"/forged-with-cert-{attempt}", {"X-Amzn-Mtls-Clientcert": _FORGED})
        assert r.get("status") == 200, f"forged header + real certificate was not served: {r!r}"
        vals = r["headers"].get(_HDR)
        assert vals is not None and len(vals) == 1, (
            f"forged header beside a real certificate reached the target as {len(vals or [])} "
            f"value(s); expected exactly one (the load balancer's own)"
        )
        assert "sim2real-forged" not in vals[0], (
            f"the forged value survived into the target's header: {vals[0][:120]!r}"
        )
        assert _chain_of(vals) == [generated], (
            "with a forged header beside a real certificate the target did not receive exactly "
            "the generated leaf+intermediate+root chain"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
