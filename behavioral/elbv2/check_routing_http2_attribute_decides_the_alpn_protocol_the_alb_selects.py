"""routing-http2-attribute-decides-the-alpn-protocol-the-alb-selects."""
from __future__ import annotations

import datetime
import socket
import ssl
import time
import urllib.parse

from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from behavioral_harness import tags

CHECK = "routing-http2-attribute-decides-the-alpn-protocol-the-alb-selects"
GROUP = "tls"
SERVICES = ["elbv2"]

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

_CIDR = "10.180.0.0/16"


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


#: Already-gone answers of the deletes this check's teardowns make; in-use answers are retried.
_GONE = frozenset({
    "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound",
    "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached", "InvalidRouteTableID.NotFound",
    "InvalidAssociationID.NotFound", "InvalidInstanceID.NotFound", "LoadBalancerNotFound",
    "TargetGroupNotFound", "ListenerNotFound", "TrustStoreNotFound", "ResourceNotFoundException",
    "NoSuchBucket", "NoSuchKey",
})
_IN_USE = frozenset({"ResourceInUse", "ResourceInUseException", "DependencyViolation"})


def _safe_cleanup(fn):
    """Teardown call: an already-gone resource counts as deleted, an in-use one is retried every
    2 s, anything else raises."""
    def _wrapped():
        deadline = time.monotonic() + 180.0
        while True:
            try:
                fn()
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code in _GONE:
                    return
                if code not in _IN_USE or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    return _wrapped


def _own_public_vpc(ctx, cidr=_CIDR, n_subnets=2):
    """A VPC this check creates, with an IGW and public subnets in n distinct AZs."""
    ec2 = ctx.client("ec2")

    def _tagspec(kind):
        return {"ResourceType": kind, "Tags": list(_TAGS)}

    vpc_id = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[_tagspec("vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(_safe_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    ]
    assert len(azs) >= n_subnets, (
        f"{ctx.region} exposes {len(azs)} available AZs, need {n_subnets} for a load balancer"
    )

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[_tagspec("internet-gateway")])["InternetGateway"]["InternetGatewayId"]

    def _drop_igw():
        _safe_cleanup(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id))()
        _safe_cleanup(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))()

    ctx.on_cleanup(_drop_igw)
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    rtb_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[_tagspec("route-table")])["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(_safe_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rtb_id)))
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    octets = cidr.split(".")
    subnet_ids = []
    for i, az in enumerate(azs[:n_subnets]):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"{octets[0]}.{octets[1]}.{i}.0/24",
            AvailabilityZone=az, TagSpecifications=[_tagspec("subnet")],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(_safe_cleanup(lambda s=sid: _delete_net(ec2, "delete_subnet", SubnetId=s)))
        ec2.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value": True})
        assoc = ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=sid)["AssociationId"]
        ctx.on_cleanup(_safe_cleanup(lambda a=assoc: ec2.disassociate_route_table(AssociationId=a)))
    return vpc_id, subnet_ids


def _open_sg(ctx, vpc_id, ports=(443,)):
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real elbv2 tls ingress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": list(_TAGS)}],
    )["GroupId"]

    def _drop_sg():
        # _delete_net retries DependencyViolation while ENIs release; an already-deleted group is gone.
        try:
            _delete_net(ec2, "delete_security_group", GroupId=sg_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidGroup.NotFound":
                raise

    ctx.on_cleanup(_drop_sg)
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": p, "ToPort": p,
             "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]}
            for p in ports
        ],
    )
    return sg_id


def _create_load_balancer(ctx, subnet_ids, **kwargs):
    """Billable resource: waited teardown registered AT CREATION (cleanups run LIFO)."""
    elb = ctx.client("elbv2")
    name = _clamp_name(kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-lb-"))
    params = dict(Name=name, Subnets=subnet_ids, Type="application",
                  Scheme="internal", Tags=list(_TAGS))
    params.update(kwargs)
    lb = _retry_throttled(lambda: elb.create_load_balancer(**params))["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]

    def _drop_lb():
        try:
            elb.delete_load_balancer(LoadBalancerArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                raise
            return
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
        lambda x: x["State"]["Code"] in ("active", "active_impaired", "failed"),
        timeout_s=timeout_s, interval_s=10,
        description="load balancer reaching a terminal provisioning state",
    )
    assert lb["State"]["Code"] == "active", (
        f"load balancer state {lb['State']!r}, expected State.Code == 'active'"
    )
    return lb


def _create_listener(ctx, lb_arn, **kwargs):
    elb = ctx.client("elbv2")
    params = dict(LoadBalancerArn=lb_arn)
    params.update(kwargs)
    listener = _retry_throttled(lambda: elb.create_listener(**params))["Listeners"][0]
    arn = listener["ListenerArn"]
    ctx.on_cleanup(_safe_cleanup(lambda: elb.delete_listener(ListenerArn=arn)))
    return listener


def _fixed(body, status="200", content_type="text/plain"):
    return [{"Type": "fixed-response", "FixedResponseConfig": {
        "StatusCode": status, "ContentType": content_type, "MessageBody": body}}]


def _make_self_signed(cn):
    """A self-signed server certificate + key, both PEM.

    Self-signed deliberately: ACM will not ISSUE a publicly trusted certificate for a domain this
    account does not own, but acm.import_certificate accepts a self-signed one, and this check grades
    the negotiated ALPN protocol rather than the chain.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        # Backdated an hour so clock skew cannot make ACM see a not-yet-valid certificate.
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )


def _import_cert(ctx, cn):
    acm = ctx.client("acm")
    cert_pem, key_pem = _make_self_signed(cn)
    arn = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem,
        Tags=[{"Key": t["Key"], "Value": t["Value"]} for t in _TAGS],
    )["CertificateArn"]

    def _drop_cert():
        # An in-use certificate cannot be deleted, and the listener's release lags its own delete,
        # so this is a bounded retry rather than a single call.
        deadline = time.monotonic() + 120.0
        while True:
            try:
                acm.delete_certificate(CertificateArn=arn)
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "ResourceNotFoundException":
                    return
                if code != "ResourceInUseException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_drop_cert)
    return arn


def _alpn(ctx, host, offered, *, port=443, timeout=15, speak_http11=False):
    """Handshake offering `offered` via ALPN; return (selected, status, body).

    `status`/`body` are None unless `speak_http11` and the server did not select "h2" — HTTP/1.1
    bytes cannot be sent over a connection that negotiated h2, so the request leg only runs where it
    is legal. A server that leaves HTTP/2 disabled does not necessarily answer the ALPN extension at
    all: `selected` can come back None (no protocol negotiated) rather than the explicit string
    "http/1.1", and a connection with no negotiated protocol is still HTTP/1.1 on the wire by
    convention, so it is probed the same way. That is a protocol constraint, not an assertion fork.
    """
    sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    sslctx.check_hostname = False
    sslctx.verify_mode = ssl.CERT_NONE
    sslctx.set_alpn_protocols(list(offered))
    # tls: the ALPN protocol the listener selects is the subject
    _t = urllib.parse.urlsplit(ctx.endpoint_url(f"https://{host}"))
    with socket.create_connection((_t.hostname, _t.port or port), timeout=timeout) as sock:
        with sslctx.wrap_socket(sock, server_hostname=host) as tls:
            selected = tls.selected_alpn_protocol()
            if not (speak_http11 and selected != "h2"):
                return selected, None, None
            tls.sendall(
                f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("latin-1"))
            chunks = []
            while True:
                part = tls.recv(65536)
                if not part:
                    break
                chunks.append(part)
    raw = b"".join(chunks)
    assert raw, (
        f"the listener on {host}:{port} selected http/1.1 and then sent no bytes for an HTTP/1.1 "
        f"request"
    )
    head, _, body = raw.partition(b"\r\n\r\n")
    status = int(head.split(b"\r\n", 1)[0].split(b" ")[1])
    return selected, status, body.decode("utf-8", "replace")


def _set_http2(ctx, lb_arn, value):
    """Set the attribute and assert the control plane reports it back before probing the data plane."""
    elb = ctx.client("elbv2")
    _retry_throttled(lambda: elb.modify_load_balancer_attributes(
        LoadBalancerArn=lb_arn,
        Attributes=[{"Key": "routing.http2.enabled", "Value": value}]))
    attrs = {a["Key"]: a["Value"] for a in elb.describe_load_balancer_attributes(
        LoadBalancerArn=lb_arn)["Attributes"]}
    got = attrs.get("routing.http2.enabled")
    assert got == value, (
        f"DescribeLoadBalancerAttributes reports routing.http2.enabled={got!r} after setting it to "
        f"{value!r}"
    )
    return attrs


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """With routing.http2.enabled on, an HTTPS listener selects ALPN "h2" for a client offering h2 and http/1.1;
    with it off the same client gets no h2 and is still served over HTTP/1.1, and restoring it brings h2 back."""
    assert ssl.HAS_ALPN, (
        "this Python's OpenSSL build has no ALPN support (ssl.HAS_ALPN is False), so no ALPN protocol "
        "can be offered at all"
    )

    vpc_id, subnet_ids = _own_public_vpc(ctx)
    sg_id = _open_sg(ctx, vpc_id, ports=(443,))
    cert_arn = _import_cert(ctx, f"{_clamp_name(ctx.unique_name('sim2real-'), 40)}.example.com")

    lb = _create_load_balancer(
        ctx, subnet_ids, Scheme="internet-facing", SecurityGroups=[sg_id])
    lb_arn = lb["LoadBalancerArn"]
    _wait_for_lb_active(ctx, lb_arn)

    # A fixed-response default action: this check is about the handshake, so a target would only add
    # failure modes unrelated to ALPN.
    _create_listener(
        ctx, lb_arn, Protocol="HTTPS", Port=443,
        Certificates=[{"CertificateArn": cert_arn}],
        DefaultActions=_fixed("H2-OK"))
    host = lb["DNSName"]

    # The documented default is on. Assert it rather than assume it, so leg 2 changes one KNOWN thing.
    attrs = {a["Key"]: a["Value"] for a in ctx.client("elbv2").describe_load_balancer_attributes(
        LoadBalancerArn=lb_arn)["Attributes"]}
    assert attrs.get("routing.http2.enabled") == "true", (
        f"a freshly created ALB reports routing.http2.enabled="
        f"{attrs.get('routing.http2.enabled')!r}, expected the documented default 'true'"
    )

    def _offer_both():
        try:
            return _alpn(ctx, host, ["h2", "http/1.1"])
        except (ssl.SSLError, OSError):
            return None

    # ---- leg 1: positive control. -----------------------------------------------------------
    selected, _s, _b = _poll_until(
        _offer_both, lambda r: r is not None and r[0] is not None,
        timeout_s=420, interval_s=10,
        description="the HTTPS listener completing an ALPN handshake at all",
    )
    assert selected == "h2", (
        f"with routing.http2.enabled=true a client offering ['h2', 'http/1.1'] negotiated "
        f"{selected!r}, expected 'h2'"
    )
    # And a client that only offers http/1.1 is served over http/1.1 in the same state.
    sel11, status11, body11 = _poll_until(
        lambda: _alpn(ctx, host, ["http/1.1"], speak_http11=True),
        lambda r: r[1] == 200, timeout_s=180, interval_s=10,
        description="the same listener selecting http/1.1 and serving the fixed response",
    )
    assert (sel11, status11, body11.strip()) == ("http/1.1", 200, "H2-OK"), (
        f"an http/1.1-only client got ALPN {sel11!r} status {status11} body "
        f"{(body11 or '').strip()[:40]!r}, expected ('http/1.1', 200, 'H2-OK')"
    )

    # ---- leg 2: break EXACTLY one thing — the attribute. ------------------------------------
    _set_http2(ctx, lb_arn, "false")
    # AWS does not select "http/1.1" explicitly here: it stops answering ALPN at all
    # (selected_alpn_protocol() -> None), so the contract is "h2 is withdrawn".
    downgraded = _poll_until(
        _offer_both, lambda r: r is not None and r[0] != "h2",
        timeout_s=300, interval_s=10,
        description="the identical h2-offering client no longer negotiating h2 after "
                    "routing.http2.enabled was set to false",
    )
    assert downgraded[0] != "h2", (
        f"with routing.http2.enabled=false the identical client still negotiated {downgraded[0]!r}, "
        f"expected anything other than 'h2'"
    )
    # EFFECT PRESENT, so the withdrawal is of h2 and not of the listener: the same offer is served.
    sel_off, status_off, body_off = _alpn(ctx, host, ["h2", "http/1.1"], speak_http11=True)
    assert sel_off != "h2", (
        f"with http2 disabled, a client offering ['h2', 'http/1.1'] still negotiated ALPN "
        f"{sel_off!r}, expected anything other than 'h2'"
    )
    assert (status_off, (body_off or "").strip()) == (200, "H2-OK"), (
        f"with http2 disabled, a client offering ['h2', 'http/1.1'] negotiated ALPN {sel_off!r} but "
        f"got status {status_off} body {(body_off or '').strip()[:40]!r}; expected the request to be "
        f"SERVED over HTTP/1.1 framing — a refused handshake would mean the attribute broke the "
        f"listener rather than withdrawing h2"
    )

    # ---- leg 3: restore the ONE thing that changed. -----------------------------------------
    _set_http2(ctx, lb_arn, "true")
    restored = _poll_until(
        _offer_both, lambda r: r is not None and r[0] == "h2",
        timeout_s=300, interval_s=10,
        description="the identical client negotiating h2 again once routing.http2.enabled is back "
                    "to true",
    )
    assert restored[0] == "h2", (
        f"after restoring routing.http2.enabled=true the identical client negotiated "
        f"{restored[0]!r}, expected 'h2' — so the downgrade was attributable to the attribute alone"
    )


# EC2 network teardown: a resource in this VPC deletes asynchronously and leaves its ENIs behind for a
# while, so each subnet / security group / VPC delete waits for them and retries DependencyViolation
# to one deadline shared by all of the check's network deletes, then raises naming the ENIs left.
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
        _time.sleep(10)
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
        _time.sleep(10)


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
