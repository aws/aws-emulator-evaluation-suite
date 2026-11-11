"""listener-ssl-policy-bounds-the-negotiated-tls-version-and-cipher."""
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

CHECK = "listener-ssl-policy-bounds-the-negotiated-tls-version-and-cipher"
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

_CIDR = "10.174.0.0/16"


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


_GONE_CODES = frozenset(
    {"Gateway.NotAttached", "NoSuchEntity", "AWS.SimpleQueueService.NonExistentQueue"})


def _gone(exc):
    """A teardown delete whose resource is already gone is done."""
    code = exc.response.get("Error", {}).get("Code", "")
    return code.endswith(("NotFound", "NotFoundException")) or code in _GONE_CODES


def _safe_cleanup(fn):
    """Teardown: a resource that is already gone is done; any other failure raises."""
    def _wrapped():
        try:
            fn()
        except ClientError as exc:
            if not _gone(exc):
                raise

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
        _safe_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))()

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
            if _gone(exc):
                return
            raise
        for _ in range(90):
            try:
                elb.describe_load_balancers(LoadBalancerArns=[arn])
            except ClientError as exc:
                if _gone(exc):
                    return
                raise
            time.sleep(2)
        raise AssertionError(f"load balancer {arn} is still listed 180s after its delete")

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
    """A self-signed server certificate + key, both PEM. ACM imports a self-signed certificate,
    and only the negotiated protocol and cipher are graded, so chain trust is irrelevant."""
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
        # An in-use certificate cannot be deleted, and the listener's release lags its own
        # delete: ResourceInUseException is retried.
        for attempt in range(30):
            try:
                acm.delete_certificate(CertificateArn=arn)
                return
            except ClientError as exc:
                if _gone(exc):
                    return
                code = exc.response.get("Error", {}).get("Code")
                if code != "ResourceInUseException" or attempt == 29:
                    raise
            time.sleep(6)

    ctx.on_cleanup(_drop_cert)
    return arn


def _handshake(ctx, host, *, port=443, max_version=None, min_version=None, sni=None, timeout=15):
    """Complete a real TLS handshake and one HTTP request; return (protocol, cipher, status, body).
    Raises ssl.SSLError / OSError on failure. Verification is off: the certificate is self-signed
    and only the negotiated protocol and cipher are graded."""
    sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    sslctx.check_hostname = False
    sslctx.verify_mode = ssl.CERT_NONE
    if min_version is not None:
        sslctx.minimum_version = min_version
    if max_version is not None:
        sslctx.maximum_version = max_version
    # tls: the listener's SSL policy is the subject
    _t = urllib.parse.urlsplit(ctx.endpoint_url(f"https://{host}"))
    with socket.create_connection((_t.hostname, _t.port or port), timeout=timeout) as sock:
        with sslctx.wrap_socket(sock, server_hostname=sni or host) as tls:
            protocol = tls.version()
            cipher = tls.cipher()[0]
            tls.sendall(
                f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("latin-1"))
            chunks = []
            while True:
                part = tls.recv(65536)
                if not part:
                    break
                chunks.append(part)
    raw = b"".join(chunks)
    assert raw, f"the TLS listener on {host}:{port} accepted a handshake and then sent no bytes"
    head, _, body = raw.partition(b"\r\n\r\n")
    status = int(head.split(b"\r\n", 1)[0].split(b" ")[1])
    return protocol, cipher, status, body.decode("utf-8", "replace")


def _set_ssl_policy(ctx, listener_arn, policy):
    """Set the policy and assert the control plane reports it back before probing the data plane."""
    elb = ctx.client("elbv2")
    _retry_throttled(lambda: elb.modify_listener(ListenerArn=listener_arn, SslPolicy=policy))
    described = elb.describe_listeners(ListenerArns=[listener_arn])["Listeners"][0]
    assert described.get("SslPolicy") == policy, (
        f"DescribeListeners reports SslPolicy={described.get('SslPolicy')!r} after setting it to "
        f"{policy!r}"
    )


def _all_policies(ctx):
    """Every application SSL policy the target reports, keyed by name, paginated by hand. Both
    policy choices derive from this answer, so no policy name or protocol list is hardcoded."""
    elb = ctx.client("elbv2")
    out = {}
    marker = None
    for _ in range(20):
        kwargs = {"LoadBalancerType": "application", "PageSize": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = elb.describe_ssl_policies(**kwargs)
        for pol in resp["SslPolicies"]:
            out[pol["Name"]] = {
                "protocols": set(pol["SslProtocols"]),
                "ciphers": {c["Name"] for c in pol["Ciphers"]},
            }
        marker = resp.get("NextMarker")
        if not marker:
            break
    assert out, "DescribeSSLPolicies returned no application SSL policies at all"
    return out


@tags("axis:rejection", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A listener's SslPolicy bounds the TLS handshake: a TLS 1.2-pinned client is refused by a
    TLS1.3-only policy while a TLS1.3 client succeeds, and the negotiated protocol and cipher are
    in the sets the target publishes via DescribeSSLPolicies; restoring the policy restores access.
    """
    vpc_id, subnet_ids = _own_public_vpc(ctx)
    sg_id = _open_sg(ctx, vpc_id, ports=(443,))

    policies = _all_policies(ctx)
    tls13_only = sorted(n for n, p in policies.items() if p["protocols"] == {"TLSv1.3"})
    tls12_and_13 = sorted(
        n for n, p in policies.items()
        if {"TLSv1.2", "TLSv1.3"} <= p["protocols"]
    )
    assert tls13_only, (
        f"DescribeSSLPolicies reported no application policy whose SslProtocols is exactly "
        f"['TLSv1.3']; names seen: {sorted(policies)!r}"
    )
    assert tls12_and_13, (
        f"DescribeSSLPolicies reported no application policy supporting both TLSv1.2 and TLSv1.3; "
        f"names seen: {sorted(policies)!r}"
    )
    strict_policy = tls13_only[0]
    permissive_policy = tls12_and_13[0]

    cert_arn = _import_cert(ctx, f"{_clamp_name(ctx.unique_name('sim2real-'), 40)}.example.com")

    lb = _create_load_balancer(
        ctx, subnet_ids, Scheme="internet-facing", SecurityGroups=[sg_id])
    _wait_for_lb_active(ctx, lb["LoadBalancerArn"])

    # A fixed-response default action: this check is about the handshake, so a target would only add
    # failure modes that have nothing to do with TLS.
    listener = _create_listener(
        ctx, lb["LoadBalancerArn"], Protocol="HTTPS", Port=443,
        Certificates=[{"CertificateArn": cert_arn}], SslPolicy=permissive_policy,
        DefaultActions=_fixed("TLS-OK"),
    )
    listener_arn = listener["ListenerArn"]
    host = lb["DNSName"]

    # ---- leg 1: positive control under the permissive policy. ------------------------------
    def _pinned_12():
        try:
            return _handshake(ctx, host, min_version=ssl.TLSVersion.TLSv1_2,
                              max_version=ssl.TLSVersion.TLSv1_2)
        except (ssl.SSLError, OSError):
            return None

    proto12, cipher12, status12, body12 = _poll_until(
        _pinned_12, lambda r: r is not None and r[2] == 200,
        timeout_s=420, interval_s=10,
        description=f"a TLS1.2-pinned client completing a handshake and getting 200 from a listener "
                    f"using policy {permissive_policy!r}",
    )
    assert (status12, body12.strip()) == (200, "TLS-OK"), (
        f"TLS1.2-pinned request returned {(status12, body12.strip()[:60])!r}, expected (200, "
        f"'TLS-OK')"
    )
    assert proto12 == "TLSv1.2", (
        f"a client pinned to maximum_version=TLSv1.2 negotiated {proto12!r}"
    )
    assert proto12 in policies[permissive_policy]["protocols"], (
        f"negotiated protocol {proto12!r} is not in the SslProtocols the target itself published for "
        f"{permissive_policy!r}: {sorted(policies[permissive_policy]['protocols'])!r}"
    )
    assert cipher12 in policies[permissive_policy]["ciphers"], (
        f"negotiated cipher {cipher12!r} is not in the Ciphers the target itself published for "
        f"{permissive_policy!r} ({len(policies[permissive_policy]['ciphers'])} entries, e.g. "
        f"{sorted(policies[permissive_policy]['ciphers'])[:4]!r})"
    )

    # ---- leg 2: break EXACTLY one thing — the SslPolicy. -----------------------------------
    _set_ssl_policy(ctx, listener_arn, strict_policy)

    def _pinned_12_error():
        try:
            _handshake(ctx, host, min_version=ssl.TLSVersion.TLSv1_2,
                       max_version=ssl.TLSVersion.TLSv1_2)
        except ssl.SSLError as exc:
            return ("ssl", f"{type(exc).__name__}:{getattr(exc, 'reason', None)}:{exc}")
        except OSError as exc:
            return ("transport", f"{type(exc).__name__}:{exc}")
        return None

    kind, detail = _poll_until(
        _pinned_12_error, lambda r: r is not None,
        timeout_s=300, interval_s=10,
        description=f"a TLS1.2-pinned handshake starting to FAIL after the listener moved to "
                    f"{strict_policy!r} (SslProtocols "
                    f"{sorted(policies[strict_policy]['protocols'])!r})",
    )
    assert kind == "ssl", (
        f"the TLS1.2-pinned client failed at the {kind} layer ({detail}); a policy refusal must "
        f"surface as a TLS alert, not as a connection error — a listener that simply became "
        f"unreachable would look identical otherwise"
    )
    upper = detail.upper()
    assert "PROTOCOL_VERSION" in upper or "HANDSHAKE_FAILURE" in upper, (
        f"the TLS1.2-pinned handshake failed with {detail!r}; expected a protocol-version or "
        f"handshake-failure alert from a TLSv1.3-only policy"
    )
    assert "CERTIFICATE" not in upper, (
        f"the TLS1.2-pinned handshake failed on the CERTIFICATE ({detail!r}), not on the protocol "
        f"version; this check disables verification, so a certificate failure means the refusal is "
        f"not attributable to the SSL policy"
    )

    # SAME-INSTANT POSITIVE CONTROL: the listener is up, reachable and serving — for TLS 1.3.
    proto13, cipher13, status13, body13 = _poll_until(
        lambda: _handshake(ctx, host, min_version=ssl.TLSVersion.TLSv1_3),
        lambda r: r[2] == 200, timeout_s=180, interval_s=10,
        description=f"a TLS1.3-capable client still getting 200 from the same listener under "
                    f"{strict_policy!r}",
    )
    assert (proto13, status13, body13.strip()) == ("TLSv1.3", 200, "TLS-OK"), (
        f"the TLS1.3 control returned protocol={proto13!r} status={status13} "
        f"body={body13.strip()[:40]!r}, expected TLSv1.3/200/'TLS-OK' — without this the failure "
        f"above is indistinguishable from 'the listener stopped working'"
    )
    assert cipher13 in policies[strict_policy]["ciphers"], (
        f"negotiated cipher {cipher13!r} is not in the Ciphers the target published for "
        f"{strict_policy!r}: {sorted(policies[strict_policy]['ciphers'])!r}"
    )

    # ---- leg 3: restore the ONE thing that changed. ----------------------------------------
    _set_ssl_policy(ctx, listener_arn, permissive_policy)
    proto_r, cipher_r, status_r, body_r = _poll_until(
        _pinned_12, lambda r: r is not None and r[2] == 200,
        timeout_s=300, interval_s=10,
        description=f"the identical TLS1.2-pinned client succeeding again once the listener is back "
                    f"on {permissive_policy!r}",
    )
    assert (proto_r, status_r, body_r.strip()) == ("TLSv1.2", 200, "TLS-OK"), (
        f"after restoring {permissive_policy!r} the TLS1.2-pinned client got protocol={proto_r!r} "
        f"status={status_r} body={body_r.strip()[:40]!r}, expected TLSv1.2/200/'TLS-OK' — so the "
        f"refusal was attributable to the SSL policy alone"
    )
    assert cipher_r in policies[permissive_policy]["ciphers"], (
        f"negotiated cipher {cipher_r!r} is not in the Ciphers published for "
        f"{permissive_policy!r}"
    )


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. So wait (bounded) for the
# resource's ENIs to go, retry DependencyViolation inside the same window, and raise naming the ENIs
# still attached when the window ends. The window is shared by all of one check's network deletes.
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
