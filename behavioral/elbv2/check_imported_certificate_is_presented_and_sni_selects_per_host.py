"""imported-certificate-is-presented-and-sni-selects-per-host."""
from __future__ import annotations

import datetime
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from behavioral_harness import tags

CHECK = "imported-certificate-is-presented-and-sni-selects-per-host"
GROUP = 'tls'
SERVICES = ['elbv2']

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


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
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _http(url, *, method="GET", headers=None, timeout=20):
    req = urllib.request.Request(url, method=method, headers=headers or {})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read().decode("utf-8", "replace")


def _default_vpc_and_subnets(ctx, num_subnets=2):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this region to place an internet-facing ALB in")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
    ])["Subnets"]
    per_az = {}
    for sub in sorted(subnets, key=lambda s: s["SubnetId"]):
        per_az.setdefault(sub["AvailabilityZone"], sub["SubnetId"])
    subnet_ids = [per_az[az] for az in sorted(per_az)][:num_subnets]
    if len(subnet_ids) < num_subnets:
        raise AssertionError(
            f"shared network VPC {vpc_id} exposes {len(subnet_ids)} AZ subnets, need {num_subnets}"
        )
    return vpc_id, subnet_ids


def _open_http_sg(ctx, vpc_id, port=80):
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real elbv2 data-plane ingress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": list(_TAGS)}],
    )["GroupId"]

    def _drop_sg():
        # The ALB's ENIs hold this group until they are released: DependencyViolation is retried.
        for attempt in range(60):
            try:
                ec2.delete_security_group(GroupId=sg_id)
                return
            except ClientError as exc:
                if _gone(exc):
                    return
                code = exc.response.get("Error", {}).get("Code")
                if code != "DependencyViolation" or attempt == 59:
                    raise
            time.sleep(10)

    ctx.on_cleanup(_drop_sg)
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": port, "ToPort": port,
            "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()],
        }],
    )
    return sg_id


def _create_load_balancer(ctx, subnet_ids, **kwargs):
    """Billable resource: waited teardown registered AT CREATION (cleanups run LIFO)."""
    elb = ctx.client("elbv2")
    name = _clamp_name(kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-lb-"))
    params = dict(
        Name=name, Subnets=subnet_ids, Type="application",
        Scheme="internal", Tags=list(_TAGS),
    )
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
    assert lb["State"]["Code"] == "active", f"load balancer state {lb['State']!r}, expected active"
    return lb


def _create_listener(ctx, lb_arn, **kwargs):
    elb = ctx.client("elbv2")
    params = dict(LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80)
    params.update(kwargs)
    listener = _retry_throttled(lambda: elb.create_listener(**params))["Listeners"][0]
    arn = listener["ListenerArn"]
    ctx.on_cleanup(lambda: elb.delete_listener(ListenerArn=arn))
    return listener


def _fixed(body, status="200"):
    return [{"Type": "fixed-response", "FixedResponseConfig": {
        "StatusCode": status, "ContentType": "text/plain", "MessageBody": body}}]


def _create_rule(ctx, listener_arn, priority, path_values, body, status="200"):
    elb = ctx.client("elbv2")
    rule = _retry_throttled(lambda: elb.create_rule(
        ListenerArn=listener_arn, Priority=priority,
        Conditions=[{"Field": "path-pattern",
                     "PathPatternConfig": {"Values": list(path_values)}}],
        Actions=_fixed(body, status), Tags=list(_TAGS),
    ))["Rules"][0]
    arn = rule["RuleArn"]

    def _drop_rule():
        try:
            elb.delete_rule(RuleArn=arn)
        except ClientError as exc:
            if not _gone(exc):
                raise

    ctx.on_cleanup(_drop_rule)
    return rule


def _wait_for_body(url, expected, *, timeout_s=300, headers=None):
    """Poll, bounded, until the load balancer serves exactly `expected` (body, or (status, body)).
    """
    seen = []

    def probe():
        try:
            status, _hdrs, body = _http(url, headers=headers)
        except (urllib.error.URLError, OSError) as exc:
            seen.append(f"<transport: {exc}>")
            return None
        seen.append(f"{status}:{body.strip()[:40]}")
        return (status, body)

    def matches(r):
        if r is None:
            return False
        if isinstance(expected, tuple):
            return (r[0], r[1].strip()) == expected
        return r[1].strip() == expected

    return _poll_until(
        probe, matches, timeout_s=timeout_s, interval_s=5,
        description=f"load balancer serving {expected!r} at {url} (observed: {seen[-8:]})",
    )
def _make_self_signed(cn):
    """A self-signed server certificate + key, both PEM. Returns (cert_pem, key_pem, serial).

    ACM imports self-signed certificates, so no owned domain is needed.
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
        # Backdated an hour so a clock skew cannot make ACM see a not-yet-valid certificate.
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_encipherment=True, content_commitment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1")]),
                       critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem, cert.serial_number


def _import_cert(ctx, cert_pem, key_pem):
    acm = ctx.client("acm")
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


def _presented(ctx, host, server_hostname, *, port=443, timeout=15):
    """Complete a real TLS handshake and return the peer certificate's (serial, CN).

    Verification is off: the certificate is compared with the imported one, not a trust root.
    """
    sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    sslctx.check_hostname = False
    sslctx.verify_mode = ssl.CERT_NONE
    # tls: the certificate the listener presents per SNI host is the subject
    _t = urllib.parse.urlsplit(ctx.endpoint_url(f"https://{host}"))
    with socket.create_connection((_t.hostname, _t.port or port), timeout=timeout) as sock:
        with sslctx.wrap_socket(sock, server_hostname=server_hostname) as tls:
            der = tls.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(der)
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    return cert.serial_number, cn


def _poll_presented(ctx, host, server_hostname, predicate, description, *, timeout_s=300):
    seen = []

    def probe():
        try:
            return _presented(ctx, host, server_hostname)
        except (ssl.SSLError, OSError) as exc:
            seen.append(f"<handshake: {type(exc).__name__}: {exc}>")
            return None

    return _poll_until(
        probe, lambda r: r is not None and predicate(r),
        timeout_s=timeout_s, interval_s=5,
        description=f"{description} (observed: {seen[-6:]})",
    )


_GONE_CODES = frozenset(
    {"Gateway.NotAttached", "NoSuchEntity", "AWS.SimpleQueueService.NonExistentQueue"})


def _gone(exc):
    """A teardown delete whose resource is already gone is done."""
    code = exc.response.get("Error", {}).get("Code", "")
    return code.endswith(("NotFound", "NotFoundException")) or code in _GONE_CODES


def _safe(fn):
    """Teardown: a resource that is already gone is done; any other failure raises."""
    def _wrapped():
        try:
            fn()
        except ClientError as exc:
            if not _gone(exc):
                raise

    return _wrapped


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """An HTTPS listener presents the imported ACM certificate in a real TLS handshake; with an
    added certificate, SNI selects it for its host and an unmatched host gets the default.
    """
    elb = ctx.client("elbv2")
    vpc_id, subnet_ids = _default_vpc_and_subnets(ctx)

    uniq = ctx.unique_name("s")[-12:]
    host_a = f"sim2real-a-{uniq}.example.com"
    host_b = f"sim2real-b-{uniq}.example.com"
    host_none = f"sim2real-none-{uniq}.example.com"

    cert_a_pem, key_a_pem, generated_a_serial = _make_self_signed(host_a)
    cert_b_pem, key_b_pem, generated_b_serial = _make_self_signed(host_b)
    assert generated_a_serial != generated_b_serial, (
        f"the two generated certificates share serial {generated_a_serial!r}"
    )
    arn_a = _import_cert(ctx, cert_a_pem, key_a_pem)
    arn_b = _import_cert(ctx, cert_b_pem, key_b_pem)

    sg_id = _open_http_sg(ctx, vpc_id, 443)
    lb = _create_load_balancer(
        ctx, subnet_ids, Scheme="internet-facing", SecurityGroups=[sg_id],
    )
    _wait_for_lb_active(ctx, lb["LoadBalancerArn"])
    dns = lb["DNSName"]

    listener = _create_listener(
        ctx, lb["LoadBalancerArn"], Port=443, Protocol="HTTPS",
        SslPolicy="ELBSecurityPolicy-2016-08",
        Certificates=[{"CertificateArn": arn_a}],
        DefaultActions=_fixed("TLS-OK"),
    )
    la = listener["ListenerArn"]

    # Serial numbers are minted locally, so a match proves this exact certificate was presented.
    presented_a_serial, presented_a_cn = _poll_presented(
        ctx, dns, host_a, lambda r: r[0] == generated_a_serial,
        f"the HTTPS listener presenting the imported certificate for {host_a!r}",
    )
    assert presented_a_serial == generated_a_serial, (
        f"the listener presented certificate serial {presented_a_serial!r}, expected the "
        f"imported {generated_a_serial!r}"
    )
    assert presented_a_cn == host_a, (
        f"the presented certificate subject CN is {presented_a_cn!r}, expected {host_a!r}"
    )

    _retry_throttled(lambda: elb.add_listener_certificates(
        ListenerArn=la, Certificates=[{"CertificateArn": arn_b}]))
    ctx.on_cleanup(_safe(lambda: elb.remove_listener_certificates(
        ListenerArn=la, Certificates=[{"CertificateArn": arn_b}])))

    def _listed():
        arns, token = set(), None
        while True:
            kw = {"ListenerArn": la}
            if token:
                kw["Marker"] = token
            page = elb.describe_listener_certificates(**kw)
            arns |= {c["CertificateArn"] for c in page["Certificates"]}
            token = page.get("NextMarker")
            if not token:
                return arns

    _poll_until(
        _listed, lambda s: {arn_a, arn_b} <= s, timeout_s=120, interval_s=3,
        description="both certificates being listed on the listener",
    )

    presented_b_serial, presented_b_cn = _poll_presented(
        ctx, dns, host_b, lambda r: r[0] == generated_b_serial,
        f"SNI for {host_b!r} selecting the added certificate",
    )
    assert presented_b_serial == generated_b_serial, (
        f"SNI for {host_b!r} presented serial {presented_b_serial!r}, expected the SNI "
        f"certificate {generated_b_serial!r}"
    )
    assert presented_b_cn == host_b, (
        f"the SNI-selected certificate subject CN is {presented_b_cn!r}, expected {host_b!r}"
    )
    assert presented_b_serial != presented_a_serial, (
        f"both SNI hostnames were served the same certificate {presented_b_serial!r}; SNI "
        f"selection did not happen"
    )

    presented_default_serial, _cn = _presented(ctx, dns, host_none)
    assert presented_default_serial == generated_a_serial, (
        f"an unmatched SNI hostname {host_none!r} was served serial "
        f"{presented_default_serial!r}, expected the listener default {generated_a_serial!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
