"""acm-never-issued-certificate-refused-by-an-https-listener-rejected."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "acm-never-issued-certificate-refused-by-an-https-listener-rejected"
GROUP = 'overly-permissive'
SERVICES = ['acm', 'elbv2']

_THROTTLE_CODES = (
    "ThrottlingException",
    "Throttling",
    "TooManyRequestsException",
    "RequestInProgressException",
)


def _retry_throttle(fn, attempts=7, base_delay=4.0):
    """Retry fn() on throttle codes (test-infra robustness, not a behavioral assertion)."""
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(base_delay * (i + 1))
    raise last


def _poll_until(probe, predicate, *, timeout_s=120, interval_s=3.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last_result = None
    while time.monotonic() < deadline:
        last_result = probe()
        if predicate(last_result):
            return last_result
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last_result!r}")


def _error(fn):
    """The AWS error (code, message) raised by fn(), or a loud failure if it unexpectedly SUCCEEDS."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"the call was expected to be REFUSED but it succeeded, returning {result!r}"
    )


def _crypto():
    """Lazily import `cryptography`; a missing package raises ImportError to the runner."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    return x509, hashes, serialization, rsa, NameOID


def _subject(cn):
    """An X.509 Name. The CN is capped at 64 characters by RFC 5280 / `cryptography`."""
    x509, _h, _s, _r, NameOID = _crypto()
    assert len(cn) <= 64, f"CN {cn!r} is {len(cn)} chars; X.509 caps it at 64"
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "sim2real-xsvc-acm-not-a-real-key"),
    ])


def _pem(cert):
    _x, _h, serialization, _r, _n = _crypto()
    return cert.public_bytes(serialization.Encoding.PEM)


def _key_pem(key):
    """PEM-serialise a key generated moments ago in this process. It is not a credential."""
    _x, _h, serialization, _r, _n = _crypto()
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _self_signed(cn):
    """A self-signed RSA-2048 leaf: the smallest thing ACM will accept and ELB v2 will serve."""
    x509, hashes, _s, rsa, _n = _crypto()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_subject(cn)).issuer_name(_subject(cn))
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _default_vpc_two_subnets_and_sg(ec2, *, ctx):
    """The shared VPC, two subnets in distinct AZs, and its default security group.

    The default group suffices: nothing connects to the load balancer, so no ingress rule is needed.
    """
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    assert vpcs, "this account has no shared network VPC, so no application load balancer can be created"
    vpc_id = vpcs[0]["VpcId"]
    by_az = {}
    for page in ec2.get_paginator("describe_subnets").paginate(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]},
                     {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]):
        for subnet in page["Subnets"]:
            by_az.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
    azs = sorted(by_az)
    assert len(azs) >= 2, (
        f"an application load balancer needs subnets in two AZs; the run's shared network {vpc_id!r} "
        f"offers {by_az!r}"
    )
    groups = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]},
                 {"Name": "group-name", "Values": ["default"]}])["SecurityGroups"]
    assert groups, f"the shared network {vpc_id!r} has no default security group"
    return vpc_id, [by_az[azs[0]], by_az[azs[1]]], groups[0]["GroupId"]


def _listeners(elb, lb_arn):
    """Every listener ARN on a load balancer, following the Marker pages."""
    arns, marker = [], None
    while True:
        kwargs = {"LoadBalancerArn": lb_arn}
        if marker:
            kwargs["Marker"] = marker
        page = elb.describe_listeners(**kwargs)
        arns.extend(listener["ListenerArn"] for listener in page["Listeners"])
        marker = page.get("NextMarker")
        if not marker:
            return sorted(arns)


def _listener_certificate_arns(elb, listener_arn):
    """Every certificate ARN on a listener, following the Marker pages."""
    arns, marker = [], None
    while True:
        kwargs = {"ListenerArn": listener_arn}
        if marker:
            kwargs["Marker"] = marker
        page = elb.describe_listener_certificates(**kwargs)
        arns.extend(c["CertificateArn"] for c in page["Certificates"])
        marker = page.get("NextMarker")
        if not marker:
            return sorted(arns)


@tags("axis:rejection", "concern:e2e", "concern:negative-classes", "cap:c1", "plane:control")
def run(ctx) -> None:
    """A never-issued ACM certificate is refused by an ALB HTTPS listener (UnsupportedCertificate)
    and no listener is created; the identical call with an ISSUED imported certificate succeeds.
    """
    acm = ctx.client("acm")
    elb = ctx.client("elbv2")
    ec2 = ctx.client("ec2")

    uid = ctx.unique_name("sim2real-xsvc-noiss-")
    failed_host = f"fail-{uid}.example.com"
    issued_host = f"good-{uid}.example.com"

    # The certificate under test: requested, never validated, and therefore never issued.
    # For an example.com name ACM moves it to terminal FAILED within seconds, so poll for FAILED
    # rather than racing PENDING_VALIDATION.
    failed_arn = _retry_throttle(lambda: acm.request_certificate(
        DomainName=failed_host, ValidationMethod="DNS",
        Tags=[{"Key": "sim2real", "Value": CHECK}]))["CertificateArn"]
    ctx.on_cleanup(lambda: _retry_throttle(
        lambda: acm.delete_certificate(CertificateArn=failed_arn), attempts=4, base_delay=3.0))
    failed_before = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=failed_arn)["Certificate"],
        lambda d: d.get("Status") == "FAILED" and "DomainName" in d,
        timeout_s=180, interval_s=5,
        description="the requested certificate settles into its terminal FAILED state",
    )
    assert failed_before["Type"] == "AMAZON_ISSUED", (
        f"the certificate under test must be ACM-managed; Type is {failed_before['Type']!r}"
    )
    assert failed_before["FailureReason"] == "ADDITIONAL_VERIFICATION_REQUIRED", (
        f"FailureReason is {failed_before['FailureReason']!r}, expected "
        "'ADDITIONAL_VERIFICATION_REQUIRED'"
    )
    assert failed_before["DomainName"] == failed_host, (
        f"the certificate under test does carry a fully-qualified domain name; DomainName is "
        f"{failed_before['DomainName']!r}"
    )
    assert failed_before.get("Serial") is None, (
        "a certificate that never issued holds no material and therefore no Serial; got "
        f"{failed_before.get('Serial')!r}"
    )

    # The control certificate: imported, ISSUED, same shape of name.
    leaf, key = _self_signed(issued_host)
    issued_arn = _retry_throttle(lambda: acm.import_certificate(
        Certificate=_pem(leaf), PrivateKey=_key_pem(key),
        Tags=[{"Key": "sim2real", "Value": CHECK}]))["CertificateArn"]

    def _delete_issued():
        for _ in range(24):
            try:
                acm.delete_certificate(CertificateArn=issued_arn)
                return
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                    return
                if exc.response["Error"]["Code"] != "ResourceInUseException":
                    raise
                time.sleep(5)
        raise RuntimeError(f"acm certificate still in use, not deleted: {issued_arn}")

    ctx.on_cleanup(_delete_issued)
    _poll_until(
        lambda: acm.describe_certificate(CertificateArn=issued_arn)["Certificate"],
        lambda d: d.get("Status") == "ISSUED",
        timeout_s=120, interval_s=3,
        description="the control certificate reaches ISSUED",
    )

    # A listener can be created while the load balancer is still provisioning; no active wait.
    _vpc_id, subnet_ids, sg_id = _default_vpc_two_subnets_and_sg(ec2, ctx=ctx)
    lb_arn = elb.create_load_balancer(
        Name=ctx.unique_name("sim2real-xsvc-lb-")[:32].rstrip("-"), Subnets=subnet_ids,
        SecurityGroups=[sg_id], Scheme="internet-facing", Type="application",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["LoadBalancers"][0]["LoadBalancerArn"]

    def _delete_lb():
        try:
            elb.delete_load_balancer(LoadBalancerArn=lb_arn)
        except ClientError as exc:
            teardown_code = exc.response.get("Error", {}).get("Code", "")
            if teardown_code not in ("LoadBalancerNotFound",):
                raise RuntimeError(f"load balancer {lb_arn} not deleted: {exc}") from exc

    ctx.on_cleanup(_delete_lb)

    assert _listeners(elb, lb_arn) == [], (
        f"the freshly created load balancer must have no listeners; got {_listeners(elb, lb_arn)!r}"
    )

    nonce = f"sim2real-xsvc-nonce-{uid}"
    actions = [{"Type": "fixed-response",
                "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain",
                                        "MessageBody": nonce}}]

    # (1) Break exactly one thing: the certificate named holds no key material.
    code, message = _error(lambda: elb.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTPS", Port=443,
        Certificates=[{"CertificateArn": failed_arn}], DefaultActions=actions))
    assert code == "UnsupportedCertificate", (
        "attaching a certificate that never issued to an HTTPS listener must be refused with "
        f"'UnsupportedCertificate'; got {code!r}"
    )
    expected = (
        f"The certificate '{failed_arn}' must have a fully-qualified domain name, a supported "
        "signature, and a supported key size."
    )
    assert message == expected, (
        f"the UnsupportedCertificate message must be {expected!r}; got {message!r}"
    )

    # (2) EFFECT ABSENT: no listener exists on the load balancer.
    assert _listeners(elb, lb_arn) == [], (
        "the refused CreateListener must not have created a listener; DescribeListeners returned "
        f"{_listeners(elb, lb_arn)!r}"
    )
    # (3) EFFECT ABSENT: the failed attach did not disturb the certificate's state either.
    failed_after = acm.describe_certificate(CertificateArn=failed_arn)["Certificate"]
    assert failed_after["Status"] == "FAILED", (
        f"the certificate's Status became {failed_after['Status']!r}; a refused attach must not "
        "move the state machine"
    )
    assert failed_after["InUseBy"] == [], (
        f"InUseBy became {failed_after['InUseBy']!r}; nothing is using this certificate"
    )

    # (4) POSITIVE CONTROL: the identical call with an ISSUED certificate succeeds.
    listener_arn = elb.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTPS", Port=443,
        Certificates=[{"CertificateArn": issued_arn}], DefaultActions=actions,
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elb.delete_listener(ListenerArn=listener_arn))
    assert _listeners(elb, lb_arn) == [listener_arn], (
        f"the control listener must be the only one; DescribeListeners returned "
        f"{_listeners(elb, lb_arn)!r}"
    )
    assert _listener_certificate_arns(elb, listener_arn) == [issued_arn], (
        "the control listener must hold exactly the ISSUED certificate; got "
        f"{_listener_certificate_arns(elb, listener_arn)!r}"
    )
    control_in_use = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=issued_arn)["Certificate"]["InUseBy"],
        lambda arns: bool(arns),
        timeout_s=180, interval_s=5,
        description="ACM reports the control certificate in use by the load balancer",
    )
    assert control_in_use == [lb_arn], (
        f"the control certificate's InUseBy must name the load balancer; got {control_in_use!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
