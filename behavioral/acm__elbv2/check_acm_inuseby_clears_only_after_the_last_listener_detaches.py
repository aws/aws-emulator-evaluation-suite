"""acm-inuseby-clears-only-after-the-last-listener-detaches."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "acm-inuseby-clears-only-after-the-last-listener-detaches"
GROUP = 'lifecycle'
SERVICES = ['acm', 'elbv2']

# Each InUseBy absence is sampled every 2 s over this fixed window.
_SAMPLE_WINDOW_S = 10.0

_THROTTLE_CODES = (
    "ThrottlingException",
    "Throttling",
    "TooManyRequestsException",
    "RequestInProgressException",
)


def _retry_throttle(fn, attempts=7, base_delay=4.0):
    """Retry fn() on throttle codes."""
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


def _poll_until(ctx, probe, predicate, *, timeout_s=120, interval_s=3.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last_result = None
    while time.monotonic() < deadline:
        last_result = probe()
        if predicate(last_result):
            return last_result
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last_result!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _serial_int(text):
    """ACM's colon-grouped hex `Serial` as an integer.

    ACM zero-pads each hex byte (`0a:...`), so comparing strings with `f"{n:x}"` would mismatch.
    """
    return int(str(text).replace(":", ""), 16)


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

    The default group suffices: the load balancer is never connected to, so no ingress is needed.
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


@tags("axis:happy-path", "concern:e2e", "concern:representation", "cap:c1", "plane:control")
def run(ctx) -> None:
    """ACM `InUseBy` is a reference set: two listeners on one load balancer report it once,
    deleting the first leaves it in place, and only the last detach clears it.

    Reference: https://docs.aws.amazon.com/acm/latest/APIReference/API_CertificateDetail.html
    """
    acm = ctx.client("acm")
    elb = ctx.client("elbv2")
    ec2 = ctx.client("ec2")

    uid = ctx.unique_name("sim2real-xsvc-refs-")
    host = f"{uid}.example.com"
    leaf, key = _self_signed(host)

    cert_arn = _retry_throttle(lambda: acm.import_certificate(
        Certificate=_pem(leaf), PrivateKey=_key_pem(key),
        Tags=[{"Key": "sim2real", "Value": CHECK}]))["CertificateArn"]

    def _delete_cert():
        for _ in range(24):
            try:
                acm.delete_certificate(CertificateArn=cert_arn)
                return
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                    return
                if exc.response["Error"]["Code"] != "ResourceInUseException":
                    raise
                time.sleep(5)
        raise RuntimeError(f"acm certificate still in use, not deleted: {cert_arn}")

    ctx.on_cleanup(_delete_cert)
    fresh = _poll_until(
        ctx, lambda: acm.describe_certificate(CertificateArn=cert_arn)["Certificate"],
        lambda d: d.get("Status") == "ISSUED",
        timeout_s=_budget_s(ctx, 120), interval_s=1,
        description="the imported certificate reaches ISSUED",
    )
    # (1) The pre-state: a certificate nothing references.
    assert fresh["InUseBy"] == [], (
        f"a freshly imported certificate is attached to nothing; InUseBy is {fresh['InUseBy']!r}"
    )

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

    nonce = f"sim2real-xsvc-nonce-{uid}"
    actions = [{"Type": "fixed-response",
                "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain",
                                        "MessageBody": nonce}}]
    live = {}

    def _make_listener(port):
        arn = elb.create_listener(
            LoadBalancerArn=lb_arn, Protocol="HTTPS", Port=port,
            Certificates=[{"CertificateArn": cert_arn}], DefaultActions=actions,
        )["Listeners"][0]["ListenerArn"]
        live[port] = arn

        def _delete():
            if live.get(port) is None:
                return
            try:
                elb.delete_listener(ListenerArn=arn)
            except ClientError as exc:
                teardown_code = exc.response.get("Error", {}).get("Code", "")
                if teardown_code not in ("ListenerNotFound",):
                    raise RuntimeError(f"listener {arn} not deleted: {exc}") from exc

        ctx.on_cleanup(_delete)
        return arn

    # A listener can be created while the load balancer is still provisioning; no active wait.
    first = _make_listener(443)
    # (2) The attach transition: InUseBy names the load balancer.
    attached = _poll_until(
        ctx, lambda: acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]["InUseBy"],
        lambda arns: bool(arns),
        timeout_s=_budget_s(ctx, 180), interval_s=1,
        description="InUseBy populates after the first listener attaches the certificate",
    )
    assert attached == [lb_arn], (
        f"InUseBy must name exactly the load balancer; got {attached!r}, expected [{lb_arn!r}]"
    )

    second = _make_listener(8443)
    assert _listeners(elb, lb_arn) == sorted([first, second]), (
        f"both listeners must exist; DescribeListeners returned {_listeners(elb, lb_arn)!r}"
    )
    # (3) Two references to the SAME load balancer are reported once, not twice. Sampled over a
    #     window so a value that is about to grow to two entries cannot pass.
    window_s = _SAMPLE_WINDOW_S
    deadline = time.monotonic() + window_s
    samples = []
    while time.monotonic() < deadline:
        samples.append(acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]["InUseBy"])
        time.sleep(2)
    assert all(s == [lb_arn] for s in samples), (
        "with two listeners on one load balancer InUseBy must report that balancer exactly once; "
        f"the samples over {window_s:.0f}s were {samples!r}"
    )

    # (4) Delete the FIRST listener. BARRIER: wait until ELB v2 itself no longer reports it, so the
    #     sampling below cannot be reading a state where the delete had not yet propagated.
    elb.delete_listener(ListenerArn=first)
    live[443] = None
    _poll_until(
        ctx, lambda: _listeners(elb, lb_arn),
        lambda arns: arns == [second],
        timeout_s=_budget_s(ctx, 120), interval_s=1,
        description="the first listener disappears from DescribeListeners",
    )
    # (5) The reference-count assertion: one listener still holds the certificate, so InUseBy must
    #     NOT have cleared. Sampled repeatedly after the barrier.
    window_s = _SAMPLE_WINDOW_S
    deadline = time.monotonic() + window_s
    held = []
    while time.monotonic() < deadline:
        held.append(acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]["InUseBy"])
        time.sleep(2)
    assert all(s == [lb_arn] for s in held), (
        "one HTTPS listener still serves this certificate, so InUseBy must still name the load "
        f"balancer; the samples over {window_s:.0f}s after the first detach were {held!r}"
    )
    still_issued = acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]
    assert still_issued["Status"] == "ISSUED", (
        f"Status must be unchanged across the attach/detach transitions; got "
        f"{still_issued['Status']!r}"
    )

    # (6) Delete the LAST listener and require the same field to clear, proving step (5) observed
    #     a live reference rather than a value that never moves. InUseBy clears ~10 s later.
    elb.delete_listener(ListenerArn=second)
    live[8443] = None
    cleared = _poll_until(
        ctx, lambda: acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]["InUseBy"],
        lambda arns: arns == [],
        timeout_s=_budget_s(ctx, 180), interval_s=1,
        description="InUseBy clears after the last listener is deleted",
    )
    assert cleared == [], f"InUseBy was still {cleared!r} after the last listener was deleted"
    assert _listeners(elb, lb_arn) == [], (
        f"no listener may remain; DescribeListeners returned {_listeners(elb, lb_arn)!r}"
    )
    final = acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]
    assert final["Status"] == "ISSUED", (
        f"detaching every listener must not change the certificate's own state; Status is "
        f"{final['Status']!r}"
    )
    assert _serial_int(final["Serial"]) == leaf.serial_number, (
        f"the stored Serial changed to {final['Serial']!r}; the imported leaf's serial is "
        f"{leaf.serial_number:x}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
