"""acm-certificate-in-use-by-a-listener-cannot-be-deleted-rejected."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "acm-certificate-in-use-by-a-listener-cannot-be-deleted-rejected"
GROUP = 'overly-permissive'
SERVICES = ['acm', 'elbv2']

_ALL_KEY_TYPES = [
    "RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096",
    "EC_prime256v1", "EC_secp384r1", "EC_secp521r1",
]

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


def _serial_int(text):
    """ACM's colon-grouped hex `Serial` as an integer.

    ACM zero-pads each hex byte (`0a:...`), so a string compare against `f"{n:x}"` can mismatch.
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
    """The shared VPC, two of its subnets in distinct AZs, and its DEFAULT security group.

    The default group needs no ingress here and cannot be stranded behind the ALB's ENI release.
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


def _certificate_arns(acm):
    """Every certificate ARN in the account, fully paginated with the keyTypes filter widened.

    ListCertificates applies a DEFAULT keyTypes filter narrower than the enum.
    """
    out = set()
    for page in acm.get_paginator("list_certificates").paginate(
            Includes={"keyTypes": list(_ALL_KEY_TYPES)}):
        out.update(c["CertificateArn"] for c in page["CertificateSummaryList"])
    return out


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
    """ACM refuses to delete a certificate held by an ALB HTTPS listener (ResourceInUseException),
    leaves it and the listener unchanged, and the same delete succeeds once the listener is gone.

    Reference: https://docs.aws.amazon.com/acm/latest/APIReference/API_DeleteCertificate.html
    """
    acm = ctx.client("acm")
    elb = ctx.client("elbv2")
    ec2 = ctx.client("ec2")

    uid = ctx.unique_name("sim2real-xsvc-inuse-")
    host = f"{uid}.example.com"
    leaf, key = _self_signed(host)

    cert_arn = _retry_throttle(lambda: acm.import_certificate(
        Certificate=_pem(leaf), PrivateKey=_key_pem(key),
        Tags=[{"Key": "sim2real", "Value": CHECK}]))["CertificateArn"]

    deleted = {"done": False}

    def _delete_cert():
        if deleted["done"]:
            return
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
    _poll_until(
        lambda: acm.describe_certificate(CertificateArn=cert_arn)["Certificate"],
        lambda d: d.get("Status") == "ISSUED",
        timeout_s=120, interval_s=3,
        description="the imported certificate reaches ISSUED",
    )

    vpc_id, subnet_ids, sg_id = _default_vpc_two_subnets_and_sg(ec2, ctx=ctx)
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

    # A listener can be created while the ALB is still provisioning, so no wait for active.
    nonce = f"sim2real-xsvc-nonce-{uid}"
    listener_arn = elb.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTPS", Port=443,
        Certificates=[{"CertificateArn": cert_arn}],
        DefaultActions=[{"Type": "fixed-response",
                         "FixedResponseConfig": {"StatusCode": "200",
                                                 "ContentType": "text/plain",
                                                 "MessageBody": nonce}}],
    )["Listeners"][0]["ListenerArn"]
    listener = {"arn": listener_arn}

    def _delete_listener():
        if listener["arn"] is None:
            return
        try:
            elb.delete_listener(ListenerArn=listener["arn"])
        except ClientError as exc:
            teardown_code = exc.response.get("Error", {}).get("Code", "")
            if teardown_code not in ("ListenerNotFound",):
                raise RuntimeError(f"listener {listener['arn']} not deleted: {exc}") from exc

    ctx.on_cleanup(_delete_listener)

    # (1) The association really exists, seen from ACM's side. Bounded poll in both directions
    #     because InUseBy is eventually consistent.
    in_use = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]["InUseBy"],
        lambda arns: bool(arns),
        timeout_s=180, interval_s=5,
        description="ACM reports the certificate in use by the load balancer",
    )
    assert in_use == [lb_arn], (
        f"InUseBy must name exactly the load balancer holding it; got {in_use!r}"
    )

    # (2) Break exactly one thing relative to a deletable certificate: it is attached.
    code, message = _error(lambda: acm.delete_certificate(CertificateArn=cert_arn))
    assert code == "ResourceInUseException", (
        "deleting a certificate served by a live HTTPS listener must be refused with "
        f"'ResourceInUseException'; got {code!r}"
    )
    account = cert_arn.split(":")[4]
    expected_in_use = f"Certificate {cert_arn} in account {account} is in use."
    assert message == expected_in_use, (
        f"the in-use refusal message must be {expected_in_use!r}; got {message!r}"
    )

    # (3) EFFECT ABSENT: the certificate is entirely unchanged by the refused delete.
    after = acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]
    assert after["Status"] == "ISSUED", (
        f"Status after the refused delete was {after['Status']!r}, expected 'ISSUED'"
    )
    assert after["InUseBy"] == [lb_arn], (
        f"InUseBy after the refused delete was {after['InUseBy']!r}, expected [{lb_arn!r}]"
    )
    assert _serial_int(after["Serial"]) == leaf.serial_number, (
        f"the stored Serial changed to {after['Serial']!r}; the imported leaf's serial is "
        f"{leaf.serial_number:x}"
    )
    # ListCertificates lags ImportCertificate by over a minute; polled after the load-balancer
    # work so the two overlap.
    listed = _poll_until(
        lambda: _certificate_arns(acm),
        lambda arns: cert_arn in arns,
        timeout_s=240, interval_s=10,
        description="the certificate appears in the fully paginated ListCertificates result",
    )
    assert cert_arn in listed, (
        "the certificate must still be listed in the account after the refused delete; it is "
        "absent from the fully paginated ListCertificates result"
    )
    # (4) EFFECT ABSENT across the boundary: the listener still holds it, so the load balancer
    #     still has something to serve.
    assert _listener_certificate_arns(elb, listener_arn) == [cert_arn], (
        "the listener must still hold the certificate after the refused delete; "
        f"DescribeListenerCertificates returned "
        f"{_listener_certificate_arns(elb, listener_arn)!r}"
    )

    # (5) POSITIVE CONTROL: remove the one blocking reference and the identical call succeeds.
    elb.delete_listener(ListenerArn=listener_arn)
    listener["arn"] = None
    cleared = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]["InUseBy"],
        lambda arns: arns == [],
        timeout_s=180, interval_s=5,
        description="InUseBy clears after the listener is deleted",
    )
    assert cleared == [], f"InUseBy was still {cleared!r} after the listener was deleted"
    _retry_throttle(lambda: acm.delete_certificate(CertificateArn=cert_arn))
    deleted["done"] = True
    gone, gone_message = _error(lambda: acm.describe_certificate(CertificateArn=cert_arn))
    assert gone == "ResourceNotFoundException", (
        "after the control delete the certificate must be gone; DescribeCertificate raised "
        f"{gone!r}"
    )
    expected_not_found = f"Could not find certificate {cert_arn}."
    assert gone_message == expected_not_found, (
        f"DescribeCertificate's not-found message must be {expected_not_found!r}; got "
        f"{gone_message!r}"
    )
    # ListCertificates lags deletion as it lags creation, so absence is read from the strongly
    # consistent DescribeCertificate and GetCertificate instead.
    gone_material, gone_material_message = _error(
        lambda: acm.get_certificate(CertificateArn=cert_arn))
    assert gone_material == "ResourceNotFoundException", (
        "GetCertificate must also stop serving the deleted certificate's material; it raised "
        f"{gone_material!r}"
    )
    assert gone_material_message == expected_not_found, (
        f"GetCertificate's not-found message must be {expected_not_found!r}; got "
        f"{gone_material_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
