"""e2e-mtls-trust-store-listener-flow."""
from __future__ import annotations

import datetime
import time
import urllib.parse
import urllib.request
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "e2e-mtls-trust-store-listener-flow"
GROUP = "e2e"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """A trust store attached to an mTLS HTTPS listener reports the association and a CRL revocation
    (count and served content); after DeleteListener the association is gone and, once deleted,
    DescribeTrustStores fails with TrustStoreNotFound."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    s3 = ctx.client("s3")
    acm = ctx.client("acm")
    elbv2 = ctx.client("elbv2")

    subnet_a, subnet_b = _default_vpc_two_az_subnets(ctx)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-test-ca")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    )

    # ALB rejects a CA:TRUE listener certificate (UnsupportedCertificate), so the listener gets a
    # separate CA:FALSE leaf certificate.
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-test-server")])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(server_subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("sim2real-test-server.example.com")]), critical=False)
        .sign(server_key, hashes.SHA256())
    )
    server_cert_pem = server_cert.public_bytes(serialization.Encoding.PEM)
    server_key_pem = server_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    )

    revoked_serial = 424242
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=1))
        .add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(revoked_serial).revocation_date(now).build()
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    crl_pem = crl.public_bytes(serialization.Encoding.PEM)

    cert_arn = acm.import_certificate(Certificate=server_cert_pem, PrivateKey=server_key_pem)["CertificateArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: acm.delete_certificate(CertificateArn=cert_arn)))

    bucket = _short_name(ctx, "sim2real-mtls-", 63).lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    s3.put_object(Bucket=bucket, Key="ca-bundle.pem", Body=cert_pem)
    s3.put_object(Bucket=bucket, Key="revoked.crl", Body=crl_pem)

    ts_name = _short_name(ctx, "sim2realts", 32)
    ts_arn = elbv2.create_trust_store(
        Name=ts_name, CaCertificatesBundleS3Bucket=bucket, CaCertificatesBundleS3Key="ca-bundle.pem"
    )["TrustStores"][0]["TrustStoreArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_trust_store(TrustStoreArn=ts_arn)))
    _poll_until(
        lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0]["Status"],
        lambda status: status == "ACTIVE",
        timeout_s=60.0,
        interval_s=3.0,
    )

    lb_name = _short_name(ctx, "sim2real-mtls-lb-", 32)
    lb_arn = elbv2.create_load_balancer(
        Name=lb_name, Subnets=[subnet_a, subnet_b], Type="application", Scheme="internal"
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)))
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda code: code == "active",
        timeout_s=240.0,
        interval_s=10.0,
    )

    tg_name = _short_name(ctx, "sim2real-mtls-tg-", 32)
    tg_arn = elbv2.create_target_group(Name=tg_name, TargetType="lambda")["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn)))

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTPS",
        Port=443,
        Certificates=[{"CertificateArn": cert_arn}],
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
        MutualAuthentication={"Mode": "verify", "TrustStoreArn": ts_arn, "IgnoreClientCertificateExpiry": False},
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_listener(ListenerArn=listener_arn)))

    # The association appears after a short propagation delay, and its ResourceArn is the load
    # balancer ARN, not the listener ARN.
    assocs = _poll_until(
        lambda: elbv2.describe_trust_store_associations(TrustStoreArn=ts_arn)["TrustStoreAssociations"],
        lambda assocs: any(a["ResourceArn"] == lb_arn for a in assocs),
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert any(a["ResourceArn"] == lb_arn for a in assocs), (
        f"load balancer {lb_arn} not reported as a trust store association, got {assocs!r}"
    )

    revocations = elbv2.add_trust_store_revocations(
        TrustStoreArn=ts_arn,
        RevocationContents=[{"S3Bucket": bucket, "S3Key": "revoked.crl", "RevocationType": "CRL"}],
    )["TrustStoreRevocations"]
    assert len(revocations) == 1, f"expected exactly 1 revocation batch, got {len(revocations)}: {revocations!r}"
    revocation_id = revocations[0]["RevocationId"]
    assert revocations[0]["NumberOfRevokedEntries"] == 1, (
        f"expected 1 revoked entry parsed from the CRL, got {revocations[0]['NumberOfRevokedEntries']!r}"
    )

    location = elbv2.get_trust_store_revocation_content(TrustStoreArn=ts_arn, RevocationId=revocation_id)["Location"]
    # Location is a presigned URL into an ELB-managed bucket (not the caller's), valid ten minutes.
    parts = urllib.parse.urlsplit(location) if isinstance(location, str) else None
    assert parts is not None and parts.scheme in ("http", "https") and parts.hostname, (
        f"expected a well-formed http(s) presigned URL, got {location!r}"
    )
    _url, _route = ctx.endpoint_route(location)
    with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=20) as resp:
        fetched_crl = resp.read()
    assert fetched_crl == crl_pem, (
        f"revocation content fetched from the presigned Location ({len(fetched_crl)} bytes) did not match "
        f"the uploaded CRL ({len(crl_pem)} bytes)"
    )

    ts_after = elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0]
    assert ts_after["TotalRevokedEntries"] == 1, (
        f"expected TotalRevokedEntries == 1 after the add, got {ts_after['TotalRevokedEntries']!r}"
    )

    elbv2.delete_listener(ListenerArn=listener_arn)
    _poll_until(
        lambda: elbv2.describe_trust_store_associations(TrustStoreArn=ts_arn)["TrustStoreAssociations"],
        lambda assocs: not any(a["ResourceArn"] == lb_arn for a in assocs),
        timeout_s=60.0,
        interval_s=3.0,
    )
    remaining = elbv2.describe_trust_store_associations(TrustStoreArn=ts_arn)["TrustStoreAssociations"]
    assert not any(a["ResourceArn"] == lb_arn for a in remaining), (
        f"load balancer {lb_arn} still reported as a trust store association after DeleteListener: {remaining!r}"
    )
    elbv2.delete_trust_store(TrustStoreArn=ts_arn)
    code, message = _error(lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn]))
    assert code == "TrustStoreNotFound", (
        f"expected DescribeTrustStores to fail with TrustStoreNotFound after DeleteTrustStore, got {code!r}"
    )
    expected = f"Trust store ARN '{ts_arn}' not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


def _ignore_not_found(fn: Callable[[], Any]) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if "NotFound" not in exc.response.get("Error", {}).get("Code", ""):
            raise


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    from botocore.exceptions import ClientError

    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("NoSuchBucket", "NotFound"):
            raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _short_name(ctx: Any, prefix: str, max_len: int) -> str:
    name = ctx.unique_name(prefix)
    return name[:max_len].rstrip("-")


def _default_vpc_two_az_subnets(ctx) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region to attach an ALB to")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network does not have subnets in >=2 Availability Zones for an ALB")
    ids = list(by_az.values())
    return ids[0], ids[1]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
