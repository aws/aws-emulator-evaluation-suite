"""trust-store-in-use-delete-fails."""
from __future__ import annotations

import datetime
import time
from typing import Any

from behavioral_harness import tags

CHECK = "trust-store-in-use-delete-fails"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTrustStore on a trust store attached to a listener fails with TrustStoreInUse and the exact message and
    keeps it; once detached and deleted, DescribeTrustStores fails with TrustStoreNotFound and the exact message."""
    elbv2 = ctx.client("elbv2")

    _, _, ca_pem, _ = _generate_self_signed_cert(ctx, "sim2real-ts-inuse-ca")
    bucket = _new_bucket_with_object(ctx, "ca-bundle.pem", ca_pem)
    ts_arn = elbv2.create_trust_store(
        Name=_ts_name(ctx, "sim2real-ts-"),
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key="ca-bundle.pem",
    )["TrustStores"][0]["TrustStoreArn"]
    ctx.on_cleanup(lambda: _safe_delete_trust_store(elbv2, ts_arn))
    _wait_ts_active(elbv2, ts_arn)

    _, _, leaf_cert_pem, leaf_key_pem = _generate_self_signed_cert(ctx, "sim2real.example.com")
    cert_arn = _import_acm_cert(ctx, leaf_cert_pem, leaf_key_pem)

    subnet_ids = _get_two_default_subnets(ctx)
    lb_arn = _new_alb(ctx, subnet_ids)
    listener_arn = _new_mtls_listener(ctx, lb_arn, cert_arn, ts_arn)

    code, message = _error(lambda: elbv2.delete_trust_store(TrustStoreArn=ts_arn))
    # ELBv2's wire error code for this modeled exception omits the "Exception" suffix that
    # botocore's generated exception class name carries.
    assert code == "TrustStoreInUse", f"expected TrustStoreInUse, got {code}"
    expected_message = f"Trust store with ARN '{ts_arn}' is currently associated"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    still_exists = elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"]
    assert still_exists and still_exists[0]["TrustStoreArn"] == ts_arn, (
        "trust store must still exist after a rejected delete"
    )

    # once the listener is gone the trust store is free to delete (sanity that the block is real)
    elbv2.delete_listener(ListenerArn=listener_arn)
    _poll_until(
        lambda: _delete_succeeds(elbv2, ts_arn),
        lambda deleted: deleted,
        timeout_s=60.0,
    )
    not_found_code, not_found_message = _error(lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn]))
    assert not_found_code == "TrustStoreNotFound", (
        f"expected TrustStoreNotFound after successful delete, got {not_found_code}"
    )
    expected_not_found = f"Trust store ARN '{ts_arn}' not found"
    assert not_found_message == expected_not_found, (
        f"expected message {expected_not_found!r}, got {not_found_message!r}"
    )


from botocore.exceptions import ClientError  # noqa: E402


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, so a target
    that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_succeeds(elbv2, arn: str) -> bool:
    try:
        elbv2.delete_trust_store(TrustStoreArn=arn)
    except ClientError:
        return False
    return True


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _ts_name(ctx, prefix: str) -> str:
    return ctx.unique_name(prefix)[:32].rstrip("-")


def _generate_self_signed_cert(ctx, common_name: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert, key, cert_pem, key_pem


def _new_bucket_with_object(ctx, key: str, body: bytes) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-elbv2-ts-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_object(Bucket=bucket, Key=key, Body=body)
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _safe_delete_trust_store(elbv2, arn: str) -> None:
    try:
        elbv2.delete_trust_store(TrustStoreArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrustStoreNotFound":
            raise


def _wait_ts_active(elbv2, arn: str, timeout_s: float = 90.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = elbv2.describe_trust_stores(TrustStoreArns=[arn])["TrustStores"][0]
        if last["Status"] == "ACTIVE":
            return last
        if last["Status"] not in ("CREATING", "ACTIVE"):
            raise AssertionError(f"unexpected trust store status: {last['Status']}")
        time.sleep(2)
    raise AssertionError(f"trust store did not become ACTIVE within {timeout_s}s (last={last!r})")


def _import_acm_cert(ctx, cert_pem: bytes, key_pem: bytes) -> str:
    acm = ctx.client("acm")
    arn = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_when_released(lambda: acm.delete_certificate(CertificateArn=arn)))
    return arn


def _delete_when_released(fn, timeout_s: float = 300.0) -> None:
    """Teardown-only: the async load balancer delete keeps the certificate in use for a while."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(10)


def _get_two_default_subnets(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to attach an ALB listener")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network does not span at least 2 availability zones")
    return list(by_az.values())[:2]


def _new_alb(ctx, subnet_ids: list[str]) -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-alb-")[:32].rstrip("-")
    arn = elbv2.create_load_balancer(
        Name=name, Subnets=subnet_ids, Scheme="internal", Type="application"
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=arn))
    deadline = time.monotonic() + 300.0
    last_code = None
    while time.monotonic() < deadline:
        lb = elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]
        last_code = lb["State"]["Code"]
        if last_code == "active":
            return arn
        if last_code == "failed":
            raise AssertionError("load balancer entered failed state")
        time.sleep(5)
    raise AssertionError(f"load balancer did not become active in time (last={last_code})")


def _new_mtls_listener(ctx, lb_arn: str, cert_arn: str, trust_store_arn: str, mode: str = "verify") -> str:
    elbv2 = ctx.client("elbv2")
    arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTPS",
        Port=443,
        Certificates=[{"CertificateArn": cert_arn}],
        DefaultActions=[
            {
                "Type": "fixed-response",
                "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain", "MessageBody": "ok"},
            }
        ],
        MutualAuthentication={"Mode": mode, "TrustStoreArn": trust_store_arn},
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _safe_delete_listener(elbv2, arn))
    return arn


def _safe_delete_listener(elbv2, arn: str) -> None:
    try:
        elbv2.delete_listener(ListenerArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ListenerNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
