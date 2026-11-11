"""get-resource-policy-nonexistent-fails."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-resource-policy-nonexistent-fails"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResourcePolicy on a trust store with no policy returns an empty policy, and on a deleted trust store's ARN
    fails with ResourceNotFound "Trust store ARN '<arn>' not found"."""
    elbv2 = ctx.client("elbv2")

    ts_arn = _create_trust_store(ctx, ctx.unique_name("sim2real-ca-"))

    # A freshly created trust store has no resource policy attached (no cross-account sharing
    # configured). Real AWS does not raise ResourceNotFoundException for this case -- it returns a
    # successful response, since the resource itself exists. The Policy field comes back as the
    # literal string "{}" (an empty JSON policy document) rather than being omitted.
    resp = elbv2.get_resource_policy(ResourceArn=ts_arn)
    policy = resp.get("Policy")
    assert policy is None or policy == "{}", (
        f"expected no resource policy (or an empty policy document) for a freshly created trust "
        f"store, got {policy!r}"
    )


    # A syntactically valid trust store ARN that no longer refers to any resource -- because the
    # trust store has genuinely been deleted -- should still fail with the generic
    # ResourceNotFoundException, since the underlying resource doesn't exist at all. (Fabricating
    # a nonexistent ID segment by hand is fragile: if the crafted ID doesn't match the exact
    # length/shape AWS expects for this resource type, the request can instead trip ARN-shape
    # validation and return a different error code. Using a real ARN whose resource was actually
    # deleted avoids that pitfall.)
    deleted_ts_arn = _create_trust_store(ctx, ctx.unique_name("sim2real-ca-deleted-"))
    elbv2.delete_trust_store(TrustStoreArn=deleted_ts_arn)
    # ELBv2's wire error code omits the "Exception" suffix of the modeled exception name
    # (TrustStoreNotFound, not TrustStoreNotFoundException), and Error.Code carries the wire value.
    deleted_code, _deleted_message = _poll_until(
        lambda: _error(lambda: elbv2.describe_trust_stores(TrustStoreArns=[deleted_ts_arn])),
        lambda err: err[0] == "TrustStoreNotFound",
        timeout_s=60,
        interval_s=3,
    )
    assert deleted_code == "TrustStoreNotFound", (
        f"trust store did not become not-found after deletion, got {deleted_code}"
    )

    code_bogus, message_bogus = _error(lambda: elbv2.get_resource_policy(ResourceArn=deleted_ts_arn))
    assert code_bogus == "ResourceNotFound", f"expected ResourceNotFound, got {code_bogus}"
    expected_message = f"Trust store ARN '{deleted_ts_arn}' not found"
    assert message_bogus == expected_message, (
        f"expected message {expected_message!r}, got {message_bogus!r}"
    )


def _error(fn):
    """Return (code, message) of the ClientError fn raises; raise AssertionError if it succeeds."""
    from botocore.exceptions import ClientError

    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp!r}")


def _safe_call(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrustStoreNotFound":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = probe()
        except AssertionError as exc:
            last = exc
        else:
            if predicate(last):
                return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed: {last!r}")


def _self_signed_cert(cn: str) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-elbv2-ts-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    resp = s3.list_object_versions(Bucket=bucket)
    objects = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("Versions", [])]
    objects += [
        {"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("DeleteMarkers", [])
    ]
    if objects:
        failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_trust_store(ctx, cn: str) -> str:
    cert_pem = _self_signed_cert(cn)
    bucket = _create_bucket(ctx)
    ctx.client("s3").put_object(Bucket=bucket, Key="ca-bundle.pem", Body=cert_pem)
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-ts-")
    resp = elbv2.create_trust_store(
        Name=name,
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key="ca-bundle.pem",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ts_arn = resp["TrustStores"][0]["TrustStoreArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: elbv2.delete_trust_store(TrustStoreArn=ts_arn)))
    _poll_until(
        lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0],
        lambda d: d["Status"] == "ACTIVE",
        timeout_s=60,
        interval_s=3,
    )
    return ts_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
