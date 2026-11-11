"""trust-store-ops-not-found."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trust-store-ops-not-found"
GROUP = 'trust-store'
SERVICES = ['elbv2']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Four trust-store ops on a well-formed but absent ARN raise TrustStoreNotFound with the exact
    message, after the same ops succeed on a real trust store as a positive control.
    """
    elb = ctx.client("elbv2")
    bucket = _create_bucket(ctx)
    ca_pem = _self_signed_ca_pem(ctx.unique_name("elbv2-ts-notfound-ca-"))
    ctx.client("s3").put_object(Bucket=bucket, Key="ca-bundle.pem", Body=ca_pem)

    real_arn = elb.create_trust_store(
        Name=ctx.unique_name("ts-")[:32].rstrip("-"),
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key="ca-bundle.pem",
        Tags=_tags_kv(),
    )["TrustStores"][0]["TrustStoreArn"]
    ctx.on_cleanup(lambda: _delete_if_present(elb, real_arn))
    _wait_for_active(ctx, real_arn)

    # Positive control: the refusals below must be about the absent ARN, not every call.
    revocations = elb.describe_trust_store_revocations(TrustStoreArn=real_arn)["TrustStoreRevocations"]
    assert revocations == [], (
        f"a freshly created trust store should have no revocations, got {revocations!r}"
    )
    associations = elb.describe_trust_store_associations(TrustStoreArn=real_arn)["TrustStoreAssociations"]
    assert associations == [], (
        f"an unassociated trust store should have no associations, got {associations!r}"
    )
    elb.modify_trust_store(
        TrustStoreArn=real_arn,
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key="ca-bundle.pem",
    )
    elb.delete_trust_store(TrustStoreArn=real_arn)

    bogus = _bogus_arn(ctx, "truststore/sim2real-behav-absent/0123456789abcdef")

    cases = [
        ("DescribeTrustStoreRevocations", lambda: elb.describe_trust_store_revocations(TrustStoreArn=bogus),
         f"Trust store ARN '{bogus}' not found"),
        ("DescribeTrustStoreAssociations", lambda: elb.describe_trust_store_associations(TrustStoreArn=bogus),
         f"Trust store ARN '{bogus}' not found"),
        ("DeleteTrustStore", lambda: elb.delete_trust_store(TrustStoreArn=bogus),
         f"Trust store ARN '{bogus}' not found"),
        ("ModifyTrustStore", lambda: elb.modify_trust_store(
            TrustStoreArn=bogus,
            CaCertificatesBundleS3Bucket=bucket,
            CaCertificatesBundleS3Key="ca-bundle.pem",
        ), f"Trust store ARN '{bogus}' not found"),
    ]
    for op, call, expected_message in cases:
        code, message = _client_error(call)
        assert code == "TrustStoreNotFound", (
            f"{op} on a well-formed but absent trust-store ARN raised {code!r}, expected TrustStoreNotFound"
        )
        assert message == expected_message, (
            f"{op} on an absent trust-store ARN: expected message {expected_message!r}, got {message!r}"
        )


def _tags_kv():
    return [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    ]


def _client_error(fn):
    """Call fn() and return (Error.Code, Error.Message) from its ClientError.

    An unexpected success raises, so acceptance is never reported as a code mismatch.
    """
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(
        f"expected a ClientError (TrustStoreNotFound), but the call SUCCEEDED and returned "
        f"{result!r}"
    )


def _bogus_arn(ctx, resource: str) -> str:
    """A well-formed but nonexistent ELBv2 ARN, so the call exercises NotFound semantics
    rather than ARN validation."""
    account = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:elasticloadbalancing:{ctx.region}:{account}:{resource}"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-ts-notfound-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _self_signed_ca_pem(common_name: str) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
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


def _delete_if_present(elb, arn: str) -> None:
    try:
        elb.delete_trust_store(TrustStoreArn=arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "TrustStoreNotFound":
            raise


def _wait_for_active(ctx, arn: str, timeout_s: float = 150.0, interval_s: float = 3.0) -> None:
    elb = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = elb.describe_trust_stores(TrustStoreArns=[arn])["TrustStores"][0]["Status"]
        if last == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"trust store {arn!r} did not reach ACTIVE within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
