"""add-trust-store-revocations-too-many-entries-fails."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "add-trust-store-revocations-too-many-entries-fails"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddTrustStoreRevocations past the trust store's revocation-content quota fails with
    TooManyTrustStoreRevocationEntries "Trust store can have up to <n> revocation contents" and adds nothing."""
    elbv2 = ctx.client("elbv2")

    ca_key, ca_cert = _generate_ca(ctx.unique_name("sim2real-ca-"))
    ts_arn = _create_trust_store(ctx, ca_cert)

    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    crl_bytes = _crl_pem(ca_key, ca_cert)

    # Quota is account-adjustable, and a single AddTrustStoreRevocations call is itself capped at
    # just 1 entry (real AWS returns a request-shape ValidationError -- "Up to 1 revocation
    # contents can be specified" -- if you try to submit more than one per call). Rather than
    # precompute an exact quota number, add revocation lists one at a time until the API itself
    # rejects one with TooManyTrustStoreRevocationEntriesException, bounding the number of
    # attempts as a safety net against an unbounded loop.
    from botocore.exceptions import ClientError

    added_keys: list[str] = []
    code = message = None
    max_attempts = 200
    for i in range(max_attempts):
        key = f"crl-{i}.pem"
        s3.put_object(Bucket=bucket, Key=key, Body=crl_bytes)
        try:
            elbv2.add_trust_store_revocations(
                TrustStoreArn=ts_arn,
                RevocationContents=[{"S3Bucket": bucket, "S3Key": key, "RevocationType": "CRL"}],
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message")
            break
        added_keys.append(key)
    else:
        raise AssertionError(f"did not hit the revocation entries quota after {max_attempts} attempts")

    # ELBv2's wire error code omits the "Exception" suffix of the modeled exception name
    # (TooManyTrustStoreRevocationEntries), and Error.Code carries the wire value.
    assert code == "TooManyTrustStoreRevocationEntries", (
        f"expected TooManyTrustStoreRevocationEntries, got {code}"
    )
    expected_message = f"Trust store can have up to {len(added_keys)} revocation contents"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # AddTrustStoreRevocations processes the referenced S3 object asynchronously, so
    # DescribeTrustStoreRevocations called immediately after the last accepted add can transiently
    # reflect fewer entries than were actually accepted. It's also paginated (Marker/NextMarker),
    # so a single unpaginated call can under-report the true count even once settled. Poll
    # (bounded), paginating fully on each probe, for the count to settle at the accepted total
    # before asserting on it.
    revocations = _poll_until(
        lambda: _describe_all_trust_store_revocations(elbv2, ts_arn),
        lambda r: len(r) == len(added_keys),
        timeout_s=90,
        interval_s=3,
    )
    assert len(revocations) == len(added_keys), (
        f"expected {len(added_keys)} revocation lists at quota, got {len(revocations)}"
    )

    # The rejected overflow entry should not have been added.
    revocations_after = _describe_all_trust_store_revocations(elbv2, ts_arn)
    assert len(revocations_after) == len(added_keys), (
        f"rejected overflow entry should not have been added: {revocations_after}"
    )


def _describe_all_trust_store_revocations(elbv2, ts_arn):
    """DescribeTrustStoreRevocations is paginated (Marker/NextMarker) -- follow all pages."""
    revocations = []
    kwargs = {"TrustStoreArn": ts_arn}
    while True:
        resp = elbv2.describe_trust_store_revocations(**kwargs)
        revocations.extend(resp.get("TrustStoreRevocations", []))
        marker = resp.get("NextMarker")
        if not marker:
            break
        kwargs["Marker"] = marker
    return revocations


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
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _generate_ca(cn: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _crl_pem(ca_key, ca_cert, revoked_serials=()) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    now = datetime.datetime.utcnow()
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=7))
    )
    for serial in revoked_serials:
        revoked = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(now).build()
        builder = builder.add_revoked_certificate(revoked)
    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.PEM)


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-elbv2-ts-")
    # us-east-1 is an S3 CreateBucket API quirk, not a check-level region pin: passing a
    # LocationConstraint there is itself rejected, so ctx.region decides the request shape only.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _tags_kv()})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _tags_kv():
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}]


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


def _create_trust_store(ctx, ca_cert) -> str:
    from cryptography.hazmat.primitives import serialization

    cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    bucket = _create_bucket(ctx)
    ctx.client("s3").put_object(Bucket=bucket, Key="ca-bundle.pem", Body=cert_pem)
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-ts-")
    resp = elbv2.create_trust_store(
        Name=name,
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key="ca-bundle.pem",
        Tags=_tags_kv(),
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
