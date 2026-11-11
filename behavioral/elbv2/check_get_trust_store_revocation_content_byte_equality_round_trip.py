"""get-trust-store-revocation-content-byte-equality-round-trip."""
from __future__ import annotations

import datetime
import time
import urllib.request

from behavioral_harness import tags

CHECK = "get-trust-store-revocation-content-byte-equality-round-trip"
GROUP = "representation"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CRL uploaded via AddTrustStoreRevocations is returned byte-identical by
    GetTrustStoreRevocationContent — the exact bytes that were uploaded, not a
    re-serialized, DER/PEM-converted, or otherwise-normalized copy."""
    ca_cert, ca_key, ca_cert_pem = _generate_self_signed_ca()
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key="ca-bundle.pem", Body=ca_cert_pem)

    elbv2 = ctx.client("elbv2")
    ts_name = ctx.unique_name("sim2real-behav-ts-")
    ts_arn = elbv2.create_trust_store(
        Name=ts_name,
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key="ca-bundle.pem",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["TrustStores"][0]["TrustStoreArn"]
    ctx.on_cleanup(lambda: _delete_trust_store_if_present(elbv2, ts_arn))
    _wait_trust_store_active(ctx, ts_arn)

    crl_pem = _generate_crl(ca_cert, ca_key)
    s3.put_object(Bucket=bucket, Key="revoked.crl", Body=crl_pem)

    revocation = elbv2.add_trust_store_revocations(
        TrustStoreArn=ts_arn,
        RevocationContents=[{"RevocationType": "CRL", "S3Bucket": bucket, "S3Key": "revoked.crl"}],
    )["TrustStoreRevocations"][0]
    revocation_id = revocation["RevocationId"]

    location = elbv2.get_trust_store_revocation_content(
        TrustStoreArn=ts_arn, RevocationId=revocation_id
    )["Location"]
    downloaded = _fetch_location_bytes(ctx, location)

    assert downloaded == crl_pem, "downloaded CRL bytes differ from the uploaded CRL"

    elbv2.delete_trust_store(TrustStoreArn=ts_arn)
    not_found = f"Trust store ARN '{ts_arn}' not found"
    try:
        elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])
    except elbv2.exceptions.TrustStoreNotFoundException as exc:
        message = exc.response["Error"].get("Message")
        assert message == not_found, message
    else:
        raise AssertionError(f"trust store {ts_arn} still describable after delete_trust_store")

    try:
        elbv2.get_trust_store_revocation_content(TrustStoreArn=ts_arn, RevocationId=revocation_id)
    except elbv2.exceptions.TrustStoreNotFoundException as exc:
        message = exc.response["Error"].get("Message")
        assert message == not_found, message
    else:
        raise AssertionError(
            f"get_trust_store_revocation_content succeeded against deleted trust store {ts_arn}"
        )


def _generate_self_signed_ca():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-behav-ca")])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return cert, key, cert_pem


def _generate_crl(ca_cert, ca_key) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    now = datetime.datetime.utcnow()
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=1))
    )
    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.PEM)


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-ts-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=name)
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=name, Key=obj["Key"])
    s3.delete_bucket(Bucket=name)


def _delete_trust_store_if_present(elbv2, arn: str) -> None:
    try:
        elbv2.delete_trust_store(TrustStoreArn=arn)
    except elbv2.exceptions.TrustStoreNotFoundException:
        pass


def _wait_trust_store_active(ctx, arn: str, timeout_s: float = 90.0, interval_s: float = 2.0) -> None:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = elbv2.describe_trust_stores(TrustStoreArns=[arn])["TrustStores"][0]["Status"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"trust store {arn} never reached ACTIVE status")


def _fetch_location_bytes(ctx, location: str) -> bytes:
    if location.startswith("s3://"):
        _, _, rest = location.partition("s3://")
        bucket, _, key = rest.partition("/")
        return ctx.client("s3").get_object(Bucket=bucket, Key=key)["Body"].read()
    _url, _route = ctx.endpoint_route(location)
    with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=30) as resp:  # noqa: S310 - AWS presigned URL
        return resp.read()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
