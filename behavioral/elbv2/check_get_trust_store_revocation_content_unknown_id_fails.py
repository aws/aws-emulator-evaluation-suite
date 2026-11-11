"""get-trust-store-revocation-content-unknown-id-fails."""
from __future__ import annotations

import datetime
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-trust-store-revocation-content-unknown-id-fails"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """GetTrustStoreRevocationContent with an unknown revocation id raises RevocationIdNotFoundException,
    while a genuine revocation id on the same trust store resolves to the exact CRL content submitted."""
    elbv2 = ctx.client("elbv2")
    store, ca_key, ca_cert = _create_active_trust_store(ctx)

    crl_pem = _self_signed_crl_pem(ca_cert, ca_key)
    ctx.client("s3").put_object(Bucket=store["bucket"], Key="content.crl.pem", Body=crl_pem)
    revocation_id = elbv2.add_trust_store_revocations(
        TrustStoreArn=store["arn"],
        RevocationContents=[
            {"RevocationType": "CRL", "S3Bucket": store["bucket"], "S3Key": "content.crl.pem"}
        ],
    )["TrustStoreRevocations"][0]["RevocationId"]

    # positive control: a genuine revocation id resolves to a real, fetchable CRL
    location = elbv2.get_trust_store_revocation_content(
        TrustStoreArn=store["arn"], RevocationId=revocation_id
    )["Location"]
    assert not (p := ctx.published_url_mismatch(location)), p
    try:
        _url, _route = ctx.endpoint_route(location)
        with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=30) as resp:
            downloaded = resp.read()
    except urllib.error.URLError as exc:
        raise AssertionError(f"unable to fetch the presigned revocation content URL: {exc}") from exc
    assert downloaded.strip() == crl_pem.strip(), (
        f"downloaded revocation content ({len(downloaded)} bytes) does not match the CRL "
        f"submitted via AddTrustStoreRevocations ({len(crl_pem)} bytes)"
    )

    # negative: an unknown revocation id on the same trust store is rejected distinctly
    code, message = _error(
        lambda: elbv2.get_trust_store_revocation_content(
            TrustStoreArn=store["arn"], RevocationId=999999
        )
    )
    assert code == "RevocationIdNotFound", (
        f"expected RevocationIdNotFoundException, got {code!r}"
    )
    expected_message = "Revocation ID '999999' not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


# ===== helpers =====
def _error(fn):
    """Return (code, message) of the ClientError fn raises; raise AssertionError if it succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp!r}")


def _self_signed_ca(common_name: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
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
    return key, cert


def _self_signed_crl_pem(ca_cert, ca_key) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=365))
    )
    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.PEM)


def _create_active_trust_store(ctx):
    from cryptography.hazmat.primitives import serialization

    elbv2 = ctx.client("elbv2")
    s3 = ctx.client("s3")
    ca_key, ca_cert = _self_signed_ca("sim2real-trust-store-ca")
    pem = ca_cert.public_bytes(serialization.Encoding.PEM)

    bucket = ctx.unique_name("sim2real-elbv2-ts-").lower().replace("_", "-")
    create_kwargs = {}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **create_kwargs)

    def _cleanup_bucket():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup_bucket)

    key = "ca-bundle.pem"
    s3.put_object(Bucket=bucket, Key=key, Body=pem)

    name = ctx.unique_name("sim2real-ts-")
    resp = elbv2.create_trust_store(
        Name=name,
        CaCertificatesBundleS3Bucket=bucket,
        CaCertificatesBundleS3Key=key,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    arn = resp["TrustStores"][0]["TrustStoreArn"]
    ctx.on_cleanup(lambda: elbv2.delete_trust_store(TrustStoreArn=arn))

    deadline = time.monotonic() + 90.0
    status = None
    while time.monotonic() < deadline:
        status = elbv2.describe_trust_stores(TrustStoreArns=[arn])["TrustStores"][0]["Status"]
        if status == "ACTIVE":
            break
        time.sleep(3.0)
    if status != "ACTIVE":
        raise AssertionError(
            f"trust store did not reach ACTIVE status in time (last status={status})"
        )

    return {"arn": arn, "bucket": bucket}, ca_key, ca_cert


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
