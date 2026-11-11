"""domain-name-mtls-ownership-verification-enforced."""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-name-mtls-ownership-verification-enforced"
GROUP = "representation"
SERVICES = ["apigatewayv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A REGIONAL domain on an ACM-imported cert round-trips its DomainNameConfigurations, and adding
    mTLS to it without OwnershipVerificationCertificateArn is rejected leaving no mTLS state.
    """
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    apigw = ctx.client("apigatewayv2")
    acm = ctx.client("acm")

    domain_name = f"{ctx.unique_name('sim2real-mtls-')}.example.com"
    cert_pem, key_pem = _generate_self_signed_cert(domain_name)
    cert_arn = _import_cert(ctx, acm, cert_pem, key_pem)

    # Positive control: a plain (non-mTLS) domain using the imported cert is created
    # fine and its DomainNameConfigurations round-trip byte-identical via GetDomainName.
    created = apigw.create_domain_name(
        DomainName=domain_name,
        DomainNameConfigurations=[{"CertificateArn": cert_arn, "EndpointType": "REGIONAL"}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_domain_name(DomainName=domain_name)))
    created_cfg = created["DomainNameConfigurations"][0]
    assert created_cfg["CertificateArn"] == cert_arn, created_cfg["CertificateArn"]
    assert created_cfg["EndpointType"] == "REGIONAL", created_cfg["EndpointType"]

    fetched = apigw.get_domain_name(DomainName=domain_name)
    fetched_cfg = fetched["DomainNameConfigurations"][0]
    assert fetched_cfg["CertificateArn"] == cert_arn, fetched_cfg["CertificateArn"]
    assert fetched_cfg["EndpointType"] == "REGIONAL", fetched_cfg["EndpointType"]
    assert not fetched.get("MutualTlsAuthentication"), fetched.get("MutualTlsAuthentication")

    # Break exactly one thing: try to ADD mTLS (via UpdateDomainName) on top of the
    # ACM-imported CertificateArn with no OwnershipVerificationCertificateArn supplied.
    bucket, key, version_id = _upload_truststore(ctx, cert_pem)
    truststore_uri = f"s3://{bucket}/{key}"

    def _attempt():
        apigw.update_domain_name(
            DomainName=domain_name,
            DomainNameConfigurations=[{"CertificateArn": cert_arn, "EndpointType": "REGIONAL"}],
            MutualTlsAuthentication={"TruststoreUri": truststore_uri, "TruststoreVersion": version_id},
        )

    code, message = _error_code(_attempt)
    assert code == "BadRequestException", f"{code!r}: {message!r}"
    assert message == (
        "Missing ownershipVerificationCertificate. To use an imported or private certificate for "
        "the domain name, ownershipVerificationCertificate is required."
    ), f"unexpected BadRequestException message: {message!r}"

    # No partial mTLS state should have been applied by the rejected update.
    after = apigw.get_domain_name(DomainName=domain_name)
    assert not after.get("MutualTlsAuthentication"), after.get("MutualTlsAuthentication")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "NoSuchBucket",
            "NoSuchKey",
            "NotFoundException",
            "ResourceNotFoundException",
        ):
            raise


def _error_code(fn):
    """Call fn(); return its error code. An unexpected SUCCESS raises rather than being
    reported as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected BadRequestException, but the call SUCCEEDED and returned {result!r}")


def _generate_self_signed_cert(common_name: str) -> tuple[bytes, bytes]:
    with tempfile.TemporaryDirectory() as d:
        key_path = Path(d) / "key.pem"
        cert_path = Path(d) / "cert.pem"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key_path), "-out", str(cert_path),
                "-days", "2", "-subj", f"/CN={common_name}",
            ],
            check=True, capture_output=True, timeout=30,
        )
        return cert_path.read_bytes(), key_path.read_bytes()


def _import_cert(ctx, acm, cert_pem: bytes, key_pem: bytes) -> str:
    resp = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _safe(lambda: acm.delete_certificate(CertificateArn=cert_arn)))
    return cert_arn


def _upload_truststore(ctx, ca_bundle_pem: bytes) -> tuple[str, str, str]:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-mtls-ts-")
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _safe(lambda: s3.delete_bucket(Bucket=bucket)))
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    key = "truststore/ca-bundle.pem"
    put_resp = s3.put_object(Bucket=bucket, Key=key, Body=ca_bundle_pem)
    version_id = put_resp["VersionId"]
    ctx.on_cleanup(lambda: _safe(lambda: s3.delete_object(Bucket=bucket, Key=key, VersionId=version_id)))
    return bucket, key, version_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

