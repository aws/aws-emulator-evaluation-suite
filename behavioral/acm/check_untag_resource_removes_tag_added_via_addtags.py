"""untag-resource-removes-tag-added-via-addtags."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags

CHECK = "untag-resource-removes-tag-added-via-addtags"
GROUP = "tagging"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """The generic UntagResource API refuses certificate ARNs, and the rejected call must not remove
    a tag added via AddTagsToCertificate; a positive control untags a tagged ACME endpoint."""
    import cryptography  # noqa: F401

    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    domain = _domain(ctx, "untagxapi")
    cert_pem, key_pem, _key = _generate_self_signed_cert(domain)
    arn = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, arn))

    tag_key = ctx.unique_name("acm-untag-")
    acm.add_tags_to_certificate(CertificateArn=arn, Tags=[{"Key": tag_key, "Value": "to-be-removed"}])
    before = {t["Key"] for t in acm.list_tags_for_certificate(CertificateArn=arn)["Tags"]}
    assert tag_key in before

    try:
        acm.untag_resource(ResourceArn=arn, TagKeys=[tag_key])
        raise AssertionError("UntagResource must reject a certificate ARN")
    except ClientError as err:
        assert err.response["Error"]["Code"] == "ValidationException", err.response["Error"]["Code"]
        expected_message = (
            "UntagResource only supports non-certificate resource types. "
            f"Resource {arn} is a certificate resource. Use RemoveTagsFromCertificate API instead."
        )
        message = err.response["Error"].get("Message")
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after = {t["Key"] for t in acm.list_tags_for_certificate(CertificateArn=arn)["Tags"]}
    assert tag_key in after, "a rejected UntagResource call must not have removed the tag"

    # positive control: UntagResource genuinely works against a resource type it supports
    # (an ACME endpoint), so the rejection above is specific to certificate ARNs.
    endpoint_arn = _create_acme_endpoint(ctx)
    endpoint_tag_key = ctx.unique_name("acm-untag-endpoint-")
    acm.tag_resource(ResourceArn=endpoint_arn, Tags=[{"Key": endpoint_tag_key, "Value": "v"}])
    endpoint_before = {
        t["Key"]: t["Value"] for t in acm.list_tags_for_resource(ResourceArn=endpoint_arn)["Tags"]
    }
    assert endpoint_before.get(endpoint_tag_key) == "v"

    acm.untag_resource(ResourceArn=endpoint_arn, TagKeys=[endpoint_tag_key])
    endpoint_after = {
        t["Key"]: t["Value"] for t in acm.list_tags_for_resource(ResourceArn=endpoint_arn)["Tags"]
    }
    assert endpoint_tag_key not in endpoint_after, (
        f"positive control: UntagResource did not remove {endpoint_tag_key!r} from a non-certificate "
        f"resource: {endpoint_after}"
    )


def _domain(ctx, tag: str) -> str:
    label = ctx.unique_name(f"acm-{tag}-").rstrip("-").lower().replace("_", "-")
    return f"{label}.example.com"


def _generate_self_signed_cert(
    common_name: str,
    sans=None,
    key=None,
    not_after_days: int = 825,
    is_ca: bool = False,
    issuer_key=None,
    issuer_cn: str | None = None,
):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    if key is None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or common_name)])
    signing_key = issuer_key or key
    san_names = [common_name] + [s for s in (sans or []) if s != common_name]
    now = datetime.datetime.utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=not_after_days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in san_names]), critical=False)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    cert = builder.sign(signing_key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem, key


def _safe_delete(acm, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        acm.delete_certificate(CertificateArn=arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_acme_endpoint(ctx, timeout_s: float = 120.0, interval_s: float = 3.0) -> str:
    acm = ctx.client("acm")
    arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact="NOT_REQUIRED",
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _safe_delete_endpoint(acm, arn))
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if status in ("ACTIVE", "FAILED"):
            break
        time.sleep(interval_s)
    if status != "ACTIVE":
        raise AssertionError(f"AcmeEndpoint {arn} did not become ACTIVE within {timeout_s}s: {status}")
    return arn


def _safe_delete_endpoint(acm, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        acm.delete_acme_endpoint(AcmeEndpointArn=arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
