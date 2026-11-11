"""tag-resource-generic-visible-via-list-tags-for-certificate."""
from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "tag-resource-generic-visible-via-list-tags-for-certificate"
GROUP = "tagging"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource rejects a certificate ARN with ValidationException and adds no tag (certificates
    use AddTagsToCertificate), while tagging an ACME endpoint succeeds as a positive control."""
    import cryptography  # noqa: F401

    from botocore.exceptions import ClientError

    acm = ctx.client("acm")

    endpoint_arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact="NOT_REQUIRED",
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _safe_delete_acme_endpoint(acm, endpoint_arn))

    control_key = ctx.unique_name("acm-generictag-control-")
    acm.tag_resource(ResourceArn=endpoint_arn, Tags=[{"Key": control_key, "Value": "control"}])
    via_endpoint = {t["Key"]: t["Value"] for t in acm.list_tags_for_resource(ResourceArn=endpoint_arn)["Tags"]}
    assert via_endpoint.get(control_key) == "control", (
        "positive control: TagResource must tag a resource type it supports"
    )

    domain = _domain(ctx, "tagxapi2")
    cert_pem, key_pem, _key = _generate_self_signed_cert(domain)
    arn = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, arn))

    tag_key = ctx.unique_name("acm-generictag-")
    try:
        acm.tag_resource(ResourceArn=arn, Tags=[{"Key": tag_key, "Value": "via-generic"}])
        raise AssertionError("TagResource must reject a certificate ARN")
    except ClientError as err:
        assert err.response["Error"]["Code"] == "ValidationException", err.response["Error"]["Code"]
        expected = (
            f"TagResource only supports non-certificate resource types. Resource {arn} "
            "is a certificate resource. Use AddTagsToCertificate API instead."
        )
        message = err.response["Error"].get("Message")
        assert message == expected, f"expected {expected!r}, got {message!r}"

    via_cert_api = {t["Key"]: t["Value"] for t in acm.list_tags_for_certificate(CertificateArn=arn)["Tags"]}
    assert tag_key not in via_cert_api, "a rejected TagResource call must not have added the tag"


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


def _safe_delete_acme_endpoint(acm, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        acm.delete_acme_endpoint(AcmeEndpointArn=arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
