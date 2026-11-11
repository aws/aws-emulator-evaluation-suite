"""list-tags-for-resource-rejects-certificate-arn."""
from __future__ import annotations

import datetime
import time
from behavioral_harness import tags
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CHECK = "list-tags-for-resource-rejects-certificate-arn"
GROUP = 'tags'
SERVICES = ['acm']

_THROTTLE_CODES = (
    "ThrottlingException",
    "Throttling",
    "TooManyRequestsException",
    "RequestInProgressException",
)

def _retry_throttle(fn, attempts=7, base_delay=4.0):
    """Retry fn() on ACM throttle codes (test-infra robustness, not a behavioral assertion)."""
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(base_delay * (i + 1))
    raise last

def _self_signed_cert(common_name, days_valid=365, key_size=2048, san_names=None):
    """Generate a self-signed cert/key pair for ImportCertificate. Returns (cert_pem, key_pem)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    sans = san_names if san_names else [common_name]
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in sans]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem

def _import_cert(ctx, acm, domain=None, **kwargs):
    """Generate a self-signed cert and import it. Returns (arn, cert_pem, key_pem)."""
    domain = domain or ctx.unique_name("sim2real-behav-imported-").rstrip("-") + ".example.com"
    cert_pem, key_pem = _self_signed_cert(domain)
    resp = _retry_throttle(
        lambda: acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem, **kwargs)
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(
        lambda: _retry_throttle(
            lambda: acm.delete_certificate(CertificateArn=arn), attempts=4, base_delay=3.0
        )
    )
    return arn, cert_pem, key_pem

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The generic ListTagsForResource MUST reject certificate ARNs (ListTagsForCertificate owns those)."""
    acm = ctx.client("acm")
    if not hasattr(acm, "list_tags_for_resource"):
        raise AssertionError("ListTagsForResource not present in the installed botocore model")

    # Positive control: ListTagsForResource must actually work against a resource type it is
    # meant for, or the rejection below cannot be told apart from "the operation rejects
    # everything". An ACME endpoint is exactly such a resource.
    endpoint_arn = _retry_throttle(
        lambda: acm.create_acme_endpoint(
            AuthorizationBehavior="PRE_APPROVED",
            CertificateAuthority={"PublicCertificateAuthority": {}},
            Contact="NOT_REQUIRED",
        )
    )["AcmeEndpointArn"]
    ctx.on_cleanup(
        lambda: _retry_throttle(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn))
    )
    _retry_throttle(
        lambda: acm.tag_resource(ResourceArn=endpoint_arn, Tags=[{"Key": "generic-check", "Value": "yes"}])
    )
    endpoint_tags = {
        t["Key"]: t["Value"] for t in acm.list_tags_for_resource(ResourceArn=endpoint_arn)["Tags"]
    }
    assert endpoint_tags.get("generic-check") == "yes", (
        f"ListTagsForResource must see a tag applied to a resource type it supports, got {endpoint_tags}"
    )

    arn, _cert_pem, _key_pem = _import_cert(ctx, acm)

    _retry_throttle(
        lambda: acm.add_tags_to_certificate(
            CertificateArn=arn, Tags=[{"Key": "generic-check", "Value": "yes"}]
        )
    )

    try:
        result = acm.list_tags_for_resource(ResourceArn=arn)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(f"ListTagsForResource on a certificate ARN must be rejected, got {result!r}")
    assert code == "ValidationException", code
    expected = (
        "ListTagsForResource only supports non-certificate resource types. "
        f"Resource {arn} is a certificate resource. Use ListTagsForCertificate API instead."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The certificate-specific API must still work and see the tag.
    specific = {t["Key"]: t["Value"] for t in acm.list_tags_for_certificate(CertificateArn=arn)["Tags"]}
    assert specific.get("generic-check") == "yes", specific


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
