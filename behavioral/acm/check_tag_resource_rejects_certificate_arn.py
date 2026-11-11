"""tag-resource-rejects-certificate-arn."""
from __future__ import annotations

import datetime
import time
from behavioral_harness import tags
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CHECK = "tag-resource-rejects-certificate-arn"
GROUP = 'overly-permissive'
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

def _best_effort(fn):
    fn()

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

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """The generic TagResource MUST reject certificate ARNs (AddTagsToCertificate owns those)."""
    acm = ctx.client("acm")
    if not hasattr(acm, "tag_resource"):
        raise AssertionError("TagResource not present in the installed botocore model")

    # Positive control: TagResource must actually work against a resource type it does own
    # (an ACME endpoint), so the rejection below is provably specific to certificate ARNs
    # rather than TagResource being broken/deny-all for this account.
    endpoint_arn = _retry_throttle(
        lambda: acm.create_acme_endpoint(
            AuthorizationBehavior="PRE_APPROVED",
            CertificateAuthority={"PublicCertificateAuthority": {}},
            Contact="NOT_REQUIRED",
        )
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn)))

    _retry_throttle(
        lambda: acm.tag_resource(ResourceArn=endpoint_arn, Tags=[{"Key": "generic", "Value": "yes"}])
    )
    endpoint_tags = {t["Key"]: t["Value"] for t in acm.list_tags_for_resource(ResourceArn=endpoint_arn)["Tags"]}
    assert endpoint_tags.get("generic") == "yes", (
        f"positive control failed: TagResource on an ACME endpoint did not apply, got {endpoint_tags}"
    )

    arn, _cert_pem, _key_pem = _import_cert(ctx, acm)

    try:
        acm.tag_resource(ResourceArn=arn, Tags=[{"Key": "generic", "Value": "no"}])
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError("TagResource accepted a certificate ARN")
    assert code == "ValidationException", code
    expected_message = (
        "TagResource only supports non-certificate resource types. "
        f"Resource {arn} is a certificate resource. Use AddTagsToCertificate API instead."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    tags = acm.list_tags_for_certificate(CertificateArn=arn)["Tags"]
    assert not any(t["Key"] == "generic" for t in tags), "rejected TagResource must not have applied the tag"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
