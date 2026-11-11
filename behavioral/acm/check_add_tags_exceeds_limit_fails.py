"""add-tags-exceeds-limit-fails."""
from __future__ import annotations

import datetime
import time
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from behavioral_harness import tags

CHECK = "add-tags-exceeds-limit-fails"
GROUP = 'overly-permissive'
SERVICES = ['acm']

_THROTTLE_CODES = (
    "ThrottlingException",
    "Throttling",
    "TooManyRequestsException",
    "RequestInProgressException",
)

def _retry_throttle(fn, attempts=7, base_delay=4.0):
    """Retry fn() on ACM throttle codes."""
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

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddTagsToCertificate rejects a 51-tag batch (over the 50-tag limit) with ValidationException
    and applies none of its tags."""
    acm = ctx.client("acm")
    arn, _cert_pem, _key_pem = _import_cert(ctx, acm)

    control_key = ctx.unique_name("sim2real-behav-tagcap-")
    _retry_throttle(
        lambda: acm.add_tags_to_certificate(
            CertificateArn=arn, Tags=[{"Key": control_key, "Value": "v-control"}]
        )
    )
    tags_after_control = acm.list_tags_for_certificate(CertificateArn=arn)["Tags"]
    control_matches = [t for t in tags_after_control if t["Key"] == control_key]
    assert control_matches, (
        f"positive control: expected {control_key} in list_tags_for_certificate, "
        f"got {tags_after_control}"
    )

    # ACM rejects an over-sized tag list at request-shape validation (ValidationException),
    # not as a resource quota violation (TooManyTagsException).
    too_many_tags = [{"Key": f"k-oversized-{i}", "Value": "v"} for i in range(51)]
    try:
        acm.add_tags_to_certificate(CertificateArn=arn, Tags=too_many_tags)
    except ClientError as _e:
        code = _e.response.get("Error", {}).get("Code")
        message = _e.response.get("Error", {}).get("Message")
    else:
        raise AssertionError("expected the 51-tag AddTagsToCertificate to be rejected, but it SUCCEEDED")
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        "1 validation error detected: Value of the input at 'tags' failed to satisfy constraint: "
        "Member must have length less than or equal to 50"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    tags_after_reject = acm.list_tags_for_certificate(CertificateArn=arn)["Tags"]
    rejected_keys = {t["Key"] for t in tags_after_reject if t["Key"].startswith("k-oversized-")}
    assert not rejected_keys, (
        f"rejected 51-tag batch must not have been partially applied, found {rejected_keys}"
    )
    surviving_control = [t for t in tags_after_reject if t["Key"] == control_key]
    assert surviving_control and surviving_control[0]["Value"] == "v-control", (
        f"control tag {control_key} must be unaffected by the rejected call, "
        f"got {tags_after_reject}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
