"""import-certificate-key-mismatch-fails."""
from __future__ import annotations

import datetime
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from behavioral_harness import tags

CHECK = "import-certificate-key-mismatch-fails"
GROUP = 'error-semantics'
SERVICES = ['acm']

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

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ImportCertificate refuses a PrivateKey that does not match the certificate's public key
    with ValidationException and the exact message, and the mismatched domain never appears in
    ListCertificates; a matched pair for a sibling domain imports."""
    acm = ctx.client("acm")

    ok_domain = ctx.unique_name("sim2real-behav-keymm-ok-").rstrip("-") + ".example.com"
    cert_pem_ok, key_pem_ok = _self_signed_cert(ok_domain)
    ctrl = acm.import_certificate(
        Certificate=cert_pem_ok, PrivateKey=key_pem_ok,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctrl_arn = ctrl["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=ctrl_arn))
    assert ctrl_arn, "positive control: importing a matched cert/key pair must succeed"

    bad_domain = ctx.unique_name("sim2real-behav-keymm-bad-").rstrip("-") + ".example.com"
    cert_pem_a, _key_pem_a = _self_signed_cert(bad_domain)
    _cert_pem_b, key_pem_b = _self_signed_cert(bad_domain.replace(".", "-b.", 1))

    try:
        result = acm.import_certificate(Certificate=cert_pem_a, PrivateKey=key_pem_b)
    except ClientError as _e:
        code = _e.response.get("Error", {}).get("Code")
        message = _e.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(f"a mismatched cert/key import succeeded and returned {result!r}")
    # ACM reports the key/certificate pairing failure as ValidationException.
    assert code == "ValidationException", (
        f"expected ValidationException for a mismatched cert/key import, got {code!r}"
    )
    expected_message = "Key provided does not match the certificate."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    listed_domains = [
        summary["DomainName"]
        for page in acm.get_paginator("list_certificates").paginate()
        for summary in page["CertificateSummaryList"]
    ]
    assert bad_domain not in listed_domains, (
        f"a rejected import must not create a certificate, but {bad_domain!r} appeared in "
        "ListCertificates"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
