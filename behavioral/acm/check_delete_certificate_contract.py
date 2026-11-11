"""op-contract-delete-certificate."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags

CHECK = "op-contract-delete-certificate"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteCertificate removes the certificate (it disappears from Describe/List);
    a second delete on the same now-gone ARN is rejected with ResourceNotFoundException."""
    acm = ctx.client("acm")
    arn, _cert_pem = _import_certificate_no_cleanup(ctx, _domain(ctx))
    cleaned = {"done": False}

    def _cleanup():
        if not cleaned["done"]:
            from botocore.exceptions import ClientError

            try:
                acm.delete_certificate(CertificateArn=arn)
            except ClientError as exc:
                # ResourceNotFoundException here just means it is already gone -- fine.
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise

    ctx.on_cleanup(_cleanup)

    # sanity: certificate exists right after import
    desc = acm.describe_certificate(CertificateArn=arn)
    assert desc["Certificate"]["Status"] == "ISSUED", f"expected ISSUED, got {desc['Certificate']['Status']!r}"

    resp = acm.delete_certificate(CertificateArn=arn)
    cleaned["done"] = True  # the explicit delete above already ran; cleanup is now a no-op safety net
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected 200 from DeleteCertificate, got {resp['ResponseMetadata']['HTTPStatusCode']}"
    )

    # deletion is eventually consistent: poll until Describe/List no longer see it
    deadline = time.monotonic() + 30.0
    expected_message = f"Could not find certificate {arn}."
    refusal = False
    while time.monotonic() < deadline:
        refusal = _certificate_gone(acm, arn)
        if refusal is not False:
            break
        time.sleep(1.0)
    assert refusal is not False, "certificate still describable 30s after delete"
    assert refusal == ("ResourceNotFoundException", expected_message), (
        f"expected ResourceNotFoundException {expected_message!r}, got {refusal!r}"
    )

    arns_listed = {c["CertificateArn"] for c in acm.list_certificates(MaxItems=1000)["CertificateSummaryList"]}
    assert arn not in arns_listed, f"deleted certificate {arn} still appears in ListCertificates"

    # error boundary: deleting the same certificate again fails since it no longer exists
    code, message = _error_code(lambda: acm.delete_certificate(CertificateArn=arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code} ({message!r})"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _certificate_gone(acm, arn):
    """(code, message) once DescribeCertificate refuses with ResourceNotFoundException, False while it still reads."""
    from botocore.exceptions import ClientError

    try:
        acm.describe_certificate(CertificateArn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return e.response["Error"]["Code"], e.response["Error"].get("Message")
        raise
    return False


def _domain(ctx) -> str:
    return f"{ctx.unique_name('sim2real-acm-')}.example.com".lower()


def _generate_self_signed_cert(common_name: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
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
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _import_certificate_no_cleanup(ctx, common_name: str):
    """Import a certificate; the caller registers its own cleanup safety net rather than
    the default unconditional one, since this check deletes the certificate itself."""
    cert_pem, key_pem = _generate_self_signed_cert(common_name)
    acm = ctx.client("acm")
    resp = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)
    return resp["CertificateArn"], cert_pem


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
