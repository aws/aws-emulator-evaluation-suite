"""op-contract-export-certificate."""
from __future__ import annotations

import datetime
import re
import time

from behavioral_harness import tags

CHECK = "op-contract-export-certificate"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ExportCertificate refuses a nonexistent ARN and a pending Export=ENABLED certificate with
    ResourceNotFoundException, and an ISSUED, IMPORTED certificate with ValidationException that carries
    no private key, each with its exact message: only issued, export-enabled certificates are exportable.
    """
    acm = ctx.client("acm")
    arn, _cert_pem = _import_certificate(ctx, _domain(ctx))

    passphrase = b"sim2real-pass-1234"

    # boundary 1: well-formed ARN, certificate does not exist
    fake_arn = _fake_certificate_arn(ctx)
    code_missing, message_missing = _error(
        lambda: acm.export_certificate(CertificateArn=fake_arn, Passphrase=passphrase)
    )
    assert code_missing == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code_missing}"
    assert message_missing == f"Could not find certificate {fake_arn}.", message_missing

    # A PENDING_VALIDATION certificate requested with Export=ENABLED is not found by the export
    # path although DescribeCertificate sees it; the poll rules out propagation lag.
    pending_arn = acm.request_certificate(
        DomainName=_unique_domain(ctx, "acmexp"),
        ValidationMethod="DNS",
        Options={"Export": "ENABLED"},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, pending_arn))
    _wait_describable(acm, pending_arn)
    code_pending, message_pending = _poll_for_error_code(
        lambda: acm.export_certificate(CertificateArn=pending_arn, Passphrase=passphrase),
        "ResourceNotFoundException",
    )
    assert code_pending == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for the pending certificate, got {code_pending}"
    )
    assert message_pending == f"Could not find an issued certificate {pending_arn}", message_pending

    # boundary 2: certificate exists and is ISSUED, but an imported certificate is
    # not an exportable certificate type
    cert = _wait_describable(acm, arn)
    assert cert["Status"] == "ISSUED", f"expected imported cert to be ISSUED, got {cert['Status']}"
    assert cert["Type"] == "IMPORTED", f"expected imported cert type IMPORTED, got {cert['Type']}"
    error_type = _client_error(
        lambda: acm.export_certificate(CertificateArn=arn, Passphrase=passphrase)
    )
    assert error_type is not None, "expected ExportCertificate to reject an imported certificate"
    code_type = error_type.response["Error"]["Code"]
    assert code_type == "ValidationException", f"expected ValidationException, got {code_type}"
    message_type = error_type.response["Error"].get("Message")
    assert message_type == f"Certificate ARN: {arn} is not an export enabled certificate", message_type
    assert "PrivateKey" not in error_type.response, "no private key material may be present in the error response"


def _error(fn):
    """The (code, message) of the ClientError fn raises; a success is a mismatch."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("expected the call to be refused, it succeeded")


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as e:
        return e


def _unique_domain(ctx, label: str) -> str:
    raw = ctx.unique_name(f"{label}-").lower()
    raw = re.sub(r"[^a-z0-9-]", "-", raw).strip("-")
    return f"{raw}.example.com"


def _poll_for_error_code(fn, expected_code, timeout_s: float = 30.0, interval_s: float = 1.5):
    """Poll (bounded) until fn fails with expected_code, which ACM can reach a few seconds after
    the certificate becomes describable; return the last-seen (code, message) at the deadline."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_code = last_message = None
    while time.monotonic() < deadline:
        try:
            fn()
            last_code = last_message = None
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            last_message = exc.response["Error"].get("Message")
            if last_code == expected_code:
                return last_code, last_message
        time.sleep(interval_s)
    return last_code, last_message


def _wait_describable(acm, arn: str, timeout_s: float = 30.0, interval_s: float = 1.5):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return acm.describe_certificate(CertificateArn=arn)["Certificate"]
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            time.sleep(interval_s)
    raise AssertionError(f"certificate {arn} never became describable: {last_exc}")


def _safe_delete(acm, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        acm.delete_certificate(CertificateArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _domain(ctx) -> str:
    return f"{ctx.unique_name('sim2real-acm-')}.example.com".lower()


def _fake_certificate_arn(ctx) -> str:
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    return f"arn:aws:acm:{ctx.region}:{account_id}:certificate/00000000-0000-0000-0000-000000000000"


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


def _import_certificate(ctx, common_name: str):
    cert_pem, key_pem = _generate_self_signed_cert(common_name)
    acm = ctx.client("acm")
    resp = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=arn))
    return arn, cert_pem


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
