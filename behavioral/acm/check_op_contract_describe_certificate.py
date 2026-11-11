"""op-contract-describeCertificate."""
from __future__ import annotations

import datetime
import re
import time

CHECK = "op-contract-describeCertificate"
GROUP = "error-semantics"
SERVICES = ["acm"]


from behavioral_harness import tags


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeCertificate reports a requested certificate as PENDING_VALIDATION/AMAZON_ISSUED with its domain,
    ARN and validation domain, and an imported RSA-2048 one as ISSUED/IMPORTED, unused, with ImportedAt; a non-ARN
    identifier is refused with ValidationException and a nonexistent ARN with ResourceNotFoundException, exactly."""
    acm = ctx.client("acm")
    domain = _unique_domain(ctx, "acmdesc")
    arn = acm.request_certificate(
        DomainName=domain,
        ValidationMethod="DNS",
        Tags=[{"Key": "sim2real-check", "Value": ctx.unique_name("acmdesc-")}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, arn))

    cert = _wait_fully_populated(acm, arn)
    assert cert["DomainName"] == domain
    assert cert["Status"] == "PENDING_VALIDATION"
    assert cert["Type"] == "AMAZON_ISSUED"
    assert cert["CertificateArn"] == arn
    validation_domains = {opt["DomainName"] for opt in cert["DomainValidationOptions"]}
    assert validation_domains == {domain}

    imported_domain = _unique_domain(ctx, "acmdesc-imp")
    cert_pem, key_pem = _generate_self_signed_cert(imported_domain)
    imported_arn = acm.import_certificate(
        Certificate=cert_pem,
        PrivateKey=key_pem,
        Tags=[{"Key": "sim2real-check", "Value": ctx.unique_name("acmdesc-")}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, imported_arn))
    detail = _wait_describable(acm, imported_arn)
    assert detail["CertificateArn"] == imported_arn, (
        f"expected CertificateArn {imported_arn!r}, got {detail.get('CertificateArn')!r}"
    )
    assert detail["DomainName"] == imported_domain, (
        f"expected DomainName {imported_domain!r}, got {detail.get('DomainName')!r}"
    )
    assert detail["Type"] == "IMPORTED", f"expected Type IMPORTED, got {detail.get('Type')!r}"
    assert detail["Status"] == "ISSUED", f"expected Status ISSUED, got {detail.get('Status')!r}"
    # ACM reports the family and bit length of the imported 2048-bit RSA key; the separator is not the contract.
    key_algorithm = detail["KeyAlgorithm"]
    assert re.search(r"(?i)rsa", key_algorithm) and "2048" in key_algorithm, (
        f"expected an RSA 2048-bit key algorithm, got {key_algorithm!r}"
    )
    assert detail.get("InUseBy", []) == [], f"expected InUseBy empty, got {detail.get('InUseBy')!r}"
    assert "ImportedAt" in detail, f"expected ImportedAt present, got keys {sorted(detail)!r}"

    # A non-ARN string fails ACM's server-side ARN pattern; it is 20+ characters so botocore's
    # client-side minimum length lets the request reach the service.
    code, message = _error_code(lambda: acm.describe_certificate(CertificateArn="not-an-acm-arn-0123456789"))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == "1 validation error detected: Value of the input at 'certificateArn' failed to satisfy constraint: Member must satisfy regular expression pattern: arn:[\\w+=/,.@-]+:acm:[\\w+=/,.@-]*:[0-9]+:[\\w+=,.@-]+(/[\\w+=,.@-]+)*", (
        f"expected the exact ValidationException message AWS returns, got {message!r}"
    )

    # A well-formed ARN in the same account and region that names no certificate is
    # refused as not found, not as invalid.
    nonexistent_arn = arn[: arn.rindex("/") + 1] + "00000000-0000-0000-0000-000000000000"
    code, message = _error_code(lambda: acm.describe_certificate(CertificateArn=nonexistent_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == f"Could not find certificate {nonexistent_arn}.", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {message!r}"
    )


# A random ".com" name, not an RFC 2606 reserved one: ACM drives a reserved-domain request to
# FAILED within seconds, while this one stays PENDING_VALIDATION for its 72-hour window.
def _unique_domain(ctx, label: str) -> str:
    raw = ctx.unique_name(f"{label}-").lower()
    raw = re.sub(r"[^a-z0-9-]", "-", raw).strip("-")
    return f"{raw}.com"


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


def _error_code(fn):
    """Call fn(); return its error code and message. A success raises: accepting a call AWS refuses is a
    mismatch of its own, not a wrong error code."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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


def _wait_fully_populated(acm, arn: str, timeout_s: float = 30.0, interval_s: float = 1.5):
    """DescribeCertificate can, for a few seconds after RequestCertificate returns,
    respond successfully but with a Certificate object that has not yet been fully
    populated (e.g. missing DomainName/DomainValidationOptions) -- AWS documents a
    delay of "several seconds" before a freshly requested certificate's information
    is retrievable. Poll until the response carries the fields a fresh AMAZON_ISSUED
    certificate must have, tolerating both ResourceNotFoundException and a
    not-yet-populated Certificate along the way."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    last_cert = None
    while time.monotonic() < deadline:
        try:
            cert = acm.describe_certificate(CertificateArn=arn)["Certificate"]
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            time.sleep(interval_s)
            continue
        last_cert = cert
        if "DomainName" in cert and "DomainValidationOptions" in cert:
            return cert
        time.sleep(interval_s)
    raise AssertionError(
        f"certificate {arn} never became fully populated: last_cert={last_cert} last_exc={last_exc}"
    )


def _safe_delete(acm, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        acm.delete_certificate(CertificateArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
