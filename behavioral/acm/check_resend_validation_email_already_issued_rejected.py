"""resend-validation-email-already-issued-rejected."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from behavioral_harness import tags

CHECK = "resend-validation-email-already-issued-rejected"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ResendValidationEmail on an ISSUED certificate raises InvalidStateException, while the same
    call succeeds on a PENDING_VALIDATION certificate under EMAIL validation."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    acm = ctx.client("acm")
    domain = f"{ctx.unique_name('sim2real-acm-resend-')}.example.com"

    # --- negative: an ISSUED (imported) certificate has no validation left to resend ---
    cert_pem, key_pem = _generate_self_signed_pem(domain)
    issued_arn = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=issued_arn))

    issued = acm.describe_certificate(CertificateArn=issued_arn)["Certificate"]
    assert issued["Status"] == "ISSUED", issued["Status"]

    code, message = _error(
        lambda: acm.resend_validation_email(
            CertificateArn=issued_arn, Domain=domain, ValidationDomain=domain
        )
    )
    assert code == "InvalidStateException", code
    expected = f"Certificate {issued_arn} is not in pending validation state"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # the rejected resend didn't affect the certificate's own state (independent read,
    # not the mutating call's own response)
    still_issued = acm.describe_certificate(CertificateArn=issued_arn)["Certificate"]
    assert still_issued["Status"] == "ISSUED", still_issued["Status"]

    # --- positive control: a real PENDING_VALIDATION / EMAIL certificate accepts it ---
    # Not ".example.com": ACM drives EMAIL validation for RFC 2606 reserved domains to a
    # terminal state within a minute, so resend is always rejected. A random ".com" domain
    # stays PENDING_VALIDATION (ACM times it out after 72 hours).
    pending_domain = f"{ctx.unique_name('sim2real-acm-resend-pend-')}.com"
    pending_arn = acm.request_certificate(
        DomainName=pending_domain,
        ValidationMethod="EMAIL",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=pending_arn))

    pending = acm.describe_certificate(CertificateArn=pending_arn)["Certificate"]
    assert pending["Status"] == "PENDING_VALIDATION", pending["Status"]

    # EMAIL-validation setup settles asynchronously (tens of seconds); until then resend raises
    # InvalidStateException ("still in progress"). The bound stays well inside the check's
    # runtime budget. ValidationEmails is not polled: it needs WHOIS records a random domain lacks.
    response = _retry_transient(
        lambda: acm.resend_validation_email(
            CertificateArn=pending_arn, Domain=pending_domain, ValidationDomain=pending_domain
        ),
        attempts=15,
        delay=6.0,
    )
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200, response["ResponseMetadata"]

    # Independent read: the accepted resend leaves the certificate PENDING_VALIDATION.
    still_pending = acm.describe_certificate(CertificateArn=pending_arn)["Certificate"]
    assert still_pending["Status"] == "PENDING_VALIDATION", still_pending["Status"]


def _error(fn: Any) -> tuple[str, str | None]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _retry_transient(fn: Any, *, attempts: int = 10, delay: float = 2.0) -> Any:
    """Bounded retry on the transient InvalidStateException ("still in progress") while ACM
    settles a just-created certificate's validation setup."""
    from botocore.exceptions import ClientError

    last_err: ClientError | None = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidStateException":
                raise
            last_err = err
            time.sleep(delay)
    assert last_err is not None
    raise last_err


def _generate_self_signed_pem(common_name: str) -> tuple[bytes, bytes]:
    """Generate a self-signed RSA certificate/key pair via the openssl CLI."""
    with tempfile.TemporaryDirectory() as tmp:
        key_path = Path(tmp) / "key.pem"
        cert_path = Path(tmp) / "cert.pem"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(key_path), "-out", str(cert_path),
                "-days", "30", "-nodes", "-subj", f"/CN={common_name}", "-sha256",
            ],
            check=True, capture_output=True,
        )
        return cert_path.read_bytes(), key_path.read_bytes()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
