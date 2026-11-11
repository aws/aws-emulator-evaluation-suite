"""update-certificate-options-invalid-state-rejected."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from behavioral_harness import tags

CHECK = "update-certificate-options-invalid-state-rejected"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateCertificateOptions raises InvalidStateException for an ISSUED IMPORTED cert and for a
    PENDING_VALIDATION cert, leaving Options unchanged; only issued ACM certs accept the change.

    Reference: https://docs.aws.amazon.com/acm/latest/APIReference/API_UpdateCertificateOptions.html
    """
    acm = ctx.client("acm")

    # An imported cert's CT-logging disposition was fixed by its issuing CA, so even ISSUED fails.
    cert_pem, key_pem = _generate_self_signed_pem(ctx.unique_name("sim2real-acm-opts-"))
    imported_arn = acm.import_certificate(
        Certificate=cert_pem,
        PrivateKey=key_pem,
        Tags=[{"Key": "sim2real-purpose", "Value": "update-options-invalid-state"}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=imported_arn))

    before = acm.describe_certificate(CertificateArn=imported_arn)["Certificate"]
    assert before["Type"] == "IMPORTED", before["Type"]
    assert before["Status"] == "ISSUED", before["Status"]

    imported_code, imported_message = _error(
        lambda: acm.update_certificate_options(
            CertificateArn=imported_arn, Options={"CertificateTransparencyLoggingPreference": "DISABLED"}
        )
    )
    assert imported_code == "InvalidStateException", imported_code
    assert imported_message == "The UpdateCertificateOptions command is not permitted for imported certificates.", imported_message

    after = acm.describe_certificate(CertificateArn=imported_arn)["Certificate"]
    assert after.get("Options") == before.get("Options"), (after.get("Options"), before.get("Options"))

    # A random ".com" name, not an RFC 2606 reserved one: ACM drives a reserved-domain request to
    # FAILED within seconds, while this one stays PENDING_VALIDATION for its 72-hour window.
    domain = f"{ctx.unique_name('sim2real-acm-opts-mig-')}.com"
    pending_arn = acm.request_certificate(
        DomainName=domain,
        ValidationMethod="EMAIL",
        Tags=[{"Key": "sim2real-purpose", "Value": "update-options-invalid-state"}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=pending_arn))

    pending_before = _wait_fully_populated(acm, pending_arn)
    assert pending_before["Status"] == "PENDING_VALIDATION", pending_before["Status"]

    code, message = _error(
        lambda: acm.update_certificate_options(
            CertificateArn=pending_arn, Options={"CertificateTransparencyLoggingPreference": "DISABLED"}
        )
    )
    assert code == "InvalidStateException", code
    assert message == "The selected certificate is not Issued and/or Valid.", message

    pending_after = acm.describe_certificate(CertificateArn=pending_arn)["Certificate"]
    assert pending_after.get("Options") == pending_before.get("Options"), (
        pending_after.get("Options"), pending_before.get("Options")
    )


def _wait_fully_populated(acm, arn, *, timeout_s=30.0, interval_s=1.5):
    """DescribeCertificate once the record carries DomainName, Options and a
    DomainValidationOptions entry with its ValidationMethod; for several seconds after
    RequestCertificate the Certificate can lack them, or the call can answer
    ResourceNotFoundException."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_cert = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            cert = acm.describe_certificate(CertificateArn=arn)["Certificate"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last_exc = exc
            time.sleep(interval_s)
            continue
        last_cert = cert
        options = cert.get("DomainValidationOptions") or []
        if "DomainName" in cert and "Options" in cert and options and "ValidationMethod" in options[0]:
            return cert
        time.sleep(interval_s)
    raise AssertionError(
        f"certificate {arn} never became fully populated within {timeout_s}s: "
        f"last_cert={last_cert!r} last_exc={last_exc!r}"
    )


def _error(fn: Any) -> tuple[str, str | None]:
    """Call fn() and return its ClientError (code, message); raise if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _generate_self_signed_pem(common_name: str) -> tuple[bytes, bytes]:
    from fidelity_tests_runner import require_tools

    require_tools("openssl")
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
