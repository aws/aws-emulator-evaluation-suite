"""import-certificate-arn-mismatch-conflict."""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Any

from behavioral_harness import tags

CHECK = "import-certificate-arn-mismatch-conflict"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Reimporting over a certificate ARN with a mismatched certificate/key pair is refused with
    ValidationException and the exact message and leaves the stored certificate unchanged; a
    valid pair overwrites it on the same ARN, and the same pair reimports idempotently."""
    acm = ctx.client("acm")
    cert1_pem, key1_pem = _generate_self_signed_pem(ctx.unique_name("sim2real-acm-imp1-"))
    arn = acm.import_certificate(
        Certificate=cert1_pem, PrivateKey=key1_pem,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=arn))

    stored_before = acm.get_certificate(CertificateArn=arn)["Certificate"]
    assert stored_before.strip() == cert1_pem.decode().strip(), (
        f"GetCertificate must echo back exactly what was just imported; "
        f"got {stored_before[:60]!r}..."
    )

    cert2_pem, key2_pem = _generate_self_signed_pem(ctx.unique_name("sim2real-acm-imp2-"))

    # --- negative: a certificate paired with a private key that does not belong to it
    #     is a structurally invalid pair and is rejected regardless of ARN reuse ---
    code, message = _error(
        lambda: acm.import_certificate(
            Certificate=cert2_pem, PrivateKey=key1_pem, CertificateArn=arn
        )
    )
    assert code == "ValidationException", (
        f"a certificate paired with a private key that does not belong to it must be "
        f"rejected as ValidationException; got {code!r}"
    )
    expected_message = "Key provided does not match the certificate."
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    stored_after_conflict = acm.get_certificate(CertificateArn=arn)["Certificate"]
    assert stored_after_conflict.strip() == cert1_pem.decode().strip(), (
        "a failed mismatched-pair reimport must not mutate the stored certificate"
    )

    # --- control: reimporting a *different but valid* certificate/key pair over an
    #     unused ARN is a plain overwrite, not a conflict -- the ARN is preserved and the
    #     stored bytes become the newly imported certificate ---
    overwrite_arn = acm.import_certificate(
        Certificate=cert2_pem, PrivateKey=key2_pem, CertificateArn=arn
    )["CertificateArn"]
    assert overwrite_arn == arn, f"a plain overwrite must reuse the ARN; got {overwrite_arn!r}"
    stored_after_overwrite = acm.get_certificate(CertificateArn=arn)["Certificate"]
    assert stored_after_overwrite.strip() == cert2_pem.decode().strip(), (
        "a valid-pair overwrite must replace the stored bytes with the newly imported "
        f"certificate; got {stored_after_overwrite[:60]!r}..."
    )

    # --- positive control: reimporting the identical certificate/key over its own ARN
    #     succeeds idempotently ---
    reimport_arn = acm.import_certificate(
        Certificate=cert2_pem, PrivateKey=key2_pem, CertificateArn=arn
    )["CertificateArn"]
    assert reimport_arn == arn, f"an idempotent reimport must reuse the ARN; got {reimport_arn!r}"
    stored_after_reimport = acm.get_certificate(CertificateArn=arn)["Certificate"]
    assert stored_after_reimport.strip() == cert2_pem.decode().strip(), (
        "an idempotent reimport of the identical certificate/key pair must leave the stored "
        f"bytes unchanged; got {stored_after_reimport[:60]!r}..."
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _generate_self_signed_pem(common_name: str) -> tuple[bytes, bytes]:
    """Generate a self-signed RSA certificate/key pair via the openssl CLI."""
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
