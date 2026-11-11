"""revoke-certificate-already-revoked-conflicts."""
from __future__ import annotations

import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from behavioral_harness import tags

CHECK = "revoke-certificate-already-revoked-conflicts"
GROUP = "concurrency"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent RevokeCertificate calls on an imported (non-revocable) certificate all fail with
    ValidationException, and it stays ISSUED with no RevokedAt."""
    acm = ctx.client("acm")
    cert_pem, key_pem = _generate_self_signed_pem(ctx.unique_name("sim2real-acm-revoke-"))
    arn = acm.import_certificate(
        Certificate=cert_pem,
        PrivateKey=key_pem,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=arn))

    desc = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert desc["Status"] == "ISSUED", desc["Status"]
    assert desc["Type"] == "IMPORTED", desc["Type"]

    def _attempt(_: int) -> tuple[str, str | None]:
        return _error(
            lambda: acm.revoke_certificate(CertificateArn=arn, RevocationReason="UNSPECIFIED")
        )

    # Only exported private-CA certificates are revocable; an imported one never is.
    with ThreadPoolExecutor(max_workers=5) as pool:
        outcomes = list(pool.map(_attempt, range(5)))
    codes = [code for code, _ in outcomes]
    messages = [message for _, message in outcomes]

    assert len(codes) == 5, f"expected 5 concurrent attempts, got {len(codes)}"
    assert all(code == "ValidationException" for code in codes), codes
    assert messages == [f"Certificate {arn} is not a public certificate."] * 5, messages

    desc_after = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert desc_after["Status"] == "ISSUED", desc_after["Status"]
    assert "RevokedAt" not in desc_after, f"RevokedAt must be absent after rejected revokes: {desc_after}"


def _error(fn: Any) -> tuple[str, str | None]:
    """The (code, message) of the ClientError fn raises, or ("SUCCEEDED", None) when it succeeds."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    return "SUCCEEDED", None


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
