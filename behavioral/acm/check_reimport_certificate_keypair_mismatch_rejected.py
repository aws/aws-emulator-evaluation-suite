"""reimport-certificate-keypair-mismatch-rejected."""
from __future__ import annotations

import os
import subprocess
import tempfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reimport-certificate-keypair-mismatch-rejected"
GROUP = "e2e"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Reimporting onto a certificate ARN with a private key that does not match the certificate is
    refused with ValidationException and the exact message and leaves the DomainName unchanged; a
    matched pair for another domain reimports onto the same ARN and changes the DomainName."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    acm = ctx.client("acm")

    domain_a = f"{_dns_label(ctx.unique_name('sim2real-acm-a'))}.example.com"
    cert_a_pem, key_a_pem = _generate_self_signed(domain_a)
    # Note: reimports below omit `Tags` -- ACM's own model documents "You cannot apply tags
    # when reimporting a certificate", so tagging is only possible on this first import.
    arn = acm.import_certificate(
        Certificate=cert_a_pem, PrivateKey=key_a_pem, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, arn))

    domain_b = f"{_dns_label(ctx.unique_name('sim2real-acm-b'))}.example.com"
    cert_b_pem, key_b_pem = _generate_self_signed(domain_b)

    # cert_b's public key does not match key_a's private key -- a genuine keypair mismatch
    code, message = _error(
        lambda: acm.import_certificate(CertificateArn=arn, Certificate=cert_b_pem, PrivateKey=key_a_pem)
    )
    assert code == "ValidationException", f"expected ValidationException for mismatched keypair, got {code!r}"
    assert message == "Key provided does not match the certificate.", message

    # the rejected mismatched re-import left the original certificate's domain untouched
    cert = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert cert["DomainName"] == domain_a, (
        f"a rejected reimport must not change DomainName; expected {domain_a!r}, got {cert['DomainName']!r}"
    )

    # positive control: re-importing with a correctly matched cert/key pair (even though
    # the domain differs) succeeds and updates the certificate in place, same ARN
    resp = acm.import_certificate(CertificateArn=arn, Certificate=cert_b_pem, PrivateKey=key_b_pem)
    assert resp["CertificateArn"] == arn, (
        f"a successful reimport must reuse the same ARN; expected {arn!r}, got {resp['CertificateArn']!r}"
    )
    cert_after = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert cert_after["DomainName"] == domain_b, (
        f"a successful reimport with a matched pair must update DomainName to {domain_b!r}; "
        f"got {cert_after['DomainName']!r}"
    )


def _dns_label(name: str) -> str:
    label = "".join(c if c.isalnum() else "-" for c in name.lower())
    return label.strip("-") or "sim2real"


def _run(cmd: list) -> None:
    result = subprocess.run(cmd, capture_output=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {result.stderr.decode(errors='replace')}")


def _generate_self_signed(common_name: str):
    with tempfile.TemporaryDirectory() as d:
        key_path = os.path.join(d, "key.pem")
        crt_path = os.path.join(d, "cert.pem")
        _run(["openssl", "genrsa", "-out", key_path, "2048"])
        _run(
            [
                "openssl", "req", "-x509", "-new", "-nodes", "-key", key_path,
                "-sha256", "-days", "30", "-subj", f"/CN={common_name}", "-out", crt_path,
            ]
        )
        with open(crt_path, "rb") as f:
            cert_pem = f.read()
        with open(key_path, "rb") as f:
            key_pem = f.read()
    return cert_pem, key_pem


def _safe_delete(acm, arn: str) -> None:
    try:
        acm.delete_certificate(CertificateArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be REFUSED but it succeeded, returning {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
