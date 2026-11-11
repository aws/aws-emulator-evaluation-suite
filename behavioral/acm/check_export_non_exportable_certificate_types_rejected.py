"""export-non-exportable-certificate-types-rejected."""
from __future__ import annotations

import os
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "export-non-exportable-certificate-types-rejected"
GROUP = "e2e"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ExportCertificate rejects default AMAZON_ISSUED and IMPORTED certs with ValidationException,
    leaving each untouched, while an unissued Export=ENABLED cert gets ResourceNotFoundException.

    Reference: https://docs.aws.amazon.com/acm/latest/APIReference/API_ExportCertificate.html"""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    acm = ctx.client("acm")
    tag_set = [{"Key": "sim2real-check", "Value": CHECK}]

    public_domain = f"{_dns_label(ctx.unique_name('sim2real-acm-pub'))}.example.com"
    public_arn = acm.request_certificate(
        DomainName=public_domain, ValidationMethod="DNS", Tags=tag_set
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, public_arn))

    code, message = _error(lambda: acm.export_certificate(CertificateArn=public_arn, Passphrase=b"Sim2RealPass123"))
    assert code == "ValidationException", f"expected ValidationException for a default AMAZON_ISSUED cert, got {code!r}"
    expected_message = f"Certificate ARN: {public_arn} is not an export enabled certificate"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # DomainName is not guaranteed while PENDING_VALIDATION, so read DomainValidationOptions,
    # which can take a moment to populate after RequestCertificate.
    def _dvo_domains():
        c = acm.describe_certificate(CertificateArn=public_arn)["Certificate"]
        assert c["Type"] == "AMAZON_ISSUED", f"expected Type AMAZON_ISSUED, got {c['Type']!r}"
        return {d["DomainName"] for d in c.get("DomainValidationOptions", [])}

    dvo_domains = _poll_until(
        _dvo_domains, lambda domains: public_domain in domains, timeout_s=30, interval_s=2
    )
    assert public_domain in dvo_domains, (
        f"rejected export mutated certificate state: {public_domain!r} missing from "
        f"DomainValidationOptions {dvo_domains!r}"
    )

    imported_domain = f"{_dns_label(ctx.unique_name('sim2real-acm-imp'))}.example.com"
    cert_pem, key_pem = _generate_self_signed(imported_domain)
    imported_arn = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem, Tags=tag_set
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, imported_arn))

    imported_code, imported_message = _error(
        lambda: acm.export_certificate(CertificateArn=imported_arn, Passphrase=b"Sim2RealPass123")
    )
    assert imported_code == "ValidationException", f"expected ValidationException for an IMPORTED cert, got {imported_code!r}"
    expected_message = f"Certificate ARN: {imported_arn} is not an export enabled certificate"
    assert imported_message == expected_message, f"expected message {expected_message!r}, got {imported_message!r}"
    imported_cert = acm.describe_certificate(CertificateArn=imported_arn)["Certificate"]
    assert imported_cert["Type"] == "IMPORTED", f"expected Type IMPORTED, got {imported_cert['Type']!r}"
    assert imported_cert["DomainName"] == imported_domain, (
        f"rejected export mutated certificate state: DomainName {imported_cert['DomainName']!r} "
        f"!= {imported_domain!r}"
    )

    # Control: the fake domain never validates, so this exportable cert stays unissued and
    # must be refused for that reason, not as a wrong certificate type.
    exportable_domain = f"{_dns_label(ctx.unique_name('sim2real-acm-exp'))}.example.com"
    exportable_arn = acm.request_certificate(
        DomainName=exportable_domain,
        ValidationMethod="DNS",
        Options={"Export": "ENABLED"},
        Tags=tag_set,
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, exportable_arn))

    exportable_code, exportable_message = _error(
        lambda: acm.export_certificate(CertificateArn=exportable_arn, Passphrase=b"Sim2RealPass123")
    )
    # Not yet issued, rather than the wrong type: ACM looks for an ISSUED certificate.
    assert exportable_code == "ResourceNotFoundException", (
        "an Export=ENABLED certificate must be refused as not-yet-issued, not with the "
        f"ValidationException of a non-exportable type, got {exportable_code!r}"
    )
    expected_message = f"Could not find an issued certificate {exportable_arn}"
    assert exportable_message == expected_message, (
        f"expected message {expected_message!r}, got {exportable_message!r}"
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
    """Call fn() and return its ClientError (code, message); raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":

    from fidelity_tests_runner import main
    main(run)
