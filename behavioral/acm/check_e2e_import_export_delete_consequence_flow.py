"""e2e-import-export-delete-consequence-flow."""
from __future__ import annotations

import os
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-import-export-delete-consequence-flow"
GROUP = "e2e"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ExportCertificate rejects an imported certificate, which GetCertificate reads back; after
    DeleteCertificate, Get, Export, Describe and AddTagsToCertificate all fail with
    ResourceNotFoundException and ListCertificates stops listing it."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    acm = ctx.client("acm")
    domain = f"{_dns_label(ctx.unique_name('sim2real-acm-e2e'))}.example.com"
    leaf_pem, leaf_key_pem, chain_pem = _generate_leaf_and_chain(domain)

    arn = acm.import_certificate(
        Certificate=leaf_pem, PrivateKey=leaf_key_pem, CertificateChain=chain_pem
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, arn))
    arn_prefix = f"arn:aws:acm:{ctx.region}:{ctx.account}:certificate/"
    assert arn.startswith(arn_prefix), f"expected the certificate ARN to start with {arn_prefix!r}, got {arn!r}"

    # ACM's ExportCertificate does not support the IMPORTED certificate type (only
    # PRIVATE-CA-issued or exportable-public certs) -- confirm that documented rejection
    # up front, then use GetCertificate as the successful read-back path before delete.
    code, status, message = _error(
        lambda: acm.export_certificate(CertificateArn=arn, Passphrase=b"Sim2RealPass123")
    )
    assert code == "ValidationException", f"ExportCertificate of an IMPORTED cert: expected ValidationException, got {code!r}"
    assert isinstance(status, int) and 400 <= status < 500, f"ExportCertificate of an IMPORTED cert: expected HTTP 4xx, got {status!r}"
    expected_message = f"Certificate ARN: {arn} is not an export enabled certificate"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    pre_delete_get = acm.get_certificate(CertificateArn=arn)
    assert pre_delete_get["Certificate"] == leaf_pem.decode("ascii")
    # ListCertificates is eventually consistent with ImportCertificate and DeleteCertificate.
    _poll_listed(acm, lambda arns: arn in arns, f"ListCertificates (RSA_2048) listing {arn!r} before delete")

    acm.delete_certificate(CertificateArn=arn)

    def _assert_not_found(label, fn):
        code, status, message = _error(fn)
        assert code == "ResourceNotFoundException", f"{label} after delete: expected ResourceNotFoundException, got {code!r}"
        assert isinstance(status, int) and 400 <= status < 500, f"{label} after delete: expected HTTP 4xx, got {status!r}"
        expected_message = f"Could not find certificate {arn}."
        assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    _assert_not_found("GetCertificate", lambda: acm.get_certificate(CertificateArn=arn))
    _assert_not_found(
        "ExportCertificate",
        lambda: acm.export_certificate(CertificateArn=arn, Passphrase=b"Sim2RealPass123"),
    )
    _assert_not_found("DescribeCertificate", lambda: acm.describe_certificate(CertificateArn=arn))

    _poll_listed(acm, lambda arns: arn not in arns, f"ListCertificates no longer listing the deleted certificate {arn!r}")

    # A mutation on the deleted id must also fail, not just reads.
    _assert_not_found(
        "AddTagsToCertificate",
        lambda: acm.add_tags_to_certificate(
            CertificateArn=arn, Tags=[{"Key": "sim2real-post-delete-probe", "Value": "x"}]
        ),
    )


def _dns_label(name: str) -> str:
    label = "".join(c if c.isalnum() else "-" for c in name.lower())
    return label.strip("-") or "sim2real"


def _run(cmd: list) -> None:
    result = subprocess.run(cmd, capture_output=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {result.stderr.decode(errors='replace')}")


def _generate_leaf_and_chain(common_name: str):
    with tempfile.TemporaryDirectory() as d:
        ca_key = os.path.join(d, "ca.key")
        ca_crt = os.path.join(d, "ca.crt")
        leaf_key = os.path.join(d, "leaf.key")
        leaf_csr = os.path.join(d, "leaf.csr")
        leaf_crt = os.path.join(d, "leaf.crt")
        _run(["openssl", "genrsa", "-out", ca_key, "2048"])
        _run(
            [
                "openssl", "req", "-x509", "-new", "-nodes", "-key", ca_key,
                "-sha256", "-days", "30", "-subj", "/CN=sim2real-test-ca", "-out", ca_crt,
            ]
        )
        _run(["openssl", "genrsa", "-out", leaf_key, "2048"])
        _run(["openssl", "req", "-new", "-key", leaf_key, "-subj", f"/CN={common_name}", "-out", leaf_csr])
        _run(
            [
                "openssl", "x509", "-req", "-in", leaf_csr, "-CA", ca_crt, "-CAkey", ca_key,
                "-CAcreateserial", "-out", leaf_crt, "-days", "30", "-sha256",
            ]
        )
        with open(leaf_crt, "rb") as f:
            leaf_pem = f.read()
        with open(leaf_key, "rb") as f:
            leaf_key_pem = f.read()
        with open(ca_crt, "rb") as f:
            ca_pem = f.read()
    return leaf_pem, leaf_key_pem, ca_pem


def _safe_delete(acm, arn: str) -> None:
    try:
        acm.delete_certificate(CertificateArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _listed_arns(acm) -> list:
    """Every RSA_2048 certificate ARN, paginated (ListCertificates lists only RSA_2048 by default)."""
    arns = []
    for page in acm.get_paginator("list_certificates").paginate(Includes={"keyTypes": ["RSA_2048"]}):
        arns.extend(c["CertificateArn"] for c in page.get("CertificateSummaryList", []))
    return arns


def _poll_listed(acm, predicate, description: str, timeout_s: float = 120.0) -> None:
    """Poll ``_listed_arns`` until ``predicate`` holds, bounded by ``timeout_s``."""
    deadline = time.monotonic() + timeout_s
    while True:
        arns = _listed_arns(acm)
        if predicate(arns):
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description}: not met within {timeout_s:.0f}s")
        time.sleep(5.0)


def _error(fn):
    """Run fn, which must be refused; return the (code, HTTP status, message) of the refusal."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message") or ""
    raise AssertionError(f"expected an error but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
