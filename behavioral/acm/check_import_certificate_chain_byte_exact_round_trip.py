"""import-certificate-chain-byte-exact-round-trip."""
from __future__ import annotations

import os
import subprocess
import tempfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-certificate-chain-byte-exact-round-trip"
GROUP = "representation"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An imported intermediate+root chain is returned byte-identical by GetCertificate;
    ExportCertificate rejects the imported certificate with ValidationException, and after
    DeleteCertificate GetCertificate fails with ResourceNotFoundException."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    acm = ctx.client("acm")
    domain = f"{_dns_label(ctx.unique_name('sim2real-acm-chain'))}.example.com"
    leaf_pem, leaf_key_pem, chain_pem = _generate_two_level_chain(domain)

    arn = acm.import_certificate(
        Certificate=leaf_pem, PrivateKey=leaf_key_pem, CertificateChain=chain_pem
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, arn))

    get_resp = acm.get_certificate(CertificateArn=arn)
    assert get_resp["Certificate"] == leaf_pem.decode(
        "ascii"
    ), "GetCertificate's Certificate did not byte-match the imported leaf"
    assert get_resp["CertificateChain"] == chain_pem.decode(
        "ascii"
    ), "GetCertificate's CertificateChain did not byte-match the imported chain"

    # ExportCertificate does not support IMPORTED certificates -- confirm the documented
    # rejection rather than assuming it round-trips the chain too
    export_code, export_message = _error(lambda: acm.export_certificate(CertificateArn=arn, Passphrase=b"Sim2RealPass123"))
    assert export_code == "ValidationException", (
        f"ExportCertificate on an IMPORTED certificate should be rejected with ValidationException, got {export_code!r}"
    )
    expected_export_message = f"Certificate ARN: {arn} is not an export enabled certificate"
    assert export_message == expected_export_message, (
        f"expected message {expected_export_message!r}, got {export_message!r}"
    )

    acm.delete_certificate(CertificateArn=arn)
    notfound_code, notfound_message = _error(lambda: acm.get_certificate(CertificateArn=arn))
    assert notfound_code == "ResourceNotFoundException", (
        f"GetCertificate after DeleteCertificate should return ResourceNotFoundException, got {notfound_code!r}"
    )
    expected_notfound_message = f"Could not find certificate {arn}."
    assert notfound_message == expected_notfound_message, (
        f"expected message {expected_notfound_message!r}, got {notfound_message!r}"
    )


def _dns_label(name: str) -> str:
    label = "".join(c if c.isalnum() else "-" for c in name.lower())
    return label.strip("-") or "sim2real"


def _run(cmd: list) -> None:
    result = subprocess.run(cmd, capture_output=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {result.stderr.decode(errors='replace')}")


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _generate_two_level_chain(common_name: str):

    with tempfile.TemporaryDirectory() as d:
        root_key = os.path.join(d, "root.key")
        root_crt = os.path.join(d, "root.crt")
        int_key = os.path.join(d, "int.key")
        int_csr = os.path.join(d, "int.csr")
        int_crt = os.path.join(d, "int.crt")
        int_ext = os.path.join(d, "int_ext.cnf")
        leaf_key = os.path.join(d, "leaf.key")
        leaf_csr = os.path.join(d, "leaf.csr")
        leaf_crt = os.path.join(d, "leaf.crt")

        _run(["openssl", "genrsa", "-out", root_key, "2048"])
        _run(
            [
                "openssl", "req", "-x509", "-new", "-nodes", "-key", root_key, "-sha256", "-days", "60",
                "-subj", "/CN=sim2real-root-ca", "-addext", "basicConstraints=critical,CA:TRUE",
                "-out", root_crt,
            ]
        )

        _run(["openssl", "genrsa", "-out", int_key, "2048"])
        _run(["openssl", "req", "-new", "-key", int_key, "-subj", "/CN=sim2real-intermediate-ca", "-out", int_csr])
        with open(int_ext, "w") as f:
            f.write("basicConstraints=critical,CA:TRUE\n")
        _run(
            [
                "openssl", "x509", "-req", "-in", int_csr, "-CA", root_crt, "-CAkey", root_key,
                "-CAcreateserial", "-days", "60", "-sha256", "-extfile", int_ext, "-out", int_crt,
            ]
        )

        _run(["openssl", "genrsa", "-out", leaf_key, "2048"])
        _run(["openssl", "req", "-new", "-key", leaf_key, "-subj", f"/CN={common_name}", "-out", leaf_csr])
        _run(
            [
                "openssl", "x509", "-req", "-in", leaf_csr, "-CA", int_crt, "-CAkey", int_key,
                "-CAcreateserial", "-days", "60", "-sha256", "-out", leaf_crt,
            ]
        )

        with open(leaf_crt, "rb") as f:
            leaf_pem = f.read()
        with open(leaf_key, "rb") as f:
            leaf_key_pem = f.read()
        with open(int_crt, "rb") as f:
            int_pem = f.read()
        with open(root_crt, "rb") as f:
            root_pem = f.read()
    return leaf_pem, leaf_key_pem, int_pem + root_pem


def _safe_delete(acm, arn: str) -> None:
    try:
        acm.delete_certificate(CertificateArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
