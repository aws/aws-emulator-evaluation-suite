"""import-certificate-pem-byte-exact-round-trip."""
from __future__ import annotations

import os
import subprocess
import tempfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-certificate-pem-byte-exact-round-trip"
GROUP = "representation"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A certificate PEM imported with CRLF line endings is returned by GetCertificate normalized
    to LF, with no other change to its content."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    acm = ctx.client("acm")
    domain = f"{_dns_label(ctx.unique_name('sim2real-acm-crlf'))}.example.com"
    cert_pem_lf, key_pem = _generate_self_signed(domain)
    assert b"\r\n" not in cert_pem_lf, "openssl output was not the expected LF-only baseline"
    cert_pem_crlf = cert_pem_lf.replace(b"\n", b"\r\n")

    arn = acm.import_certificate(
        Certificate=cert_pem_crlf, PrivateKey=key_pem,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete(acm, arn))

    returned = acm.get_certificate(CertificateArn=arn)["Certificate"]
    expected_lf = cert_pem_lf.decode("ascii")
    # Compare the raw response: normalizing it first would also pass a target that echoes the
    # CRLF PEM back unchanged.
    contains_crlf = "\r\n" in returned
    assert returned == expected_lf, (
        "GetCertificate must return the certificate normalized to LF line endings with no other "
        f"content change; returned contains CRLF={contains_crlf!r}, "
        f"len(returned)={len(returned)} vs len(expected_lf)={len(expected_lf)}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
