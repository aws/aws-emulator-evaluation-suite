"""concurrent-update-domain-name-single-winner."""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "concurrent-update-domain-name-single-winner"
GROUP = "concurrency"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateDomainName calls with an imported CA-signed cert are both refused.

    Each racer gets BadRequestException "Certificate is invalid." and the domain never becomes
    visible, while ACM reports the same certificate ISSUED.
    """
    # Custom-domain certificates for AppSync must live in us-east-1 regardless of the
    # API's own region, so pin every client here to us-east-1 rather than ctx.region.
    appsync = _appsync_useast1_client(ctx)
    acm = _acm_useast1_client(ctx)
    base = _domain_base(ctx, "sim2real-concurrentdomain")
    # NOT "*.example.com": AppSync's CreateDomainName rejects RFC 2606 reserved
    # example/test/invalid domains outright with BadRequestException("Invalid domain name.").
    domain_name = f"{base}.sim2real-appsync-test.com"
    cert_arn = _create_self_signed_domain_cert(ctx, domain_name, acm)

    # Positive control: ACM itself reports the certificate healthy and ISSUED, so the
    # AppSync refusal below is AppSync's own cross-service validation refusing it --
    # not a broken cert, a permissions gap, or an unreachable API.
    cert_status = acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]["Status"]
    assert cert_status == "ISSUED", (
        f"positive control failed: ACM reports {cert_status!r} for the imported "
        "certificate, expected ISSUED"
    )

    def _create():
        try:
            appsync.create_domain_name(domainName=domain_name, certificateArn=cert_arn)
            return ("ok", "")
        except ClientError as exc:
            err = exc.response["Error"]
            return (err["Code"], err.get("Message", ""))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [f.result() for f in [pool.submit(_create), pool.submit(_create)]]

    for code, message in results:
        assert code == "BadRequestException", (
            f"expected BadRequestException rejecting a non-Amazon-issued certificate, "
            f"got {code!r} ({message!r})"
        )
        assert message == "Certificate is invalid.", (
            f"expected the exact certificate-invalid refusal, got {message!r}"
        )

    try:
        appsync.get_domain_name(domainName=domain_name)
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "NotFoundException", (
            f"domain must not exist after both racers were rejected, got "
            f"{exc.response['Error']['Code']!r}"
        )
        assert exc.response["Error"].get("Message") == "Domain name not found", (
            f"expected the exact NotFound message, got {exc.response['Error'].get('Message')!r}"
        )
    else:
        raise AssertionError(
            "domain must not exist after both racers were rejected, but GetDomainName succeeded"
        )


def _domain_base(ctx, prefix: str) -> str:
    raw = ctx.unique_name(f"{prefix}-").lower()
    return re.sub(r"[^a-z0-9-]", "-", raw).strip("-")


def _acm_useast1_client(ctx):
    return ctx.client("acm", region="us-east-1")


def _appsync_useast1_client(ctx):
    return ctx.client("appsync", region="us-east-1")


def _create_self_signed_domain_cert(ctx, domain: str, acm) -> str:
    """Build a CA + CA-signed leaf certificate chain covering `domain` and import it into ACM
    (us-east-1). A bare self-signed LEAF cert (issuer == subject) is rejected outright by
    CreateDomainName with BadRequestException("Certificate is invalid"); an actual two-cert chain
    with a genuine issuer is required -- and, as this check exists to demonstrate, CreateDomainName
    rejects that too."""
    require_tools("openssl")
    with tempfile.TemporaryDirectory() as tmp:
        ca_key_path = os.path.join(tmp, "ca-key.pem")
        ca_cert_path = os.path.join(tmp, "ca-cert.pem")
        leaf_key_path = os.path.join(tmp, "leaf-key.pem")
        leaf_csr_path = os.path.join(tmp, "leaf.csr")
        leaf_cert_path = os.path.join(tmp, "leaf-cert.pem")
        ext_path = os.path.join(tmp, "leaf-ext.cnf")

        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", ca_key_path, "-out", ca_cert_path,
                "-days", "3", "-nodes", "-subj", "/CN=sim2real-appsync-test-ca",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            ],
            check=True, capture_output=True, timeout=30,
        )
        subprocess.run(
            [
                "openssl", "req", "-newkey", "rsa:2048", "-keyout", leaf_key_path,
                "-out", leaf_csr_path, "-nodes", "-subj", f"/CN={domain}",
            ],
            check=True, capture_output=True, timeout=30,
        )
        with open(ext_path, "w") as f:
            f.write(
                f"subjectAltName=DNS:{domain}\n"
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature,keyEncipherment\n"
                "extendedKeyUsage=serverAuth\n"
            )
        subprocess.run(
            [
                "openssl", "x509", "-req", "-in", leaf_csr_path,
                "-CA", ca_cert_path, "-CAkey", ca_key_path, "-CAcreateserial",
                "-out", leaf_cert_path, "-days", "2", "-sha256", "-extfile", ext_path,
            ],
            check=True, capture_output=True, timeout=30,
        )

        with open(leaf_key_path, "rb") as f:
            key_pem = f.read()
        with open(leaf_cert_path, "rb") as f:
            cert_pem = f.read()
        with open(ca_cert_path, "rb") as f:
            chain_pem = f.read()

    cert_name = ctx.unique_name("sim2real-behav-appsync-cert-")
    resp = acm.import_certificate(
        Certificate=cert_pem,
        PrivateKey=key_pem,
        CertificateChain=chain_pem,
        Tags=[{"Key": "Name", "Value": cert_name}],
    )
    cert_arn = resp["CertificateArn"]

    def _cleanup_cert():
        # AppSync keeps a rejected CreateDomainName's certificate marked in use for a while.
        deadline = time.monotonic() + 180.0
        while True:
            try:
                acm.delete_certificate(CertificateArn=cert_arn)
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "ResourceNotFoundException":
                    return
                if code != "ResourceInUseException" or time.monotonic() >= deadline:
                    raise
            time.sleep(5.0)

    ctx.on_cleanup(_cleanup_cert)
    return cert_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
