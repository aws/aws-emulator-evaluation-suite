"""delete-domain-name-nonexistent-rejected."""
from __future__ import annotations

import os
import subprocess
import tempfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-domain-name-nonexistent-rejected"
GROUP = "overly-permissive"
SERVICES = ["apigatewayv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDomainName for a domain that was never created returns NotFoundException, not a
    permissive no-op success; deleting a domain that genuinely exists actually removes it."""
    apigwv2 = ctx.client("apigatewayv2")
    label = ctx.unique_name("sim2real-apigwv2-nonexistent-").lower().replace("_", "-")
    nonexistent_domain = f"{label}.example.com"

    code, message = _error_code(lambda: apigwv2.delete_domain_name(DomainName=nonexistent_domain))
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}: {message!r}"
    assert message == "Invalid domain name identifier specified", (
        f"unexpected NotFoundException message: {message!r}"
    )

    # positive control: a real domain, once deleted, is actually gone (delete is not a no-op
    # either -- it has the expected effect on a domain that DOES exist).
    real_domain = _create_domain_name(ctx)
    # independent read confirming the domain actually exists before we touch it -- otherwise
    # a target whose create is itself a no-op would pass this control vacuously.
    apigwv2.get_domain_name(DomainName=real_domain)
    apigwv2.delete_domain_name(DomainName=real_domain)
    code_after_delete, message_after_delete = _error_code(
        lambda: apigwv2.get_domain_name(DomainName=real_domain)
    )
    assert code_after_delete == "NotFoundException", (
        f"expected domain gone after delete, got {code_after_delete!r}: {message_after_delete!r}"
    )
    assert message_after_delete == "Invalid domain name identifier specified", (
        f"unexpected NotFoundException message: {message_after_delete!r}"
    )


def _error_code(fn):
    """(code, message) of the ClientError fn() raised. An unexpected success RAISES."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _import_self_signed_cert(ctx, common_name):
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    acm = ctx.client("acm")
    with tempfile.TemporaryDirectory() as d:
        key_path = os.path.join(d, "key.pem")
        cert_path = os.path.join(d, "cert.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_path, "-out", cert_path,
                "-days", "365", "-nodes", "-subj", f"/CN={common_name}",
            ],
            check=True, capture_output=True,
        )
        with open(cert_path, "rb") as f:
            cert_pem = f.read()
        with open(key_path, "rb") as f:
            key_pem = f.read()
    resp = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_retrying_in_use(acm, cert_arn))
    return cert_arn


def _delete_cert_retrying_in_use(acm, cert_arn, deadline_s=45.0):
    """ACM's InUseBy bookkeeping lags the deletion of the domain name that referenced the
    certificate, so an immediate DeleteCertificate can see ResourceInUseException. Retry
    within the cleanup budget instead of leaking the certificate."""
    import time

    deadline = time.monotonic() + deadline_s
    delay = 3.0
    while True:
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(delay)
            delay = min(delay * 1.5, 10.0)


def _create_domain_name(ctx):
    apigwv2 = ctx.client("apigatewayv2")
    label = ctx.unique_name("sim2real-apigwv2-").lower().replace("_", "-")
    domain_name = f"{label}.example.com"
    cert_arn = _import_self_signed_cert(ctx, domain_name)
    apigwv2.create_domain_name(
        DomainName=domain_name,
        DomainNameConfigurations=[{"CertificateArn": cert_arn, "EndpointType": "REGIONAL"}],
    )
    return domain_name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
