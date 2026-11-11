"""domain-name-regional-provisioning-status-window."""
from __future__ import annotations

import os
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "domain-name-regional-provisioning-status-window"
GROUP = "visibility-timeout-ttl"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDomainName's domainNameStatus transitions to AVAILABLE within the provisioning window."""
    domain = ctx.unique_name("sim2real-behav-").replace("_", "-") + ".example.com"
    require_tools("openssl")
    cert_pem, key_pem = _generate_self_signed_cert(domain)

    acm = ctx.client("acm")
    apigw = ctx.client("apigateway")

    imported = acm.import_certificate(
        Certificate=cert_pem.encode("utf-8"),
        PrivateKey=key_pem.encode("utf-8"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    cert_arn = imported["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_when_released(acm, cert_arn))

    created = _create_domain_name_retrying(
        apigw,
        domainName=domain,
        regionalCertificateArn=cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: apigw.delete_domain_name(domainName=domain))

    initial_status = created["domainNameStatus"]
    assert initial_status != "FAILED", (
        f"CreateDomainName immediately reported FAILED: {created.get('domainNameStatusMessage')!r}"
    )
    statuses = [initial_status]

    deadline = time.monotonic() + 180
    final = statuses[-1]
    while time.monotonic() < deadline and final != "AVAILABLE":
        resp = apigw.get_domain_name(domainName=domain)
        final = resp["domainNameStatus"]
        statuses.append(final)
        if final == "FAILED":
            raise AssertionError(
                f"domainNameStatus reached FAILED: {resp.get('domainNameStatusMessage')}"
            )
        if final != "AVAILABLE":
            time.sleep(5)

    assert final == "AVAILABLE", (
        f"domainNameStatus never reached AVAILABLE within the 180s provisioning window; "
        f"observed sequence={statuses}"
    )


def _create_domain_name_retrying(apigw, *, max_attempts: int = 4, **kwargs):
    """CreateDomainName is throttled account-wide on real AWS (TooManyRequestsException);
    retry with exponential backoff instead of failing on the first hit."""
    from botocore.exceptions import ClientError
    delay = 3.0
    for attempt in range(max_attempts):
        try:
            return apigw.create_domain_name(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] == "TooManyRequestsException" and attempt < max_attempts - 1:
                time.sleep(delay)
                delay = min(delay * 2, 15.0)
                continue
            raise


def _generate_self_signed_cert(common_name: str) -> tuple[str, str]:
    with tempfile.TemporaryDirectory() as tmp:
        key_path = os.path.join(tmp, "key.pem")
        cert_path = os.path.join(tmp, "cert.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", key_path, "-out", cert_path, "-days", "30",
                "-subj", f"/CN={common_name}",
            ],
            check=True, capture_output=True, timeout=30,
        )
        with open(cert_path) as f:
            cert_pem = f.read()
        with open(key_path) as f:
            key_pem = f.read()
    return cert_pem, key_pem


# budget.cleanup_timeout for behavioral/apigateway
_CLEANUP_S = 900.0


def _delete_cert_when_released(acm, arn: str) -> None:
    """DeleteCertificate, retrying ResourceInUseException every 2 s while ACM still counts the
    deleted domain name as a user, up to the cleanup budget; any other error raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + _CLEANUP_S
    while True:
        try:
            acm.delete_certificate(CertificateArn=arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
