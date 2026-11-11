"""create-domain-name-duplicate-conflict."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "create-domain-name-duplicate-conflict"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDomainName for an already-existing domain returns BadRequestException, not a silent
    success or a cert overwrite."""
    apigw = ctx.client("apigateway")
    domain_name = f"{ctx.unique_name('sim2real-bhv-dom-')}.example.com".lower()

    # REGIONAL still requires a certificate on real AWS: a REGIONAL domain name
    # needs a regionalCertificateArn. Import a throwaway self-signed cert into
    # ACM for it, which is unrelated to the duplicate-create behavior under test.
    cert_arn = _acm_import_cert(ctx, domain_name)

    _create_domain_name_retrying(
        apigw,
        domainName=domain_name,
        regionalCertificateArn=cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]},
    )
    ctx.on_cleanup(lambda: _safe_delete_domain(apigw, domain_name))

    # Confirm it actually exists before probing the duplicate-create path.
    described = apigw.get_domain_name(domainName=domain_name)
    assert described["domainName"] == domain_name, (
        f"expected the just-created domain {domain_name!r} to read back, got {described.get('domainName')!r}"
    )

    # Use a DIFFERENT cert for the duplicate attempt so an overwrite (rather than a
    # clean rejection) would be visible at the independent read below.
    other_cert_arn = _acm_import_cert(ctx, domain_name)

    # The duplicate-create call is itself subject to the same account-wide
    # CreateDomainName throttle (TooManyRequestsException) as the initial
    # create above; retry it with backoff so a transient throttle doesn't
    # mask the duplicate-name rejection code under test.
    code, message = _error(
        lambda: apigw.create_domain_name(
            domainName=domain_name,
            regionalCertificateArn=other_cert_arn,
            endpointConfiguration={"types": ["REGIONAL"]},
        )
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException on duplicate CreateDomainName, got {code!r}"
    )
    assert message == "The domain name you provided already exists.", f"unexpected BadRequestException message {message!r}"

    # Effect-absent: the rejected duplicate must not have overwritten the existing
    # domain's certificate binding.
    unchanged = apigw.get_domain_name(domainName=domain_name)
    assert unchanged["regionalCertificateArn"] == cert_arn, (
        "rejected duplicate CreateDomainName must not overwrite the existing certificate, "
        f"expected {cert_arn!r}, got {unchanged.get('regionalCertificateArn')!r}"
    )


def _error(fn: Any, max_attempts: int = 6) -> tuple[str, str]:
    """Call fn(); return (code, message) of the refusal. A call that succeeds fails the check.
    CreateDomainName is account-wide rate-limited on real AWS, so a TooManyRequestsException is
    retried with backoff rather than read as the call's own outcome."""
    from botocore.exceptions import ClientError

    delay = 5.0
    for attempt in range(max_attempts):
        try:
            result = fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TooManyRequestsException" and attempt < max_attempts - 1:
                time.sleep(delay)
                delay = min(delay * 2, 60.0)
                continue
            return code, e.response["Error"].get("Message")
        raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")
    raise AssertionError("unreachable: the retry loop always returns or raises")


def _openssl_self_signed_cert(common_name: str) -> tuple[str, str]:
    with tempfile.TemporaryDirectory() as d:
        key_path = Path(d) / "key.pem"
        crt_path = Path(d) / "crt.pem"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(key_path), "-out", str(crt_path),
                "-days", "2", "-nodes", "-subj", f"/CN={common_name}",
            ],
            check=True, capture_output=True, timeout=30,
        )
        return crt_path.read_text(), key_path.read_text()


def _acm_import_cert(ctx, common_name: str) -> str:
    require_tools("openssl")
    cert_pem, key_pem = _openssl_self_signed_cert(common_name)
    acm = ctx.client("acm")
    resp = acm.import_certificate(Certificate=cert_pem.encode(), PrivateKey=key_pem.encode())
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_certificate_when_released(acm, arn))
    return arn


def _create_domain_name_retrying(apigw, *, max_attempts: int = 6, **kwargs):
    """CreateDomainName is throttled account-wide on real AWS (TooManyRequestsException);
    retry with exponential backoff instead of failing on the first hit."""
    from botocore.exceptions import ClientError

    delay = 5.0
    for attempt in range(max_attempts):
        try:
            return apigw.create_domain_name(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] == "TooManyRequestsException" and attempt < max_attempts - 1:
                time.sleep(delay)
                delay = min(delay * 2, 60.0)
                continue
            raise


def _safe_delete_domain(apigw, domain: str) -> None:
    try:
        apigw.delete_domain_name(domainName=domain)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _delete_certificate_when_released(acm, arn: str, timeout_s: float = 300.0) -> None:
    """ACM reports a certificate in use for a while after its domain name is deleted; retry
    DeleteCertificate on ResourceInUseException until a bounded deadline."""
    import time as _time

    from botocore.exceptions import ClientError

    deadline = _time.monotonic() + timeout_s
    while True:
        try:
            acm.delete_certificate(CertificateArn=arn)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceInUseException" or _time.monotonic() > deadline:
                raise
            _time.sleep(10)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
