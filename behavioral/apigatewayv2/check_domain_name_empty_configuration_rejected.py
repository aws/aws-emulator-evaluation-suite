"""domain-name-empty-configuration-rejected."""
from __future__ import annotations

import os
import subprocess
import tempfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-name-empty-configuration-rejected"
GROUP = "state-machine"
SERVICES = ["apigatewayv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDomainName with an empty DomainNameConfigurations list is rejected with
    BadRequestException, no domain name is left behind, and supplying a real configuration
    for the same domain name still succeeds (positive control)."""
    apigw = ctx.client("apigatewayv2")

    domain = _domain_name(ctx, "sim2real-dup-dn")

    # Break exactly one thing: an empty configuration list is not a valid domain name spec.
    code, message = _error_code(
        lambda: apigw.create_domain_name(DomainName=domain, DomainNameConfigurations=[])
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}: {message!r}"
    assert message == "Invalid input. Expected one domain name configuration", (
        f"unexpected BadRequestException message: {message!r}"
    )

    # Effect absent: nothing was created for this domain name.
    not_found_code, not_found_msg = _error_code(lambda: apigw.get_domain_name(DomainName=domain))
    assert not_found_code == "NotFoundException", (
        f"expected NotFoundException for the rejected domain name, got {not_found_code!r}: {not_found_msg!r}"
    )
    assert not_found_msg == NOT_FOUND_MESSAGE, f"unexpected NotFoundException message: {not_found_msg!r}"

    # Positive control: the same domain name with a real configuration succeeds.
    cert_arn = _self_signed_cert_arn(ctx, domain)
    created = _retry_throttled(
        lambda: apigw.create_domain_name(
            DomainName=domain,
            DomainNameConfigurations=[
                {"CertificateArn": cert_arn, "EndpointType": "REGIONAL", "SecurityPolicy": "TLS_1_2"}
            ],
        )
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_domain_name(DomainName=domain)))
    assert created["DomainName"] == domain, f"expected DomainName {domain!r}, got {created.get('DomainName')!r}"

    # Delete proves gone: an independent read now returns the specific not-found code, and a
    # mutation on the dead domain name also fails the same way.
    apigw.delete_domain_name(DomainName=domain)
    deleted_read_code, deleted_read_msg = _error_code(lambda: apigw.get_domain_name(DomainName=domain))
    assert deleted_read_code == "NotFoundException", (
        f"expected NotFoundException after delete, got {deleted_read_code!r}: {deleted_read_msg!r}"
    )
    assert deleted_read_msg == NOT_FOUND_MESSAGE, f"unexpected NotFoundException message: {deleted_read_msg!r}"
    deleted_second_delete_code, second_delete_msg = _error_code(
        lambda: apigw.delete_domain_name(DomainName=domain)
    )
    assert deleted_second_delete_code == "NotFoundException", (
        f"expected NotFoundException deleting an already-deleted domain name, got "
        f"{deleted_second_delete_code!r}: {second_delete_msg!r}"
    )
    assert second_delete_msg == NOT_FOUND_MESSAGE, f"unexpected NotFoundException message: {second_delete_msg!r}"


NOT_FOUND_MESSAGE = "Invalid domain name identifier specified"


def _domain_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    label = "".join(c if c.isalnum() or c == "-" else "-" for c in raw.lower()).strip("-")
    return f"{label}.example.com"


def _self_signed_cert_arn(ctx, domain: str) -> str:
    """Generate a throwaway self-signed certificate via openssl and import it into ACM."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    acm = ctx.client("acm")
    with tempfile.TemporaryDirectory() as tmp:
        key_path = os.path.join(tmp, "key.pem")
        cert_path = os.path.join(tmp, "cert.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_path, "-out", cert_path,
                "-days", "30", "-nodes", "-subj", f"/CN={domain}",
            ],
            check=True,
            capture_output=True,
        )
        with open(cert_path, "rb") as f:
            cert_bytes = f.read()
        with open(key_path, "rb") as f:
            key_bytes = f.read()
    resp = acm.import_certificate(Certificate=cert_bytes, PrivateKey=key_bytes)
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: _delete_cert_when_released(acm, cert_arn)))
    return cert_arn


def _error_code(fn):
    import time

    for attempt in range(4):
        try:
            result = fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message")
            if code in ("TooManyRequestsException", "LimitExceededException", "ThrottlingException") and attempt < 3:
                time.sleep(3.0 * (attempt + 1))
                continue
            return code, message
        raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")
    raise AssertionError("unreachable")


def _retry_throttled(fn, *, attempts: int = 6, base_delay: float = 3.0):
    import time

    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("TooManyRequestsException", "LimitExceededException", "ThrottlingException") and attempt < attempts - 1:
                last_exc = exc
                time.sleep(base_delay * (attempt + 1))
                continue
            raise
    raise last_exc


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NotFoundException", "ResourceNotFoundException"):
            raise


# budget.cleanup_timeout for behavioral/apigatewayv2
_CLEANUP_S = 900.0


def _delete_cert_when_released(acm, arn: str) -> None:
    """DeleteCertificate, retrying ResourceInUseException every 2 s while ACM still counts the
    domain name as a user, up to the cleanup budget; any other error raises."""
    import time

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
