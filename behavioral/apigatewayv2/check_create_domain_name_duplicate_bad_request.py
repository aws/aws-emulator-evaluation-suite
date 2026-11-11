"""create-domain-name-duplicate-bad-request."""
from __future__ import annotations

import os
import subprocess
import tempfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-domain-name-duplicate-bad-request"
GROUP = "error-semantics"
SERVICES = ["apigatewayv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a domain name that already exists fails with BadRequestException and its exact
    message, leaving the original untouched; a different domain name is still created."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    apigw = ctx.client("apigatewayv2")

    domain = _domain_name(ctx, "sim2real-behav-dup")
    cert_arn = _self_signed_cert_arn(ctx, domain, teardown_deadline)
    config = [{"CertificateArn": cert_arn, "EndpointType": "REGIONAL", "SecurityPolicy": "TLS_1_2"}]

    created = _retry_throttled(
        lambda: apigw.create_domain_name(
            DomainName=domain, DomainNameConfigurations=config, Tags={"sim2real-check": CHECK}
        )
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_domain_name(DomainName=domain)))
    original_arn = created["DomainNameArn"]

    # Use a fresh certificate for the duplicate attempt so only the domain-name collision
    # itself is exercised (re-sending the identical config can be treated as a retried
    # request rather than a genuine conflict).
    dup_cert_arn = _self_signed_cert_arn(ctx, domain, teardown_deadline)
    dup_config = [
        {"CertificateArn": dup_cert_arn, "EndpointType": "REGIONAL", "SecurityPolicy": "TLS_1_2"}
    ]
    code, message = _error_code(
        lambda: apigw.create_domain_name(DomainName=domain, DomainNameConfigurations=dup_config)
    )
    # AWS returns BadRequestException here, not the ConflictException the API reference implies.
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}: {message!r}"
    expected_message = "The domain name you provided already exists."
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    still_there = apigw.get_domain_name(DomainName=domain)
    assert still_there["DomainNameArn"] == original_arn, (
        f"rejected duplicate create mutated the original domain name: "
        f"expected arn {original_arn!r}, got {still_there['DomainNameArn']!r}"
    )

    other_domain = _domain_name(ctx, "sim2real-behav-dup-ctrl")
    other_cert_arn = _self_signed_cert_arn(ctx, other_domain, teardown_deadline)
    other = _retry_throttled(
        lambda: apigw.create_domain_name(
            DomainName=other_domain,
            DomainNameConfigurations=[
                {"CertificateArn": other_cert_arn, "EndpointType": "REGIONAL", "SecurityPolicy": "TLS_1_2"}
            ],
            Tags={"sim2real-check": CHECK},
        )
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_domain_name(DomainName=other_domain)))
    assert other["DomainName"] == other_domain, (
        f"positive control failed: expected {other_domain!r}, got {other['DomainName']!r}"
    )


def _domain_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    label = "".join(c if c.isalnum() or c == "-" else "-" for c in raw.lower()).strip("-")
    return f"{label}.example.com"


def _self_signed_cert_arn(ctx, domain: str, teardown_deadline) -> str:
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
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: _delete_cert_when_released(acm, cert_arn, teardown_deadline)))
    return cert_arn


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target ACCEPTING a call real AWS refuses is a failure, not a code mismatch.
    Throttling is retried."""
    import time

    from botocore.exceptions import ClientError

    for attempt in range(4):
        try:
            result = fn()
        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code")
            if code in ("TooManyRequestsException", "ThrottlingException") and attempt < 3:
                time.sleep(3.0 * (attempt + 1))
                continue
            return code, error.get("Message")
        raise AssertionError(
            f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
        )
    raise AssertionError("unreachable: the loop always returns or raises")


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


def _delete_cert_when_released(acm, arn: str, teardown_deadline) -> None:
    """DeleteCertificate, retrying ResourceInUseException every 2 s while ACM still counts the
    domain name as a user, up to the cleanup budget; any other error raises."""
    import time

    deadline = teardown_deadline.setdefault("t", time.monotonic() + _CLEANUP_S)
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
