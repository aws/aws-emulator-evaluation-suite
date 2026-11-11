"""update-domain-name-nonexistent-not-found."""
from __future__ import annotations

import os
import subprocess
import tempfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-domain-name-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["apigatewayv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDomainName on a domain name that was never created (or already deleted) returns
    NotFoundException, and no resource is materialized by the attempt -- while the identical
    call shape succeeds against a domain that really exists."""
    apigw = ctx.client("apigatewayv2")

    missing_domain = _domain_name(ctx, "sim2real-behav-updmiss")
    code, message = _error_code(
        lambda: apigw.update_domain_name(DomainName=missing_domain, RoutingMode="ROUTING_RULE_ONLY")
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}: {message!r}"
    expected_message = "Invalid domain name identifier specified"
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # Effect absent: the update did not implicitly create the domain.
    still_missing, missing_message = _error_code(lambda: apigw.get_domain_name(DomainName=missing_domain))
    assert still_missing == "NotFoundException", (
        f"update on a never-created domain must not materialize it, got {still_missing!r}"
    )
    expected_message = "Invalid domain name identifier specified"
    assert missing_message == expected_message, f"expected {expected_message!r}, got {missing_message!r}"

    # Also exercise the delete-then-update case: a domain that existed and was removed.
    deleted_domain = _domain_name(ctx, "sim2real-behav-upddel")
    deleted_cert_arn = _self_signed_cert_arn(ctx, deleted_domain)
    _retry_throttled(
        lambda: apigw.create_domain_name(
            DomainName=deleted_domain,
            Tags={"sim2real-check": CHECK},
            DomainNameConfigurations=[
                {"CertificateArn": deleted_cert_arn, "EndpointType": "REGIONAL", "SecurityPolicy": "TLS_1_2"}
            ],
        )
    )
    apigw.delete_domain_name(DomainName=deleted_domain)
    code_after_delete, message2 = _error_code(
        lambda: apigw.update_domain_name(DomainName=deleted_domain, RoutingMode="ROUTING_RULE_ONLY")
    )
    assert code_after_delete == "NotFoundException", (
        f"expected NotFoundException, got {code_after_delete!r}: {message2!r}"
    )
    expected_message = "Invalid domain name identifier specified"
    assert message2 == expected_message, f"expected {expected_message!r}, got {message2!r}"

    # Effect absent: the update-after-delete did not resurrect the domain.
    still_gone, gone_message = _error_code(lambda: apigw.get_domain_name(DomainName=deleted_domain))
    assert still_gone == "NotFoundException", (
        f"update on a deleted domain must not resurrect it, got {still_gone!r}"
    )
    expected_message = "Invalid domain name identifier specified"
    assert gone_message == expected_message, f"expected {expected_message!r}, got {gone_message!r}"

    # Positive control: updating a domain that genuinely exists succeeds.
    real_domain = _domain_name(ctx, "sim2real-behav-updreal")
    cert_arn = _self_signed_cert_arn(ctx, real_domain)
    _retry_throttled(
        lambda: apigw.create_domain_name(
            DomainName=real_domain,
            Tags={"sim2real-check": CHECK},
            DomainNameConfigurations=[
                {"CertificateArn": cert_arn, "EndpointType": "REGIONAL", "SecurityPolicy": "TLS_1_2"}
            ],
        )
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_domain_name(DomainName=real_domain)))
    updated = apigw.update_domain_name(DomainName=real_domain, RoutingMode="ROUTING_RULE_ONLY")
    assert updated["DomainName"] == real_domain, f"expected {real_domain!r}, got {updated['DomainName']!r}"
    assert updated["RoutingMode"] == "ROUTING_RULE_ONLY", (
        f"expected ROUTING_RULE_ONLY, got {updated['RoutingMode']!r}"
    )

    # The terminal read is independent of the mutating call: confirm the routing mode
    # actually persisted server-side, not merely echoed in UpdateDomainName's own response.
    reread = apigw.get_domain_name(DomainName=real_domain)
    assert reread["RoutingMode"] == "ROUTING_RULE_ONLY", (
        f"expected persisted ROUTING_RULE_ONLY, got {reread['RoutingMode']!r}"
    )


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
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: acm.delete_certificate(CertificateArn=cert_arn)))
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
    raise AssertionError("exhausted retries on throttling without a definitive response")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
