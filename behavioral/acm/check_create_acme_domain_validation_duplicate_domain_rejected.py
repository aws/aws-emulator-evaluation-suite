"""create-acme-domain-validation-duplicate-domain-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-acme-domain-validation-duplicate-domain-rejected"
GROUP = "representation"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second AcmeDomainValidation for the same domain on the same endpoint is rejected with
    ConflictException and the endpoint keeps exactly the original entry, while a different domain
    on the same endpoint still validates, so the conflict keys on (endpoint, domain)."""
    acm = ctx.client("acm")
    _require_acme_api(acm)

    endpoint_arn = _create_active_acme_endpoint(ctx, acm)

    domain_name = f"{uuid.uuid4().hex[:10]}.sim2real.example"
    prevalidation = {"DnsPrevalidation": {"DomainScope": {"ExactDomain": "ENABLED"}}}

    first_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn, DomainName=domain_name, PrevalidationOptions=prevalidation
    )["AcmeDomainValidationArn"]
    ctx.on_cleanup(lambda: _delete_domain_validation(acm, first_arn))

    # Break exactly one thing: request the identical domain again on the same endpoint.
    code, message = _error_code(
        lambda: acm.create_acme_domain_validation(
            AcmeEndpointArn=endpoint_arn, DomainName=domain_name, PrevalidationOptions=prevalidation
        )
    )
    assert code == "ConflictException", f"expected ConflictException for duplicate domain, got {code!r}"
    expected_message = f"An ACME domain validation for {domain_name} already exists."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: still exactly one domain validation for this endpoint.
    domains_after_reject = [
        d["DomainName"]
        for d in acm.list_acme_domain_validations(AcmeEndpointArn=endpoint_arn)["AcmeDomainValidations"]
    ]
    assert domains_after_reject.count(domain_name) == 1, (
        f"expected exactly 1 validation for {domain_name}, found {domains_after_reject.count(domain_name)}"
    )

    # Positive control: a genuinely different domain on the same endpoint is not blocked.
    other_domain = f"{uuid.uuid4().hex[:10]}.sim2real.example"
    second_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn, DomainName=other_domain, PrevalidationOptions=prevalidation
    )["AcmeDomainValidationArn"]
    ctx.on_cleanup(lambda: _delete_domain_validation(acm, second_arn))

    domains_after_control = [
        d["DomainName"]
        for d in acm.list_acme_domain_validations(AcmeEndpointArn=endpoint_arn)["AcmeDomainValidations"]
    ]
    assert domain_name in domains_after_control, f"{domain_name} missing from {domains_after_control}"
    assert other_domain in domains_after_control, f"{other_domain} missing from {domains_after_control}"


def _require_acme_api(client) -> None:
    if "CreateAcmeEndpoint" not in client.meta.service_model.operation_names:
        raise AssertionError(
            "installed botocore lacks the ACM ACME endpoint operations "
            "(CreateAcmeEndpoint/CreateAcmeDomainValidation/ListAcmeDomainValidations) -- "
            "upgrade botocore/boto3 to a version that models the ACM ACME endpoint API surface"
        )


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_domain_validation(acm, arn, timeout_s: float = 60.0, interval_s: float = 3.0) -> None:
    """Teardown delete that retries ACM's transient concurrent-modification refusal."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            acm.delete_acme_domain_validation(AcmeDomainValidationArn=arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met within {timeout_s}s, last value={last!r}")


def _create_active_acme_endpoint(ctx, acm) -> str:
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {"AllowedKeyAlgorithms": ["RSA_2048"]}},
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acme-ep-")}],
    )
    arn = resp["AcmeEndpointArn"]

    def _cleanup_endpoint():
        try:
            acm.delete_acme_endpoint(AcmeEndpointArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_endpoint)
    status = _poll_until(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=60.0,
        interval_s=3.0,
    )
    if status != "ACTIVE":
        raise AssertionError(f"ACME endpoint entered {status}, expected ACTIVE")
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
