"""acme-domain-validation-nonexistent-endpoint-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "acme-domain-validation-nonexistent-endpoint-rejected"
GROUP = "e2e"
SERVICES = ["acm"]

# AcmeDomainValidationStatus values a live (not deleted) record can show: ACM verifies the
# CNAME for up to 72 hours but may settle it within seconds, so any of them can be first.
# https://docs.aws.amazon.com/acm/latest/userguide/acm-acme-domain-validation.html
_LIVE_STATUSES = ("VALIDATING", "VALID", "INVALID")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAcmeDomainValidation against a nonexistent AcmeEndpointArn raises
    ResourceNotFoundException with the exact message and creates nothing, while the same
    call against a real endpoint creates a live record for the domain."""
    acm = ctx.client("acm")

    real_endpoint_arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
    )["AcmeEndpointArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=real_endpoint_arn))
    )

    endpoint_status = _poll_until(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=real_endpoint_arn)["AcmeEndpoint"]["Status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=120.0,
    )
    assert endpoint_status == "ACTIVE", f"expected the prerequisite endpoint to reach ACTIVE, got {endpoint_status!r}"

    bogus_endpoint_arn = real_endpoint_arn.rsplit("/", 1)[0] + "/nonexistent-00000000-0000-0000-0000-000000000000"
    domain = f"{ctx.unique_name('sim2realbogus').rstrip('-')}.example.com".lower()

    code, message = _error_code(
        lambda: acm.create_acme_domain_validation(
            AcmeEndpointArn=bogus_endpoint_arn,
            DomainName=domain,
            PrevalidationOptions={"DnsPrevalidation": {}},
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == f"Could not find ACME endpoint {bogus_endpoint_arn}.", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {message!r}"
    )

    # Effect absent: nothing got created for this domain under the real endpoint.
    real_endpoint_validations = acm.list_acme_domain_validations(AcmeEndpointArn=real_endpoint_arn)[
        "AcmeDomainValidations"
    ]
    assert not any(v["DomainName"] == domain for v in real_endpoint_validations), (
        f"domain {domain!r} leaked into the real endpoint's validations after the bogus-ARN call"
    )

    # Positive control: the identical call against the REAL endpoint succeeds.
    validation_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=real_endpoint_arn,
        DomainName=domain,
        PrevalidationOptions={"DnsPrevalidation": {}},
    )["AcmeDomainValidationArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: acm.delete_acme_domain_validation(AcmeDomainValidationArn=validation_arn))
    )
    described = acm.describe_acme_domain_validation(AcmeDomainValidationArn=validation_arn)["AcmeDomainValidation"]
    assert described["DomainName"] == domain, f"expected DomainName {domain!r}, got {described['DomainName']!r}"
    assert described["Status"] in _LIVE_STATUSES, f"expected a live status, got {described['Status']!r}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
