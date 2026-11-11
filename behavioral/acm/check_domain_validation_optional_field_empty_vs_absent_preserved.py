"""domain-validation-optional-field-empty-vs-absent-preserved."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-validation-optional-field-empty-vs-absent-preserved"
GROUP = "representation"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An explicit empty HostedZoneId (min length 1) is rejected with ValidationException, while
    omitting the optional field succeeds: empty and absent are not normalized to one outcome.
    """
    acm = ctx.client("acm")
    endpoint_arn, _ = _create_active_acme_endpoint(ctx, acm)

    base = ctx.unique_name("sim2real-acme-dv").lower().replace("_", "-").strip("-")
    empty_domain = f"{base}-empty.example.com"
    omitted_domain = f"{base}-omitted.example.com"

    # botocore enforces the min length client-side; disable its parameter validation so the
    # empty string reaches the service and the service's own rejection is asserted.
    unvalidated_acm = ctx.client("acm", config=Config(parameter_validation=False))
    code, message = _error_code(
        lambda: unvalidated_acm.create_acme_domain_validation(
            AcmeEndpointArn=endpoint_arn,
            DomainName=empty_domain,
            PrevalidationOptions={"DnsPrevalidation": {"HostedZoneId": ""}},
        )
    )
    assert code == "ValidationException", f"expected ValidationException for empty HostedZoneId, got {code}"
    assert message == "2 validation errors detected: Value '' at 'prevalidationOptions.dnsPrevalidation.hostedZoneId' failed to satisfy constraint: Member must have length greater than or equal to 1; Value '' at 'prevalidationOptions.dnsPrevalidation.hostedZoneId' failed to satisfy constraint: Member must satisfy regular expression pattern: Z[A-Z0-9]+", (
        f"expected the exact ValidationException message AWS returns, got {message!r}"
    )

    # The empty-string attempt must not have left behind any domain validation for that domain.
    listing = acm.list_acme_domain_validations(AcmeEndpointArn=endpoint_arn)["AcmeDomainValidations"]
    assert not any(dv["DomainName"] == empty_domain for dv in listing), (
        "a domain validation was created despite the rejected empty HostedZoneId"
    )

    # Positive control: omitting HostedZoneId succeeds, so the rejection was specific to "".
    resp = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=omitted_domain,
        PrevalidationOptions={"DnsPrevalidation": {}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    dv_arn = resp["AcmeDomainValidationArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn))

    described = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"]
    assert described["DomainName"] == omitted_domain
    # VALIDATING lasts seconds on AWS; the record may already have settled by this read.
    assert described["Status"] in ("VALIDATING", "VALID", "INVALID"), (
        f"unexpected status, full record: {described!r}"
    )
    assert described["PrevalidationType"] == "DNS", (
        f"unexpected PrevalidationType, full record: {described!r}"
    )


def _create_active_acme_endpoint(ctx, acm, timeout_s: float = 180.0, interval_s: float = 5.0):
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        Contact="NOT_REQUIRED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))

    deadline = time.monotonic() + timeout_s
    endpoint = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
    while endpoint["Status"] == "CREATING" and time.monotonic() < deadline:
        time.sleep(interval_s)
        endpoint = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
    if endpoint["Status"] != "ACTIVE":
        raise AssertionError(
            f"ACME endpoint never reached ACTIVE (status={endpoint['Status']}, "
            f"reason={endpoint.get('FailureReason')})"
        )
    return arn, endpoint["EndpointUrl"]


def _error_code(fn):
    """Call fn(); return its error (code, message). A success raises, since AWS rejects the call."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
