"""create-acme-domain-validation-malformed-domain-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-acme-domain-validation-malformed-domain-rejected"
GROUP = "overly-permissive"
SERVICES = ["acm"]

# AcmeDomainValidationStatus values a live (not deleted) record can show: ACM verifies the
# CNAME for up to 72 hours but may settle it within seconds, so any of them can be first.
# https://docs.aws.amazon.com/acm/latest/userguide/acm-acme-domain-validation.html
_LIVE_STATUSES = ("VALIDATING", "VALID", "INVALID")

# Underscores (and other characters outside [a-z0-9-]) are not permitted by ACM's DomainName
# pattern (^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]*[a-z0-9])?$).
_MALFORMED_DOMAIN = "invalid_domain_name.example.com"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAcmeDomainValidation rejects a malformed DomainName with the exact ValidationException
    and creates nothing for it, while a valid domain on the same endpoint creates a live record."""
    acm = ctx.client("acm")
    endpoint_arn = _create_acme_endpoint(ctx, acm)

    try:
        bad_resp = acm.create_acme_domain_validation(
            AcmeEndpointArn=endpoint_arn,
            DomainName=_MALFORMED_DOMAIN,
            PrevalidationOptions={"DnsPrevalidation": {}},
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"]["Message"]
    else:
        bad_arn = bad_resp["AcmeDomainValidationArn"]
        ctx.on_cleanup(
            lambda: acm.delete_acme_domain_validation(AcmeDomainValidationArn=bad_arn)
        )
        raise AssertionError(
            "expected ValidationException for a malformed domain name, but the call "
            f"SUCCEEDED and created {bad_arn!r}"
        )
    assert code == "ValidationException", (
        f"expected ValidationException for a malformed domain name, got {code!r}"
    )
    assert message == "1 validation error detected: Value 'invalid_domain_name.example.com' at 'domainName' failed to satisfy constraint: Member must satisfy regular expression pattern: ([a-z0-9]([a-z0-9-]*[a-z0-9])?\\.)*[a-z0-9]([a-z0-9-]*[a-z0-9])?", (
        f"expected the exact ValidationException message AWS returns, got {message!r}"
    )

    listed = acm.list_acme_domain_validations(AcmeEndpointArn=endpoint_arn).get(
        "AcmeDomainValidations", []
    )
    assert not any(dv.get("DomainName") == _MALFORMED_DOMAIN for dv in listed), (
        "a domain validation resource was created for a rejected malformed domain name"
    )

    valid_domain = ctx.unique_name("sim2real-valid-domain-") + ".example.com"
    resp = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=valid_domain,
        PrevalidationOptions={"DnsPrevalidation": {}},
        Tags=[{"Key": "sim2real-check", "Value": ctx.unique_name("acme-malformed-domain-")}],
    )
    dv_arn = resp["AcmeDomainValidationArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn))
    assert "/acme-domain-validation/" in dv_arn, (
        f"expected an acme-domain-validation ARN, got {dv_arn!r}"
    )

    described = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)[
        "AcmeDomainValidation"
    ]
    assert described["DomainName"] == valid_domain, (
        f"expected DomainName {valid_domain!r}, got {described['DomainName']!r}"
    )
    assert described["Status"] in _LIVE_STATUSES, (
        f"expected a live Status for a freshly created domain validation, "
        f"got {described['Status']!r}"
    )


def _create_acme_endpoint(ctx, acm, contact: str = "NOT_REQUIRED") -> str:
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        Contact=contact,
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Tags=[{"Key": "sim2real-check", "Value": ctx.unique_name("acme-malformed-domain-")}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
