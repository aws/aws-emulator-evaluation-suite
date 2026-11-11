"""delete-acme-endpoint-cascades-to-dependent-removal."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-acme-endpoint-cascades-to-dependent-removal"
GROUP = "e2e"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteAcmeEndpoint on an endpoint with an active domain validation succeeds and cascades:
    the domain validation is removed too (ListAcmeDomainValidations / Describe), not orphaned."""
    acm = ctx.client("acm")

    endpoint_arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acme-ep-")}],
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn)))

    _poll_until(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"]["Status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=120,
        interval_s=3,
    )

    domain = f"{_dns_label(ctx.unique_name('sim2real-acme-dv'))}.example.com"
    dv_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain,
        PrevalidationOptions={"DnsPrevalidation": {"DomainScope": {"ExactDomain": "ENABLED"}}},
    )["AcmeDomainValidationArn"]

    # sanity: the dependent is visible before the cascading delete
    pre_arns = [
        v["AcmeDomainValidationArn"]
        for v in acm.list_acme_domain_validations(AcmeEndpointArn=endpoint_arn).get(
            "AcmeDomainValidations", []
        )
    ]
    assert dv_arn in pre_arns, "domain validation was not visible before the endpoint delete"

    # DeleteAcmeEndpoint succeeds directly -- it is not blocked by the dependent
    acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn)

    deleted_code, deleted_message = _poll_until(
        lambda: _error(lambda: acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)),
        lambda c: c[0] == "ResourceNotFoundException",
        timeout_s=60,
        interval_s=3,
    )
    assert deleted_code == "ResourceNotFoundException", (
        f"expected the deleted endpoint to 404 on describe, got {deleted_code!r}"
    )
    assert deleted_message == f"Could not find ACME endpoint {endpoint_arn}.", deleted_message

    # the cascade also removed the dependent domain validation, not just the endpoint
    dv_deleted_code, dv_deleted_message = _poll_until(
        lambda: _error(lambda: acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)),
        lambda c: c[0] == "ResourceNotFoundException",
        timeout_s=60,
        interval_s=3,
    )
    assert dv_deleted_code == "ResourceNotFoundException", (
        f"expected the cascade to remove the dependent domain validation too, got {dv_deleted_code!r}"
    )
    assert dv_deleted_message == f"Could not find ACME domain validation {dv_arn}.", dv_deleted_message


def _dns_label(name: str) -> str:
    label = "".join(c if c.isalnum() else "-" for c in name.lower())
    return label.strip("-") or "sim2real"


def _safe_call(fn) -> None:
    fn()


def _error(fn):
    """The (code, message) of the ClientError fn raises, or ("SUCCEEDED", None) when it succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return "SUCCEEDED", None


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
