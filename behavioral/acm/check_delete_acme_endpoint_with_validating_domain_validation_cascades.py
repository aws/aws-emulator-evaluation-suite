"""delete-acme-endpoint-with-validating-domain-validation-cascades."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-acme-endpoint-with-validating-domain-validation-cascades"
GROUP = "overly-permissive"
SERVICES = ["acm"]

# AcmeDomainValidationStatus values a live (not deleted) record can show: ACM verifies the
# CNAME for up to 72 hours but may settle it within seconds, so any of them can be first.
# https://docs.aws.amazon.com/acm/latest/userguide/acm-acme-domain-validation.html
_LIVE_STATUSES = ("VALIDATING", "VALID", "INVALID")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A live AcmeDomainValidation does not block DeleteAcmeEndpoint: the endpoint delete
    succeeds and the endpoint goes away, and the dependent domain validation then raises
    ResourceNotFoundException on Describe rather than surviving as an orphan."""
    acm = ctx.client("acm")
    endpoint_arn = _create_active_endpoint(ctx)

    domain = f"{ctx.unique_name('sim2real-acmedv-')}.example.com"
    dv_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain,
        PrevalidationOptions={"DnsPrevalidation": {}},
    )["AcmeDomainValidationArn"]
    ctx.on_cleanup(lambda: _ignore(lambda: acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn)))

    dv_status = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)[
        "AcmeDomainValidation"
    ]["Status"]
    assert dv_status in _LIVE_STATUSES, f"expected a live fresh domain validation, got {dv_status}"

    # Deleting the endpoint while the domain validation is still active succeeds
    # outright -- this is a real, documented counter-example to a naive
    # "must clear dependents first" assumption for this particular resource pair.
    acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn)
    final = _poll_until(
        lambda: _status_or_gone(acm, endpoint_arn),
        lambda s: s == "GONE",
        timeout_s=60,
        interval_s=3,
    )
    assert final == "GONE", (
        f"endpoint was not fully removed by the cascading delete despite an active "
        f"domain validation, expected GONE, got {final}"
    )

    # The invariant that matters: the dependent domain validation does not linger
    # as an orphan once its owning endpoint is gone.
    dv_gone_code, dv_gone_message = _poll_until(
        lambda: _error(lambda: acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)),
        lambda outcome: outcome[0] == "ResourceNotFoundException",
        timeout_s=90,
        interval_s=3,
    )
    assert dv_gone_code == "ResourceNotFoundException", (
        f"domain validation was never cleaned up after its endpoint was deleted, last code={dv_gone_code}"
    )
    assert dv_gone_message == f"Could not find ACME domain validation {dv_arn}.", dv_gone_message


def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """The (code, message) of the ClientError fn raises, or ("SUCCEEDED", None) when it succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return "SUCCEEDED", None


def _ignore(fn: Callable[[], Any]) -> None:
    fn()


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 60.0, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _status_or_gone(acm, arn: str) -> str:
    try:
        return acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return "GONE"
        raise


def _create_active_endpoint(ctx, contact: str = "NOT_REQUIRED") -> str:
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {"AllowedKeyAlgorithms": ["EC_prime256v1"]}},
        Contact=contact,
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acme-ep-")}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _ignore(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn)))
    status = _poll_until(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=120,
        interval_s=3,
    )
    assert status == "ACTIVE", f"ACME endpoint did not become ACTIVE (status={status})"
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
