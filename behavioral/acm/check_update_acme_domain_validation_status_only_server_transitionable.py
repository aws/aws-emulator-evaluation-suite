"""update-acme-domain-validation-status-only-server-transitionable."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "update-acme-domain-validation-status-only-server-transitionable"
GROUP = "server-side"
SERVICES = ["acm"]

_RESET_ATTEMPTS = 3
_SCOPES = (
    {"ExactDomain": "ENABLED", "Subdomains": "ENABLED", "Wildcards": "DISABLED"},
    {"ExactDomain": "ENABLED", "Subdomains": "DISABLED", "Wildcards": "DISABLED"},
)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """UpdateAcmeDomainValidation applies a PrevalidationOptions change and returns Status to
    VALIDATING; Status only reaches a terminal state via the server's own DNS verification."""
    acm = ctx.client("acm")
    endpoint_arn = _create_endpoint(ctx)
    _wait_for_endpoint_active(ctx, endpoint_arn)

    domain_name = f"{ctx.unique_name('sim2real-acm-dv-').lower()}.example.com"
    dv_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain_name,
        PrevalidationOptions={
            "DnsPrevalidation": {
                "DomainScope": {
                    "ExactDomain": "ENABLED",
                    "Subdomains": "DISABLED",
                    "Wildcards": "DISABLED",
                }
            }
        },
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acm-dv-")}],
    )["AcmeDomainValidationArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn))

    before = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)[
        "AcmeDomainValidation"
    ]
    assert before["Status"] in ("VALIDATING", "VALID", "INVALID"), f"unexpected status on a freshly created domain validation: {before['Status']!r}"
    scope_before = before["PrevalidationDetails"]["DnsPrevalidation"]["DomainScope"]
    assert scope_before["Subdomains"] == "DISABLED", f"expected the requested Subdomains=DISABLED to be echoed back, got {scope_before['Subdomains']!r}"

    # AWS rejects the update with ValidationException while the validation is still
    # VALIDATING, so it must first settle into a terminal state (VALID/INVALID). The reset
    # VALIDATING lasts seconds, so the update is repeated (alternating scopes) until the first
    # Describe showing the advanced UpdatedAt also shows VALIDATING.
    seen = []
    for attempt in range(_RESET_ATTEMPTS):
        settled = _wait_for_dv_status(acm, dv_arn, {"VALID", "INVALID"})
        updated_at_before = settled["UpdatedAt"]
        requested = _SCOPES[attempt % 2]
        acm.update_acme_domain_validation(
            AcmeDomainValidationArn=dv_arn,
            PrevalidationOptions={"DnsPrevalidation": {"DomainScope": requested}},
        )

        after = _poll_for_updated_at_change(acm, dv_arn, updated_at_before)
        scope_after = after["PrevalidationDetails"]["DnsPrevalidation"]["DomainScope"]
        assert scope_after["Subdomains"] == requested["Subdomains"], "the requested PrevalidationOptions change did not apply"
        seen.append(after["Status"])
        if after["Status"] == "VALIDATING":
            break
    else:
        # The request has no Status field; AWS resets Status to VALIDATING as a side effect.
        raise AssertionError(
            f"Status became {seen!r} merely from {_RESET_ATTEMPTS} UpdateAcmeDomainValidation calls "
            "-- Status must only be advanced by server-side verification"
        )


def _wait_for_dv_status(acm, dv_arn: str, target_statuses: set, timeout_s: float = 90.0, interval_s: float = 3.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"]
        if last["Status"] in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"domain validation {dv_arn} never reached {target_statuses}, last={last}")


def _poll_for_updated_at_change(acm, dv_arn: str, prior_updated_at, timeout_s: float = 30.0, interval_s: float = 0.5) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"]
        if last["UpdatedAt"] > prior_updated_at:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"UpdatedAt never advanced past {prior_updated_at}, last={last}")



def _create_endpoint(ctx: Any) -> str:
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact="NOT_REQUIRED",
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acm-ep-")}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))
    return arn


def _wait_for_endpoint_active(ctx: Any, arn: str, timeout_s: float = 180.0) -> dict:
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        endpoint = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
        status = endpoint["Status"]
        if status == "ACTIVE":
            return endpoint
        if status == "FAILED":
            raise AssertionError(f"ACME endpoint {arn} failed: {endpoint.get('FailureReason')}")
        time.sleep(3)
    raise AssertionError(f"ACME endpoint {arn} never became ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
