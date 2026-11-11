"""update-acme-domain-validation-transitions-status."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-acme-domain-validation-transitions-status"
GROUP = "state-machine"
SERVICES = ["acm"]

_RESET_ATTEMPTS = 3
_SCOPES = (
    {"ExactDomain": "ENABLED", "Subdomains": "DISABLED", "Wildcards": "ENABLED"},
    {"ExactDomain": "ENABLED", "Subdomains": "DISABLED", "Wildcards": "DISABLED"},
)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAcmeDomainValidation resets the validation's Status field (documented as resetting
    to VALIDATING when PrevalidationOptions change), and the new state/UpdatedAt is visible on
    the next Describe."""
    acm = ctx.client("acm")
    endpoint_arn = _create_active_endpoint(ctx, acm)

    domain = _domain_name(ctx, "dv-update")
    dv_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain,
        PrevalidationOptions={
            "DnsPrevalidation": {
                "DomainScope": {"ExactDomain": "ENABLED", "Subdomains": "DISABLED", "Wildcards": "DISABLED"}
            }
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["AcmeDomainValidationArn"]
    ctx.on_cleanup(lambda: _delete_if_present(lambda: acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn)))

    before = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"]
    assert before["Status"] in ("VALIDATING", "VALID", "INVALID"), (
        f"unexpected status on a freshly created validation: {before['Status']}"
    )

    # real AWS rejects UpdateAcmeDomainValidation while the validation is still VALIDATING
    # ("Cannot update ACME domain validation in VALIDATING status"); it must first settle into
    # a terminal state (VALID/INVALID) before a prevalidation-options change is accepted. The
    # reset VALIDATING lasts seconds, so the update is repeated (alternating scopes) until the
    # first Describe showing the advanced UpdatedAt also shows VALIDATING.
    seen = []
    for attempt in range(_RESET_ATTEMPTS):
        settled = _wait_for_dv_status(acm, dv_arn, {"VALID", "INVALID"})
        updated_at_before = settled["UpdatedAt"]
        acm.update_acme_domain_validation(
            AcmeDomainValidationArn=dv_arn,
            PrevalidationOptions={"DnsPrevalidation": {"DomainScope": _SCOPES[attempt % 2]}},
        )
        after = _poll_for_updated_at_change(acm, dv_arn, updated_at_before)
        seen.append(after["Status"])
        if after["Status"] == "VALIDATING":
            break
    else:
        raise AssertionError(
            f"expected Status reset to VALIDATING after an update, got {seen!r} in {_RESET_ATTEMPTS} updates"
        )
    assert after["UpdatedAt"] > updated_at_before, (
        f"expected UpdatedAt to advance past {updated_at_before}, got {after['UpdatedAt']}"
    )


def _delete_if_present(fn):
    """Teardown delete: return once it succeeds or the resource is already gone, retry a
    ConflictException while a dependent resource is still being released, raise the rest."""
    deadline = time.monotonic() + 30
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "NoSuchEntity"):
                return
            if code != "ConflictException" or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _domain_name(ctx, label: str) -> str:
    token = ctx.unique_name(f"sim2real-{label}-").lower().strip("-")
    return f"{token}.example.com"


def _create_active_endpoint(ctx, acm, contact: str | None = None) -> str:
    kwargs = {
        "AuthorizationBehavior": "PRE_APPROVED",
        "CertificateAuthority": {"PublicCertificateAuthority": {}},
        "Tags": [{"Key": "sim2real", "Value": CHECK}],
    }
    if contact:
        kwargs["Contact"] = contact
    arn = acm.create_acme_endpoint(**kwargs)["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_if_present(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn)))
    status = _wait_for_endpoint_status(acm, arn, {"ACTIVE", "FAILED"})
    if status != "ACTIVE":
        raise AssertionError(f"endpoint entered {status} instead of ACTIVE")
    return arn


def _wait_for_endpoint_status(acm, arn: str, target_statuses: set, timeout_s: float = 90.0, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        last_status = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last_status in target_statuses:
            return last_status
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {arn} never reached {target_statuses}, last status={last_status}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
