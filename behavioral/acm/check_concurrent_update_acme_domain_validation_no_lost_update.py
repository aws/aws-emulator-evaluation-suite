"""concurrent-update-acme-domain-validation-no-lost-update."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-update-acme-domain-validation-no-lost-update"
GROUP = "concurrency"
SERVICES = ["acm"]

_RACE_ATTEMPTS = 3


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two racing UpdateAcmeDomainValidation calls with conflicting scopes on a resource read
    VALIDATING are both rejected with ValidationException and leave its DomainScope unchanged; the
    same update succeeds once the validation reaches a terminal status."""
    acm = ctx.client("acm")
    endpoint_arn = _create_acme_endpoint(ctx, acm)

    initial_scope = {"ExactDomain": "ENABLED", "Subdomains": "DISABLED", "Wildcards": "DISABLED"}
    scope_a = {"ExactDomain": "ENABLED", "Subdomains": "ENABLED", "Wildcards": "DISABLED"}
    scope_b = {"ExactDomain": "DISABLED", "Subdomains": "DISABLED", "Wildcards": "ENABLED"}

    # VALIDATING lasts seconds on AWS, so the race is graded on the first record read VALIDATING
    # whose racers are both refused; a record that settles before the read or during the race is
    # deleted and replaced by a fresh one.
    attempts = []
    for _ in range(_RACE_ATTEMPTS):
        domain = ctx.unique_name("sim2real-concurrent-dv-") + ".example.com"
        dv_arn = acm.create_acme_domain_validation(
            AcmeEndpointArn=endpoint_arn,
            DomainName=domain,
            PrevalidationOptions={"DnsPrevalidation": {"DomainScope": initial_scope}},
        )["AcmeDomainValidationArn"]
        cleanup_state = {"deleted": False}
        ctx.on_cleanup(_cleanup_dv(acm, dv_arn, cleanup_state))

        before = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)[
            "AcmeDomainValidation"
        ]
        assert before["Status"] in ("VALIDATING", "VALID", "INVALID"), (
            f"unexpected status on a freshly created domain validation: {before['Status']!r}"
        )
        outcomes = None
        if before["Status"] == "VALIDATING":
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [
                    pool.submit(_update, acm, dv_arn, scope_a),
                    pool.submit(_update, acm, dv_arn, scope_b),
                ]
                outcomes = [f.result() for f in futures]
        attempts.append((before["Status"], outcomes))
        if outcomes is not None and None not in outcomes:
            break
        acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn)
        cleanup_state["deleted"] = True
    else:
        raise AssertionError(
            f"no race on a domain validation read VALIDATING had both updates refused in "
            f"{_RACE_ATTEMPTS} fresh records; (status read, outcomes) per record: {attempts!r}"
        )
    codes = [outcome[0] for outcome in outcomes]
    messages = [outcome[1] for outcome in outcomes]

    assert codes == ["ValidationException", "ValidationException"], (
        f"expected both concurrent updates against a VALIDATING domain validation to be "
        f"rejected with ValidationException, got {codes!r}"
    )
    expected_message = "Cannot update ACME domain validation in VALIDATING status."
    assert messages == [expected_message, expected_message], messages

    final = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)[
        "AcmeDomainValidation"
    ]
    final_scope = final["PrevalidationDetails"]["DnsPrevalidation"]["DomainScope"]
    before_scope = before["PrevalidationDetails"]["DnsPrevalidation"]["DomainScope"]

    assert final_scope == before_scope == initial_scope, (
        f"domain validation scope changed after two rejected concurrent updates: "
        f"before={before_scope!r} after={final_scope!r} -- indicates a lost/partial write "
        f"despite both callers being rejected"
    )

    # The terminal status comes from ACM's own DNS verification, not a client update; the
    # update must then apply, so the rejections above are a state guard, not a broken operation.
    settled = _wait_for_dv_terminal(ctx, acm, dv_arn, timeout_s=_budget_s(ctx, 90.0))
    acm.update_acme_domain_validation(
        AcmeDomainValidationArn=dv_arn,
        PrevalidationOptions={"DnsPrevalidation": {"DomainScope": scope_a}},
    )
    after = _poll_for_updated_at_change(
        ctx, acm, dv_arn, settled["UpdatedAt"], timeout_s=_budget_s(ctx, 30.0)
    )
    after_scope = after["PrevalidationDetails"]["DnsPrevalidation"]["DomainScope"]
    assert after_scope == scope_a, (
        f"expected UpdateAcmeDomainValidation to succeed once the domain validation reached a "
        f"terminal status, applying the same scope that was rejected while VALIDATING -- got "
        f"{after_scope!r}, indicating the operation cannot succeed at all rather than being "
        f"correctly guarded"
    )


def _update(acm, dv_arn: str, scope: dict):
    """UpdateAcmeDomainValidation to scope; its refusal's (code, message), or None on success."""
    from botocore.exceptions import ClientError

    try:
        acm.update_acme_domain_validation(
            AcmeDomainValidationArn=dv_arn,
            PrevalidationOptions={"DnsPrevalidation": {"DomainScope": scope}},
        )
        return None
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")


def _cleanup_dv(acm, dv_arn: str, cleanup_state: dict):
    def _cleanup():
        if not cleanup_state["deleted"]:
            acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn)

    return _cleanup


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _create_acme_endpoint(ctx, acm, contact: str = "NOT_REQUIRED") -> str:
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        Contact=contact,
        CertificateAuthority={"PublicCertificateAuthority": {}},
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))
    return arn


def _wait_for_dv_terminal(ctx, acm, dv_arn: str, timeout_s: float = 90.0, interval_s: float = 1.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"]
        if last["Status"] in ("VALID", "INVALID"):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain validation {dv_arn} reaching a terminal status: the run budget ended first; not graded")
    raise AssertionError(f"domain validation {dv_arn} never reached a terminal status, last={last}")


def _poll_for_updated_at_change(ctx, acm, dv_arn: str, prior_updated_at, timeout_s: float = 30.0, interval_s: float = 1.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"]
        if last["UpdatedAt"] > prior_updated_at:
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"UpdatedAt advancing past {prior_updated_at}: the run budget ended first; not graded")
    raise AssertionError(f"UpdatedAt never advanced past {prior_updated_at}, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
