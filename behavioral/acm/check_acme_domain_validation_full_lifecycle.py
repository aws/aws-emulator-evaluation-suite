"""acme-domain-validation-full-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "acme-domain-validation-full-lifecycle"
GROUP = "state-machine"
SERVICES = ["acm"]

_GUARD_ATTEMPTS = 3
_SUCCEEDED = ("succeeded", None)
_NOT_ATTEMPTED = ("not attempted", None)
_INITIAL_SCOPE = {"ExactDomain": "ENABLED", "Subdomains": "DISABLED", "Wildcards": "DISABLED"}
_WIDER_SCOPE = {"ExactDomain": "ENABLED", "Subdomains": "ENABLED", "Wildcards": "DISABLED"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An update to an ACME domain validation read VALIDATING is rejected with ValidationException
    and changes nothing, the identical update succeeds once it settles, and Describe raises
    not-found after delete."""
    acm = ctx.client("acm")
    endpoint_arn = _create_active_endpoint(ctx, acm)

    # VALIDATING lasts seconds on AWS, so the guard is graded on the first record whose update is
    # refused after a read showed it VALIDATING; a record that settles before the read or between
    # the read and the update is deleted and replaced by a fresh one.
    attempts = []
    for _ in range(_GUARD_ATTEMPTS):
        domain = f"{ctx.unique_name('sim2real-acmedv-')}.example.com".lower()
        dv_arn = acm.create_acme_domain_validation(
            AcmeEndpointArn=endpoint_arn,
            DomainName=domain,
            PrevalidationOptions={"DnsPrevalidation": {"DomainScope": _INITIAL_SCOPE}},
        )["AcmeDomainValidationArn"]
        cleanup_state = {"deleted": False}
        ctx.on_cleanup(_cleanup_dv(acm, dv_arn, cleanup_state))

        dv = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"]
        assert dv["AcmeDomainValidationArn"] == dv_arn
        assert dv["DomainName"] == domain
        assert dv["Status"] in ("VALIDATING", "VALID", "INVALID"), f"unexpected initial status: {dv['Status']}"
        scope = dv["PrevalidationDetails"]["DnsPrevalidation"]["DomainScope"]
        assert scope["ExactDomain"] == "ENABLED"
        assert scope["Subdomains"] == "DISABLED"

        outcome = _NOT_ATTEMPTED
        if dv["Status"] == "VALIDATING":
            outcome = _outcome(
                lambda: acm.update_acme_domain_validation(
                    AcmeDomainValidationArn=dv_arn,
                    PrevalidationOptions={"DnsPrevalidation": {"DomainScope": _WIDER_SCOPE}},
                )
            )
        attempts.append((dv["Status"], outcome))
        if outcome not in (_SUCCEEDED, _NOT_ATTEMPTED):
            break
        acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn)
        cleanup_state["deleted"] = True
    else:
        raise AssertionError(
            f"no UpdateAcmeDomainValidation was refused on a domain validation read VALIDATING in "
            f"{_GUARD_ATTEMPTS} fresh records; (status read, update outcome) per record: {attempts!r}"
        )

    # The DNS CNAME was never provisioned. Real ACM rejects UpdateAcmeDomainValidation while a
    # validation is still mid-flight in VALIDATING: the update is a no-op on the resource, not
    # silently applied.
    update_code, update_message = outcome
    assert update_code == "ValidationException", (
        f"expected ValidationException updating a VALIDATING domain validation, got {update_code}"
    )
    expected_update_message = "Cannot update ACME domain validation in VALIDATING status."
    assert update_message == expected_update_message, (
        f"expected message {expected_update_message!r}, got {update_message!r}"
    )

    # Effect must be absent: the scope on the resource is unchanged by the rejected update. The
    # status may already have settled by this read.
    unchanged = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"]
    assert unchanged["Status"] in ("VALIDATING", "VALID", "INVALID"), (
        f"unexpected status after rejected update: {unchanged['Status']}"
    )
    unchanged_scope = unchanged["PrevalidationDetails"]["DnsPrevalidation"]["DomainScope"]
    assert unchanged_scope["ExactDomain"] == "ENABLED"
    assert unchanged_scope["Subdomains"] == "DISABLED", "update should have been rejected, not applied"

    # Restore leg: the rejection above is gated by state (VALIDATING), not a permanently
    # unusable request shape. Once the validation settles into a terminal state via the
    # server's own DNS verification, the identical update now succeeds.
    settled = _poll_until(
        lambda: acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"],
        lambda dv: dv["Status"] != "VALIDATING",
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert settled["Status"] in ("VALID", "INVALID"), f"unexpected settled status: {settled['Status']}"

    acm.update_acme_domain_validation(
        AcmeDomainValidationArn=dv_arn,
        PrevalidationOptions={"DnsPrevalidation": {"DomainScope": _WIDER_SCOPE}},
    )
    restored = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"]
    restored_scope = restored["PrevalidationDetails"]["DnsPrevalidation"]["DomainScope"]
    assert restored_scope["Subdomains"] == "ENABLED", (
        f"identical update should have succeeded once settled, got scope={restored_scope}"
    )

    # Delete and confirm the resource is gone.
    acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn)
    cleanup_state["deleted"] = True
    code, message = _poll_until_refused(
        lambda: acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn), timeout_s=60.0, interval_s=2.0
    )
    assert code == "ResourceNotFoundException", f"unexpected code after delete: {code}"
    expected_message = f"Could not find ACME domain validation {dv_arn}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _outcome(fn):
    """Call fn(); return its refusal's (code, message), or _SUCCEEDED when it succeeds."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return _SUCCEEDED


def _cleanup_dv(acm, dv_arn, cleanup_state):
    def _cleanup():
        if not cleanup_state["deleted"]:
            _delete_quietly(lambda: acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn))

    return _cleanup


def _poll_until_refused(fn, timeout_s=60.0, interval_s=2.0):
    """Poll fn() until it is refused; return the refusal's (code, message), raise on timeout."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"the call kept succeeding for {timeout_s}s after the delete")


def _delete_quietly(fn):
    from botocore.exceptions import ClientError

    fn()


def _create_active_endpoint(ctx, acm):
    arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        Contact="NOT_REQUIRED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acme-ep-")}],
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_quietly(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn)))
    _poll_until(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"],
        lambda status: status in ("ACTIVE", "FAILED"),
        timeout_s=60.0,
        interval_s=2.0,
    )
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
