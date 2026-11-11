"""provisioned-limit-exceeds-quota-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "provisioned-limit-exceeds-quota-rejected"
GROUP = "representation"
SERVICES = ["cognito-idp"]

# LimitManagement (GetProvisionedLimit/UpdateProvisionedLimit) is rate-limited to
# roughly 1 request/second/account; retries below back off on the documented
# TooManyRequestsException instead of pacing every call with a blind sleep.
_THROTTLE_MAX_ATTEMPTS = 8
_THROTTLE_INITIAL_BACKOFF_S = 1.0

# UserFederation is not used as a fixed category by any other check in this
# directory (UserCreation and UserAuthentication are heavily reused), which
# keeps this check's account-global mutation out of their way.
_CATEGORY = "UserFederation"
_LIMIT_DEFINITION = {"LimitClass": "API_CATEGORY", "Attributes": {"Category": _CATEGORY}}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:cognito-idp-provisioned-limits")
def run(ctx) -> None:
    """UpdateProvisionedLimit with a RequestedLimitValue far beyond any account max is refused with
    ServiceQuotaExceededException and leaves the value unchanged, while reasserting the current
    value either succeeds or is refused with the specific "already the current value" message."""
    cognito = ctx.client("cognito-idp")

    baseline = _retry_throttle(lambda: cognito.get_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION))["Limit"]
    baseline_value = baseline.get("ProvisionedLimitValue", baseline.get("FreeLimitValue"))
    assert baseline_value is not None, (
        f"GetProvisionedLimit returned neither ProvisionedLimitValue nor FreeLimitValue: {baseline!r}"
    )

    absurd_value = 2_000_000_000  # far beyond any plausible account-level max RPS
    code, message = _rejection(
        lambda: _retry_throttle(
            lambda: cognito.update_provisioned_limit(
                LimitDefinition=_LIMIT_DEFINITION, RequestedLimitValue=absurd_value
            )
        )
    )
    assert code == "ServiceQuotaExceededException", f"expected ServiceQuotaExceededException, got {code!r}"
    # The ceiling an account without a Service Quotas grant reports is its own provisioned
    # value.
    expected_message = f"Requested value {absurd_value} exceeds Service Quota ceiling of {baseline_value}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    unchanged = _retry_throttle(lambda: cognito.get_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION))["Limit"]
    unchanged_value = unchanged.get("ProvisionedLimitValue", unchanged.get("FreeLimitValue"))
    assert unchanged_value == baseline_value, (
        f"the provisioned limit changed even though the oversized update was rejected: "
        f"{baseline_value} -> {unchanged_value}"
    )

    # Positive control (see docstring for the two acceptable outcomes).
    try:
        control = _retry_throttle(
            lambda: cognito.update_provisioned_limit(
                LimitDefinition=_LIMIT_DEFINITION, RequestedLimitValue=baseline_value
            )
        )["Limit"]
        control_value = control.get("ProvisionedLimitValue", control.get("FreeLimitValue"))
        assert control_value == baseline_value, (
            f"positive control failed: reapplying the current value returned {control_value}, "
            f"expected {baseline_value}"
        )
    except ClientError as exc:
        control_code = exc.response["Error"]["Code"]
        control_message = exc.response["Error"].get("Message", "")
        assert (control_code, control_message) == (
            "InvalidParameterException",
            "Requested value is the same as the current provisioned limit",
        ), (
            f"positive control failed: reapplying the account's own current value was rejected with "
            f"{control_code!r} ({control_message!r}), not the specific 'already the current value' diagnostic"
        )

    final = _retry_throttle(lambda: cognito.get_provisioned_limit(LimitDefinition=_LIMIT_DEFINITION))["Limit"]
    final_value = final.get("ProvisionedLimitValue", final.get("FreeLimitValue"))
    assert final_value == baseline_value, (
        f"provisioned limit drifted from baseline after the positive control: {baseline_value} -> {final_value}"
    )


# ===== helpers =====


def _rejection(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS
    raises, because a target that accepts a call real AWS refuses must not be reported
    as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _retry_throttle(fn):
    """Retry ``fn`` on the documented TooManyRequestsException with backoff.

    Bounded (deadline = _THROTTLE_MAX_ATTEMPTS) so a persistently throttled account
    fails loudly instead of stalling on an unconditional sleep. Any other ClientError
    (including ServiceQuotaExceededException and InvalidParameterException, the codes
    this check exists to assert) propagates immediately and untouched.
    """
    delay = _THROTTLE_INITIAL_BACKOFF_S
    for attempt in range(_THROTTLE_MAX_ATTEMPTS):
        try:
            return fn()
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] != "TooManyRequestsException"
                or attempt == _THROTTLE_MAX_ATTEMPTS - 1
            ):
                raise
            time.sleep(delay)
            delay = min(delay * 1.5, 5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
