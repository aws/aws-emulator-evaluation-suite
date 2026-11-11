"""preferences-member-account-discount-visibility-roundtrip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "preferences-member-account-discount-visibility-roundtrip"
GROUP = "state"
SERVICES = ["cost-optimization-hub"]


@tags("axis:rejection", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cost-optimization-hub-enrollment", "resource:account-singleton:cost-optimization-hub-preferences")
def run(ctx) -> None:
    """On a member account, UpdatePreferences(memberAccountDiscountVisibility) fails with ValidationException
    and its exact message and leaves the field unchanged, while an update of savingsEstimationMode on the
    same account persists."""
    # Cost Optimization Hub's control plane exists only in us-east-1, regardless of ctx.region.
    coh = ctx.client("cost-optimization-hub", region="us-east-1")

    # GetPreferences/UpdatePreferences reject an unenrolled account. A never-enrolled
    # account reports no item at all rather than an explicit "Inactive" one.
    existing = coh.list_enrollment_statuses()["items"]
    original_enrollment = existing[0]["status"] if existing else "Inactive"
    ctx.on_cleanup(lambda: coh.update_enrollment_status(status=original_enrollment))
    if original_enrollment != "Active":
        coh.update_enrollment_status(status="Active")
        _poll_until(
            lambda: coh.list_enrollment_statuses()["items"][0]["status"],
            lambda status: status == "Active",
            timeout_s=30.0,
        )

    original = coh.get_preferences()
    ctx.on_cleanup(lambda: _restore(coh, original))

    # Positive control: this account/session can genuinely write preferences at all.
    control_mode = "BeforeDiscounts"
    control = coh.update_preferences(savingsEstimationMode=control_mode)
    assert control["savingsEstimationMode"] == control_mode, (
        f"positive control failed: expected UpdatePreferences echo savingsEstimationMode="
        f"{control_mode!r}, got {control['savingsEstimationMode']!r}"
    )

    baseline_visibility = original.get("memberAccountDiscountVisibility")
    target = "None" if baseline_visibility != "None" else "All"

    error = _client_error(lambda: coh.update_preferences(memberAccountDiscountVisibility=target))
    assert error.get("Code") == "ValidationException", (
        f"expected ValidationException from a non-management account setting "
        f"memberAccountDiscountVisibility={target!r}, got {error.get('Code')!r} "
        f"({error.get('Message')!r})"
    )
    message = error.get("Message", "")
    expected_message = "Only management accounts can update member account discount visibility."
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    unchanged = coh.get_preferences()
    assert unchanged.get("memberAccountDiscountVisibility") == baseline_visibility, (
        f"expected memberAccountDiscountVisibility to remain {baseline_visibility!r} after the "
        f"rejected update, got {unchanged.get('memberAccountDiscountVisibility')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS rejects this call for a non-management account, but it SUCCEEDED and "
        f"returned {result!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"condition not met within {timeout_s}s, last value: {last!r}")


def _restore(coh, original: dict) -> None:
    # memberAccountDiscountVisibility is deliberately excluded: this check never succeeds in
    # changing it (that rejection is the contract under test), and on a non-management account
    # even resubmitting its own unchanged value hits the same ValidationException, which would
    # turn a correct teardown into a cleanup failure.
    kwargs = {}
    if "savingsEstimationMode" in original:
        kwargs["savingsEstimationMode"] = original["savingsEstimationMode"]
    if original.get("preferredCommitment"):
        kwargs["preferredCommitment"] = original["preferredCommitment"]
    if kwargs:
        coh.update_preferences(**kwargs)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
