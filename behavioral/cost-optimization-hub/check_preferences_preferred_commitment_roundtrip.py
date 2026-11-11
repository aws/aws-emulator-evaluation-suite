"""preferences-preferred-commitment-roundtrip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "preferences-preferred-commitment-roundtrip"
GROUP = "state"
SERVICES = ["cost-optimization-hub"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cost-optimization-hub-enrollment", "resource:account-singleton:cost-optimization-hub-preferences")
def run(ctx) -> None:
    """UpdatePreferences(preferredCommitment.term/paymentOption) persists and round-trips exactly."""
    # cost-optimization-hub is a region-pinned control plane; region=us-east-1 keeps
    # real AWS and the emulator on the same endpoint that ctx.client wires for both.
    coh = ctx.client("cost-optimization-hub", region="us-east-1")

    # GetPreferences/UpdatePreferences reject an unenrolled account outright (AccessDeniedException:
    # "AWS account is not enrolled for recommendations").
    enrollment_items = coh.list_enrollment_statuses()["items"]
    original_enrollment = enrollment_items[0]["status"] if enrollment_items else "Inactive"
    ctx.on_cleanup(lambda: coh.update_enrollment_status(status=original_enrollment))
    if original_enrollment != "Active":
        coh.update_enrollment_status(status="Active")

    # ListEnrollmentStatuses reporting Active does not mean the preferences backend
    # has caught up yet; bound the wait on the call this check actually needs.
    original = _poll_until(
        lambda: _try(lambda: coh.get_preferences()),
        lambda result: result is not None,
        timeout_s=60.0,
        interval_s=2.0,
    )
    ctx.on_cleanup(lambda: _restore(coh, original))

    target = {"term": "OneYear", "paymentOption": "PartialUpfront"}
    update_resp = coh.update_preferences(preferredCommitment=target)
    assert update_resp["preferredCommitment"]["term"] == "OneYear", update_resp
    assert update_resp["preferredCommitment"]["paymentOption"] == "PartialUpfront", update_resp

    fetched = coh.get_preferences()
    assert fetched["preferredCommitment"]["term"] == "OneYear", fetched
    assert fetched["preferredCommitment"]["paymentOption"] == "PartialUpfront", fetched


def _try(fn):
    """Run fn(); on the specific not-yet-enrolled AccessDeniedException return None
    (caller retries); any other outcome (success or a different error) propagates."""
    from botocore.exceptions import ClientError

    try:
        return fn()
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message", "")
        if code == "AccessDeniedException" and "not enrolled" in message.lower():
            return None
        raise


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _restore(coh, original: dict) -> None:
    kwargs = {}
    if "savingsEstimationMode" in original:
        kwargs["savingsEstimationMode"] = original["savingsEstimationMode"]
    if "memberAccountDiscountVisibility" in original:
        kwargs["memberAccountDiscountVisibility"] = original["memberAccountDiscountVisibility"]
    if original.get("preferredCommitment"):
        kwargs["preferredCommitment"] = original["preferredCommitment"]
    if kwargs:
        coh.update_preferences(**kwargs)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
