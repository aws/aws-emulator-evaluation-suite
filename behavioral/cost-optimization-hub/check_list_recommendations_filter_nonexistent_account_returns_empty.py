"""list-recommendations-filter-nonexistent-account-returns-empty."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-recommendations-filter-nonexistent-account-returns-empty"
GROUP = "error-semantics"
SERVICES = ["cost-optimization-hub"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:cost-optimization-hub-enrollment")
def run(ctx) -> None:
    """On a member account, ListRecommendations with no filter succeeds, while any accountIds filter (here
    111122223333) fails with AccessDeniedException and its exact message: the account filter is an
    organization-view feature."""
    # cost-optimization-hub is a region-pinned control plane; region=us-east-1 keeps
    # real AWS and the emulator on the same endpoint that ctx.client wires for both.
    coh = ctx.client("cost-optimization-hub", region="us-east-1")

    # ListRecommendations rejects every caller with AccessDeniedException until the
    # account is enrolled — create-or-adopt that prerequisite and restore it after. A
    # never-enrolled account has no items at all (not even an "Inactive" record).
    enrollment_items = coh.list_enrollment_statuses()["items"]
    original_status = enrollment_items[0]["status"] if enrollment_items else "Inactive"
    ctx.on_cleanup(lambda: coh.update_enrollment_status(status=original_status))
    if original_status != "Active":
        coh.update_enrollment_status(status="Active")
        _poll_until(
            lambda: coh.list_enrollment_statuses()["items"][0],
            lambda item: item["status"] == "Active",
            timeout_s=30.0,
        )

    # Positive control: an unfiltered call succeeds — no organization-role restriction
    # blocks the operation itself, only its accountIds filter (below). Enrollment
    # showing Active in ListEnrollmentStatuses does not mean the recommendation
    # backend has caught up yet: right after the transition this call can still
    # answer AccessDeniedException for a few seconds before settling, so the wait is
    # bounded on this call directly rather than assumed from the enrollment read.
    unfiltered = _poll_until(
        lambda: _try(lambda: coh.list_recommendations(maxResults=10)),
        lambda result: result is not None,
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert isinstance(unfiltered["items"], list)

    # A documentation account ID outside the caller's organization; any accountIds value
    # triggers the same denial for a member-account caller. The unfiltered call above
    # succeeded, so this denial is not retried: it is the contract, not propagation.
    foreign_account_id = "111122223333"
    code, message = _error_code(
        lambda: coh.list_recommendations(
            filter={"accountIds": [foreign_account_id]}, maxResults=10
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}: {message}"
    assert message == (
        "Cannot get enrollment statuses for member accounts of the organization. "
        "This is because your account is not the management account of the organization."
    ), message


def _try(fn):
    """Run fn(); on the specific member-account-propagation AccessDeniedException return
    None (caller retries); any other outcome (success or a different error) propagates."""
    from botocore.exceptions import ClientError

    try:
        return fn()
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message", "")
        if code == "AccessDeniedException" and "management account" in message.lower():
            return None
        raise


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
