"""enrollment-status-idempotent-reactivation."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "enrollment-status-idempotent-reactivation"
GROUP = "state"
SERVICES = ["cost-optimization-hub"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cost-optimization-hub-enrollment")
def run(ctx) -> None:
    """Calling UpdateEnrollmentStatus(Active) twice in a row succeeds idempotently both times."""
    # cost-optimization-hub exists only in us-east-1 on real AWS; pinned for both targets.
    coh = ctx.client("cost-optimization-hub", region="us-east-1")

    original_items = coh.list_enrollment_statuses()["items"]
    # A never-enrolled account has no entry at all yet; that state is Inactive.
    original_status = original_items[0]["status"] if original_items else "Inactive"
    ctx.on_cleanup(lambda: coh.update_enrollment_status(status=original_status))

    first = coh.update_enrollment_status(status="Active")
    assert first["status"] == "Active", f"expected Active, got {first['status']!r}"
    _poll_until(
        lambda: coh.list_enrollment_statuses()["items"][0],
        lambda item: item["status"] == "Active",
        timeout_s=30.0,
    )

    # Re-applying the same status must not error and must remain Active.
    second = coh.update_enrollment_status(status="Active")
    assert second["status"] == "Active", f"expected Active, got {second['status']!r}"

    final = _poll_until(
        lambda: coh.list_enrollment_statuses()["items"][0],
        lambda item: item["status"] == "Active",
        timeout_s=30.0,
    )
    assert final["status"] == "Active", f"expected Active, got {final['status']!r}"


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
