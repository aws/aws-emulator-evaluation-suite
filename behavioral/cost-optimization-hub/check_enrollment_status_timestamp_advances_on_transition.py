"""enrollment-status-timestamp-advances-on-transition."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "enrollment-status-timestamp-advances-on-transition"
GROUP = "state"
SERVICES = ["cost-optimization-hub"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:cost-optimization-hub-enrollment")
def run(ctx) -> None:
    """lastUpdatedTimestamp advances on a real status transition while createdTimestamp stays fixed."""
    # Cost Optimization Hub's control plane exists only in us-east-1, regardless of ctx.region.
    coh = ctx.client("cost-optimization-hub", region="us-east-1")

    # A never-enrolled account reports zero items rather than an explicit status; there is
    # no "unenroll" call, so the closest restorable state is Inactive.
    existing = coh.list_enrollment_statuses()["items"]
    original_status = existing[0]["status"] if existing else "Inactive"
    ctx.on_cleanup(lambda: coh.update_enrollment_status(status=original_status))

    # Establish a known starting state (Inactive) and capture its timestamps.
    coh.update_enrollment_status(status="Inactive")
    baseline = _poll_until(
        lambda: coh.list_enrollment_statuses()["items"][0],
        lambda item: item["status"] == "Inactive",
        timeout_s=30.0,
    )
    created_before = baseline["createdTimestamp"]
    updated_before = baseline["lastUpdatedTimestamp"]

    # Timestamp resolution may not distinguish two calls issued in the same instant, and
    # that collision cannot be waited out by re-reading a value that will never change on
    # its own — so re-issue the transition itself, bounded, until a fresh timestamp shows up.
    def _reactivate_and_read():
        coh.update_enrollment_status(status="Active")
        return coh.list_enrollment_statuses()["items"][0]

    after = _poll_until(
        _reactivate_and_read,
        lambda item: item["status"] == "Active" and item["lastUpdatedTimestamp"] > updated_before,
        timeout_s=30.0,
    )

    assert after["lastUpdatedTimestamp"] > updated_before, (
        f"expected lastUpdatedTimestamp to advance past {updated_before!r}, got {after['lastUpdatedTimestamp']!r}"
    )
    assert after["createdTimestamp"] == created_before, (
        f"expected createdTimestamp to stay {created_before!r}, got {after['createdTimestamp']!r}"
    )


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
