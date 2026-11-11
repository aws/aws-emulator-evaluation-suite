"""enrollment-status-inactive-transition."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "enrollment-status-inactive-transition"
GROUP = "state"
SERVICES = ["cost-optimization-hub"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cost-optimization-hub-enrollment")
def run(ctx) -> None:
    """UpdateEnrollmentStatus(Inactive) transitions the account and ListEnrollmentStatuses reflects it."""
    # cost-optimization-hub has a single API endpoint, us-east-1 only — region-pinned, not a literal.
    coh = ctx.client("cost-optimization-hub", region="us-east-1")

    # A never-enrolled account reports no item at all, not an explicit "Inactive" one.
    enrollment_items = coh.list_enrollment_statuses().get("items", [])
    original_status = enrollment_items[0]["status"] if enrollment_items else "Inactive"
    ctx.on_cleanup(lambda: coh.update_enrollment_status(status=original_status))

    # Make sure we're starting from Active so the Inactive transition is observable.
    coh.update_enrollment_status(status="Active")
    _poll_until(
        lambda: coh.list_enrollment_statuses()["items"][0],
        lambda item: item["status"] == "Active",
        timeout_s=30.0,
    )

    resp = coh.update_enrollment_status(status="Inactive")
    assert resp["status"] == "Inactive", (
        f"UpdateEnrollmentStatus echo: expected status='Inactive', got {resp.get('status')!r}"
    )

    final = _poll_until(
        lambda: coh.list_enrollment_statuses()["items"][0],
        lambda item: item["status"] == "Inactive",
        timeout_s=30.0,
    )
    assert final["status"] == "Inactive", (
        f"ListEnrollmentStatuses after transition: expected status='Inactive', "
        f"got {final.get('status')!r}"
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
