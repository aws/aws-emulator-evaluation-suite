"""enrollment-status-active-transition."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "enrollment-status-active-transition"
GROUP = "state"
SERVICES = ["cost-optimization-hub"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cost-optimization-hub-enrollment")
def run(ctx) -> None:
    """UpdateEnrollmentStatus(Active) transitions the account and ListEnrollmentStatuses reflects it."""
    # cost-optimization-hub is a single-region (us-east-1) control plane; pinned via
    # ctx.client(region=...) rather than botocore's per-service resolution.
    coh = ctx.client("cost-optimization-hub", region="us-east-1")

    original = coh.list_enrollment_statuses()["items"][0]
    original_status = original["status"]
    ctx.on_cleanup(lambda: coh.update_enrollment_status(status=original_status))

    # Establish a known starting state (Inactive) so the transition to Active is
    # actually observed, rather than possibly re-asserting an already-Active account.
    coh.update_enrollment_status(status="Inactive")
    _poll_until(
        lambda: coh.list_enrollment_statuses()["items"][0],
        lambda item: item["status"] == "Inactive",
        timeout_s=30.0,
    )

    resp = coh.update_enrollment_status(status="Active")
    assert resp["status"] == "Active", f"expected UpdateEnrollmentStatus to return Active, got {resp['status']!r}"

    final = _poll_until(
        lambda: coh.list_enrollment_statuses()["items"][0],
        lambda item: item["status"] == "Active",
        timeout_s=30.0,
    )
    assert final["status"] == "Active", f"expected ListEnrollmentStatuses to reflect Active, got {final['status']!r}"


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
