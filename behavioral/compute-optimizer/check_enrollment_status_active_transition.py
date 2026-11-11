"""enrollment-status-active-transition."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "enrollment-status-active-transition"
GROUP = "state-machine"
SERVICES = ["compute-optimizer"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx) -> None:
    """UpdateEnrollmentStatus(Active) returns Active or Pending and GetEnrollmentStatus then reaches Active,
    with memberAccountsEnrolled false and numberOfMemberAccountsOptedIn 0 for a non-management account."""
    co = ctx.client("compute-optimizer")
    resp = co.update_enrollment_status(status="Active")
    assert resp["status"] in ("Active", "Pending"), (
        f"UpdateEnrollmentStatus(Active) returned unexpected status: {resp['status']!r}"
    )

    final_status = _poll_until_active(co, timeout_s=180.0, interval_s=5.0)
    assert final_status == "Active", f"expected terminal status Active, got {final_status!r}"

    status_resp = co.get_enrollment_status()
    assert status_resp["status"] == "Active", (
        f"independent GetEnrollmentStatus read expected Active, got {status_resp['status']!r}"
    )
    # Real fields from the response, not a shape check on an absent-by-default key: a
    # standalone account never has member accounts opted in, so both must read as the
    # standalone-account defaults (see the docstring assumption).
    assert status_resp["memberAccountsEnrolled"] is False, (
        f"expected memberAccountsEnrolled=False for a standalone account, "
        f"got {status_resp['memberAccountsEnrolled']!r}"
    )
    assert status_resp["numberOfMemberAccountsOptedIn"] == 0, (
        f"expected numberOfMemberAccountsOptedIn=0 for a standalone account, "
        f"got {status_resp['numberOfMemberAccountsOptedIn']!r}"
    )


def _poll_until_active(co, timeout_s: float, interval_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = co.get_enrollment_status()["status"]
        if last == "Active":
            return last
        time.sleep(interval_s)
    raise AssertionError(f"enrollment status never reached Active, last seen: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
