"""enrollment-configuration-get-reflects-valid-status."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "enrollment-configuration-get-reflects-valid-status"
GROUP = "state"
SERVICES = ["compute-optimizer-automation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx: Any) -> None:
    """GetEnrollmentConfiguration reflects the status UpdateEnrollmentConfiguration actually set,
    through the async Pending -> Active convergence, via a read on a different operation."""
    _ensure_base_enrolled(ctx)
    client = ctx.client("compute-optimizer-automation")

    # Mutate: request Active. The response's own status is not the terminal state — the
    # documented contract is that it may still be converging (Pending) right after the call.
    update_result = client.update_enrollment_configuration(status="Active")
    assert update_result["status"] in ("Active", "Pending"), (
        f"expected UpdateEnrollmentConfiguration(status=Active) to echo Active or Pending, "
        f"got {update_result['status']!r}"
    )

    # Independent read, on a different operation than the one that mutated, polled with a
    # bounded retry rather than a sleep, until the account reaches the terminal state.
    deadline = time.monotonic() + 120
    cfg = client.get_enrollment_configuration()
    while cfg["status"] == "Pending":
        if time.monotonic() >= deadline:
            break
        time.sleep(3)
        cfg = client.get_enrollment_configuration()
    if cfg["status"] == "Failed":
        raise AssertionError(f"enrollment configuration failed: {cfg.get('statusReason')}")
    if cfg["status"] != "Active":
        raise AssertionError(
            "GetEnrollmentConfiguration did not converge to Active within 120s of "
            f"UpdateEnrollmentConfiguration(status=Active); last observed status={cfg['status']!r}",
        )

    # Calling it twice in a row must be stable at the now-terminal state (no side effects from a
    # plain read, and no further drift once Active is reached).
    cfg_again = client.get_enrollment_configuration()
    assert cfg_again["status"] == "Active" == cfg["status"], (
        f"expected a stable Active status across two immediate reads, "
        f"got {cfg['status']!r} then {cfg_again['status']!r}"
    )


def _ensure_base_enrolled(ctx) -> None:
    """The compute-optimizer-automation API surface (including GetEnrollmentConfiguration
    itself) requires the account to first be opted in to the base AWS Compute Optimizer
    service; otherwise every call raises OptInRequiredException."""
    

    co = ctx.client("compute-optimizer")
    status = co.get_enrollment_status().get("status")
    if status == "Active":
        return
    co.update_enrollment_status(status="Active", includeMemberAccounts=False)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        status = co.get_enrollment_status().get("status")
        if status == "Active":
            return
        if status == "Failed":
            raise AssertionError("compute-optimizer base enrollment failed")
        time.sleep(3)
    raise AssertionError(
        "compute-optimizer base enrollment did not reach Active within 120s",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
