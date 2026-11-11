"""cancel-capacity-reservation-not-active-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-capacity-reservation-not-active-fails"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelCapacityReservation on a reservation that is already CANCELLED fails
    with InvalidRequestException instead of succeeding idempotently."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-behav-capres-")
    athena.create_capacity_reservation(
        Name=name, TargetDpus=4, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )

    def _status():
        return athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]

    def _cleanup():
        # Cancel once ACTIVE (PENDING refuses Cancel), delete once CANCELLED;
        # only an unknown name ("Reservation with name ... not found.") means nothing is left.
        cancelled = False
        status = None
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            try:
                status = _status()
                if status in ("CANCELLED", "FAILED"):
                    athena.delete_capacity_reservation(Name=name)
                    return
                if status == "ACTIVE" and not cancelled:
                    athena.cancel_capacity_reservation(Name=name)
                    cancelled = True
            except ClientError as exc:
                if "not found" in exc.response["Error"].get("Message", ""):
                    return
                raise
            time.sleep(2)
        raise TimeoutError(f"capacity reservation {name} not deleted within 300s (last status {status})")

    ctx.on_cleanup(_cleanup)

    # CancelCapacityReservation is itself rejected while the reservation is still
    # PENDING ("Reservation cannot be modified when state is PENDING"); it only
    # accepts a cancel once provisioning has reached ACTIVE. Wait for that first.
    _poll_until(lambda: _status(), lambda s: s == "ACTIVE", timeout_s=180, interval_s=5)

    # Positive control: the first cancel on a live (ACTIVE) reservation
    # must succeed and drive it to CANCELLED.
    athena.cancel_capacity_reservation(Name=name)
    status = _poll_until(lambda: _status(), lambda s: s == "CANCELLED", timeout_s=180, interval_s=5)
    assert status == "CANCELLED", f"expected CANCELLED after positive-control cancel, got {status}"

    # Negative: cancelling an already-CANCELLED reservation must be rejected,
    # not treated as an idempotent no-op success.
    code, message = _error(lambda: athena.cancel_capacity_reservation(Name=name))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == "Reservation cannot be modified when state is CANCELLED", repr(message)

    # the rejected call did not mutate the reservation's state
    status_after_reject = _status()
    assert status_after_reject == "CANCELLED", (
        f"expected status to remain CANCELLED after the rejected cancel, got {status_after_reject}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because accepting input AWS refuses must not read as a mere error mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
