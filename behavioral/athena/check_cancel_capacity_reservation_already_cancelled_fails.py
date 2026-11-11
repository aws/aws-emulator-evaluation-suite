"""cancel-capacity-reservation-already-cancelled-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-capacity-reservation-already-cancelled-fails"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Calling CancelCapacityReservation a second time on a reservation that
    is already CANCELLED is rejected with InvalidRequestException rather
    than being treated as an idempotent no-op success."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-behav-cr-")
    athena.create_capacity_reservation(
        Name=name, TargetDpus=4, Tags=[{"Key": "sim2real:managed", "Value": "true"}]
    )
    ctx.on_cleanup(lambda: _best_effort_delete(athena, name))

    # A freshly created reservation starts out PENDING while DPUs are being
    # allocated; CancelCapacityReservation rejects a reservation that is
    # still PENDING ("Reservation cannot be modified when state is
    # PENDING"). Wait for the reservation to reach ACTIVE before exercising
    # the cancel behavior under test.
    status = _poll_until_status(athena, name, {"ACTIVE"}, timeout_s=600, interval_s=15)
    assert status == "ACTIVE", (
        f"capacity reservation did not reach ACTIVE before cancel, last status {status}"
    )

    # Positive control: the first cancel succeeds and settles the reservation
    # to CANCELLED.
    athena.cancel_capacity_reservation(Name=name)
    status_after_first = _poll_until_status(athena, name, {"CANCELLED"}, timeout_s=120, interval_s=5)
    assert status_after_first == "CANCELLED", (
        f"expected CANCELLED after first cancel settled, got {status_after_first}"
    )

    # Negative: a second cancel on an already-cancelled reservation is
    # rejected, not a silent success.
    code, message = _error(lambda: athena.cancel_capacity_reservation(Name=name))
    assert code == "InvalidRequestException", (
        f"CancelCapacityReservation on already-cancelled reservation: expected "
        f"InvalidRequestException, got {code}"
    )
    assert message == "Reservation cannot be modified when state is CANCELLED", repr(message)

    # The rejected call must not have mutated the reservation: an
    # independent read (GetCapacityReservation, not the cancel call itself)
    # still shows CANCELLED.
    status_after_second = athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]
    assert status_after_second == "CANCELLED", (
        f"rejected cancel must not change state; expected CANCELLED, got {status_after_second}"
    )


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because accepting input AWS refuses must not read as a mere error mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection but call succeeded and returned {result!r}")


def _best_effort_delete(athena, name):
    """Cancel (once ACTIVE) and delete (once CANCELLED) the reservation; only an unknown name is gone."""
    cancelled = False
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            status = athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]
            if status == "CANCELLED":
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
    raise TimeoutError(f"capacity reservation {name} not deleted within 60s (last status {status})")


def _poll_until_status(athena, name, target_statuses, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            status = athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]
        except ClientError:
            return None
        if status in target_statuses:
            return status
        time.sleep(interval_s)
    return status


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
