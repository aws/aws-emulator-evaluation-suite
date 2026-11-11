"""delete-capacity-reservation-without-cancel-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-capacity-reservation-without-cancel-fails"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCapacityReservation on a reservation that has not been cancelled is rejected with
    InvalidRequestException and leaves it intact; once CANCELLED, delete succeeds and the name
    is refused afterwards (positive control)."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-cr-")
    athena.create_capacity_reservation(
        Name=name, TargetDpus=4, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _teardown(athena, name))

    # Negative: delete before cancel is rejected, and the reservation is not removed. The
    # refusal names the reservation's current state, read just before the delete.
    state_before = athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]
    code, message = _error(lambda: athena.delete_capacity_reservation(Name=name))
    assert code == "InvalidRequestException", (
        f"DeleteCapacityReservation on non-cancelled reservation: expected "
        f"InvalidRequestException, got {code}"
    )
    assert message == (
        f"Reservation state is {state_before}. "
        "Reservation can only be deleted when state is CANCELLED"
    ), message
    still_there = athena.get_capacity_reservation(Name=name)["CapacityReservation"]
    assert still_there["Name"] == name, f"reservation removed by the rejected delete: {still_there}"
    assert still_there["Status"] != "CANCELLED", (
        f"reservation status advanced to CANCELLED despite the rejected delete: {still_there}"
    )
    assert still_there["TargetDpus"] == 4, (
        f"TargetDpus changed by the rejected delete: expected 4, got {still_there['TargetDpus']}"
    )
    names_after = {cr["Name"] for cr in athena.list_capacity_reservations()["CapacityReservations"]}
    assert name in names_after, (
        f"reservation missing from ListCapacityReservations after the rejected delete: {names_after}"
    )

    # Positive control: once genuinely CANCELLED, delete succeeds and the
    # reservation is gone. The reservation must first leave PENDING (it
    # cannot be cancelled while still PENDING: "Reservation cannot be
    # modified when state is PENDING") before it can be cancelled.
    active_status = _poll_until_status(athena, name, {"ACTIVE"}, timeout_s=600, interval_s=15)
    assert active_status == "ACTIVE", (
        f"reservation never left PENDING within 600s; last status={active_status!r}"
    )
    athena.cancel_capacity_reservation(Name=name)
    status = _poll_until_status(athena, name, {"CANCELLED"}, timeout_s=120, interval_s=5)
    assert status == "CANCELLED", (
        f"cancellation did not complete within 120s; last status={status!r}"
    )
    athena.delete_capacity_reservation(Name=name)
    code, message = _error(lambda: athena.get_capacity_reservation(Name=name))
    assert code == "InvalidRequestException", (
        f"GetCapacityReservation after delete: expected InvalidRequestException, got {code}"
    )
    assert message == f"Reservation with name {name} not found.", message
    # The deleted reservation is not merely unreadable, it is unusable: a mutation
    # issued against the dead id also fails, with the same specific error.
    cancel_after_delete, cancel_message = _error(lambda: athena.cancel_capacity_reservation(Name=name))
    assert cancel_after_delete == "InvalidRequestException", (
        f"CancelCapacityReservation on deleted reservation: expected "
        f"InvalidRequestException, got {cancel_after_delete}"
    )
    assert cancel_message == f"Reservation with name {name} not found.", cancel_message


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises,
    because turning acceptance into a code-mismatch would let an over-permissive target read
    as merely wrong rather than as accepting what real AWS refuses."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _teardown(athena, name):
    # Cancel once the reservation is ACTIVE (PENDING refuses Cancel), delete it once CANCELLED;
    # only an unknown name ("... not found.") counts as already gone.
    cancelled = False
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            status = athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]
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
    raise TimeoutError(f"capacity reservation {name} not deleted within 180s (last status {status})")


def _poll_until_status(athena, name, target_statuses, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]
        if status in target_statuses:
            return status
        time.sleep(interval_s)
    raise TimeoutError(f"status never reached {target_statuses} within {timeout_s}s; last={status!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
