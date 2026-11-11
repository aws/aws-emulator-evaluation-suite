"""capacity-reservation-update-while-pending-conflicts."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "capacity-reservation-update-while-pending-conflicts"
GROUP = "concurrency"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second UpdateCapacityReservation during the first one's UPDATE_PENDING window is rejected
    with InvalidRequestException naming the state, and the last accepted update's TargetDpus lands."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-athena-capres-")
    _try_create_capacity_reservation(ctx, name, 4)

    status = _poll_reservation_status(ctx, name, {"ACTIVE", "FAILED"}, timeout_s=600)
    assert status == "ACTIVE", f"reservation never became ACTIVE, ended at {status!r}"

    athena.update_capacity_reservation(Name=name, TargetDpus=8)
    # The state read right before the second call decides its expected outcome: UPDATE_PENDING
    # must refuse it, a reservation that already applied the first update accepts it.
    pending = athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]
    assert pending in ("UPDATE_PENDING", "ACTIVE"), (
        f"an accepted update must leave the reservation UPDATE_PENDING or ACTIVE, read {pending!r}")
    if pending == "UPDATE_PENDING":
        try:
            athena.update_capacity_reservation(Name=name, TargetDpus=12)
        except ClientError as exc:
            code, message = exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        else:
            raise AssertionError(
                "a second update while the reservation reads UPDATE_PENDING must be rejected, "
                "but it SUCCEEDED")
        assert code == "InvalidRequestException", code
        assert message == "Reservation cannot be modified when state is UPDATE_PENDING", message
        winner = 8
    else:
        athena.update_capacity_reservation(Name=name, TargetDpus=12)
        winner = 12
    final_status = _poll_reservation_status(ctx, name, {"ACTIVE", "FAILED"}, timeout_s=600)
    assert final_status == "ACTIVE", f"reservation update never settled, ended at {final_status!r}"
    final = athena.get_capacity_reservation(Name=name)["CapacityReservation"]
    assert final["TargetDpus"] == winner, (
        f"final TargetDpus {final['TargetDpus']} does not match the last accepted update {winner}"
    )


def _try_create_capacity_reservation(ctx, name, target_dpus):
    athena = ctx.client("athena")
    athena.create_capacity_reservation(
        Name=name,
        TargetDpus=target_dpus,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _cleanup_capacity_reservation(ctx, name))


def _cleanup_capacity_reservation(ctx, name):
    athena = ctx.client("athena")
    try:
        status = athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]
    except ClientError as exc:
        # Only an unknown name ("Reservation with name ... not found.") means nothing is left.
        if "not found" in exc.response["Error"].get("Message", ""):
            return
        raise
    deadline = time.monotonic() + 600
    # A PENDING or UPDATE_PENDING reservation refuses the cancel; wait for it to settle.
    while status in ("PENDING", "UPDATE_PENDING") and time.monotonic() < deadline:
        time.sleep(2)
        status = athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]
    if status not in ("CANCELLED", "CANCELLING"):
        athena.cancel_capacity_reservation(Name=name)
    while time.monotonic() < deadline:
        try:
            status = athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]
        except ClientError as exc:
            if "not found" in exc.response["Error"].get("Message", ""):
                return
            raise
        if status == "CANCELLED":
            break
        time.sleep(2)
    athena.delete_capacity_reservation(Name=name)


def _poll_reservation_status(ctx, name, target_states, timeout_s, interval_s=8.0):
    athena = ctx.client("athena")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]
        if status in target_states:
            return status
        time.sleep(interval_s)
    raise AssertionError(
        f"reservation {name!r} did not reach any of {target_states} within {timeout_s}s "
        f"(last status: {status!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
