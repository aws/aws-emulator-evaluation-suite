"""capacity-reservation-lifecycle-create-get-update-cancel-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "capacity-reservation-lifecycle-create-get-update-cancel-delete"
GROUP = "state-machine"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A capacity reservation walks PENDING->ACTIVE->UPDATE_PENDING->ACTIVE->CANCELLING->
    CANCELLED, is only deletable once CANCELLED, ListCapacityReservations reflects every
    transition, and once deleted the name is refused by both a read and a mutation."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-athena-capres-")
    _try_create_capacity_reservation(ctx, name, 4)

    initial = athena.get_capacity_reservation(Name=name)["CapacityReservation"]
    assert initial["Status"] in ("PENDING", "ACTIVE"), initial["Status"]
    assert initial["TargetDpus"] == 4

    active = _poll_reservation_status(ctx, name, {"ACTIVE", "FAILED"}, timeout_s=600)
    assert active["Status"] == "ACTIVE", f"reservation never became ACTIVE, ended at {active['Status']!r}"
    assert active["AllocatedDpus"] >= 4, active["AllocatedDpus"]
    active_names = {r["Name"]: r for r in _list_all_reservations(ctx)}
    assert name in active_names
    assert active_names[name]["Status"] == "ACTIVE"
    assert active_names[name]["TargetDpus"] == 4

    # Not deletable while ACTIVE (must be CANCELLED first).
    code, message = _error(lambda: athena.delete_capacity_reservation(Name=name))
    assert code == "InvalidRequestException", code
    assert message == (
        "Reservation state is ACTIVE. Reservation can only be deleted when state is CANCELLED"
    ), message
    # The forbidden delete did not happen: the reservation is still readable.
    assert athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"] == "ACTIVE"

    athena.update_capacity_reservation(Name=name, TargetDpus=8)
    updated = _poll_reservation_status(ctx, name, {"ACTIVE", "FAILED"}, timeout_s=600)
    assert updated["Status"] == "ACTIVE", f"reservation update never settled, ended at {updated['Status']!r}"
    assert updated["TargetDpus"] == 8
    assert updated["AllocatedDpus"] >= 8, updated["AllocatedDpus"]
    listed = {r["Name"]: r for r in _list_all_reservations(ctx)}
    assert listed[name]["TargetDpus"] == 8

    athena.cancel_capacity_reservation(Name=name)
    cancelled = _poll_reservation_status(ctx, name, {"CANCELLED", "FAILED"}, timeout_s=300)
    assert cancelled["Status"] == "CANCELLED", f"reservation never CANCELLED, ended at {cancelled['Status']!r}"

    athena.delete_capacity_reservation(Name=name)
    code, message = _error(lambda: athena.get_capacity_reservation(Name=name))
    assert code == "InvalidRequestException", code
    assert message == f"Reservation with name {name} not found.", message
    remaining_names = {r["Name"] for r in _list_all_reservations(ctx)}
    assert name not in remaining_names
    # The dead name also refuses a mutation, not just a read.
    code, message = _error(lambda: athena.update_capacity_reservation(Name=name, TargetDpus=8))
    assert code == "InvalidRequestException", code
    assert message == f"Reservation with name {name} not found.", message


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because turning
    acceptance into a falsy sentinel would hide an over-permissive target behind a plain
    code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _try_create_capacity_reservation(ctx, name, target_dpus):
    athena = ctx.client("athena")
    athena.create_capacity_reservation(
        Name=name, TargetDpus=target_dpus, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _cleanup_capacity_reservation(ctx, name))


def _cleanup_capacity_reservation(ctx, name):
    athena = ctx.client("athena")
    try:
        status = athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]
    except ClientError as exc:
        # The body deletes the reservation itself; "Reservation with name ... not found." is gone.
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
    reservation = None
    while time.monotonic() < deadline:
        reservation = athena.get_capacity_reservation(Name=name)["CapacityReservation"]
        if reservation["Status"] in target_states:
            return reservation
        time.sleep(interval_s)
    last_status = reservation["Status"] if reservation else None
    raise AssertionError(
        f"reservation {name} did not reach {target_states} within {timeout_s}s; last status {last_status!r}"
    )


def _list_all_reservations(ctx):
    athena = ctx.client("athena")
    out = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = athena.list_capacity_reservations(**kwargs)
        out.extend(resp.get("CapacityReservations", []))
        token = resp.get("NextToken")
        if not token:
            return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
