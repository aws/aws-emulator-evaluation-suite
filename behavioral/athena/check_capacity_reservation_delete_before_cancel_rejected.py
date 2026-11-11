"""capacity-reservation-delete-before-cancel-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "capacity-reservation-delete-before-cancel-rejected"
GROUP = "state-machine"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCapacityReservation is rejected while the reservation is not CANCELLED, the
    reservation is left intact, and delete succeeds once Cancel has completed (positive
    control)."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-cr-del-")

    athena.create_capacity_reservation(
        Name=name,
        TargetDpus=4,
        Tags=[{"Key": "sim2real", "Value": "capacity-reservation-delete-before-cancel-rejected"}],
    )
    ctx.on_cleanup(lambda: _safe_teardown(athena, name))

    before = athena.get_capacity_reservation(Name=name)["CapacityReservation"]
    assert before["Status"] in ("PENDING", "ACTIVE"), (
        f"expected freshly created reservation to be PENDING or ACTIVE, got {before['Status']!r}"
    )

    # The refusal names the state it met, so hold the reservation at its resting ACTIVE state
    # before the forbidden delete; CancelCapacityReservation also needs ACTIVE further down.
    _poll_until(
        lambda: athena.get_capacity_reservation(Name=name)["CapacityReservation"],
        lambda cr: cr["Status"] == "ACTIVE",
        timeout_s=300.0,
        interval_s=10.0,
    )

    # Negative: delete while not CANCELLED must be rejected.
    code, message = _error(lambda: athena.delete_capacity_reservation(Name=name))
    assert code == "InvalidRequestException", (
        f"DeleteCapacityReservation before Cancel: expected InvalidRequestException, got {code!r}"
    )
    assert message == (
        "Reservation state is ACTIVE. Reservation can only be deleted when state is CANCELLED"
    ), repr(message)

    # Effect absent: the reservation must still exist, untouched.
    still_there = athena.get_capacity_reservation(Name=name)["CapacityReservation"]
    assert still_there["Name"] == name, (
        f"rejected delete must leave the reservation in place, got name={still_there['Name']!r}"
    )
    assert still_there["TargetDpus"] == 4, (
        f"rejected delete must not alter TargetDpus, got {still_there['TargetDpus']!r}"
    )
    names_after = {cr["Name"] for cr in athena.list_capacity_reservations()["CapacityReservations"]}
    assert name in names_after, (
        f"rejected delete must leave {name!r} visible in ListCapacityReservations"
    )

    # Positive control: cancel then delete succeeds.
    athena.cancel_capacity_reservation(Name=name)
    _poll_until(
        lambda: athena.get_capacity_reservation(Name=name)["CapacityReservation"],
        lambda cr: cr["Status"] == "CANCELLED",
        timeout_s=240.0,
        interval_s=5.0,
    )
    athena.delete_capacity_reservation(Name=name)
    final_code, final_message = _error(lambda: athena.get_capacity_reservation(Name=name))
    assert final_code == "InvalidRequestException", (
        f"GetCapacityReservation after a CANCELLED reservation is deleted: "
        f"expected InvalidRequestException, got {final_code!r}"
    )
    assert final_message == f"Reservation with name {name} not found.", repr(final_message)


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    timeout_s: float = 300.0,
    interval_s: float = 10.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because accepting input AWS refuses must not read as a mere error mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_teardown(athena: Any, name: str) -> None:
    from botocore.exceptions import ClientError

    # Cancel once the reservation is ACTIVE (PENDING refuses Cancel), delete it once CANCELLED;
    # only an unknown name ("... not found.") counts as already gone.
    cancelled = False
    deadline = time.monotonic() + 180.0
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
        time.sleep(2.0)
    raise TimeoutError(f"capacity reservation {name} not deleted within 180s (last status {status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
