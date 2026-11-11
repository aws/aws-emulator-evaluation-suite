"""athena-capacity-reservation-pending-then-cancelled-transition."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "athena-capacity-reservation-pending-then-cancelled-transition"
GROUP = "state"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCapacityReservation starts PENDING; CancelCapacityReservation drives it to CANCELLED."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-behav-athena-cr-")

    athena.create_capacity_reservation(
        Name=name, TargetDpus=4, Tags=[{"Key": "sim2real:managed", "Value": "true"}]
    )
    ctx.on_cleanup(lambda: _safe_delete(athena, name))

    reservation = athena.get_capacity_reservation(Name=name)["CapacityReservation"]
    assert reservation["Name"] == name, f"expected Name={name!r}, got {reservation['Name']!r}"
    assert reservation["TargetDpus"] == 4, f"expected TargetDpus=4, got {reservation['TargetDpus']!r}"
    assert reservation["Status"] in ("PENDING", "ACTIVE"), (
        f"expected freshly-created reservation status in (PENDING, ACTIVE), got {reservation['Status']!r}"
    )

    names = [r["Name"] for r in athena.list_capacity_reservations()["CapacityReservations"]]
    assert name in names, f"expected {name!r} in ListCapacityReservations, got {names!r}"

    # Real AWS rejects CancelCapacityReservation while the reservation is still PENDING
    # ("Reservation cannot be modified when state is PENDING"); the reservation must first
    # finish its (async) transition to ACTIVE before it can be cancelled.
    active = _poll_until(
        lambda: athena.get_capacity_reservation(Name=name)["CapacityReservation"],
        lambda r: r["Status"] == "ACTIVE",
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert active["Status"] == "ACTIVE", f"expected ACTIVE after polling, got {active['Status']!r}"

    athena.cancel_capacity_reservation(Name=name)
    final = _poll_until(
        lambda: athena.get_capacity_reservation(Name=name)["CapacityReservation"],
        lambda r: r["Status"] == "CANCELLED",
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert final["Status"] == "CANCELLED", f"expected CANCELLED after cancel, got {final['Status']!r}"


def _safe_delete(athena, name: str) -> None:
    # Cancel once ACTIVE (PENDING refuses Cancel), delete once CANCELLED;
    # only an unknown name ("Reservation with name ... not found.") means nothing is left.
    cancelled = False
    status = None
    deadline = time.monotonic() + 300
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
    raise TimeoutError(f"capacity reservation {name} not deleted within 300s (last status {status})")


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
