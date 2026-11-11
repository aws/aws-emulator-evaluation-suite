"""capacity-reservation-timestamp-precision-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "capacity-reservation-timestamp-precision-preserved"
GROUP = "representation"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCapacityReservation's CreationTime round-trips unchanged across repeated reads."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-capres-")
    athena.create_capacity_reservation(
        Name=name,
        TargetDpus=4,
        Tags=[{"Key": "sim2real", "Value": "capacity-reservation-timestamp"}],
    )

    def _cleanup():
        # A PENDING or UPDATE_PENDING reservation refuses the cancel; wait for it to settle,
        # then cancel and wait for CANCELLED, the only state that accepts the delete.
        deadline = time.monotonic() + 600.0
        status = athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]
        while status in ("PENDING", "UPDATE_PENDING") and time.monotonic() < deadline:
            time.sleep(5.0)
            status = athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]
        if status not in ("CANCELLED", "CANCELLING"):
            athena.cancel_capacity_reservation(Name=name)
        while status != "CANCELLED" and time.monotonic() < deadline:
            time.sleep(5.0)
            status = athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]
        athena.delete_capacity_reservation(Name=name)

    ctx.on_cleanup(_cleanup)

    first = athena.get_capacity_reservation(Name=name)["CapacityReservation"]

    # Freeze detector: three reads spaced over elapsed wall-clock time must all agree with
    # the first, so a target that recomputes/refreshes the timestamp on read is caught.
    for _ in range(3):
        time.sleep(1.5)
        current = athena.get_capacity_reservation(Name=name)["CapacityReservation"]
        assert current["CreationTime"] == first["CreationTime"], (
            f"CreationTime changed across reads: {first['CreationTime']!r} != {current['CreationTime']!r}"
        )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
