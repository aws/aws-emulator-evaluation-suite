"""capacity-reservation-target-dpus-numeric-precision-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "capacity-reservation-target-dpus-numeric-precision-preserved"
GROUP = "representation"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A non-round integer TargetDpus given to CreateCapacityReservation reads back unchanged from
    GetCapacityReservation, with no rounding or truncation."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2reservation").replace("-", "")
    # Non-round, small enough for default quotas, and a multiple of 4: TargetDpus must be one,
    # so any other value fails validation before the stored value can be compared.
    target_dpus = 44

    athena.create_capacity_reservation(Name=name, TargetDpus=target_dpus)

    def _cleanup() -> None:
        from botocore.exceptions import ClientError

        # Cancel once the reservation has left PENDING (PENDING refuses Cancel), delete it once
        # CANCELLED; only an unknown name ("... not found.") counts as already gone.
        cancelled = False
        status = None
        deadline = time.monotonic() + 600
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
            time.sleep(3)
        raise TimeoutError(f"capacity reservation {name} not deleted within 600s (last status {status})")

    ctx.on_cleanup(_cleanup)

    reservation = athena.get_capacity_reservation(Name=name)["CapacityReservation"]
    assert reservation["Name"] == name
    assert reservation["TargetDpus"] == target_dpus, (
        f"expected TargetDpus == {target_dpus!r}, got {reservation['TargetDpus']!r} "
        f"(type {type(reservation['TargetDpus'])})"
    )
    assert isinstance(reservation["TargetDpus"], int)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
