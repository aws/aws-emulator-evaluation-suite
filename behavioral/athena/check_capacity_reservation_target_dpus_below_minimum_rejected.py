"""capacity-reservation-target-dpus-below-minimum-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "capacity-reservation-target-dpus-below-minimum-rejected"
GROUP = "e2e"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCapacityReservation with TargetDpus below the minimum of 4 is rejected by the
    service (sent with client-side validation off), no reservation exists under that name,
    and TargetDpus=4 still creates fine (positive control)."""
    from botocore.config import Config
    from botocore.exceptions import ClientError

    athena = ctx.client("athena")
    unvalidated = ctx.client("athena", config=Config(parameter_validation=False))
    rejected_name = ctx.unique_name("sim2real-behav-capbad-")
    try:
        result = unvalidated.create_capacity_reservation(Name=rejected_name, TargetDpus=1)
    except ClientError as exc:
        code, message = exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    else:
        raise AssertionError(
            f"expected TargetDpus=1 (below the 4-DPU minimum) to be rejected, but the call "
            f"SUCCEEDED and returned {result!r}"
        )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    assert message == "Capacity must be requested in increments of 4.", repr(message)

    # effect absent: no reservation was created under the rejected name.
    names = _list_all_reservation_names(ctx)
    assert rejected_name not in names, "a reservation was created despite the invalid TargetDpus"

    # positive control: the minimum valid TargetDpus (4) succeeds.
    valid_name = ctx.unique_name("sim2real-behav-capgood-")
    athena.create_capacity_reservation(
        Name=valid_name, TargetDpus=4,
        Tags=[{"Key": "sim2real", "Value": "capacity-reservation-target-dpus-below-minimum-rejected"}],
    )
    ctx.on_cleanup(lambda: _cancel_and_delete_reservation(ctx, valid_name))
    reservation = athena.get_capacity_reservation(Name=valid_name)["CapacityReservation"]
    assert reservation["TargetDpus"] == 4, f"expected TargetDpus=4, got {reservation['TargetDpus']!r}"


def _list_all_reservation_names(ctx) -> list[str]:
    athena = ctx.client("athena")
    names: list[str] = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = athena.list_capacity_reservations(**kwargs)
        names.extend(r["Name"] for r in resp.get("CapacityReservations", []))
        token = resp.get("NextToken")
        if not token:
            break
    return names


def _cancel_and_delete_reservation(ctx, name: str) -> None:
    athena = ctx.client("athena")
    from botocore.exceptions import ClientError

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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
