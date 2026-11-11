"""capacity-reservation-target-dpus-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "capacity-reservation-target-dpus-round-trip"
GROUP = "representation"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A numeric TargetDpus value written via Create/Update comes back byte-for-byte identical
    (exact integer, no float coercion or rounding) on a subsequent Get."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-behav-capres-repr-")
    athena.create_capacity_reservation(Name=name, TargetDpus=4)
    ctx.on_cleanup(lambda: _cleanup_reservation(athena, name))

    _poll_until(
        lambda: _get_status(athena, name),
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=300,
        interval_s=10,
    )
    res = athena.get_capacity_reservation(Name=name)["CapacityReservation"]
    assert res["Status"] == "ACTIVE", f"expected Status ACTIVE, got {res['Status']!r}"
    target = res["TargetDpus"]
    assert isinstance(target, int) and not isinstance(target, bool), (
        f"expected TargetDpus to be an exact int, got {target!r} (type {type(target)})"
    )
    assert target == 4, f"expected TargetDpus 4, got {target!r}"

    # Real AWS rejects UpdateCapacityReservation unless TargetDpus is a multiple of 4
    # (InvalidRequestException: "Capacity must be requested in increments of 4").
    athena.update_capacity_reservation(Name=name, TargetDpus=12)
    _poll_until(
        lambda: _get_status(athena, name),
        lambda s: s == "ACTIVE",
        timeout_s=300,
        interval_s=10,
    )
    res = athena.get_capacity_reservation(Name=name)["CapacityReservation"]
    target = res["TargetDpus"]
    allocated = res["AllocatedDpus"]
    assert isinstance(target, int) and not isinstance(target, bool), (
        f"expected TargetDpus to be an exact int, got {target!r} (type {type(target)})"
    )
    assert target == 12, f"expected exact TargetDpus 12, got {target!r}"
    assert isinstance(allocated, int) and not isinstance(allocated, bool), (
        f"expected AllocatedDpus to be an exact int, got {allocated!r} (type {type(allocated)})"
    )
    assert allocated == 12, f"expected exact AllocatedDpus 12, got {allocated!r}"


def _get_status(athena, name: str) -> str:
    return athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _cleanup_reservation(athena, name: str) -> None:
    from botocore.exceptions import ClientError

    # Cancel once the reservation is ACTIVE (PENDING refuses Cancel), delete it once CANCELLED;
    # only an unknown name ("... not found.") counts as already gone.
    cancelled = False
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            status = _get_status(athena, name)
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
