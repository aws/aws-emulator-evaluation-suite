"""capacity-reservation-negative-dpu-target-rejected."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "capacity-reservation-negative-dpu-target-rejected"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Create/UpdateCapacityReservation reject a zero or negative TargetDpus with
    InvalidRequestException and the service's validation message, changing nothing."""
    athena = ctx.client("athena")
    # botocore enforces the modeled TargetDpus minimum (4) client-side; without this client
    # the broken calls never reach the service.
    unvalidated = ctx.client("athena", config=Config(parameter_validation=False))

    bogus_name = ctx.unique_name("sim2real-athena-capres-neg-")
    _assert_rejected_unallocatable(
        lambda: unvalidated.create_capacity_reservation(Name=bogus_name, TargetDpus=0)
    )
    names = {r["Name"] for r in athena.list_capacity_reservations()["CapacityReservations"]}
    assert bogus_name not in names, "a rejected create must not have left a reservation behind"

    live_name = ctx.unique_name("sim2real-athena-capres-neg-live-")
    athena.create_capacity_reservation(
        Name=live_name, TargetDpus=4, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _safe_cancel_and_delete(athena, live_name))

    # Wait for ACTIVE: a PENDING-state rejection would be indistinguishable from the
    # negative-TargetDpus rejection.
    _poll_until(
        lambda: athena.get_capacity_reservation(Name=live_name)["CapacityReservation"]["Status"],
        lambda s: s == "ACTIVE",
        timeout_s=600.0,
        interval_s=10.0,
        description=f"{live_name} to reach ACTIVE before probing the update rejection",
    )

    _assert_rejected_unallocatable(
        lambda: unvalidated.update_capacity_reservation(Name=live_name, TargetDpus=-5)
    )
    unchanged = athena.get_capacity_reservation(Name=live_name)["CapacityReservation"]
    assert unchanged["TargetDpus"] == 4, (
        f"a rejected update must not change TargetDpus, got {unchanged['TargetDpus']}"
    )

    # Positive control: a valid positive TargetDpus update on the same reservation succeeds.
    athena.update_capacity_reservation(Name=live_name, TargetDpus=8)
    updated = _poll_until(
        lambda: athena.get_capacity_reservation(Name=live_name)["CapacityReservation"],
        lambda r: r["TargetDpus"] == 8,
        timeout_s=60.0,
        interval_s=5.0,
        description=f"{live_name} TargetDpus to converge to 8 after the valid update",
    )
    assert updated["TargetDpus"] == 8, f"expected the valid update to persist, got {updated['TargetDpus']}"


def _assert_rejected_unallocatable(fn):
    try:
        fn()
    except ClientError as exc:
        code, message = exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        assert code == "InvalidRequestException", (
            f"expected InvalidRequestException for an unallocatable TargetDpus, got {code}"
        )
        assert message == (
            "1 validation error detected: Value at 'targetDpus' failed to satisfy constraint: "
            "Member must have value greater than or equal to 1"
        ), repr(message)
        return
    raise AssertionError("expected an unallocatable TargetDpus to be rejected, but the call succeeded")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} (last value: {last!r})")


def _safe_cancel_and_delete(athena, name: str) -> None:
    def _status():
        return athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]

    try:
        _status()
    except ClientError as exc:
        # Only an unknown name ("Reservation with name ... not found.") means nothing is left.
        if "not found" in exc.response["Error"].get("Message", ""):
            return
        raise
    # A PENDING or UPDATE_PENDING reservation refuses the cancel; wait for it to settle, then
    # cancel, wait for CANCELLED (the only state that accepts a delete) and delete.
    status = _poll_until(
        _status, lambda s: s not in ("PENDING", "UPDATE_PENDING"), timeout_s=600.0, interval_s=5.0,
        description=f"cleanup settle of {name}",
    )
    if status not in ("CANCELLING", "CANCELLED"):
        athena.cancel_capacity_reservation(Name=name)
    _poll_until(_status, lambda s: s == "CANCELLED", timeout_s=600.0, interval_s=5.0,
                description=f"cleanup cancel of {name}")
    athena.delete_capacity_reservation(Name=name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
