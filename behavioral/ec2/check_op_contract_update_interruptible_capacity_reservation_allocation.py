"""op-contract-update-interruptible-capacity-reservation-allocation."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-update-interruptible-capacity-reservation-allocation"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateInterruptibleCapacityReservationAllocation: DryRun on an active allocation returns
    DryRunOperation and leaves TargetInstanceCount unchanged, the same call without DryRun shrinks
    it, and a non-existent reservation is rejected with InvalidCapacityReservationId.NotFound."""
    ec2 = ctx.client("ec2")

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    source_id = ec2.create_capacity_reservation(
        InstanceType="t3.micro",
        InstancePlatform="Linux/UNIX",
        AvailabilityZone=az,
        InstanceCount=2,
        EndDateType="unlimited",
        TagSpecifications=[
            {
                "ResourceType": "capacity-reservation",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-icra-uc-")}],
            }
        ],
    )["CapacityReservation"]["CapacityReservationId"]
    ctx.on_cleanup(lambda: _release_reservation(ec2, source_id, timeout_s=50))

    _poll_until(
        lambda: _reservation(ec2, source_id)["State"],
        lambda s: s == "active",
        timeout_s=60,
        interval_s=3,
    )

    created = ec2.create_interruptible_capacity_reservation_allocation(
        CapacityReservationId=source_id, InstanceCount=2
    )
    assert created["TargetInstanceCount"] == 2, f"unexpected TargetInstanceCount: {created!r}"

    _poll_until(
        lambda: _allocation(ec2, source_id)["Status"],
        lambda s: s == "active",
        timeout_s=90,
        interval_s=3,
    )

    # --- DryRun boundary: permission check ahead of mutation, no effect on the real target ---
    dry_run_code, dry_run_message = _error(
        lambda: ec2.update_interruptible_capacity_reservation_allocation(
            CapacityReservationId=source_id,
            TargetInstanceCount=1,
            DryRun=True,
        )
    )
    assert (dry_run_code, dry_run_message) == ("DryRunOperation", _DRY_RUN_MESSAGE), (
        f"expected DryRunOperation {_DRY_RUN_MESSAGE!r}, got {dry_run_code!r} {dry_run_message!r}"
    )
    unchanged = _allocation(ec2, source_id)["TargetInstanceCount"]
    assert unchanged == 2, f"DryRun must not change TargetInstanceCount, got {unchanged}"

    # --- Real success path: the identical call without DryRun actually shrinks it ---
    updated = ec2.update_interruptible_capacity_reservation_allocation(
        CapacityReservationId=source_id, TargetInstanceCount=1
    )
    assert updated["TargetInstanceCount"] == 1, f"unexpected TargetInstanceCount: {updated!r}"

    confirmed = _poll_until(
        lambda: _allocation(ec2, source_id)["TargetInstanceCount"],
        lambda t: t == 1,
        timeout_s=90,
        interval_s=3,
    )
    assert confirmed == 1, f"independent read did not observe the shrink: {confirmed}"

    # --- NotFound boundary: a nonexistent target reservation is rejected distinctly ---
    nonexistent_reservation_id = "cr-00000000000000000"
    not_found_code, not_found_message = _error(
        lambda: ec2.update_interruptible_capacity_reservation_allocation(
            CapacityReservationId=nonexistent_reservation_id,
            TargetInstanceCount=1,
        )
    )
    expected = (
        "InvalidCapacityReservationId.NotFound",
        f"The capacity-reservation ID '{nonexistent_reservation_id}' does not exist",
    )
    assert (not_found_code, not_found_message) == expected, (
        f"expected {expected!r}, got {(not_found_code, not_found_message)!r}"
    )

    # The source reservation cannot be cancelled while an interruptible allocation is
    # active; reclaim it and cancel here, inside the check's own budget, so teardown
    # only has to tolerate the already-cancelled reservation.
    _release_reservation(ec2, source_id, timeout_s=240)


# ===== helpers =====

def _reservation(ec2, reservation_id: str) -> dict:
    return ec2.describe_capacity_reservations(CapacityReservationIds=[reservation_id])[
        "CapacityReservations"
    ][0]


def _allocation(ec2, reservation_id: str) -> dict:
    alloc = _reservation(ec2, reservation_id).get("InterruptibleCapacityAllocation")
    assert alloc, f"no InterruptibleCapacityAllocation on reservation {reservation_id}"
    return alloc


def _error(fn: Callable[[], Any]):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to raise a ClientError, but it succeeded")


def _release_reservation(ec2, reservation_id: str, *, timeout_s: float) -> None:
    """Reclaim any interruptible allocation (TargetInstanceCount=0), then cancel the source
    reservation. Both steps are retried: the reclaim is refused while a previous update is
    still in progress, and the cancel is refused (Unsupported) until the reclaim completes."""
    from botocore.exceptions import ClientError

    done = ("IncorrectState", "InvalidCapacityReservationId.NotFound")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            alloc = _reservation(ec2, reservation_id).get("InterruptibleCapacityAllocation") or {}
        except ClientError as exc:
            if exc.response["Error"]["Code"] in done:
                return
            raise
        if alloc and alloc.get("TargetInstanceCount") != 0:
            try:
                ec2.update_interruptible_capacity_reservation_allocation(
                    CapacityReservationId=reservation_id, TargetInstanceCount=0
                )
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "InvalidCapacityReservationId.NotFound":
                    return
                if time.monotonic() >= deadline:
                    raise
                time.sleep(2)
                continue
        try:
            ec2.cancel_capacity_reservation(CapacityReservationId=reservation_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in done:
                return
            if code != "Unsupported" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(
    probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
