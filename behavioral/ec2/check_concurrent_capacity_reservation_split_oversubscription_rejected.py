"""concurrent-capacity-reservation-split-oversubscription-rejected."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "concurrent-capacity-reservation-split-oversubscription-rejected"
GROUP = "concurrency"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two simultaneous splits of 3 instances from a 4-instance Capacity Reservation never both succeed: exactly
    one wins, the other fails with an error code, and the source keeps 1 and the new reservation holds 3.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-crsplitrace-")
    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    source_id = ec2.create_capacity_reservation(
        InstanceType="t3.micro",
        InstancePlatform="Linux/UNIX",
        AvailabilityZone=az,
        InstanceCount=4,
        TagSpecifications=_tag_spec("capacity-reservation", name),
    )["CapacityReservation"]["CapacityReservationId"]

    def _cleanup(cr_id: str):
        _error_code(lambda: ec2.cancel_capacity_reservation(CapacityReservationId=cr_id))

    ctx.on_cleanup(lambda: _cleanup(source_id))

    _poll_until(lambda: _cr_state(ec2, source_id), lambda s: s == "active", timeout_s=60, interval_s=3)

    barrier = threading.Barrier(2)

    def _split(tag_suffix: str):
        barrier.wait(timeout=30)
        try:
            resp = ec2.create_capacity_reservation_by_splitting(
                SourceCapacityReservationId=source_id,
                InstanceCount=3,
                TagSpecifications=_tag_spec("capacity-reservation", name + tag_suffix),
            )
            return ("ok", resp["DestinationCapacityReservation"]["CapacityReservationId"])
        except Exception as exc:
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError):
                return ("error", exc.response["Error"]["Code"])
            raise

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_split, "-a")
        fut_b = pool.submit(_split, "-b")
        result_a = fut_a.result()
        result_b = fut_b.result()

    results = [result_a, result_b]
    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    assert len(successes) == 1, f"expected exactly one split to succeed, got {results}"
    assert len(failures) == 1, f"expected exactly one split to be rejected, got {results}"
    # The loser's code varies (ConcurrentCapacityReservationAccess, UnsupportedOperation, or
    # InternalError under contention); what must hold is the capacity invariant below.
    assert failures[0][1], f"expected the losing concurrent split to fail with a non-empty error code, got {results}"

    dest_id = successes[0][1]
    ctx.on_cleanup(lambda: _cleanup(dest_id))


    final = ec2.describe_capacity_reservations(CapacityReservationIds=[source_id, dest_id])[
        "CapacityReservations"
    ]
    by_id = {c["CapacityReservationId"]: c for c in final}
    # Combined capacity is conserved -- the race never over-allocates beyond the source's total.
    assert by_id[source_id]["TotalInstanceCount"] == 1, (
        f"expected source to retain 1 instance after the winning 3-instance split, "
        f"got {by_id[source_id]['TotalInstanceCount']}"
    )
    assert by_id[dest_id]["TotalInstanceCount"] == 3, (
        f"expected the winning split's destination to hold 3 instances, "
        f"got {by_id[dest_id]['TotalInstanceCount']}"
    )
    assert by_id[source_id]["TotalInstanceCount"] + by_id[dest_id]["TotalInstanceCount"] == 4, (
        f"expected combined source+destination capacity to equal the source's original 4 instances, "
        f"got {by_id[source_id]['TotalInstanceCount'] + by_id[dest_id]['TotalInstanceCount']}"
    )


def _tag_spec(resource_type: str, name: str) -> list[dict[str, Any]]:
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
        }
    ]


def _cr_state(ec2, cr_id: str):
    return ec2.describe_capacity_reservations(CapacityReservationIds=[cr_id])["CapacityReservations"][0]["State"]


def _error_code(fn: Callable[[], Any]):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float):
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
