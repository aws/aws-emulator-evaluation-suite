"""concurrent-modify-instance-capacity-reservation-attributes-race."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-modify-instance-capacity-reservation-attributes-race"
GROUP = "concurrency"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two simultaneous ModifyInstanceCapacityReservationAttributes on one stopped instance, each to a different
    reservation, bind it to exactly one; once started, the winner shows 0 available instances and the loser 1.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-crattrsrace-")
    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}]
    )["AvailabilityZones"][0]["ZoneName"]

    ami_id = _latest_al2023_ami(ctx)
    instance_id = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        Placement={"AvailabilityZone": az},
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}],
        SubnetId=_network_subnet_in(ctx, az),
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _safe_terminate(ec2, instance_id))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 200})
    ec2.stop_instances(InstanceIds=[instance_id])
    ec2.get_waiter("instance_stopped").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 200})

    cr_a = ec2.create_capacity_reservation(
        InstanceType="t3.micro",
        InstancePlatform="Linux/UNIX",
        AvailabilityZone=az,
        InstanceCount=1,
        InstanceMatchCriteria="targeted",
        TagSpecifications=_tag_spec("capacity-reservation", name + "-a"),
    )["CapacityReservation"]["CapacityReservationId"]
    ctx.on_cleanup(lambda: _cancel_cr(ec2, cr_a))
    cr_b = ec2.create_capacity_reservation(
        InstanceType="t3.micro",
        InstancePlatform="Linux/UNIX",
        AvailabilityZone=az,
        InstanceCount=1,
        InstanceMatchCriteria="targeted",
        TagSpecifications=_tag_spec("capacity-reservation", name + "-b"),
    )["CapacityReservation"]["CapacityReservationId"]
    ctx.on_cleanup(lambda: _cancel_cr(ec2, cr_b))

    _poll_until(lambda: _cr_state(ec2, cr_a), lambda s: s == "active", timeout_s=60, interval_s=3)
    _poll_until(lambda: _cr_state(ec2, cr_b), lambda s: s == "active", timeout_s=60, interval_s=3)

    barrier = threading.Barrier(2)

    def _target(cr_id: str):
        barrier.wait(timeout=30)
        return _call_retrying_incorrect_state(
            lambda: ec2.modify_instance_capacity_reservation_attributes(
                InstanceId=instance_id,
                CapacityReservationSpecification={
                    "CapacityReservationTarget": {"CapacityReservationId": cr_id}
                },
            ),
            timeout_s=120.0,
            interval_s=5.0,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_target, cr_a)
        fut_b = pool.submit(_target, cr_b)
        result_a = fut_a.result()
        result_b = fut_b.result()

    def _current_target():
        spec = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0].get(
            "CapacityReservationSpecification", {}
        )
        return spec.get("CapacityReservationTarget", {}).get("CapacityReservationId")

    final_target = _poll_until(
        _current_target, lambda t: t in (cr_a, cr_b), timeout_s=60, interval_s=3
    )
    assert final_target in (cr_a, cr_b), (
        f"instance not bound to exactly one target reservation after the race, results were "
        f"a={result_a!r} b={result_b!r}, observed target={final_target!r}"
    )

    ec2.start_instances(InstanceIds=[instance_id])
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 200})

    other_target = cr_b if final_target == cr_a else cr_a
    reservations = _poll_until(
        lambda: ec2.describe_capacity_reservations(CapacityReservationIds=[cr_a, cr_b])["CapacityReservations"],
        lambda rs: {c["CapacityReservationId"]: c["AvailableInstanceCount"] for c in rs}.get(final_target) == 0,
        timeout_s=60,
        interval_s=3,
    )
    by_id = {c["CapacityReservationId"]: c for c in reservations}
    assert by_id[final_target]["AvailableInstanceCount"] == 0, (
        "winning Capacity Reservation's AvailableInstanceCount does not reflect the bound instance"
    )
    assert by_id[other_target]["AvailableInstanceCount"] == 1, (
        "losing Capacity Reservation's capacity was unexpectedly consumed"
    )


def _tag_spec(resource_type: str, name: str) -> list[dict[str, Any]]:
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
        }
    ]


def _latest_al2023_ami(ctx):
    ssm = ctx.client("ssm")
    param_name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    return ssm.get_parameter(Name=param_name)["Parameter"]["Value"]


def _call_retrying_incorrect_state(fn: Callable[[], Any], *, timeout_s: float, interval_s: float):
    """Call fn(), retrying while AWS transiently reports IncorrectInstanceState.

    A just-stopped instance can still trail its capacity-reservation subsystem, during which an
    otherwise-valid CapacityReservationTarget assignment spuriously reports the instance as being in
    an incorrect state. Returns ("ok", response) or ("error", code); any error other than a
    still-transient IncorrectInstanceState is returned immediately so callers can assert on it
    directly.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ("ok", fn())
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "IncorrectInstanceState" or time.monotonic() >= deadline:
                return ("error", code)
            time.sleep(interval_s)


def _cr_state(ec2, cr_id: str):
    return ec2.describe_capacity_reservations(CapacityReservationIds=[cr_id])["CapacityReservations"][0]["State"]


def _cancel_cr(ec2, cr_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ec2.cancel_capacity_reservation(CapacityReservationId=cr_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidCapacityReservationId.NotFound":
            raise


def _safe_terminate(ec2, instance_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
        ec2.get_waiter("instance_terminated").wait(
            InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 200}
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
            raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed value: {last!r}")


def _network_subnet_in(ctx, zone) -> str:
    """The shared network's subnet in `zone`."""
    by_zone = ctx.network().subnets
    if zone not in by_zone:
        raise AssertionError(f"the run's shared network has no subnet in {zone}")
    return by_zone[zone]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
