"""op-contract-modify-instance-capacity-reservation-attributes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-modify-instance-capacity-reservation-attributes"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyInstanceCapacityReservationAttributes flips CapacityReservationPreference and rejects an unknown reservation target."""
    ec2 = ctx.client("ec2")
    instance_id = _run_instance(ctx, ec2, "t3.micro")
    ctx.on_cleanup(lambda: _terminate(ec2, instance_id))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    # AWS modifies these settings only on a stopped instance; a running one answers
    # IncorrectInstanceState for as long as it runs.
    ec2.stop_instances(InstanceIds=[instance_id])
    ec2.get_waiter("instance_stopped").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    resp, err, _ = _call_retrying_incorrect_state(
        lambda: ec2.modify_instance_capacity_reservation_attributes(
            InstanceId=instance_id,
            CapacityReservationSpecification={"CapacityReservationPreference": "none"},
        ),
        timeout_s=180.0,
        interval_s=15.0,
    )
    assert err is None, f"unexpected error setting preference to none: {err}"
    assert resp["Return"] is True

    # DescribeInstances is eventually consistent with the modify call, so read it in a bounded poll.
    spec = _poll_spec(ec2, instance_id, lambda sp: sp.get("CapacityReservationPreference") == "none")
    assert spec.get("CapacityReservationPreference") == "none", f"CapacityReservationSpecification={spec}"

    _, code, message = _call_retrying_incorrect_state(
        lambda: ec2.modify_instance_capacity_reservation_attributes(
            InstanceId=instance_id,
            CapacityReservationSpecification={
                "CapacityReservationTarget": {"CapacityReservationId": "cr-00000000000000000"}
            },
        ),
        timeout_s=180.0,
        interval_s=15.0,
    )
    assert code == "InvalidCapacityReservationId.NotFound", (
        f"expected InvalidCapacityReservationId.NotFound, got {code}"
    )
    expected_message = "The capacity-reservation ID 'cr-00000000000000000' does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    described_after_rejection = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0][
        "Instances"
    ][0]
    rejected_spec = described_after_rejection["CapacityReservationSpecification"]
    assert "CapacityReservationTarget" not in rejected_spec, (
        f"rejected CapacityReservationTarget was applied anyway: {rejected_spec}"
    )
    assert rejected_spec["CapacityReservationPreference"] == "none", (
        f"preference drifted from 'none' despite the target update being rejected: {rejected_spec}"
    )

    # Restore the default so the instance is left in its natural state. This is cleanup, not
    # part of the contract this check asserts (already exercised above), so it is best-effort
    # and bounded well short of the earlier calls' budget -- it must not itself risk blowing
    # through the check's overall wall-clock limit. The instance is stopped at this point,
    # which this call supports just as well as the CapacityReservationTarget assignment did.
    def _restore() -> None:
        _call_retrying_incorrect_state(
            lambda: ec2.modify_instance_capacity_reservation_attributes(
                InstanceId=instance_id,
                CapacityReservationSpecification={"CapacityReservationPreference": "open"},
            ),
            timeout_s=120.0,
            interval_s=15.0,
        )

    ctx.on_cleanup(_restore)


def _call_retrying_incorrect_state(fn, *, timeout_s=360.0, interval_s=15.0):
    """Call fn(), retrying while AWS transiently reports IncorrectInstanceState.

    A freshly-running instance (per the instance_running/instance_status_ok waiters) can
    still trail its capacity-reservation subsystem by a few minutes in some regions/accounts,
    during which any call touching capacity reservation attributes can spuriously report the
    instance as being in an incorrect state. Real testing against live AWS showed this lag
    clearing well within the bounds callers use below; the check's overall wall-clock budget
    does not allow retrying indefinitely (or for the ~30 minutes some worst-case reports
    describe), so each call site picks a bound tight enough to still fit comfortably inside
    that overall budget while remaining ample for the lag actually observed.

    Returns (response, error_code, error_message); both error fields are None on success, and any error other than
    a still-transient IncorrectInstanceState is returned (not raised) so callers can assert
    on it directly.
    """
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn(), None, None
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code != "IncorrectInstanceState" or time.monotonic() >= deadline:
                return None, code, e.response["Error"]["Message"]
            time.sleep(interval_s)



def _poll_spec(ec2, instance_id, predicate, timeout_s=120.0):
    """The instance's CapacityReservationSpecification once predicate holds, or the last one read."""
    import time

    deadline = time.monotonic() + timeout_s
    while True:
        spec = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0].get(
            "CapacityReservationSpecification", {}
        )
        if predicate(spec) or time.monotonic() >= deadline:
            return spec
        time.sleep(2)


def _latest_al2023_ami(ec2) -> str:
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no amazon-owned al2023 AMIs found in this region")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _run_instance(ctx, ec2, instance_type: str) -> str:
    ami_id = _latest_al2023_ami(ec2)
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType=instance_type,
        MinCount=1,
        MaxCount=1,
        SubnetId=ctx.network().subnet_ids[0],
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-i-")}],
            }
        ],
    )
    return resp["Instances"][0]["InstanceId"]


def _terminate(ec2, instance_id: str) -> None:
    ec2.terminate_instances(InstanceIds=[instance_id])
    ec2.get_waiter("instance_terminated").wait(
        InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
