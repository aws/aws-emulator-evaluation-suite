"""detach-volume-not-attached-state-conflict-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "detach-volume-not-attached-state-conflict-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DetachVolume on an existing, never-attached volume fails with IncorrectState and leaves it
    'available', while the same call on an attached volume succeeds as a positive control."""
    ec2 = ctx.client("ec2")

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    vol_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=_tag_spec(ctx, "volume", ctx.unique_name("sim2real-navol-")),
    )["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=vol_id))

    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[vol_id])["Volumes"][0]["State"],
        lambda s: s == "available",
        timeout_s=60.0,
    )

    code, message = _error(lambda: ec2.detach_volume(VolumeId=vol_id))
    assert code == "IncorrectState", code
    assert message == f"Volume '{vol_id}' is in the 'available' state.", (
        f"unexpected IncorrectState message: {message!r}"
    )

    # the rejected detach must not have mutated the volume's state
    state = ec2.describe_volumes(VolumeIds=[vol_id])["Volumes"][0]["State"]
    assert state == "available"

    # Positive control: a *different*, currently-attached volume's DetachVolume
    # succeeds on the identical call shape. Without this, a target that rejects
    # every DetachVolume call with IncorrectState -- rather than genuinely
    # distinguishing an attached volume from one that never was -- would pass
    # the two assertions above too.
    control_az, subnet_id = sorted(ctx.network().subnets.items())[0]

    ami_id = ctx.client("ssm").get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    instance_id = _run_instance_with_retry(
        ec2,
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=_tag_spec(ctx, "instance", ctx.unique_name("sim2real-navol-inst-")),
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    control_vol_id = ec2.create_volume(
        AvailabilityZone=control_az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=_tag_spec(ctx, "volume", ctx.unique_name("sim2real-navol-ctrl-")),
    )["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=control_vol_id))
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[control_vol_id])["Volumes"][0]["State"],
        lambda s: s == "available",
        timeout_s=60.0,
    )

    ec2.attach_volume(Device="/dev/sdf", InstanceId=instance_id, VolumeId=control_vol_id)
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[control_vol_id])["Volumes"][0]["Attachments"],
        lambda atts: bool(atts) and atts[0]["State"] == "attached",
        timeout_s=60.0,
    )

    ec2.detach_volume(VolumeId=control_vol_id)
    control_state = _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[control_vol_id])["Volumes"][0],
        lambda v: v["State"] == "available" and v["Attachments"] == [],
        timeout_s=60.0,
    )
    assert control_state["State"] == "available"
    assert control_state["Attachments"] == []


def _tag_spec(ctx, resource_type: str, name: str):
    return [
        {
            "ResourceType": resource_type,
            "Tags": [
                {"Key": "Name", "Value": name},
                {"Key": "sim2real", "Value": "true"},
                {"Key": "sim2real-created", "Value": str(int(time.time()))},
            ],
        }
    ]


def _run_instance_with_retry(ec2, attempts=5, interval_s=3.0, **kwargs):
    """run_instances, tolerating the brief window where a just-created subnet has not
    yet propagated to every EC2 API code path (InvalidSubnetID.NotFound)."""
    last_exc = None
    for _ in range(attempts):
        try:
            return ec2.run_instances(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidSubnetID.NotFound":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _terminate_and_wait(ec2, instance_id):
    ec2.terminate_instances(InstanceIds=[instance_id])
    ec2.get_waiter("instance_terminated").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn):
    """Call fn() and return the (code, message) of its ClientError; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
