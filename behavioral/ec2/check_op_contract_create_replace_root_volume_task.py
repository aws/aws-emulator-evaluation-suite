"""op-contract-create-replace-root-volume-task."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-create-replace-root-volume-task"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateReplaceRootVolumeTask: rejected on a not-yet-running instance; succeeds once running."""
    ec2 = ctx.client("ec2")
    ami_id = _latest_al2023_ami(ctx)
    name = ctx.unique_name("sim2real-rrv-")
    subnet_id = _create_subnet(ctx, ec2, name)

    run_resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": name}],
            }
        ],
    )
    instance_id = run_resp["Instances"][0]["InstanceId"]

    def _terminate():
        ec2.terminate_instances(InstanceIds=[instance_id])
        ec2.get_waiter("instance_terminated").wait(
            InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )

    ctx.on_cleanup(_terminate)

    # Error boundary: the instance is freshly launched (pending), not yet running/stopped.
    # DescribeInstances can lag behind RunInstances (eventual consistency), so tolerate a
    # transient InvalidInstanceID.NotFound right after creation instead of failing outright.
    state = _describe_instance_state(ec2, instance_id)
    if state == "pending":
        code, message = _error(lambda: ec2.create_replace_root_volume_task(InstanceId=instance_id))
        assert code == "IncorrectInstanceState", f"expected IncorrectInstanceState, got {code!r}"
        assert message == "Instance is not in the running state.", f"unexpected IncorrectInstanceState message: {message!r}"

        tasks_after_rejection = ec2.describe_replace_root_volume_tasks(
            Filters=[{"Name": "instance-id", "Values": [instance_id]}]
        )["ReplaceRootVolumeTasks"]
        assert not tasks_after_rejection, (
            f"expected no replace-root-volume task after rejected call, "
            f"got {tasks_after_rejection!r}"
        )

    waiter = ec2.get_waiter("instance_running")
    waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 100})

    # Success path: instance is now running.
    resp = ec2.create_replace_root_volume_task(InstanceId=instance_id)
    task = resp["ReplaceRootVolumeTask"]
    task_id = task["ReplaceRootVolumeTaskId"]
    assert task["InstanceId"] == instance_id, (
        f"expected task InstanceId {instance_id!r}, got {task['InstanceId']!r}"
    )
    assert task["TaskState"] in ("pending", "in-progress", "succeeded"), (
        f"unexpected initial TaskState {task['TaskState']!r}"
    )

    final_state = _poll_until(
        lambda: ec2.describe_replace_root_volume_tasks(ReplaceRootVolumeTaskIds=[task_id])[
            "ReplaceRootVolumeTasks"
        ][0]["TaskState"],
        lambda s: s in ("succeeded", "failed", "failed-detached"),
        timeout_s=240.0,
        interval_s=5.0,
    )
    assert final_state == "succeeded", f"replace-root-volume task ended in {final_state!r}"


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. A success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _create_subnet(ctx, ec2, name):
    """A dedicated VPC and subnet for the instance, removed after it terminates."""
    tags = lambda rt: [{"ResourceType": rt, "Tags": [{"Key": "Name", "Value": name}]}]  # noqa: E731
    vpc_id = ec2.create_vpc(CidrBlock="10.205.0.0/16", TagSpecifications=tags("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.205.1.0/24", AvailabilityZone=az, TagSpecifications=tags("subnet")
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    return subnet_id


def _retry_delete(fn, *, timeout_s=180.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for predicate; last value={last!r}")


def _describe_instance_state(ec2, instance_id, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0][
                "Instances"
            ][0]["State"]["Name"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidInstanceID.NotFound" and (
                time.monotonic() < deadline
            ):
                time.sleep(interval_s)
                continue
            raise


def _latest_al2023_ami(ctx):
    ec2 = ctx.client("ec2")
    resp = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-2023*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )
    images = resp.get("Images", [])
    if not images:

        raise AssertionError("no al2023 AMI available in this region/account")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
