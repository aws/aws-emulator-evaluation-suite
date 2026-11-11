"""op-contract-modify-instance-cpu-options."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-modify-instance-cpu-options"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyInstanceCpuOptions requires a stopped instance: rejected while running, applied once stopped."""
    ec2 = ctx.client("ec2")
    instance_id = _run_instance(ctx, ec2, "c5.large")
    ctx.on_cleanup(lambda: _terminate(ec2, instance_id))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    # Being "running" per the waiter can still trail full status-check readiness by a wide
    # margin on a freshly-launched instance, which is exactly the same lag that can cause
    # this state-conflict call to spuriously misbehave; wait for status checks too before
    # relying on the conflict being reported.
    ec2.get_waiter("instance_status_ok").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    pre_attempt_cpu_opts = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0][
        "Instances"
    ][0]["CpuOptions"]

    # Wrong-status transition: CPU options can only change on a stopped instance; AWS rejects
    # the call on a running instance with InvalidState. Issue it once: retrying can hit a
    # same-valued no-op success on a just-launched instance.
    code, msg = _error(
        lambda: ec2.modify_instance_cpu_options(InstanceId=instance_id, CoreCount=1, ThreadsPerCore=1)
    )
    assert code == "InvalidState", f"expected InvalidState, got {code}"
    expected = f"The instance '{instance_id}' is not in an allowed state: stopped"
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # The rejected call must have had no effect: CpuOptions on an independent read still
    # match what was observed before the attempt, not the requested CoreCount/ThreadsPerCore.
    post_attempt_cpu_opts = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0][
        "Instances"
    ][0]["CpuOptions"]
    assert post_attempt_cpu_opts == pre_attempt_cpu_opts, (
        f"expected CpuOptions unchanged at {pre_attempt_cpu_opts}, got {post_attempt_cpu_opts}"
    )

    ec2.stop_instances(InstanceIds=[instance_id])
    ec2.get_waiter("instance_stopped").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    resp = ec2.modify_instance_cpu_options(InstanceId=instance_id, CoreCount=1, ThreadsPerCore=1)
    assert resp["CoreCount"] == 1 and resp["ThreadsPerCore"] == 1, resp

    # CPU options only take effect the next time the instance is started -- while it
    # remains stopped, DescribeInstances' CpuOptions can still reflect the pre-modification
    # values. Real testing against live AWS confirmed this: the modification must be
    # verified after starting the instance back up, not while it is still stopped.
    ec2.start_instances(InstanceIds=[instance_id])
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    described = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    cpu_opts = described["CpuOptions"]
    assert cpu_opts["CoreCount"] == 1 and cpu_opts["ThreadsPerCore"] == 1, cpu_opts


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses fails loudly instead of as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-i-")}],
            }
        ],
        SubnetId=ctx.network().subnet_ids[0],
    )
    return resp["Instances"][0]["InstanceId"]


def _terminate(ec2, instance_id: str) -> None:
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
        ec2.get_waiter("instance_terminated").wait(
            InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
