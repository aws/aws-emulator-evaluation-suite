"""op-contract-modify-instance-maintenance-options."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-modify-instance-maintenance-options"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyInstanceMaintenanceOptions disables auto-recovery on a running instance and rejects an unknown instance."""
    ec2 = ctx.client("ec2")
    instance_id = _run_instance(ctx, ec2, "t3.micro")
    ctx.on_cleanup(lambda: _terminate(ec2, instance_id))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    resp = ec2.modify_instance_maintenance_options(InstanceId=instance_id, AutoRecovery="disabled")
    assert resp["AutoRecovery"] == "disabled", resp
    assert resp["InstanceId"] == instance_id, f"expected InstanceId {instance_id}, got {resp.get('InstanceId')}"

    described = _poll_until(
        ec2,
        instance_id,
        lambda opts: opts["AutoRecovery"] == "disabled",
    )
    assert described["MaintenanceOptions"]["AutoRecovery"] == "disabled", described

    ec2.modify_instance_maintenance_options(InstanceId=instance_id, AutoRecovery="default")
    described = _poll_until(
        ec2,
        instance_id,
        lambda opts: opts["AutoRecovery"] == "default",
    )
    assert described["MaintenanceOptions"]["AutoRecovery"] == "default", described

    # A hand-rolled hex ID (even one that is correctly *shaped*, e.g. all zeros) can still
    # trip this API's own format pre-check as malformed rather than reaching the not-found
    # path, and so can some single-character mutations of a real ID. Derive the nonexistent
    # ID by mutating the last character of the real (still-running) instance's own ID,
    # skipping candidates the format pre-check refuses as malformed: only the input's
    # well-formedness is searched; the not-found code and message are asserted below.
    for digit in "0123456789abcdef":
        if digit == instance_id[-1]:
            continue
        bogus_instance_id = instance_id[:-1] + digit
        code, msg = _error(
            lambda: ec2.modify_instance_maintenance_options(
                InstanceId=bogus_instance_id, AutoRecovery="disabled"
            )
        )
        if code != "InvalidInstanceID.Malformed":
            break
    assert code == "InvalidInstanceID.NotFound", f"expected InvalidInstanceID.NotFound, got {code}"
    expected = f"The instance ID '{bogus_instance_id}' does not exist"
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"


def _poll_until(ec2, instance_id, predicate, *, timeout_s=60.0, interval_s=3.0):
    """DescribeInstances can briefly lag ModifyInstanceMaintenanceOptions's write."""
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
        if predicate(last["MaintenanceOptions"]):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


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
