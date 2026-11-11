"""terminate-termination-protected-instance-rejected."""
from __future__ import annotations


from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "terminate-termination-protected-instance-rejected"
GROUP = "overly-permissive"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TerminateInstances on an instance with DisableApiTermination=True is rejected; disabling protection lets it terminate."""
    ec2 = ctx.client("ec2")
    ami_id = _latest_al2023_ami(ctx)
    name = ctx.unique_name("sim2real-behav-")
    reservation = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        DisableApiTermination=True,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}],
        SubnetId=ctx.network().subnet_ids[0],
    )
    instance_id = reservation["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _safe_terminate(ec2, instance_id))

    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 200})

    code, message = _error(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    assert code == "OperationNotPermitted", f"expected OperationNotPermitted, got {code}"
    expected_message = (
        f"The instance '{instance_id}' may not be terminated. "
        f"Modify its 'disableApiTermination' instance attribute and try again."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    state = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]["State"]["Name"]
    assert state in ("running", "pending"), f"protected instance unexpectedly moved to {state}"

    ec2.modify_instance_attribute(InstanceId=instance_id, DisableApiTermination={"Value": False})
    ec2.terminate_instances(InstanceIds=[instance_id])
    ec2.get_waiter("instance_terminated").wait(
        InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 200}
    )

    final_state = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]["State"]["Name"]
    assert final_state == "terminated", f"expected instance to terminate once protection was disabled, got {final_state}"


def _latest_al2023_ami(ctx):
    ssm = ctx.client("ssm")
    name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    return ssm.get_parameter(Name=name)["Parameter"]["Value"]


def _safe_terminate(ec2, instance_id):
    try:
        ec2.modify_instance_attribute(InstanceId=instance_id, DisableApiTermination={"Value": False})
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] != "InvalidInstanceID.NotFound"
            and not (err["Code"] == "IncorrectInstanceState" and "must be in a 'running', 'pending', 'stopping' or 'stopped' state" in err.get("Message", ""))
        ):
            raise
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
            raise


def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
