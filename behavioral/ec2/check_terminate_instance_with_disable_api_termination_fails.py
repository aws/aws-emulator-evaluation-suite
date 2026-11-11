"""terminate-instance-with-disable-api-termination-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError


from behavioral_harness import tags


def _test_ami_id(ec2):
    """Return an x86_64 HVM EBS ImageId usable for RunInstances tests."""
    strict = [
        {"Name": "state", "Values": ["available"]},
        {"Name": "architecture", "Values": ["x86_64"]},
        {"Name": "virtualization-type", "Values": ["hvm"]},
        {"Name": "root-device-type", "Values": ["ebs"]},
    ]
    attempts = [
        {"Owners": ["amazon"], "Filters": strict + [{"Name": "name", "Values": ["al2023-ami-2023*-x86_64"]}]},
        {"Owners": ["amazon"], "Filters": strict + [{"Name": "name", "Values": ["amzn2-ami-hvm-*-x86_64-gp2"]}]},
        {"Owners": ["amazon"], "Filters": strict},
    ]
    for kw in attempts:
        images = ec2.describe_images(**kw).get("Images", [])
        if not images:
            continue
        images.sort(key=lambda i: i.get("CreationDate", ""), reverse=True)
        return images[0]["ImageId"]
    raise AssertionError("could not discover a usable test AMI")


def _wait_instance_state(ec2, instance_id, state, timeout_s=180):
    """Poll DescribeInstances until the instance reaches *state* (swallows the
    eventually-consistent InvalidInstanceID.NotFound window right after launch)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = ec2.describe_instances(InstanceIds=[instance_id])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidInstanceID.NotFound":
                last = "__not_yet_visible__"
                time.sleep(3)
                continue
            raise
        reservations = resp.get("Reservations", [])
        if not reservations or not reservations[0].get("Instances"):
            last = "__not_yet_visible__"
        else:
            last = reservations[0]["Instances"][0]["State"]["Name"]
        if last == state:
            return last
        time.sleep(3)
    raise AssertionError(
        f"instance {instance_id} did not reach {state!r} within {timeout_s}s (last {last!r})"
    )


CHECK = "terminate-instance-with-disable-api-termination-fails"
GROUP = 'overly-permissive'
SERVICES = ['ec2']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TerminateInstances on an instance with DisableApiTermination=true must fail with
    OperationNotPermitted, and clearing the flag must let the identical call succeed
    (overly-permissive check)."""
    ec2 = ctx.client("ec2")
    ami = _test_ami_id(ec2)
    instance_id = ec2.run_instances(
        ImageId=ami, InstanceType="t3.micro", MinCount=1, MaxCount=1,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
        SubnetId=ctx.network().subnet_ids[0],
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    _wait_instance_state(ec2, instance_id, "running")
    ec2.modify_instance_attribute(InstanceId=instance_id, DisableApiTermination={"Value": True})
    # Independent read: confirm the flag actually took effect before relying on it
    # as the thing under test, rather than assuming the modify call was honored.
    attr = ec2.describe_instance_attribute(InstanceId=instance_id, Attribute="disableApiTermination")
    assert attr["DisableApiTermination"]["Value"] is True, (
        f"expected DisableApiTermination=True after modify, got {attr}"
    )
    # Ensure teardown can terminate even if an assertion below fails: LIFO runs
    # this before the terminate cleanup registered at launch.
    ctx.on_cleanup(lambda: _clear_termination_protection(ec2, instance_id))

    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
        code = message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "OperationNotPermitted", f"expected OperationNotPermitted, got {code}"
    expected = (
        f"The instance '{instance_id}' may not be terminated. "
        "Modify its 'disableApiTermination' instance attribute and try again."
    )
    assert message == expected, f"unexpected message: {message!r}"

    # Sanity: the instance must still be running (the emulator must not have
    # silently terminated it despite returning/raising an error).
    state = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]["State"]["Name"]
    assert state == "running", f"expected instance to remain running, got {state}"

    # Clear protection and confirm it independently, then demand the *identical*
    # terminate call now succeeds — without this, a target that rejects every
    # TerminateInstances call unconditionally would pass the assertions above.
    ec2.modify_instance_attribute(InstanceId=instance_id, DisableApiTermination={"Value": False})
    attr = ec2.describe_instance_attribute(InstanceId=instance_id, Attribute="disableApiTermination")
    assert attr["DisableApiTermination"]["Value"] is False, (
        f"expected DisableApiTermination=False after clearing, got {attr}"
    )

    ec2.terminate_instances(InstanceIds=[instance_id])
    _wait_instance_state(ec2, instance_id, "terminated")


def _clear_termination_protection(ec2, instance_id):
    """Clear DisableApiTermination so the terminate teardown can run; an instance the check already
    terminated has nothing to clear."""
    state = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]["State"]["Name"]
    if state in ("shutting-down", "terminated"):
        return
    ec2.modify_instance_attribute(InstanceId=instance_id, DisableApiTermination={"Value": False})


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
