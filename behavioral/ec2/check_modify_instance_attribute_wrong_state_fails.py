"""modify-instance-attribute-wrong-state-fails."""
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
        try:
            images = ec2.describe_images(**kw).get("Images", [])
        except Exception:
            continue
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


CHECK = "modify-instance-attribute-wrong-state-fails"
GROUP = 'error-semantics'
SERVICES = ['ec2']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyInstanceAttribute(InstanceType) is rejected with IncorrectInstanceState while the
    instance is running, the type is unchanged by the rejected call (independent read), and the
    identical call succeeds once the instance is stopped (independent read confirms the new type)."""
    ec2 = ctx.client("ec2")
    ami = _test_ami_id(ec2)
    instance_id = ec2.run_instances(
        ImageId=ami, InstanceType="t3.micro", MinCount=1, MaxCount=1,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
        SubnetId=ctx.network().subnet_ids[0],
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    _wait_instance_state(ec2, instance_id, "running")
    try:
        result = ec2.modify_instance_attribute(
            InstanceId=instance_id, InstanceType={"Value": "t3.small"}
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        msg = exc.response["Error"].get("Message")
    else:
        raise AssertionError(
            f"expected IncorrectInstanceState on a running instance, but the call succeeded: {result!r}"
        )
    assert code == "IncorrectInstanceState", f"expected IncorrectInstanceState, got {code}"
    expected = f"The instance '{instance_id}' is not in the 'stopped' state."
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # Effect-absent: an independent read (a different operation than the rejected mutation)
    # confirms the type genuinely did not change while running.
    attr = ec2.describe_instance_attribute(InstanceId=instance_id, Attribute="instanceType")
    assert attr["InstanceType"]["Value"] == "t3.micro", (
        f"expected instanceType to remain 't3.micro' after the rejected modify while running, "
        f"got {attr['InstanceType']['Value']!r}"
    )

    # Restore: instanceType is only mutable while stopped, so the identical call must now succeed.
    ec2.stop_instances(InstanceIds=[instance_id])
    _wait_instance_state(ec2, instance_id, "stopped")
    ec2.modify_instance_attribute(InstanceId=instance_id, InstanceType={"Value": "t3.small"})

    # Positive control: an independent read confirms the modify was actually applied.
    attr = ec2.describe_instance_attribute(InstanceId=instance_id, Attribute="instanceType")
    assert attr["InstanceType"]["Value"] == "t3.small", (
        f"expected instanceType 't3.small' after modify on a stopped instance, "
        f"got {attr['InstanceType']['Value']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
