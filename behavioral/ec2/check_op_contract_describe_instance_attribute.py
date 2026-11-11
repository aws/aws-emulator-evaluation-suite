"""op-contract-describe-instance-attribute."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-instance-attribute"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeInstanceAttribute reflects real attribute values of a running instance and
    rejects a well-formed but nonexistent instance ID with InvalidParameterValue."""
    ec2 = ctx.client("ec2")
    ami_id = _find_al2023_ami(ctx)
    instance_id = _launch_instance(ctx, ami_id, instance_type="t3.micro")

    disable_termination = ec2.describe_instance_attribute(
        InstanceId=instance_id, Attribute="disableApiTermination"
    )
    assert disable_termination["InstanceId"] == instance_id, (
        f"expected InstanceId {instance_id!r} echoed back, got {disable_termination['InstanceId']!r}"
    )
    assert disable_termination["DisableApiTermination"]["Value"] is False, (
        f"expected disableApiTermination default False, got {disable_termination['DisableApiTermination']['Value']!r}"
    )

    instance_type_attr = ec2.describe_instance_attribute(InstanceId=instance_id, Attribute="instanceType")
    assert instance_type_attr["InstanceType"]["Value"] == "t3.micro", (
        f"expected instanceType t3.micro, got {instance_type_attr['InstanceType']['Value']!r}"
    )

    # Error boundary: a well-formed but nonexistent instance ID is rejected, not returned empty.
    # (Unlike DescribeInstances, DescribeInstanceAttribute reports this as InvalidParameterValue.)
    bogus_instance_id = "i-0000000000000000f"
    code, message = _error(
        lambda: ec2.describe_instance_attribute(InstanceId=bogus_instance_id, Attribute="instanceType")
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}"
    expected = f"Value ({bogus_instance_id}) for parameter instanceId is invalid. Expected: 'i-...'."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Return fn()'s (code, message); a success raises, never reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _find_al2023_ami(ctx) -> str:
    ec2 = ctx.client("ec2")
    resp = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )
    images = resp.get("Images", [])
    if not images:
        raise AssertionError("no amazon-owned al2023 AMI visible in this account/region")
    images.sort(key=lambda i: i.get("CreationDate", ""), reverse=True)
    return images[0]["ImageId"]


def _launch_instance(ctx, ami_id: str, instance_type: str = "t3.micro", extra_kwargs: dict | None = None) -> str:
    ec2 = ctx.client("ec2")
    kwargs: dict[str, Any] = dict(
        ImageId=ami_id,
        InstanceType=instance_type,
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ec2-")}],
            }
        ],
    )
    if extra_kwargs:
        kwargs.update(extra_kwargs)
    try:
        resp = ec2.run_instances(**kwargs)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("VPCIdNotSpecified", "MissingInput"):
            raise AssertionError(f"cannot launch instance: {code}")
        raise

    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    waiter = ec2.get_waiter("instance_running")
    waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 100})
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
