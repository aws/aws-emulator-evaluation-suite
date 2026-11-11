"""op-contract-reset-instance-attribute."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-reset-instance-attribute"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ResetInstanceAttribute restores sourceDestCheck to true on a running instance; resetting
    kernel while running is rejected with IncorrectInstanceState and leaves the attribute
    unchanged, and the same call succeeds once the instance is stopped."""
    ec2 = ctx.client("ec2")

    ami_id = _latest_al2023_ami(ec2)
    instance = ec2.run_instances(
        ImageId=ami_id, InstanceType="t3.micro", MinCount=1, MaxCount=1,
        TagSpecifications=_tags("instance", ctx.unique_name("sim2real-ria-")),
        SubnetId=ctx.network().subnet_ids[0],
    )["Instances"][0]
    instance_id = instance["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    _poll_until(lambda: ec2.describe_instances(InstanceIds=[instance_id])
                ["Reservations"][0]["Instances"][0]["State"]["Name"],
                lambda s: s == "running", timeout_s=180, interval_s=5, ignore_not_found=True)

    ec2.modify_instance_attribute(InstanceId=instance_id, SourceDestCheck={"Value": False})
    disabled = ec2.describe_instance_attribute(
        InstanceId=instance_id, Attribute="sourceDestCheck")["SourceDestCheck"]["Value"]
    assert disabled is False, "sourceDestCheck was not disabled before reset"

    ec2.reset_instance_attribute(InstanceId=instance_id, Attribute="sourceDestCheck")

    restored = ec2.describe_instance_attribute(
        InstanceId=instance_id, Attribute="sourceDestCheck")["SourceDestCheck"]["Value"]
    assert restored is True, f"sourceDestCheck was not reset to its default: {restored}"

    kernel_before = ec2.describe_instance_attribute(
        InstanceId=instance_id, Attribute="kernel")["KernelId"].get("Value")

    code, message = _error(lambda: ec2.reset_instance_attribute(InstanceId=instance_id, Attribute="kernel"))
    assert code == "IncorrectInstanceState", f"expected IncorrectInstanceState, got {code}"
    assert message == f"The instance '{instance_id}' is not in the 'stopped' state.", (
        f"unexpected IncorrectInstanceState message {message!r}")

    kernel_after_rejected = ec2.describe_instance_attribute(
        InstanceId=instance_id, Attribute="kernel")["KernelId"].get("Value")
    assert kernel_after_rejected == kernel_before, (
        f"a rejected ResetInstanceAttribute(kernel) must not change the kernel attribute: "
        f"{kernel_before!r} -> {kernel_after_rejected!r}"
    )

    ec2.stop_instances(InstanceIds=[instance_id])
    _poll_until(lambda: ec2.describe_instances(InstanceIds=[instance_id])
                ["Reservations"][0]["Instances"][0]["State"]["Name"],
                lambda s: s == "stopped", timeout_s=180, interval_s=5)

    ec2.reset_instance_attribute(InstanceId=instance_id, Attribute="kernel")
    kernel_after_restore = ec2.describe_instance_attribute(
        InstanceId=instance_id, Attribute="kernel")["KernelId"].get("Value")
    assert kernel_after_restore == kernel_before, (
        f"ResetInstanceAttribute(kernel) must succeed once the instance is stopped: "
        f"{kernel_before!r} -> {kernel_after_restore!r}"
    )


def _tags(resource_type: str, name: str) -> list[dict]:
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _error(fn):
    """Return the (code, message) of the ClientError fn() raises; a success raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0, ignore_not_found=False):
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = probe()
        except ClientError as exc:
            if ignore_not_found and exc.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                time.sleep(interval_s)
                continue
            raise
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _latest_al2023_ami(ec2) -> str:
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no al2023 AMI found in this region")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
