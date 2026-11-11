"""get-console-screenshot-invalid-instance-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-console-screenshot-invalid-instance-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetConsoleScreenshot succeeds against a real running instance and rejects a
    made-up instance id of this shape with InvalidInstanceID.Malformed - AWS's
    own instance-id format validation runs before any existence lookup."""
    ec2 = ctx.client("ec2")
    instance_id = _launch_probe_instance(ctx)

    resp = _poll_until(
        lambda: ec2.get_console_screenshot(InstanceId=instance_id),
        lambda r: r.get("InstanceId") == instance_id,
        timeout_s=90.0,
    )
    assert resp["InstanceId"] == instance_id, (
        f"expected echoed InstanceId {instance_id!r}, got {resp.get('InstanceId')!r}"
    )
    assert "ResponseMetadata" in resp, (
        "expected a ResponseMetadata envelope on a successful GetConsoleScreenshot response"
    )

    bogus_instance_id = "i-0123456789abcdef0"
    code, message = _error(
        lambda: ec2.get_console_screenshot(InstanceId=bogus_instance_id)
    )
    assert code == "InvalidInstanceID.Malformed", f"expected InvalidInstanceID.Malformed, got {code!r}"
    expected = f"The instance ID '{bogus_instance_id}' is malformed"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its error as (code, message). An unexpected SUCCESS raises rather than
    returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _latest_al2023_ami(ec2) -> str:
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
            {"Name": "architecture", "Values": ["x86_64"]},
            {"Name": "virtualization-type", "Values": ["hvm"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no Amazon Linux 2023 AMI available to launch a probe instance")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _launch_probe_instance(ctx) -> str:
    ec2 = ctx.client("ec2")
    ami_id = _latest_al2023_ami(ec2)
    try:
        resp = ec2.run_instances(
            ImageId=ami_id,
            InstanceType="t3.micro",
            MinCount=1,
            MaxCount=1,
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-")}],
                }
            ],
            SubnetId=ctx.network().subnet_ids[0],
        )
    except ClientError as exc:
        raise AssertionError(f"could not launch probe instance: {exc.response.get('Error', {}).get('Code')}")

    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    waiter = ec2.get_waiter("instance_running")
    waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
