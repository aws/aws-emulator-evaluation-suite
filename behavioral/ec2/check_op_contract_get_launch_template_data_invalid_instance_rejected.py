"""op-contract-get-launch-template-data-invalid-instance-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-get-launch-template-data-invalid-instance-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetLaunchTemplateData reflects a real running instance's configuration, and
    rejects a nonexistent instance id.
    """
    ec2 = ctx.client("ec2")

    image_id = _latest_amazon_linux_ami(ec2)
    instance_name = ctx.unique_name("sim2real-gltd-")
    reservation = ec2.run_instances(
        ImageId=image_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": instance_name}]}
        ],
        SubnetId=ctx.network().subnet_ids[0],
    )
    instance_id = reservation["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    ec2.get_waiter("instance_running").wait(
        InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 100}
    )

    # success-path contract: the launch template data mirrors the running instance.
    data = ec2.get_launch_template_data(InstanceId=instance_id)["LaunchTemplateData"]
    assert data["ImageId"] == image_id
    assert data["InstanceType"] == "t3.micro"

    # error boundary (overly-permissive probe): a well-formed but nonexistent instance
    # id must be rejected with the standard EC2 not-found code.
    code = _error_code(
        lambda: ec2.get_launch_template_data(InstanceId="i-00000000000000000")
    )
    _assert_invalid_id(code, "Instance")


def _latest_amazon_linux_ami(ec2):
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no Amazon Linux 2023 AMI found to launch from")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


def _assert_invalid_id(code, token):
    assert code is not None, "expected a ClientError but the call succeeded"
    assert code.endswith(".NotFound") or code.endswith(".Malformed"), (
        f"expected a *.NotFound/*.Malformed error code, got {code!r}"
    )
    assert token.lower() in code.lower(), f"expected {token!r} referenced in code, got {code!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
