"""ec2-run-from-launch-template."""
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

def _delete_launch_template(ec2, lt_id):
    """Teardown: the body deletes the template itself, so InvalidLaunchTemplateId.NotFound is done."""
    try:
        ec2.delete_launch_template(LaunchTemplateId=lt_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidLaunchTemplateId.NotFound":
            raise


CHECK = "ec2-run-from-launch-template"
GROUP = 'launch-template'
SERVICES = ['ec2']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An instance launched only by LaunchTemplateId (no InstanceType/ImageId on RunInstances)
    reports the template's InstanceType and ImageId in DescribeInstances.
    """
    ec2 = ctx.client("ec2")
    image_id = _test_ami_id(ec2)
    lt_name = ctx.unique_name("sim2real-behav-lt-")

    created = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": image_id, "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["LaunchTemplate"]
    lt_id = created["LaunchTemplateId"]
    ctx.on_cleanup(lambda: _delete_launch_template(ec2, lt_id))

    resp = ec2.run_instances(
        LaunchTemplate={"LaunchTemplateId": lt_id}, MinCount=1, MaxCount=1,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )
    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    _wait_instance_state(ec2, instance_id, "running")

    # Read back via DescribeInstances rather than trusting RunInstances' own response.
    described = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    assert described["InstanceType"] == "t3.micro", (
        f"instance did not inherit the template's InstanceType t3.micro, got {described['InstanceType']}"
    )
    assert described["ImageId"] == image_id, (
        f"instance did not inherit the template's ImageId {image_id}, got {described['ImageId']}"
    )

    ec2.terminate_instances(InstanceIds=[instance_id])
    _wait_instance_state(ec2, instance_id, "terminated")

    ec2.delete_launch_template(LaunchTemplateId=lt_id)

    try:
        ec2.describe_launch_templates(LaunchTemplateIds=[lt_id])
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "InvalidLaunchTemplateId.NotFound", (
            f"expected InvalidLaunchTemplateId.NotFound reading a deleted launch template, "
            f"got {exc.response['Error']['Code']}"
        )
        assert exc.response["Error"]["Message"] == (
            "At least one of the launch templates specified in the request does not exist."
        ), exc.response["Error"]
    else:
        raise AssertionError("launch template still describable after delete_launch_template")

    try:
        ec2.run_instances(LaunchTemplate={"LaunchTemplateId": lt_id}, MinCount=1, MaxCount=1)
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "InvalidLaunchTemplateId.NotFound", (
            f"expected RunInstances against a deleted launch template to fail with "
            f"InvalidLaunchTemplateId.NotFound, got {exc.response['Error']['Code']}"
        )
        assert exc.response["Error"]["Message"] == (
            f"The specified launch template, with template ID {lt_id}, does not exist."
        ), exc.response["Error"]
    else:
        raise AssertionError("RunInstances against a deleted launch template unexpectedly succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
