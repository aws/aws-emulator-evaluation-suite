"""create-launch-template-conflicting-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-launch-template-conflicting-name-rejected"
GROUP = "negative-classes"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateLaunchTemplate with a name already in use is rejected as a conflicting-name error
    (InvalidLaunchTemplateName.AlreadyExistsException) -- distinct from the ASG duplicate-name
    (AlreadyExistsFault) boundary -- and does not disturb the existing template's data."""
    ec2 = ctx.client("ec2")
    ami_id = _valid_ami(ctx)
    name = ctx.unique_name("sim2real-behav-lt-")
    first = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"InstanceType": "t3.micro", "ImageId": ami_id},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": _tags_kv()}],
    )
    lt_id = first["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    code, message = _error_code(
        lambda: ec2.create_launch_template(
            LaunchTemplateName=name,
            LaunchTemplateData={"InstanceType": "t3.small", "ImageId": ami_id},
        )
    )
    assert code == "InvalidLaunchTemplateName.AlreadyExistsException", (
        f"expected InvalidLaunchTemplateName.AlreadyExistsException, got {code!r}"
    )
    assert message == "Launch template name already in use.", (
        f"expected the exact conflicting-name message, got {message!r}"
    )

    # effect absent: the original template still has exactly one version, unaltered
    versions = ec2.describe_launch_template_versions(LaunchTemplateId=lt_id)["LaunchTemplateVersions"]
    assert len(versions) == 1, f"expected exactly 1 version after the rejected duplicate, got {len(versions)}"
    assert versions[0]["LaunchTemplateData"]["InstanceType"] == "t3.micro", (
        f"expected the original version's InstanceType unchanged at t3.micro, "
        f"got {versions[0]['LaunchTemplateData']['InstanceType']!r}"
    )

    # positive control: a distinct, unused name succeeds
    other_name = ctx.unique_name("sim2real-behav-lt2-")
    other = ec2.create_launch_template(
        LaunchTemplateName=other_name,
        LaunchTemplateData={"InstanceType": "t3.micro", "ImageId": ami_id},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": _tags_kv()}],
    )
    other_id = other["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=other_id))

    # terminal read: independent of the creating call, at the destination
    found = ec2.describe_launch_templates(LaunchTemplateIds=[other_id])["LaunchTemplates"]
    assert len(found) == 1, f"expected the distinct-name template to be listed, got {len(found)} matches"
    assert found[0]["LaunchTemplateName"] == other_name, (
        f"expected listed name {other_name!r}, got {found[0]['LaunchTemplateName']!r}"
    )


_MANAGED_TAGS = {"sim2real": "behav-lt-conflicting-name", "sim2real:managed": "true"}


def _tags_kv():
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _error_code(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a conflicting-name rejection, but the call SUCCEEDED: {result!r}")


def _valid_ami(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
