"""launch-template-version-management."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "launch-template-version-management"
GROUP = 'launch-template'
SERVICES = ['ec2']


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateLaunchTemplateVersion adds a version and ModifyLaunchTemplate can repoint the default."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    ami_id = _default_ami_id(ec2)
    lt = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=_ec2_tag_specs("launch-template"),
    )
    lt_id = lt["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: _swallow(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id)))
    assert lt["LaunchTemplate"]["DefaultVersionNumber"] == 1, (
        f"expected a freshly created launch template to default to version 1, got {lt['LaunchTemplate']}"
    )

    v2 = ec2.create_launch_template_version(
        LaunchTemplateId=lt_id,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.small"},
    )
    assert v2["LaunchTemplateVersion"]["VersionNumber"] == 2, (
        f"expected the first CreateLaunchTemplateVersion call to produce version 2, got {v2['LaunchTemplateVersion']}"
    )

    versions = ec2.describe_launch_template_versions(LaunchTemplateId=lt_id)["LaunchTemplateVersions"]
    assert {v["VersionNumber"] for v in versions} == {1, 2}, f"expected versions 1,2, got {versions}"

    ec2.modify_launch_template(LaunchTemplateId=lt_id, DefaultVersion="2")
    desc = ec2.describe_launch_templates(LaunchTemplateIds=[lt_id])["LaunchTemplates"][0]
    assert desc["DefaultVersionNumber"] == 2, f"expected default version 2, got {desc}"

    # A second CreateLaunchTemplate with the same name must fail, not overwrite.
    dup_code, dup_message = _error(
        lambda: ec2.create_launch_template(
            LaunchTemplateName=name, LaunchTemplateData={"ImageId": ami_id}
        )
    )
    assert dup_code == "InvalidLaunchTemplateName.AlreadyExistsException", (
        f"expected InvalidLaunchTemplateName.AlreadyExistsException, got {dup_code}"
    )
    assert dup_message == "Launch template name already in use.", f"unexpected duplicate-name message {dup_message!r}"


def _error(fn):
    """Call fn(); return the AWS (code, message). An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")

def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidLaunchTemplateId.NotFound":
            raise

# Marker tag on every resource this check creates, so leftovers can be found by tag.
_MANAGED_TAG_KEY = "sim2real-managed"
_MANAGED_TAG_VALUE = "true"


def _ec2_tag_specs(resource_type: str, name: str | None = None) -> list[dict]:
    """TagSpecifications carrying the managed-resource marker tag."""
    tags = [{"Key": _MANAGED_TAG_KEY, "Value": _MANAGED_TAG_VALUE}]
    if name:
        tags.append({"Key": "Name", "Value": name})
    return [{"ResourceType": resource_type, "Tags": tags}]

def _default_ami_id(ec2) -> str:
    """An Amazon-owned AL2 AMI, falling back to a well-formed placeholder id when
    DescribeImages is unavailable to the caller."""
    try:
        images = ec2.describe_images(
            Owners=["amazon"],
            Filters=[{"Name": "name", "Values": ["amzn2-ami-hvm-*-x86_64-gp2"]}],
        ).get("Images", [])
        if images:
            return images[0]["ImageId"]
    except Exception:  # noqa: BLE001
        pass
    return "ami-0123456789abcdef0"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
