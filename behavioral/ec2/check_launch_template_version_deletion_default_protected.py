"""launch-template-version-deletion-default-protected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call *fn*; return the AWS (code, message). An unexpected SUCCESS raises, because an emulator
    accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_launch_template_if_present(ec2, lt_id):
    """Teardown: the check deletes the template itself; tolerate it being gone already."""
    try:
        ec2.delete_launch_template(LaunchTemplateId=lt_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidLaunchTemplateId.NotFound":
            raise


def _default_ami_id(ec2):
    """A usable AMI id, falling back to a well-formed placeholder (a launch
    template does not validate the AMI at create time)."""
    try:
        images = ec2.describe_images(
            Owners=["amazon"],
            Filters=[{"Name": "name", "Values": ["amzn2-ami-hvm-*-x86_64-gp2"]}],
        ).get("Images", [])
        if images:
            return images[0]["ImageId"]
    except Exception:
        pass
    return "ami-0123456789abcdef0"

CHECK = "launch-template-version-deletion-default-protected"
GROUP = 'launch-template'
SERVICES = ['ec2']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteLaunchTemplateVersions cannot remove the default version; DeleteLaunchTemplate can."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("lt-")
    ami_id = _default_ami_id(ec2)
    lt = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )
    lt_id = lt["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: _delete_launch_template_if_present(ec2, lt_id))

    ec2.create_launch_template_version(
        LaunchTemplateId=lt_id,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.small"},
    )

    # Version 1 is the default; deleting it is refused at the top level.
    default_code, default_message = _error(
        lambda: ec2.delete_launch_template_versions(LaunchTemplateId=lt_id, Versions=["1"])
    )
    assert default_code == "InvalidParameterValue", (
        f"expected InvalidParameterValue deleting the default version, got {default_code}"
    )
    assert default_message == "The default version cannot be deleted. Either specify another version as default or delete the launch template.", f"unexpected default-version message {default_message!r}"

    # The rejected delete must have had no effect: both versions are still there,
    # confirmed via an independent read (not the failed call's own response).
    after_reject = {
        v["VersionNumber"]
        for v in ec2.describe_launch_template_versions(LaunchTemplateId=lt_id)["LaunchTemplateVersions"]
    }
    assert after_reject == {1, 2}, f"expected versions 1 and 2 to survive the rejected delete, got {after_reject}"

    # A nonexistent version is reported per-item rather than raising.
    resp2 = ec2.delete_launch_template_versions(LaunchTemplateId=lt_id, Versions=["99"])
    bad = resp2.get("UnsuccessfullyDeletedLaunchTemplateVersions", [])
    assert len(bad) == 1, f"expected version 99 to be reported unsuccessful, got {resp2}"
    assert bad[0]["ResponseError"]["Code"] == "launchTemplateVersionDoesNotExist", f"unexpected per-item error: {bad}"
    assert bad[0]["ResponseError"]["Message"] == "The launch template version does not exist.", f"unexpected per-item error: {bad}"

    # The non-default version deletes cleanly.
    ok = ec2.delete_launch_template_versions(LaunchTemplateId=lt_id, Versions=["2"])
    assert len(ok.get("SuccessfullyDeletedLaunchTemplateVersions", [])) == 1, f"got {ok}"

    ec2.delete_launch_template(LaunchTemplateId=lt_id)
    gone, gone_message = _error(
        lambda: ec2.describe_launch_templates(LaunchTemplateIds=[lt_id])
    )
    assert gone == "InvalidLaunchTemplateId.NotFound", (
        f"expected InvalidLaunchTemplateId.NotFound, got {gone}"
    )
    assert gone_message == "At least one of the launch templates specified in the request does not exist.", f"unexpected not-found message {gone_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
