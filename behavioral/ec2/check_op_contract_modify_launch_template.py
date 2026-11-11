"""op-contract-modify-launch-template."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-modify-launch-template"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyLaunchTemplate changes the default version and rejects a version number that does not exist."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    created = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "Name", "Value": name}]}],
    )["LaunchTemplate"]
    lt_id = created["LaunchTemplateId"]
    assert created["DefaultVersionNumber"] == 1, f"expected new template's default version to be 1, got {created['DefaultVersionNumber']}"
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    version2 = ec2.create_launch_template_version(
        LaunchTemplateId=lt_id,
        LaunchTemplateData={"InstanceType": "t3.small"},
    )["LaunchTemplateVersion"]
    assert version2["VersionNumber"] == 2, f"expected the new version to be numbered 2, got {version2['VersionNumber']}"

    # success path: promote version 2 to be the default
    resp = ec2.modify_launch_template(LaunchTemplateId=lt_id, DefaultVersion="2")
    lt = resp["LaunchTemplate"]
    assert lt["DefaultVersionNumber"] == 2, f"expected ModifyLaunchTemplate to report default version 2, got {lt['DefaultVersionNumber']}"
    assert lt["LaunchTemplateId"] == lt_id, f"expected response to describe {lt_id}, got {lt['LaunchTemplateId']}"

    described = ec2.describe_launch_templates(LaunchTemplateIds=[lt_id])["LaunchTemplates"][0]
    assert described["DefaultVersionNumber"] == 2, (
        f"expected an independent DescribeLaunchTemplates read to confirm default version 2, got {described['DefaultVersionNumber']}"
    )

    # error boundary: version number that was never created
    code, message = _error(
        lambda: ec2.modify_launch_template(LaunchTemplateId=lt_id, DefaultVersion="999")
    )
    assert code == "InvalidLaunchTemplateId.VersionNotFound", f"expected VersionNotFound code, got {code}"
    assert message == "The launch template version 999 is not found for the specified launch template.", message

    # The rejected modify must have had no effect: the default is still version 2,
    # confirmed via an independent read (not the failed call's own response).
    after_reject = ec2.describe_launch_templates(LaunchTemplateIds=[lt_id])["LaunchTemplates"][0]
    assert after_reject["DefaultVersionNumber"] == 2, (
        f"expected the default version to remain 2 after the rejected modify, got {after_reject['DefaultVersionNumber']}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
