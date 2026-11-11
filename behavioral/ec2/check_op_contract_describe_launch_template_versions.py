"""op-contract-describe-launch-template-versions."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-launch-template-versions"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeLaunchTemplateVersions lists both versions, keeps v1 as default, resolves $Latest/
    $Default to 2/1, and rejects a fabricated template id as InvalidLaunchTemplateId.Malformed."""
    ec2 = ctx.client("ec2")

    name = ctx.unique_name("sim2real-behav-ltv-")
    created = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real-managed", "Value": "true"}]}
        ],
    )["LaunchTemplate"]
    lt_id = created["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    ec2.create_launch_template_version(
        LaunchTemplateId=lt_id,
        LaunchTemplateData={"InstanceType": "t3.small"},
    )

    resp = ec2.describe_launch_template_versions(LaunchTemplateId=lt_id)
    versions = sorted(resp["LaunchTemplateVersions"], key=lambda v: v["VersionNumber"])
    assert [v["VersionNumber"] for v in versions] == [1, 2], f"got {versions}"
    assert versions[0]["LaunchTemplateData"]["InstanceType"] == "t3.micro", (
        f"expected v1 InstanceType t3.micro, got {versions[0]['LaunchTemplateData']}"
    )
    assert versions[1]["LaunchTemplateData"]["InstanceType"] == "t3.small", (
        f"expected v2 InstanceType t3.small, got {versions[1]['LaunchTemplateData']}"
    )
    # Creating a new version does not change the default version (still 1) unless asked to.
    assert versions[0]["DefaultVersion"] is True, f"expected v1 to still be default, got {versions[0]}"
    assert versions[1]["DefaultVersion"] is False, f"expected v2 to not be default, got {versions[1]}"

    latest = ec2.describe_launch_template_versions(
        LaunchTemplateId=lt_id, Versions=["$Latest"]
    )["LaunchTemplateVersions"]
    assert len(latest) == 1 and latest[0]["VersionNumber"] == 2, (
        f"expected $Latest to resolve to exactly version 2, got {latest}"
    )
    default = ec2.describe_launch_template_versions(
        LaunchTemplateId=lt_id, Versions=["$Default"]
    )["LaunchTemplateVersions"]
    assert len(default) == 1 and default[0]["VersionNumber"] == 1, (
        f"expected $Default to resolve to exactly version 1, got {default}"
    )

    # EC2 validates the id before any lookup, so a hex-looking fabricated id is Malformed,
    # not NotFound.
    code, message = _client_error(
        lambda: ec2.describe_launch_template_versions(
            LaunchTemplateId="lt-0123456789abcdef0"
        )
    )
    assert code == "InvalidLaunchTemplateId.Malformed", f"expected Malformed, got {code!r}"
    expected_message = "Malformed launch template Id: lt-0123456789abcdef0"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected this call to fail, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
