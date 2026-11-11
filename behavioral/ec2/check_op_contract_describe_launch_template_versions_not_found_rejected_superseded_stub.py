"""op-contract-describe-launch-template-versions-not-found-rejected-superseded-stub."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-launch-template-versions-not-found-rejected-superseded-stub"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeLaunchTemplateVersions returns a created launch template's version 1 as the default with
    its LaunchTemplateData; a hex-shaped never-issued template ID fails with
    InvalidLaunchTemplateId.Malformed and its exact message."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")

    lt = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    resp = ec2.describe_launch_template_versions(LaunchTemplateId=lt_id)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
    versions = resp["LaunchTemplateVersions"]
    assert len(versions) == 1
    v1 = versions[0]
    assert v1["VersionNumber"] == 1
    assert v1["DefaultVersion"] is True
    assert v1["LaunchTemplateData"]["InstanceType"] == "t3.micro"
    assert v1["LaunchTemplateId"] == lt_id

    # A hex-shaped but never-issued id fails the service's id-space check
    # before any existence lookup, and is rejected as Malformed.
    bogus_id = "lt-0123456789abcdef0"
    code, message = _error(lambda: ec2.describe_launch_template_versions(LaunchTemplateId=bogus_id))
    assert code == "InvalidLaunchTemplateId.Malformed", f"expected Malformed, got {code!r}"
    assert message == f"Malformed launch template Id: {bogus_id}", message


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
