"""op-contract-describe-launch-templates-not-found-rejected-superseded-stub."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-launch-templates-not-found-rejected-superseded-stub"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeLaunchTemplates returns a new template by name with its id and version markers;
    a hex-shaped but never-issued template id is rejected as InvalidLaunchTemplateId.Malformed."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")

    lt = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real-managed", "Value": "true"}]}
        ],
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    resp = ec2.describe_launch_templates(LaunchTemplateNames=[name])
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
    templates = resp["LaunchTemplates"]
    assert len(templates) == 1
    assert templates[0]["LaunchTemplateName"] == name
    assert templates[0]["LaunchTemplateId"] == lt_id
    assert templates[0]["DefaultVersionNumber"] == 1
    assert templates[0]["LatestVersionNumber"] == 1

    # A hex-shaped but never-issued id fails the service's id-space check
    # before any existence lookup, and is rejected as Malformed.
    bogus_id = "lt-0123456789abcdef0"
    code, message = _client_error(lambda: ec2.describe_launch_templates(LaunchTemplateIds=[bogus_id]))
    assert code == "InvalidLaunchTemplateId.Malformed", f"expected Malformed, got {code!r}"
    expected_message = f"The following launch template ids are malformed: {bogus_id}"
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"


def _client_error(fn):
    """Call fn() and return the (code, message) it is refused with; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
