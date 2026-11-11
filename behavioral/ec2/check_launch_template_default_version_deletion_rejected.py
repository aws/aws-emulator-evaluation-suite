"""launch-template-default-version-deletion-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "launch-template-default-version-deletion-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteLaunchTemplateVersions rejects deleting the CURRENT DEFAULT version: you must
    reassign the default to another version first. This is a state-conflict boundary, not
    just a bogus-id lookup."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-ltv-def-")

    lt = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": "1"}]}
        ],
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    assert lt["DefaultVersionNumber"] == 1

    ec2.create_launch_template_version(
        LaunchTemplateId=lt_id,
        LaunchTemplateData={"InstanceType": "t3.small"},
    )
    ec2.modify_launch_template(LaunchTemplateId=lt_id, DefaultVersion="2")
    described = ec2.describe_launch_templates(LaunchTemplateIds=[lt_id])["LaunchTemplates"][0]
    assert described["DefaultVersionNumber"] == 2

    # attempting to delete the (now) default version 2 must be rejected with a top-level
    # ClientError.
    try:
        ec2.delete_launch_template_versions(LaunchTemplateId=lt_id, Versions=["2"])
        raise AssertionError("expected DeleteLaunchTemplateVersions to reject the default version")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "InvalidParameterValue", (
            f"expected a default-version-protection error code, got {code}"
        )
        message = exc.response["Error"].get("Message")
        assert message == "The default version cannot be deleted. Either specify another version as default or delete the launch template.", f"unexpected default-version-protection message {message!r}"

    # version 2 must still exist since the delete attempt was rejected
    remaining_after_reject = ec2.describe_launch_template_versions(LaunchTemplateId=lt_id)[
        "LaunchTemplateVersions"
    ]
    assert {v["VersionNumber"] for v in remaining_after_reject} == {1, 2}

    # the same rejection holds even when the default version shares a batch with a
    # deletable non-default one, and the deletable one is not partially removed either.
    try:
        ec2.delete_launch_template_versions(LaunchTemplateId=lt_id, Versions=["1", "2"])
        raise AssertionError("expected a mixed batch containing the default version to be rejected")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "InvalidParameterValue", (
            f"expected a default-version-protection error code for the mixed batch, got {code}"
        )
        message = exc.response["Error"].get("Message")
        assert message == "The default version cannot be deleted. Either specify another version as default or delete the launch template.", f"unexpected default-version-protection message {message!r}"
    remaining_after_mixed_reject = ec2.describe_launch_template_versions(LaunchTemplateId=lt_id)[
        "LaunchTemplateVersions"
    ]
    assert {v["VersionNumber"] for v in remaining_after_mixed_reject} == {1, 2}, (
        "a rejected mixed batch must not delete the non-default version either"
    )

    # restore: reassign the default away from version 2 ...
    ec2.modify_launch_template(LaunchTemplateId=lt_id, DefaultVersion="1")
    restored = ec2.describe_launch_templates(LaunchTemplateIds=[lt_id])["LaunchTemplates"][0]
    assert restored["DefaultVersionNumber"] == 1

    # ... and the IDENTICAL call that was rejected moments ago now succeeds, proving the
    # rejection tracked default-ness and not the template/version identity.
    resp2 = ec2.delete_launch_template_versions(LaunchTemplateId=lt_id, Versions=["2"])
    assert {v["VersionNumber"] for v in resp2["SuccessfullyDeletedLaunchTemplateVersions"]} == {2}

    remaining = ec2.describe_launch_template_versions(LaunchTemplateId=lt_id)["LaunchTemplateVersions"]
    assert {v["VersionNumber"] for v in remaining} == {1}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
