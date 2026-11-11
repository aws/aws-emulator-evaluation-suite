"""op-contract-delete-launch-template-versions."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-delete-launch-template-versions"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteLaunchTemplateVersions: batch delete of a non-default version succeeds while
    an unknown version number in the same batch reports a per-item error (partial-failure
    contract - the API never raises a top-level ClientError for a bad version number)."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-ltv-")

    lt = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    ec2.create_launch_template_version(
        LaunchTemplateId=lt_id,
        LaunchTemplateData={"InstanceType": "t3.small"},
    )
    versions = ec2.describe_launch_template_versions(LaunchTemplateId=lt_id)["LaunchTemplateVersions"]
    got_versions = {v["VersionNumber"] for v in versions}
    assert got_versions == {1, 2}, f"expected versions {{1, 2}} after create, got {got_versions}"

    # success path + error boundary in ONE batch call: version 2 (non-default, deletable)
    # and version 99 (doesn't exist) are requested together.
    resp = ec2.delete_launch_template_versions(
        LaunchTemplateId=lt_id,
        Versions=["2", "99"],
    )

    succeeded = {v["VersionNumber"] for v in resp["SuccessfullyDeletedLaunchTemplateVersions"]}
    assert succeeded == {2}, f"expected version 2 to be deleted, got {succeeded}"

    failures = resp["UnsuccessfullyDeletedLaunchTemplateVersions"]
    assert len(failures) == 1 and failures[0]["VersionNumber"] == 99, (
        f"expected exactly one per-item failure for version 99, got {failures}"
    )
    code = failures[0]["ResponseError"]["Code"]
    message = failures[0]["ResponseError"].get("Message")
    # real AWS reports a bare (non "Invalid<Resource>.<Reason>"-style) code for a
    # missing version number in this per-item failure entry: "launchTemplateVersionDoesNotExist".
    assert code == "launchTemplateVersionDoesNotExist", (
        f"expected a version-not-found error code, got {code}"
    )
    assert message == "The launch template version does not exist.", f"unexpected message {message!r}"

    remaining = ec2.describe_launch_template_versions(LaunchTemplateId=lt_id)["LaunchTemplateVersions"]
    remaining_versions = {v["VersionNumber"] for v in remaining}
    assert remaining_versions == {1}, (
        f"expected only version 1 to remain after the batch delete, got {remaining_versions}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
