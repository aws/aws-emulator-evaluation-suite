"""op-contract-delete-launch-template."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-launch-template"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteLaunchTemplate: DryRun boundary + real delete removes template and all versions."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-lt-")

    lt = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real-managed", "Value": "true"}]}
        ],
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: _delete_if_present(ec2, lt_id))

    # add a second version so we can assert ALL versions vanish, not just the default
    ec2.create_launch_template_version(
        LaunchTemplateId=lt_id,
        LaunchTemplateData={"InstanceType": "t3.small"},
    )
    versions = ec2.describe_launch_template_versions(LaunchTemplateId=lt_id)["LaunchTemplateVersions"]
    assert len(versions) == 2, f"expected 2 versions (default + new), got {len(versions)}"

    # error boundary: DryRun short-circuits with DryRunOperation, template survives
    code, message = _error(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id, DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"
    surviving = ec2.describe_launch_templates(LaunchTemplateIds=[lt_id])["LaunchTemplates"]
    assert len(surviving) == 1, f"expected the template to survive a DryRun delete, got {surviving}"

    # success path: deleting the template deletes ALL of its versions
    resp = ec2.delete_launch_template(LaunchTemplateId=lt_id)
    assert resp["LaunchTemplate"]["LaunchTemplateId"] == lt_id, (
        f"expected delete response to echo {lt_id}, got {resp['LaunchTemplate']['LaunchTemplateId']}"
    )

    not_found = f"The specified launch template, with template ID {lt_id}, does not exist."
    code, message = _error(lambda: ec2.describe_launch_templates(LaunchTemplateIds=[lt_id]))
    assert code == "InvalidLaunchTemplateId.NotFound", f"expected NotFound, got {code}"
    assert message == "At least one of the launch templates specified in the request does not exist.", f"unexpected DescribeLaunchTemplates message {message!r}"

    code, message = _error(lambda: ec2.describe_launch_template_versions(LaunchTemplateId=lt_id))
    assert code == "InvalidLaunchTemplateId.NotFound", f"expected NotFound, got {code}"
    assert message == not_found, f"unexpected DescribeLaunchTemplateVersions message {message!r}"

    # a mutation on the dead id must fail too, not silently no-op: a second delete of an
    # already-deleted template is not the idempotent-no-op shape some other EC2 deletes use.
    code, message = _error(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    assert code == "InvalidLaunchTemplateId.NotFound", f"expected a double-delete NotFound, got {code}"
    assert message == not_found, f"unexpected double-delete message {message!r}"


def _delete_if_present(ec2, lt_id):
    """Teardown: the check deletes the template itself, so an already-gone template is fine."""
    try:
        ec2.delete_launch_template(LaunchTemplateId=lt_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidLaunchTemplateId.NotFound":
            raise


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a call that
    succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
