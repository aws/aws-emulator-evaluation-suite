"""action-create-describe-delete-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "action-create-describe-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAction lineage entity is describable; DeleteAction removes it, and afterward both
    an independent DescribeAction and a repeat DeleteAction 404 on the dead id."""
    sm = ctx.client("sagemaker")
    action_name = ctx.unique_name("sim2real-sm-action-")

    created = sm.create_action(
        ActionName=action_name,
        Source={"SourceUri": f"s3://sim2real-lineage/{action_name}", "SourceType": "Custom"},
        ActionType="ModelDeployment",
        Description="sim2real behavioral lifecycle check",
        Tags=[{"Key": "Name", "Value": action_name}],
    )
    action_arn = created["ActionArn"]
    ctx.on_cleanup(lambda: _delete_action_if_present(ctx, action_name))

    described = sm.describe_action(ActionName=action_name)
    assert described["ActionName"] == action_name, (
        f"expected ActionName {action_name!r}, got {described.get('ActionName')!r}"
    )
    assert described["ActionArn"] == action_arn, (
        f"expected ActionArn {action_arn!r}, got {described.get('ActionArn')!r}"
    )
    assert described["ActionType"] == "ModelDeployment", (
        f"expected ActionType 'ModelDeployment', got {described.get('ActionType')!r}"
    )
    assert described["Source"]["SourceType"] == "Custom", (
        f"expected Source.SourceType 'Custom', got {described.get('Source', {}).get('SourceType')!r}"
    )
    assert described["Description"] == "sim2real behavioral lifecycle check", (
        f"expected Description to round-trip, got {described.get('Description')!r}"
    )

    sm.delete_action(ActionName=action_name)

    describe_err = _client_error(lambda: sm.describe_action(ActionName=action_name))
    assert describe_err["Code"] == "ResourceNotFound", (
        f"expected ResourceNotFound describing a deleted action, got {describe_err!r}"
    )
    expected_describe = f"Action '{action_arn}' does not exist."
    assert describe_err["Message"] == expected_describe, (
        f"expected message {expected_describe!r}, got {describe_err.get('Message')!r}"
    )

    delete_err = _client_error(lambda: sm.delete_action(ActionName=action_name))
    assert delete_err["Code"] == "ResourceNotFound", (
        f"expected ResourceNotFound on a repeat delete of a dead action, got {delete_err!r}"
    )
    expected_delete = f"Action '{action_arn}' does not exist."
    assert delete_err["Message"] == expected_delete, (
        f"expected message {expected_delete!r}, got {delete_err.get('Message')!r}"
    )


def _delete_action_if_present(ctx, action_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        sm.delete_action(ActionName=action_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
