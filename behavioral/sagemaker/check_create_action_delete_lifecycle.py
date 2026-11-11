"""create-action-delete-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-action-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAction followed by DeleteAction fully removes the lineage entity; a repeat
    DeleteAction and a repeat DescribeAction both return ResourceNotFound."""
    sm = ctx.client("sagemaker")
    action_name = ctx.unique_name("sim2real-behav-action-")

    create_resp = sm.create_action(
        ActionName=action_name,
        Source={"SourceUri": f"s3://sim2real-behav/{action_name}", "SourceType": "S3Uri"},
        ActionType="ModelDeployment",
        Description="sim2real behavioral check lineage action",
    )
    action_arn = create_resp["ActionArn"]
    ctx.on_cleanup(lambda: _delete_action_ignore_not_found(sm, action_name))

    described = sm.describe_action(ActionName=action_name)
    assert described["ActionArn"] == action_arn, (
        f"expected describe_action to echo {action_arn!r}, got {described['ActionArn']!r}"
    )
    assert described["ActionType"] == "ModelDeployment", (
        f"expected ActionType 'ModelDeployment', got {described['ActionType']!r}"
    )

    sm.delete_action(ActionName=action_name)

    code, message = _error(lambda: sm.describe_action(ActionName=action_name))
    assert code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {code!r}"
    expected_message = f"Action 'arn:aws:sagemaker:{ctx.region}:{ctx.account}:action/{action_name}' does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    repeat_code, repeat_message = _error(lambda: sm.delete_action(ActionName=action_name))
    assert repeat_code == "ResourceNotFound", f"expected ResourceNotFound on repeat delete, got {repeat_code!r}"
    expected_repeat_message = f"Action 'arn:aws:sagemaker:{ctx.region}:{ctx.account}:action/{action_name}' does not exist."
    assert repeat_message == expected_repeat_message, (
        f"expected message {expected_repeat_message!r}, got {repeat_message!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_action_ignore_not_found(sm, action_name):
    from botocore.exceptions import ClientError

    try:
        sm.delete_action(ActionName=action_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
