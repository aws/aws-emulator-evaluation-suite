"""action-create-describe-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "action-create-describe-delete"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A lineage Action's attributes persist across create->describe and the resource is
    gone (404) after delete."""
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-behav-action-")
    source_uri = f"s3://sim2real-behav-bucket/{name}"

    sm.create_action(
        ActionName=name,
        Source={"SourceUri": source_uri, "SourceType": "SageMakerModel"},
        ActionType="ModelDeployment",
        Description="sim2real behavioral fidelity check action",
        Properties={"env": "test"},
        Status="InProgress",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_action_best_effort(sm, name))

    described = sm.describe_action(ActionName=name)
    assert described["ActionArn"], "expected a non-empty ActionArn on describe"
    assert described["Source"]["SourceUri"] == source_uri, (
        f"expected SourceUri {source_uri!r}, got {described['Source']['SourceUri']!r}"
    )
    assert described["Source"]["SourceType"] == "SageMakerModel", (
        f"expected SourceType 'SageMakerModel', got {described['Source']['SourceType']!r}"
    )
    assert described["ActionType"] == "ModelDeployment", (
        f"expected ActionType 'ModelDeployment', got {described['ActionType']!r}"
    )
    assert described["Status"] == "InProgress", (
        f"expected Status 'InProgress', got {described['Status']!r}"
    )
    assert described["Properties"] == {"env": "test"}, (
        f"expected Properties {{'env': 'test'}}, got {described['Properties']!r}"
    )

    sm.delete_action(ActionName=name)

    arn = described["ActionArn"]
    code, message = _error(lambda: sm.describe_action(ActionName=name))
    assert code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {code}"
    assert message == f"Action '{arn}' does not exist.", f"unexpected DescribeAction message: {message!r}"

    # A mutation on the dead id must also fail, not just the read.
    update_code, update_message = _error(lambda: sm.update_action(ActionName=name, Status="Completed"))
    assert update_code == "ResourceNotFound", (
        f"expected UpdateAction on a deleted action to fail ResourceNotFound, got {update_code}"
    )
    assert update_message == f"Action '{arn}' does not exist.", f"unexpected UpdateAction message: {update_message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to fail, but it SUCCEEDED and returned {result!r}")


def _delete_action_best_effort(sm, name):
    try:
        sm.delete_action(ActionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
