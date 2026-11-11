"""action-create-delete-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "action-create-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Action goes Create -> Describe(exists) -> Delete -> Describe/Delete = ResourceNotFound."""
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-action-")

    resp = sm.create_action(
        ActionName=name,
        Source={"SourceUri": f"s3://sim2real-behav-lineage/{name}", "SourceType": "Approval"},
        ActionType="ModelDeployment",
        Tags=[{"Key": "Name", "Value": name}],
    )
    arn = resp["ActionArn"]

    cleaned = {"done": False}

    def _cleanup() -> None:
        if not cleaned["done"]:
            try:
                sm.delete_action(ActionName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFound":
                    raise

    ctx.on_cleanup(_cleanup)

    desc = sm.describe_action(ActionName=name)
    assert desc["ActionArn"] == arn, f"expected ActionArn {arn!r}, got {desc.get('ActionArn')!r}"
    assert desc["ActionType"] == "ModelDeployment", (
        f"expected ActionType 'ModelDeployment', got {desc.get('ActionType')!r}"
    )

    sm.delete_action(ActionName=name)
    cleaned["done"] = True

    describe_err = _client_error(lambda: sm.describe_action(ActionName=name))
    assert describe_err["Code"] == "ResourceNotFound", (
        f"expected ResourceNotFound describing a deleted action, got {describe_err!r}"
    )
    expected_describe = f"Action '{arn}' does not exist."
    assert describe_err["Message"] == expected_describe, (
        f"expected message {expected_describe!r}, got {describe_err.get('Message')!r}"
    )

    delete_err = _client_error(lambda: sm.delete_action(ActionName=name))
    assert delete_err["Code"] == "ResourceNotFound", (
        f"expected ResourceNotFound on a repeat delete of a dead action, got {delete_err!r}"
    )
    expected_delete = f"Action '{arn}' does not exist."
    assert delete_err["Message"] == expected_delete, (
        f"expected message {expected_delete!r}, got {delete_err.get('Message')!r}"
    )


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
