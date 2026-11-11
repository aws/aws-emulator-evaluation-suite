"""action-lifecycle-transitions."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "action-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Action is retrievable after CreateAction and DescribeAction 404s after DeleteAction."""
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-action-")
    source_uri = f"https://example.com/sim2real/actions/{name}"

    create_resp = sm.create_action(
        ActionName=name,
        Source={"SourceUri": source_uri, "SourceType": "Custom"},
        ActionType="ModelDeployment",
        Description="sim2real behavioral fidelity check",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    action_arn = create_resp["ActionArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sm.delete_action(ActionName=name)))

    described = sm.describe_action(ActionName=name)
    assert described["ActionArn"] == action_arn, f"expected ActionArn {action_arn}, got {described['ActionArn']}"
    assert described["ActionName"] == name, f"expected ActionName {name}, got {described['ActionName']}"
    assert described["ActionType"] == "ModelDeployment", (
        f"expected ActionType ModelDeployment, got {described['ActionType']}"
    )
    assert described["Source"]["SourceUri"] == source_uri, (
        f"expected Source.SourceUri {source_uri}, got {described['Source']['SourceUri']}"
    )

    sm.delete_action(ActionName=name)

    describe_err = _client_error(lambda: sm.describe_action(ActionName=name))
    assert describe_err["Code"] == "ResourceNotFound", f"expected ResourceNotFound after delete, got {describe_err!r}"
    expected_describe = f"Action '{action_arn}' does not exist."
    assert describe_err["Message"] == expected_describe, (
        f"expected message {expected_describe!r}, got {describe_err.get('Message')!r}"
    )

    # A mutation on the dead id must also fail — not just the read.
    update_err = _client_error(lambda: sm.update_action(ActionName=name, Description="post-delete"))
    assert update_err["Code"] == "ResourceNotFound", (
        f"expected UpdateAction on a deleted action to fail with ResourceNotFound, got {update_err!r}"
    )
    expected_update = f"Action '{action_arn}' does not exist."
    assert update_err["Message"] == expected_update, (
        f"expected message {expected_update!r}, got {update_err.get('Message')!r}"
    )


def _client_error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected this call against a deleted action to fail, but it SUCCEEDED: {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
