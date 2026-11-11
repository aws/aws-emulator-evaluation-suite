"""action-lifecycle-create-describe-delete."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "action-lifecycle-create-describe-delete"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An Action transitions from created to describable to a 404 on describe after delete,
    and a repeat delete on the now-dead id fails the same way."""
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-action-")
    source_uri = f"s3://sim2real-lineage-bucket/{name}"

    created = sm.create_action(
        ActionName=name,
        Source={"SourceUri": source_uri, "SourceType": "Custom"},
        ActionType="ModelDeployment",
        Description="sim2real behavioral check action",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    arn = created["ActionArn"]
    ctx.on_cleanup(lambda: _delete_action_ignore(sm, name))

    desc = sm.describe_action(ActionName=name)
    assert desc["ActionArn"] == arn, f"expected ActionArn {arn!r}, got {desc.get('ActionArn')!r}"
    assert desc["ActionName"] == name, f"expected ActionName {name!r}, got {desc.get('ActionName')!r}"
    assert desc["ActionType"] == "ModelDeployment", (
        f"expected ActionType ModelDeployment, got {desc.get('ActionType')!r}"
    )
    assert desc["Source"]["SourceUri"] == source_uri, (
        f"expected SourceUri {source_uri!r}, got {desc.get('Source', {}).get('SourceUri')!r}"
    )

    sm.delete_action(ActionName=name)

    describe_err = _client_error(lambda: sm.describe_action(ActionName=name))
    assert describe_err["Code"] == "ResourceNotFound", (
        f"expected ResourceNotFound on describe after delete, got {describe_err!r}"
    )
    expected_describe = f"Action '{arn}' does not exist."
    assert describe_err["Message"] == expected_describe, (
        f"expected message {expected_describe!r}, got {describe_err.get('Message')!r}"
    )

    delete_err = _client_error(lambda: sm.delete_action(ActionName=name))
    assert delete_err["Code"] == "ResourceNotFound", (
        f"expected ResourceNotFound on repeat delete of dead id, got {delete_err!r}"
    )
    expected_delete = f"Action '{arn}' does not exist."
    assert delete_err["Message"] == expected_delete, (
        f"expected message {expected_delete!r}, got {delete_err.get('Message')!r}"
    )


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


def _delete_action_ignore(sm, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        sm.delete_action(ActionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
