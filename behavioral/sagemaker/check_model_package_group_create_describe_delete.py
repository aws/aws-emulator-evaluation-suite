"""model-package-group-create-describe-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "model-package-group-create-describe-delete"
GROUP = 'lifecycle'
SERVICES = ['sagemaker']

def _create_model_package_group(ctx, name=None):
    sm = ctx.client("sagemaker")
    name = name or ctx.unique_name("sim2real-behav-mpg-")
    arn = sm.create_model_package_group(
        ModelPackageGroupName=name,
        ModelPackageGroupDescription="behav registry group",
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )["ModelPackageGroupArn"]
    ctx.on_cleanup(lambda: _delete_group_tolerating_absence(sm, name))
    return name, arn


def _delete_group_tolerating_absence(sm, name):
    """The check deletes the group itself as part of its claim, so a teardown delete can
    legitimately find it already gone."""
    try:
        sm.delete_model_package_group(ModelPackageGroupName=name)
    except ClientError as exc:
        if exc.response["Error"].get("Code") != "ValidationException":
            raise


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateModelPackageGroup -> Describe reports Completed status -> Delete -> gone
    and unusable, and the freed name is immediately reusable."""
    sm = ctx.client("sagemaker")
    name, arn = _create_model_package_group(ctx)

    desc = sm.describe_model_package_group(ModelPackageGroupName=name)
    assert desc["ModelPackageGroupArn"] == arn, desc
    assert desc["ModelPackageGroupName"] == name, desc
    # A newly created group is immediately usable (registry metadata only).
    assert desc["ModelPackageGroupStatus"] == "Completed", desc["ModelPackageGroupStatus"]

    sm.delete_model_package_group(ModelPackageGroupName=name)

    describe_code, describe_message = _error(
        lambda: sm.describe_model_package_group(ModelPackageGroupName=name)
    )
    assert describe_code == "ValidationException", f"describe after delete: {describe_code!r}"
    expected_message = f"ModelPackageGroup {arn} does not exist."
    assert describe_message == expected_message, (
        f"expected message {expected_message!r}, got {describe_message!r}"
    )

    delete_again_code, delete_again_message = _error(
        lambda: sm.delete_model_package_group(ModelPackageGroupName=name)
    )
    assert delete_again_code == "ValidationException", f"delete after delete: {delete_again_code!r}"
    expected_message = f"ModelPackageGroup {arn} does not exist."
    assert delete_again_message == expected_message, (
        f"expected message {expected_message!r}, got {delete_again_message!r}"
    )

    # The name is not permanently reserved: once the group is truly gone, it is reusable.
    sm.create_model_package_group(
        ModelPackageGroupName=name,
        ModelPackageGroupDescription="behav registry group (reused name)",
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )
    ctx.on_cleanup(lambda: _delete_group_tolerating_absence(sm, name))

    # Independent read at the destination proves the reused name is a real, live group again.
    redesc = sm.describe_model_package_group(ModelPackageGroupName=name)
    assert redesc["ModelPackageGroupArn"] == arn, (redesc, arn)
    assert redesc["ModelPackageGroupStatus"] == "Completed", redesc["ModelPackageGroupStatus"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
