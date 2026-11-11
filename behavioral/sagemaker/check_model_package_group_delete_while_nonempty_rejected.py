"""model-package-group-delete-while-nonempty-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-package-group-delete-while-nonempty-rejected"
GROUP = "e2e"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteModelPackageGroup on a group holding a model package is rejected with
    ValidationException and leaves the group intact; once the package is removed the same
    delete succeeds (positive control), so the refusal is state-conditional."""
    sm = ctx.client("sagemaker")

    group_name = ctx.unique_name("sim2real-mpg-")
    tag_key_value = [{"Key": "sim2real", "Value": CHECK}]
    group_arn = sm.create_model_package_group(
        ModelPackageGroupName=group_name, Tags=tag_key_value
    )["ModelPackageGroupArn"]
    ctx.on_cleanup(lambda: _delete_group(sm, group_name))

    # A versioned model package can be registered against a group with only
    # metadata (no InferenceSpecification/SourceAlgorithmSpecification yet --
    # those can be filled in later via UpdateModelPackage); this avoids
    # CreateModelPackage's cross-account-image / image-existence validation
    # entirely while still producing a real, non-empty group.
    model_package_arn = sm.create_model_package(
        ModelPackageGroupName=group_name,
        ModelApprovalStatus="PendingManualApproval",
        ModelPackageDescription="sim2real behavioral probe placeholder version",
    )["ModelPackageArn"]

    ctx.on_cleanup(lambda: _delete_model_package(sm, model_package_arn))

    code, message = _error(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        f"Model Package Group {group_arn} cannot be deleted because it still contains "
        "Model Packages."
    )
    assert message == expected_message, (
        f"refusal must name the group and state it still contains model packages: "
        f"expected {expected_message!r}, got {message!r}"
    )

    # Effect absent: the group must still exist, unaffected by the rejected call.
    still_there = sm.describe_model_package_group(ModelPackageGroupName=group_name)
    assert still_there["ModelPackageGroupArn"] == group_arn
    assert still_there["ModelPackageGroupStatus"] != "Deleting"

    # Positive control: once the group is actually empty, the identical call succeeds.
    sm.delete_model_package(ModelPackageName=model_package_arn)
    sm.delete_model_package_group(ModelPackageGroupName=group_name)
    final_code, final_message = _error(lambda: sm.describe_model_package_group(ModelPackageGroupName=group_name))
    assert final_code == "ValidationException", f"C={final_code!r}"
    expected_message = f"ModelPackageGroup {group_arn} does not exist."
    assert final_message == expected_message, (
        f"expected message {expected_message!r}, got {final_message!r}"
    )


def _delete_group(sm, group_name):
    _delete_if_present(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))


def _delete_model_package(sm, model_package_arn):
    _delete_if_present(lambda: sm.delete_model_package(ModelPackageName=model_package_arn))


def _delete_if_present(fn) -> None:
    """Teardown delete: returns once SageMaker reports the resource does not exist, retries the
    'still contains Model Packages' refusal while a package delete settles, and raises the rest."""
    deadline = time.monotonic() + 30
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            err = exc.response["Error"]
            message = err.get("Message", "")
            gone = err["Code"] == "ResourceNotFound" or (
                err["Code"] == "ValidationException" and "does not exist" in message
            )
            if gone:
                return
            if "still contains" not in message or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises,
    because accepting a call AWS refuses is a failure, not a message mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
